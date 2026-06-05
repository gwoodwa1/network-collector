package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type parserFixtureManifest struct {
	ConfigFile  string              `yaml:"config_file"`
	ParsersFile string              `yaml:"parsers_file"`
	Cases       []parserFixtureCase `yaml:"cases"`
}

type parserFixtureCase struct {
	Name             string             `yaml:"name"`
	Input            string             `yaml:"input"`
	BaselineInput    string             `yaml:"baseline_input"`
	Parser           string             `yaml:"parser"`
	BaselineParser   string             `yaml:"baseline_parser"`
	ConfigRef        *parserFixtureRef  `yaml:"config_ref"`
	BaselineRef      *parserFixtureRef  `yaml:"baseline_config_ref"`
	BaselineRegister string             `yaml:"baseline_register"`
	Validation       *ValidationConfig  `yaml:"validation"`
	Validations      []ValidationConfig `yaml:"validations"`
	Vars             map[string]string  `yaml:"vars"`
	ExpectPass       *bool              `yaml:"expect_pass"`
}

type parserFixtureRef struct {
	SSHIndex int    `yaml:"ssh_index"`
	Step     string `yaml:"step"`
}

func TestParserFixtures(t *testing.T) {
	manifestPath := filepath.Join("testdata", "parser-fixtures.yaml")
	manifest, err := loadParserFixtureManifest(manifestPath)
	if err != nil {
		t.Fatalf("failed to load parser fixture manifest: %v", err)
	}
	if len(manifest.Cases) == 0 {
		t.Fatalf("parser fixture manifest has no cases")
	}

	baseDir := filepath.Dir(manifestPath)
	parsersPath := fixturePath(baseDir, manifest.ParsersFile, "../../parsers.yaml")
	parsers, err := loadParsers(parsersPath, "")
	if err != nil {
		t.Fatalf("failed to load fixture parsers %q: %v", parsersPath, err)
	}

	configPath := fixturePath(baseDir, manifest.ConfigFile, "../../config.yaml")
	config, err := loadFixtureConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load fixture config %q: %v", configPath, err)
	}

	for _, tc := range manifest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			runParserFixtureCase(t, baseDir, tc, config, parsers.Parsers)
		})
	}
}

func loadParserFixtureManifest(path string) (parserFixtureManifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return parserFixtureManifest{}, err
	}

	var manifest parserFixtureManifest
	if err := yaml.Unmarshal(b, &manifest); err != nil {
		return parserFixtureManifest{}, err
	}
	return manifest, nil
}

func fixturePath(baseDir, configured, fallback string) string {
	path := strings.TrimSpace(configured)
	if path == "" {
		path = fallback
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

func loadFixtureConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var config Config
	if err := yaml.Unmarshal(b, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func runParserFixtureCase(t *testing.T, baseDir string, tc parserFixtureCase, config Config, parsers map[string]ParserModuleConfig) {
	t.Helper()

	if strings.TrimSpace(tc.Name) == "" {
		t.Fatalf("fixture case missing name")
	}
	if strings.TrimSpace(tc.Input) == "" {
		t.Fatalf("fixture case %q missing input", tc.Name)
	}

	step, hasStepRef, err := fixtureStepFromConfig(config, tc.ConfigRef)
	if err != nil {
		t.Fatalf("failed to resolve config_ref: %v", err)
	}
	baselineStep, hasBaselineRef, err := fixtureStepFromConfig(config, tc.BaselineRef)
	if err != nil {
		t.Fatalf("failed to resolve baseline_config_ref: %v", err)
	}

	parserName := strings.TrimSpace(tc.Parser)
	if parserName == "" && hasStepRef {
		parserName = strings.TrimSpace(step.Parser)
	}
	if parserName == "" {
		t.Fatalf("fixture case %q needs parser or config_ref with parser", tc.Name)
	}

	validations := fixtureValidations(tc, step, hasStepRef)
	if len(validations) == 0 {
		t.Fatalf("fixture case %q needs validation/validations or config_ref with validation", tc.Name)
	}

	vars := map[string]string{}
	for k, v := range tc.Vars {
		vars[k] = v
	}
	if strings.TrimSpace(tc.BaselineInput) != "" {
		registerName := strings.TrimSpace(tc.BaselineRegister)
		if registerName == "" && hasBaselineRef {
			registerName = strings.TrimSpace(baselineStep.Register)
		}
		if registerName == "" {
			t.Fatalf("fixture case %q needs baseline_register or baseline config step register", tc.Name)
		}

		baselineParser := strings.TrimSpace(tc.BaselineParser)
		if baselineParser == "" && hasBaselineRef {
			baselineParser = strings.TrimSpace(baselineStep.Parser)
		}
		if baselineParser == "" {
			baselineParser = parserName
		}

		baselineParsed := parseFixtureInput(t, baseDir, tc.BaselineInput, baselineParser, parsers)
		vars[registerName] = baselineParsed
	}

	parsed := parseFixtureInput(t, baseDir, tc.Input, parserName, parsers)

	results, overall, err := runStepValidations(parsed, validations, vars)
	if err != nil {
		if fixtureExpectPass(tc) {
			t.Fatalf("fixture validations errored: %v", err)
		}
		return
	}
	if fixtureExpectPass(tc) && !overall.Pass {
		t.Fatalf("fixture validations failed: overall=%+v results=%+v parsed=%s", overall, results, parsed)
	}
	if !fixtureExpectPass(tc) && overall.Pass {
		t.Fatalf("fixture validations passed but expected failure: overall=%+v results=%+v parsed=%s", overall, results, parsed)
	}
}

func parseFixtureInput(t *testing.T, baseDir, input, parserName string, parsers map[string]ParserModuleConfig) string {
	t.Helper()

	inputPath := fixturePath(baseDir, input, "")
	output, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("failed to read fixture input %q: %v", inputPath, err)
	}

	parsed, err := parseOutputWithModule(string(output), parserName, parsers)
	if err != nil {
		t.Fatalf("failed to parse fixture input %q with parser %q: %v", inputPath, parserName, err)
	}
	return parsed
}

func fixtureExpectPass(tc parserFixtureCase) bool {
	if tc.ExpectPass == nil {
		return true
	}
	return *tc.ExpectPass
}

func fixtureStepFromConfig(config Config, ref *parserFixtureRef) (StepConfig, bool, error) {
	if ref == nil {
		return StepConfig{}, false, nil
	}
	if ref.SSHIndex < 0 || ref.SSHIndex >= len(config.SSH) {
		return StepConfig{}, false, errFixture("ssh index %d out of range", ref.SSHIndex)
	}

	device := config.SSH[ref.SSHIndex]
	stepName := strings.TrimSpace(ref.Step)
	if stepName == "" {
		return StepConfig{
			Name:        "device-command",
			Command:     device.Command,
			Parser:      device.Parser,
			Validation:  device.Validation,
			Validations: device.Validations,
		}, true, nil
	}

	for _, step := range device.Steps {
		if strings.TrimSpace(step.Name) == stepName {
			return step, true, nil
		}
	}
	return StepConfig{}, false, errFixture("step %q not found in ssh[%d]", stepName, ref.SSHIndex)
}

func fixtureValidations(tc parserFixtureCase, step StepConfig, hasStepRef bool) []ValidationConfig {
	validations := []ValidationConfig{}
	if hasStepRef {
		validations = append(validations, stepValidations(step)...)
	}
	if tc.Validation != nil {
		validations = append(validations, *tc.Validation)
	}
	validations = append(validations, tc.Validations...)
	return validations
}

func errFixture(format string, args ...interface{}) error {
	return fmt.Errorf(strings.TrimSpace(format), args...)
}
