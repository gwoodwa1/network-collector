package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/gwoodwa1/network-collector/pkg/credentials"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
	"github.com/gwoodwa1/network-collector/pkg/validation"
	"github.com/sirikothe/gotextfsm"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type RetryConfig struct {
	IntervalSeconds int  `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	MaxAttempts     int  `mapstructure:"max_attempts" yaml:"max_attempts"`
	UntilPass       bool `mapstructure:"until_pass" yaml:"until_pass"`
}

type SSHProbeConfig struct {
	Port            int `mapstructure:"port" yaml:"port"`
	IntervalSeconds int `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	MaxAttempts     int `mapstructure:"max_attempts" yaml:"max_attempts"`
	TimeoutSeconds  int `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	PostWaitSeconds int `mapstructure:"post_wait_seconds" yaml:"post_wait_seconds"`
}

type ValidationActionConfig struct {
	Action  string            `mapstructure:"action" yaml:"action"`
	Command string            `mapstructure:"cmd" yaml:"cmd"`
	Message string            `mapstructure:"message" yaml:"message"`
	Steps   []StepConfig      `mapstructure:"steps" yaml:"steps"`
	Output  *StepOutputConfig `mapstructure:"output" yaml:"output"`
}

type StepConfig struct {
	Name           string                  `mapstructure:"name" yaml:"name"`
	Message        string                  `mapstructure:"message" yaml:"message"`
	Command        string                  `mapstructure:"cmd" yaml:"cmd"`
	Parser         string                  `mapstructure:"parser" yaml:"parser"`
	WaitSeconds    int                     `mapstructure:"wait_seconds" yaml:"wait_seconds"`
	ReturnToPrompt *bool                   `mapstructure:"return_to_prompt" yaml:"return_to_prompt"`
	SSHProbe       *SSHProbeConfig         `mapstructure:"ssh_probe" yaml:"ssh_probe"`
	Validation     *ValidationConfig       `mapstructure:"validation" yaml:"validation"`
	Validations    []ValidationConfig      `mapstructure:"validations" yaml:"validations"`
	Retry          *RetryConfig            `mapstructure:"retry" yaml:"retry"`
	Register       string                  `mapstructure:"register" yaml:"register"`
	OnPass         *ValidationActionConfig `mapstructure:"on_pass" yaml:"on_pass"`
	OnFail         *ValidationActionConfig `mapstructure:"on_fail" yaml:"on_fail"`
	Output         *StepOutputConfig       `mapstructure:"output" yaml:"output"`
	Repeat         *RepeatConfig           `mapstructure:"repeat" yaml:"repeat"`
}

type RepeatConfig struct {
	Count           int          `mapstructure:"count" yaml:"count"`
	IntervalSeconds int          `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	StopOnFailure   *bool        `mapstructure:"stop_on_failure" yaml:"stop_on_failure"`
	Steps           []StepConfig `mapstructure:"steps" yaml:"steps"`
}

type DeviceConfig struct {
	Hostname         string             `mapstructure:"hostname" yaml:"hostname"`
	IP               string             `mapstructure:"ip" yaml:"ip"`
	Host             string             `mapstructure:"host" yaml:"host"`
	Hosts            []string           `mapstructure:"hosts" yaml:"hosts"`
	Group            string             `mapstructure:"group" yaml:"group"`
	Groups           []string           `mapstructure:"groups" yaml:"groups"`
	Type             string             `mapstructure:"type" yaml:"type"`
	Timeout          int                `mapstructure:"timeout" yaml:"timeout"`
	OperationTimeout int                `mapstructure:"operation_timeout" yaml:"operation_timeout"`
	Steps            []StepConfig       `mapstructure:"steps" yaml:"steps"`
	Command          string             `mapstructure:"cmd" yaml:"cmd"`
	Parser           string             `mapstructure:"parser" yaml:"parser"`
	Validation       *ValidationConfig  `mapstructure:"validation" yaml:"validation"`
	Validations      []ValidationConfig `mapstructure:"validations" yaml:"validations"`
}

type ValidationConfig struct {
	Extractor    string      `mapstructure:"extractor" yaml:"extractor"`
	Pattern      string      `mapstructure:"pattern" yaml:"pattern"`
	JSONPath     string      `mapstructure:"json_path" yaml:"json_path"`
	Condition    string      `mapstructure:"condition" yaml:"condition"`
	Expected     interface{} `mapstructure:"expected" yaml:"expected"`
	ExpectedType string      `mapstructure:"expected_type" yaml:"expected_type"`
}

type Config struct {
	Imports       []string        `mapstructure:"imports" yaml:"imports"`
	NamePlaybook  string          `mapstructure:"name_playbook" yaml:"name_playbook"`
	InventoryFile string          `mapstructure:"inventory_file" yaml:"inventory_file"`
	ParsersFile   string          `mapstructure:"parsers_file" yaml:"parsers_file"`
	Execution     ExecutionConfig `mapstructure:"execution" yaml:"execution"`
	Output        OutputConfig    `mapstructure:"output" yaml:"output"`
	SSH           []DeviceConfig  `mapstructure:"ssh" yaml:"ssh"`
}

type OutputConfig struct {
	Directory   string `mapstructure:"directory" yaml:"directory"`
	SaveRaw     bool   `mapstructure:"save_raw" yaml:"save_raw"`
	SaveParsed  bool   `mapstructure:"save_parsed" yaml:"save_parsed"`
	SummaryFile string `mapstructure:"summary_file" yaml:"summary_file"`
}

type StepOutputConfig struct {
	SaveRaw    *bool `mapstructure:"save_raw" yaml:"save_raw"`
	SaveParsed *bool `mapstructure:"save_parsed" yaml:"save_parsed"`
}

type ExecutionConfig struct {
	MaxParallel          int `mapstructure:"max_parallel" yaml:"max_parallel"`
	StartIntervalSeconds int `mapstructure:"start_interval_seconds" yaml:"start_interval_seconds"`
	CanaryCount          int `mapstructure:"canary_count" yaml:"canary_count"`
	FailureThreshold     int `mapstructure:"failure_threshold" yaml:"failure_threshold"`
}

type InventoryHostConfig struct {
	Name             string `yaml:"name"`
	Hostname         string `yaml:"hostname"`
	IP               string `yaml:"ip"`
	Address          string `yaml:"address"`
	Type             string `yaml:"type"`
	Timeout          int    `yaml:"timeout"`
	OperationTimeout int    `yaml:"operation_timeout"`
}

type InventoryGroupConfig struct {
	Hosts []string `yaml:"hosts"`
}

type InventoryConfig struct {
	Hosts  []InventoryHostConfig           `yaml:"hosts"`
	Groups map[string]InventoryGroupConfig `yaml:"groups"`
}

type ParserFieldConfig struct {
	Pattern  string `yaml:"pattern"`
	Group    int    `yaml:"group"`
	Repeated bool   `yaml:"repeated"`
	Type     string `yaml:"type"`
}

type ParserModuleConfig struct {
	Type     string                       `yaml:"type"`
	Pattern  string                       `yaml:"pattern"`
	Template string                       `yaml:"template"`
	Root     string                       `yaml:"root"`
	Fields   map[string]ParserFieldConfig `yaml:"fields"`
	baseDir  string
}

type ParsersConfig struct {
	Parsers map[string]ParserModuleConfig `yaml:"parsers"`
}

type deviceValidation struct {
	Hostname string                      `json:"hostname"`
	IP       string                      `json:"ip"`
	Result   validation.ValidationResult `json:"result"`
}

type deviceRunResult struct {
	index      int
	aggregated []deviceValidation
	artifacts  []outputArtifact
	failed     bool
}

type outputArtifact struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Step     string `json:"step"`
	Attempt  int    `json:"attempt"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
}

type runSummary struct {
	RunID       string             `json:"run_id"`
	Playbook    string             `json:"playbook,omitempty"`
	StartedAt   time.Time          `json:"started_at"`
	CompletedAt time.Time          `json:"completed_at"`
	Failed      bool               `json:"failed"`
	Validations []deviceValidation `json:"validations"`
	Artifacts   []outputArtifact   `json:"artifacts"`
}

type deviceVariableState struct {
	mu        sync.Mutex
	cond      *sync.Cond
	variables map[string]string
	order     []int
	next      int
}

var failureLogMu sync.Mutex

// version is replaced at release build time with the Git tag.
var version = "dev"

type stepExecutionContext struct {
	hostname    string
	ip          string
	deviceType  string
	username    string
	password    string
	opts        []ssh.Option
	jsonOut     bool
	sessionLog  io.Writer
	failureLog  string
	variables   map[string]string
	aggregated  *[]deviceValidation
	runFailed   *bool
	parsers     map[string]ParserModuleConfig
	output      OutputConfig
	runDir      string
	deviceIndex int
	artifacts   *[]outputArtifact
	artifactSeq int
}

func renderTemplate(input string, vars map[string]string) (string, error) {
	re := regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
	missing := map[string]bool{}

	output := re.ReplaceAllStringFunc(input, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		name := parts[1]
		value, ok := vars[name]
		if !ok {
			missing[name] = true
			return match
		}
		return value
	})

	if len(missing) > 0 {
		keys := make([]string, 0, len(missing))
		for key := range missing {
			keys = append(keys, key)
		}
		return output, fmt.Errorf("undefined variables: %s", strings.Join(keys, ", "))
	}

	return output, nil
}

func renderExpectedValue(expected interface{}, vars map[string]string) (interface{}, error) {
	if s, ok := expected.(string); ok && strings.Contains(s, "{{") {
		rendered, err := renderTemplate(s, vars)
		if err != nil {
			return nil, err
		}
		return rendered, nil
	}
	return expected, nil
}

func cloneDeviceConfig(device DeviceConfig) DeviceConfig {
	device.Host = ""
	device.Hosts = nil
	device.Group = ""
	device.Groups = nil
	return device
}

func inventoryHostKey(host InventoryHostConfig) string {
	name := strings.TrimSpace(host.Name)
	if name != "" {
		return name
	}
	return strings.TrimSpace(host.Hostname)
}

func inventoryHostIP(host InventoryHostConfig) string {
	ip := strings.TrimSpace(host.IP)
	if ip != "" {
		return ip
	}
	return strings.TrimSpace(host.Address)
}

func applyInventoryHost(device DeviceConfig, host InventoryHostConfig) DeviceConfig {
	resolved := cloneDeviceConfig(device)
	name := inventoryHostKey(host)
	if strings.TrimSpace(resolved.Hostname) == "" {
		resolved.Hostname = name
	}
	if strings.TrimSpace(resolved.IP) == "" {
		resolved.IP = inventoryHostIP(host)
	}
	if strings.TrimSpace(resolved.Type) == "" {
		resolved.Type = strings.TrimSpace(host.Type)
	}
	if resolved.Timeout == 0 {
		resolved.Timeout = host.Timeout
	}
	if resolved.OperationTimeout == 0 {
		resolved.OperationTimeout = host.OperationTimeout
	}
	return resolved
}

func resolveInventoryPath(inventoryFile, configFile string) string {
	path := strings.TrimSpace(inventoryFile)
	if path == "" {
		path = "inventory.yaml"
	}
	if !filepath.IsAbs(path) && strings.TrimSpace(configFile) != "" {
		path = filepath.Join(filepath.Dir(configFile), path)
	}
	return path
}

func loadInventory(inventoryFile, configFile string) (*InventoryConfig, error) {
	path := resolveInventoryPath(inventoryFile, configFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var inventory InventoryConfig
	if err := yaml.Unmarshal(b, &inventory); err != nil {
		return nil, err
	}
	return &inventory, nil
}

func loadOptionalInventory(inventoryFile, configFile string) (*InventoryConfig, error) {
	explicit := strings.TrimSpace(inventoryFile) != ""
	path := resolveInventoryPath(inventoryFile, configFile)
	if !explicit {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	}
	return loadInventory(inventoryFile, configFile)
}

func resolveParsersPath(parsersFile, configFile string) string {
	path := strings.TrimSpace(parsersFile)
	if path == "" {
		path = "parsers.yaml"
	}
	if !filepath.IsAbs(path) && strings.TrimSpace(configFile) != "" {
		path = filepath.Join(filepath.Dir(configFile), path)
	}
	return path
}

func loadParsers(parsersFile, configFile string) (*ParsersConfig, error) {
	path := resolveParsersPath(parsersFile, configFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var parsers ParsersConfig
	if err := yaml.Unmarshal(b, &parsers); err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(path)
	for name, parser := range parsers.Parsers {
		parser.baseDir = baseDir
		parsers.Parsers[name] = parser
	}
	return &parsers, nil
}

func loadOptionalParsers(parsersFile, configFile string) (*ParsersConfig, error) {
	explicit := strings.TrimSpace(parsersFile) != ""
	path := resolveParsersPath(parsersFile, configFile)
	if !explicit {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	}
	return loadParsers(parsersFile, configFile)
}

func parserGroupIndex(field ParserFieldConfig, submatchCount int) int {
	if field.Group > 0 {
		return field.Group
	}
	if submatchCount > 1 {
		return 1
	}
	return 0
}

func coerceParsedValue(value string, valueType string) (interface{}, error) {
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "", "string":
		return value, nil
	case "int":
		i, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		return i, nil
	default:
		return nil, fmt.Errorf("unsupported parser field type: %s", valueType)
	}
}

func parseWithRegexModule(output string, parser ParserModuleConfig) (string, error) {
	parsed := map[string]interface{}{}
	for fieldName, field := range parser.Fields {
		if strings.TrimSpace(field.Pattern) == "" {
			return "", fmt.Errorf("parser field %q missing pattern", fieldName)
		}

		re, err := regexp.Compile(field.Pattern)
		if err != nil {
			return "", fmt.Errorf("parser field %q has invalid regex: %w", fieldName, err)
		}

		if field.Repeated {
			values := []interface{}{}
			for _, match := range re.FindAllStringSubmatch(output, -1) {
				group := parserGroupIndex(field, len(match))
				if group >= len(match) {
					return "", fmt.Errorf("parser field %q group %d not found", fieldName, group)
				}
				value, err := coerceParsedValue(match[group], field.Type)
				if err != nil {
					return "", fmt.Errorf("parser field %q failed to coerce value: %w", fieldName, err)
				}
				values = append(values, value)
			}
			parsed[fieldName] = values
			continue
		}

		match := re.FindStringSubmatch(output)
		if len(match) == 0 {
			parsed[fieldName] = ""
			continue
		}
		group := parserGroupIndex(field, len(match))
		if group >= len(match) {
			return "", fmt.Errorf("parser field %q group %d not found", fieldName, group)
		}
		value, err := coerceParsedValue(match[group], field.Type)
		if err != nil {
			return "", fmt.Errorf("parser field %q failed to coerce value: %w", fieldName, err)
		}
		parsed[fieldName] = value
	}

	b, err := json.Marshal(parsed)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseWithRegexRecords(output string, parser ParserModuleConfig) (string, error) {
	if strings.TrimSpace(parser.Pattern) == "" {
		return "", fmt.Errorf("regex_records parser missing pattern")
	}
	re, err := regexp.Compile(parser.Pattern)
	if err != nil {
		return "", fmt.Errorf("regex_records parser has invalid regex: %w", err)
	}

	records := make([]map[string]interface{}, 0)
	for _, match := range re.FindAllStringSubmatch(output, -1) {
		record := make(map[string]interface{}, len(parser.Fields))
		for fieldName, field := range parser.Fields {
			group := parserGroupIndex(field, len(match))
			if group >= len(match) {
				return "", fmt.Errorf("parser field %q group %d not found", fieldName, group)
			}
			value, err := coerceParsedValue(match[group], field.Type)
			if err != nil {
				return "", fmt.Errorf("parser field %q failed to coerce value: %w", fieldName, err)
			}
			record[fieldName] = value
		}
		records = append(records, record)
	}

	root := strings.TrimSpace(parser.Root)
	if root == "" {
		root = "records"
	}
	encoded, err := json.Marshal(map[string]interface{}{root: records})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func parseWithTextFSM(output string, parser ParserModuleConfig) (string, error) {
	templatePath := strings.TrimSpace(parser.Template)
	if templatePath == "" {
		return "", fmt.Errorf("textfsm parser missing template")
	}
	if !filepath.IsAbs(templatePath) {
		templatePath = filepath.Join(parser.baseDir, templatePath)
	}
	templateBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read TextFSM template %q: %w", templatePath, err)
	}

	var fsm gotextfsm.TextFSM
	if err := fsm.ParseString(string(templateBytes)); err != nil {
		return "", fmt.Errorf("invalid TextFSM template %q: %w", templatePath, err)
	}
	var parsed gotextfsm.ParserOutput
	if err := parsed.ParseTextString(output, fsm, true); err != nil {
		return "", fmt.Errorf("TextFSM parse failed with template %q: %w", templatePath, err)
	}

	root := strings.TrimSpace(parser.Root)
	if root == "" {
		root = "records"
	}
	encoded, err := json.Marshal(map[string]interface{}{root: parsed.Dict})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func parseOutputWithModule(output, parserName string, parsers map[string]ParserModuleConfig) (string, error) {
	parserName = strings.TrimSpace(parserName)
	if parserName == "" {
		return output, nil
	}
	parser, ok := parsers[parserName]
	if !ok {
		return "", fmt.Errorf("parser %q not found", parserName)
	}

	switch strings.ToLower(strings.TrimSpace(parser.Type)) {
	case "", "regex":
		return parseWithRegexModule(output, parser)
	case "regex_records":
		return parseWithRegexRecords(output, parser)
	case "textfsm":
		return parseWithTextFSM(output, parser)
	default:
		return "", fmt.Errorf("unsupported parser type %q for parser %q", parser.Type, parserName)
	}
}

func inventoryIndex(inventory *InventoryConfig) (map[string]InventoryHostConfig, error) {
	index := map[string]InventoryHostConfig{}
	if inventory == nil {
		return index, nil
	}

	for _, host := range inventory.Hosts {
		key := inventoryHostKey(host)
		if key == "" {
			return nil, fmt.Errorf("inventory host missing name or hostname")
		}
		if inventoryHostIP(host) == "" {
			return nil, fmt.Errorf("inventory host %q missing ip or address", key)
		}
		if _, exists := index[key]; exists {
			return nil, fmt.Errorf("duplicate inventory host %q", key)
		}
		index[key] = host
	}
	return index, nil
}

func inventoryTargets(device DeviceConfig) []string {
	targets := []string{}
	if strings.TrimSpace(device.Host) != "" {
		targets = append(targets, strings.TrimSpace(device.Host))
	}
	for _, host := range device.Hosts {
		if strings.TrimSpace(host) != "" {
			targets = append(targets, strings.TrimSpace(host))
		}
	}
	return targets
}

func inventoryGroupNames(device DeviceConfig) []string {
	groups := []string{}
	if strings.TrimSpace(device.Group) != "" {
		groups = append(groups, strings.TrimSpace(device.Group))
	}
	for _, group := range device.Groups {
		if strings.TrimSpace(group) != "" {
			groups = append(groups, strings.TrimSpace(group))
		}
	}
	return groups
}

func resolveInventoryDevices(devices []DeviceConfig, inventory *InventoryConfig) ([]DeviceConfig, error) {
	hostIndex, err := inventoryIndex(inventory)
	if err != nil {
		return nil, err
	}

	var resolved []DeviceConfig
	for _, device := range devices {
		targets := inventoryTargets(device)
		for _, groupName := range inventoryGroupNames(device) {
			if inventory == nil || inventory.Groups == nil {
				return nil, fmt.Errorf("inventory group %q requested but no inventory groups are loaded", groupName)
			}
			group, ok := inventory.Groups[groupName]
			if !ok {
				return nil, fmt.Errorf("inventory group %q not found", groupName)
			}
			for _, host := range group.Hosts {
				if strings.TrimSpace(host) != "" {
					targets = append(targets, strings.TrimSpace(host))
				}
			}
		}

		if len(targets) == 0 {
			resolved = append(resolved, cloneDeviceConfig(device))
			continue
		}

		for _, target := range targets {
			host, ok := hostIndex[target]
			if !ok {
				return nil, fmt.Errorf("inventory host %q not found", target)
			}
			resolved = append(resolved, applyInventoryHost(device, host))
		}
	}
	return resolved, nil
}

func waitDuration(waitSeconds int) (time.Duration, error) {
	if waitSeconds < 0 {
		return 0, fmt.Errorf("wait_seconds must be greater than or equal to 0")
	}
	return time.Duration(waitSeconds) * time.Second, nil
}

func shouldReturnToPrompt(returnToPrompt *bool) bool {
	return returnToPrompt == nil || *returnToPrompt
}

func validationActionForResult(step StepConfig, result validation.ValidationResult) *ValidationActionConfig {
	if result.Status == "pass" {
		return step.OnPass
	}
	if result.Status == "fail" || result.Status == "error" {
		return step.OnFail
	}
	return nil
}

func stepValidations(step StepConfig) []ValidationConfig {
	validations := []ValidationConfig{}
	if step.Validation != nil {
		validations = append(validations, *step.Validation)
	}
	validations = append(validations, step.Validations...)
	return validations
}

func registerParserOutput(vars map[string]string, step StepConfig, parsedOutput string) bool {
	name := strings.TrimSpace(step.Register)
	if name == "" {
		return false
	}
	vars[name] = parsedOutput
	return true
}

func variableScopeKey(hostname, ip string) string {
	return strings.TrimSpace(hostname) + "\x00" + strings.TrimSpace(ip)
}

func overallValidationResult(results []validation.ValidationResult) validation.ValidationResult {
	if len(results) == 0 {
		return validation.ValidationResult{}
	}

	overall := validation.ValidationResult{
		Pass:      true,
		Status:    "pass",
		Message:   "all validations passed",
		Timestamp: time.Now(),
	}
	for _, result := range results {
		if result.Status == "error" {
			overall.Pass = false
			overall.Status = "error"
			overall.Message = "one or more validations errored"
			return overall
		}
		if !result.Pass || result.Status == "fail" {
			overall.Pass = false
			overall.Status = "fail"
			overall.Message = "one or more validations failed"
			return overall
		}
	}
	return overall
}

func isFailureResult(result validation.ValidationResult) bool {
	return result.Status == "fail" || result.Status == "error" || !result.Pass && result.Status != ""
}

func recordStepFailure(ctx *stepExecutionContext, stepName, message string) {
	if ctx == nil {
		return
	}
	if err := appendFailureMessage(ctx, stepName, "error", message); err != nil {
		if ctx.runFailed != nil {
			*ctx.runFailed = true
		}
		slog.Error("error writing failure log", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
		writeSessionf(ctx.sessionLog, "[step:%s] failed to write failure log: %v\n", stepName, err)
	}
}

func validationErrorResult(err error) validation.ValidationResult {
	return validation.ValidationResult{
		Pass:      false,
		Status:    "error",
		Message:   err.Error(),
		Err:       err.Error(),
		Timestamp: time.Now(),
	}
}

func runStepValidations(output string, rules []ValidationConfig, vars map[string]string) ([]validation.ValidationResult, validation.ValidationResult, error) {
	results := []validation.ValidationResult{}
	for _, cfg := range rules {
		pattern, err := renderTemplate(cfg.Pattern, vars)
		if err != nil {
			wrapped := fmt.Errorf("error rendering validation pattern: %w", err)
			results = append(results, validationErrorResult(wrapped))
			return results, overallValidationResult(results), wrapped
		}

		jsonPath, err := renderTemplate(cfg.JSONPath, vars)
		if err != nil {
			wrapped := fmt.Errorf("error rendering validation json_path: %w", err)
			results = append(results, validationErrorResult(wrapped))
			return results, overallValidationResult(results), wrapped
		}

		expected, err := renderExpectedValue(cfg.Expected, vars)
		if err != nil {
			wrapped := fmt.Errorf("error rendering validation expected value: %w", err)
			results = append(results, validationErrorResult(wrapped))
			return results, overallValidationResult(results), wrapped
		}

		rule := validation.ValidationRule{
			Extractor:    cfg.Extractor,
			Pattern:      pattern,
			JSONPath:     jsonPath,
			Condition:    cfg.Condition,
			Expected:     expected,
			ExpectedType: cfg.ExpectedType,
		}

		vres, verr := validation.ValidateOutput(output, rule)
		if verr != nil {
			if vres.Status == "" {
				vres = validationErrorResult(verr)
			}
			results = append(results, vres)
			return results, overallValidationResult(results), verr
		}
		results = append(results, vres)
	}
	return results, overallValidationResult(results), nil
}

func stringToBoolDecodeHook(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
	if from.Kind() != reflect.String || to.Kind() != reflect.Bool {
		return data, nil
	}

	switch strings.ToLower(strings.TrimSpace(data.(string))) {
	case "yes", "y":
		return true, nil
	case "no", "n":
		return false, nil
	default:
		value, err := strconv.ParseBool(strings.TrimSpace(data.(string)))
		if err != nil {
			return data, nil
		}
		return value, nil
	}
}

type resolvedSSHProbe struct {
	Port     int
	Interval time.Duration
	Attempts int
	Timeout  time.Duration
	PostWait time.Duration
}

func resolveSSHProbeConfig(cfg *SSHProbeConfig) (resolvedSSHProbe, error) {
	probe := resolvedSSHProbe{
		Port:     22,
		Interval: 30 * time.Second,
		Attempts: 20,
		Timeout:  5 * time.Second,
	}
	if cfg == nil {
		return probe, nil
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return probe, fmt.Errorf("ssh_probe.port must be between 1 and 65535")
	}
	if cfg.Port > 0 {
		probe.Port = cfg.Port
	}
	if cfg.IntervalSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.interval_seconds must be greater than or equal to 0")
	}
	if cfg.IntervalSeconds > 0 {
		probe.Interval = time.Duration(cfg.IntervalSeconds) * time.Second
	}
	if cfg.MaxAttempts < 0 {
		return probe, fmt.Errorf("ssh_probe.max_attempts must be greater than or equal to 0")
	}
	if cfg.MaxAttempts > 0 {
		probe.Attempts = cfg.MaxAttempts
	}
	if cfg.TimeoutSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.timeout_seconds must be greater than or equal to 0")
	}
	if cfg.TimeoutSeconds > 0 {
		probe.Timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	if cfg.PostWaitSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.post_wait_seconds must be greater than or equal to 0")
	}
	if cfg.PostWaitSeconds > 0 {
		probe.PostWait = time.Duration(cfg.PostWaitSeconds) * time.Second
	}
	return probe, nil
}

func sshProbeAddress(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

func waitForSSHPort(host string, cfg *SSHProbeConfig) error {
	probe, err := resolveSSHProbeConfig(cfg)
	if err != nil {
		return err
	}

	address := sshProbeAddress(host, probe.Port)
	var lastErr error
	for attempt := 1; attempt <= probe.Attempts; attempt++ {
		conn, err := net.DialTimeout("tcp", address, probe.Timeout)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		if attempt < probe.Attempts {
			time.Sleep(probe.Interval)
		}
	}
	return fmt.Errorf("ssh probe failed for %s after %d attempts: %w", address, probe.Attempts, lastErr)
}

func closeSSHClient(client *ssh.Client) error {
	if client == nil {
		return nil
	}
	return client.Close()
}

type validationActionOutcome struct {
	StopDevice bool
	RunFailed  bool
}

func executeValidationAction(ctx *stepExecutionContext, client **ssh.Client, action *ValidationActionConfig, stepName string) (validationActionOutcome, error) {
	if action == nil {
		return validationActionOutcome{}, nil
	}

	if strings.TrimSpace(action.Message) != "" {
		message, err := renderTemplate(action.Message, ctx.variables)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action message: %w", err)
		}
		writeSessionf(ctx.sessionLog, "[step:%s] action: %s\n", stepName, message)
		if !ctx.jsonOut {
			fmt.Printf("device=%s step=%s action=%q\n", ctx.hostname, stepName, message)
		}
	}

	actionName := strings.ToLower(strings.TrimSpace(action.Action))
	if actionName == "" && strings.TrimSpace(action.Command) != "" {
		actionName = "cmd"
	}
	if actionName == "" && len(action.Steps) > 0 {
		actionName = "steps"
	}

	switch actionName {
	case "", "none", "noop", "no_op":
		return validationActionOutcome{}, nil
	case "exit", "stop":
		return validationActionOutcome{StopDevice: true}, nil
	case "fail":
		return validationActionOutcome{StopDevice: true, RunFailed: true}, nil
	case "cmd", "command", "run":
		if client == nil || *client == nil {
			return validationActionOutcome{}, fmt.Errorf("cannot run validation action command without an active SSH session")
		}
		cmd, err := renderTemplate(strings.TrimSpace(action.Command), ctx.variables)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action command: %w", err)
		}
		if cmd == "" {
			return validationActionOutcome{}, fmt.Errorf("validation action command cannot be empty")
		}
		output, err := (*client).Execute(cmd)
		if err != nil {
			return validationActionOutcome{}, err
		}
		writeSessionf(ctx.sessionLog, "\n[step:%s] action command=%q\n%s\n", stepName, cmd, output)
		if !ctx.jsonOut {
			fmt.Printf("device=%s step=%s action_command=%q\n%s\n", ctx.hostname, stepName, cmd, output)
		}
		if err := saveStepArtifact(ctx, StepConfig{Output: action.Output}, stepName+"-action", 1, "raw", output); err != nil {
			return validationActionOutcome{}, err
		}
		if len(action.Steps) == 0 {
			return validationActionOutcome{}, nil
		}
		fallthrough
	case "steps":
		if len(action.Steps) == 0 {
			return validationActionOutcome{}, nil
		}
		if executeSteps(ctx, client, action.Steps) {
			return validationActionOutcome{StopDevice: true}, nil
		}
		return validationActionOutcome{}, nil
	default:
		return validationActionOutcome{}, fmt.Errorf("unsupported validation action: %s", action.Action)
	}
}

const (
	maxRepeatCount = 1000
	maxRepeatDepth = 3
)

func repeatStopsOnFailure(config RepeatConfig) bool {
	return config.StopOnFailure == nil || *config.StopOnFailure
}

func validateRepeatConfig(config RepeatConfig, depth int) error {
	if depth > maxRepeatDepth {
		return fmt.Errorf("repeat nesting exceeds maximum depth of %d", maxRepeatDepth)
	}
	if config.Count < 1 {
		return fmt.Errorf("repeat.count must be at least 1")
	}
	if config.Count > maxRepeatCount {
		return fmt.Errorf("repeat.count must not exceed %d", maxRepeatCount)
	}
	if config.Count > 1 && config.IntervalSeconds < 1 {
		return fmt.Errorf("repeat.interval_seconds must be at least 1 when count is greater than 1")
	}
	if config.IntervalSeconds < 0 {
		return fmt.Errorf("repeat.interval_seconds must be greater than or equal to 0")
	}
	if len(config.Steps) == 0 {
		return fmt.Errorf("repeat.steps must contain at least one step")
	}
	for _, step := range config.Steps {
		if step.Retry != nil && step.Retry.UntilPass && step.Retry.MaxAttempts < 1 {
			return fmt.Errorf("repeat step %q uses retry.until_pass without a finite max_attempts", strings.TrimSpace(step.Name))
		}
		if step.Repeat != nil {
			if err := validateRepeatConfig(*step.Repeat, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func executeRepeat(ctx *stepExecutionContext, client **ssh.Client, config RepeatConfig, stepName string, depth int, sleep func(time.Duration)) bool {
	if err := validateRepeatConfig(config, depth); err != nil {
		*ctx.runFailed = true
		slog.Error("invalid repeat step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
		recordStepFailure(ctx, stepName, fmt.Sprintf("invalid repeat step: %v", err))
		return true
	}

	interval := time.Duration(config.IntervalSeconds) * time.Second
	for iteration := 1; iteration <= config.Count; iteration++ {
		slog.Info("starting repeat iteration", "hostname", ctx.hostname, "step", stepName, "iteration", iteration, "count", config.Count)
		writeSessionf(ctx.sessionLog, "[step:%s] repeat iteration %d/%d\n", stepName, iteration, config.Count)

		iterationFailed := false
		iterationCtx := *ctx
		iterationCtx.runFailed = &iterationFailed
		iterationStopped := executeStepsAtDepth(&iterationCtx, client, config.Steps, depth)
		ctx.artifactSeq = iterationCtx.artifactSeq
		if iterationStopped {
			if iterationFailed {
				*ctx.runFailed = true
			}
			return true
		}
		if iterationFailed {
			*ctx.runFailed = true
			if repeatStopsOnFailure(config) {
				slog.Warn("stopping repeat after failed iteration", "hostname", ctx.hostname, "step", stepName, "iteration", iteration)
				writeSessionf(ctx.sessionLog, "[step:%s] repeat stopped after failed iteration %d/%d\n", stepName, iteration, config.Count)
				break
			}
		}

		if iteration < config.Count {
			slog.Info("waiting between repeat iterations", "hostname", ctx.hostname, "step", stepName, "duration", interval)
			writeSessionf(ctx.sessionLog, "[step:%s] waiting %s before repeat iteration %d/%d\n", stepName, interval, iteration+1, config.Count)
			sleep(interval)
		}
	}
	return false
}

func executeSteps(ctx *stepExecutionContext, client **ssh.Client, steps []StepConfig) bool {
	return executeStepsAtDepth(ctx, client, steps, 0)
}

func executeStepsAtDepth(ctx *stepExecutionContext, client **ssh.Client, steps []StepConfig, depth int) bool {
	stopDeviceSteps := false
	for _, step := range steps {
		stepName := strings.TrimSpace(step.Name)
		if stepName == "" {
			stepName = "unnamed"
		}

		if err := logStepMessage(ctx, stepName, step.Message); err != nil {
			*ctx.runFailed = true
			slog.Error("error rendering step message", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			writeSessionf(ctx.sessionLog, "[step:%s] message error: %v\n", stepName, err)
			recordStepFailure(ctx, stepName, fmt.Sprintf("message error: %v", err))
			continue
		}

		if step.Repeat != nil {
			if strings.TrimSpace(step.Command) != "" || step.WaitSeconds != 0 || step.SSHProbe != nil || len(stepValidations(step)) > 0 {
				*ctx.runFailed = true
				stopDeviceSteps = true
				err := fmt.Errorf("repeat step cannot also define cmd, wait_seconds, ssh_probe, or validations")
				slog.Error("invalid repeat step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				recordStepFailure(ctx, stepName, err.Error())
				break
			}
			if executeRepeat(ctx, client, *step.Repeat, stepName, depth+1, time.Sleep) {
				stopDeviceSteps = true
				break
			}
			continue
		}

		wait, err := waitDuration(step.WaitSeconds)
		if err != nil {
			*ctx.runFailed = true
			slog.Error("invalid wait step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			recordStepFailure(ctx, stepName, fmt.Sprintf("invalid wait step: %v", err))
			continue
		}
		if wait > 0 {
			slog.Info("waiting before step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "duration", wait)
			writeSessionf(ctx.sessionLog, "\n[step:%s] waiting %s\n", stepName, wait)
			time.Sleep(wait)
		}

		if step.SSHProbe != nil {
			probe, err := resolveSSHProbeConfig(step.SSHProbe)
			if err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("invalid SSH probe step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("invalid SSH probe step: %v", err))
				break
			}

			if err := closeSSHClient(*client); err != nil {
				slog.Warn("error closing stale SSH connection before probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] warning: failed to close stale SSH connection before probe: %v\n", stepName, err)
			}
			*client = nil

			slog.Info("probing SSH port", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			writeSessionf(ctx.sessionLog, "\n[step:%s] probing SSH port on %s\n", stepName, ctx.ip)
			if err := waitForSSHPort(ctx.ip, step.SSHProbe); err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("SSH probe failed", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] SSH probe failed: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("SSH probe failed: %v", err))
				break
			}
			writeSessionf(ctx.sessionLog, "[step:%s] SSH probe succeeded\n", stepName)

			if probe.PostWait > 0 {
				slog.Info("waiting after successful SSH probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "duration", probe.PostWait)
				writeSessionf(ctx.sessionLog, "[step:%s] waiting %s after successful SSH probe\n", stepName, probe.PostWait)
				time.Sleep(probe.PostWait)
			}

			*client = ssh.NewClient(ctx.opts...)
			if err := (*client).Connect(ctx.ip, ctx.username, ctx.password, ctx.deviceType); err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("error reconnecting to SSH device after probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] failed to reconnect after SSH probe: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("failed to reconnect after SSH probe: %v", err))
				break
			}
			writeSessionf(ctx.sessionLog, "[step:%s] SSH session re-established\n", stepName)
		}

		cmd, err := renderTemplate(strings.TrimSpace(step.Command), ctx.variables)
		if err != nil {
			*ctx.runFailed = true
			slog.Error("error rendering command", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			recordStepFailure(ctx, stepName, fmt.Sprintf("command render error: %v", err))
			continue
		}
		if cmd == "" {
			if wait > 0 || step.SSHProbe != nil || strings.TrimSpace(step.Message) != "" {
				continue
			}
			*ctx.runFailed = true
			slog.Warn("skipping empty step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			recordStepFailure(ctx, stepName, "empty step command")
			continue
		}

		var finalResult validation.ValidationResult
		var finalValidationResults []validation.ValidationResult
		attempt := 0
		for {
			attempt++

			if client == nil || *client == nil {
				*ctx.runFailed = true
				slog.Error("cannot execute step without an active SSH session", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
				writeSessionf(ctx.sessionLog, "\n[step:%s] command error: no active SSH session\n", stepName)
				recordStepFailure(ctx, stepName, "command error: no active SSH session")
				break
			}

			output, err := (*client).Execute(cmd)
			if err != nil {
				if !shouldReturnToPrompt(step.ReturnToPrompt) {
					slog.Info("step ended without prompt as expected", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "\n[step:%s] command ended without prompt as expected: %v\n", stepName, err)
					if err := closeSSHClient(*client); err != nil {
						slog.Warn("error closing SSH connection after no-prompt step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
						writeSessionf(ctx.sessionLog, "[step:%s] warning: failed to close SSH connection after no-prompt step: %v\n", stepName, err)
					}
					*client = nil
					break
				}
				*ctx.runFailed = true
				slog.Error("error executing step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "\n[step:%s] command error: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("command error: %v", err))
				break
			}

			writeSessionf(ctx.sessionLog, "\n[step:%s] device=%s command=%q\n%s\n", stepName, ctx.hostname, cmd, output)
			if !ctx.jsonOut {
				fmt.Printf("device=%s step=%s command=%q\n%s\n", ctx.hostname, stepName, cmd, output)
			}
			if err := saveStepArtifact(ctx, step, stepName, attempt, "raw", output); err != nil {
				*ctx.runFailed = true
				slog.Error("error saving raw command output", "hostname", ctx.hostname, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] output error: %v\n", stepName, err)
			}

			validationOutput := output
			if strings.TrimSpace(step.Parser) != "" {
				parsedOutput, err := parseOutputWithModule(output, step.Parser, ctx.parsers)
				if err != nil {
					*ctx.runFailed = true
					slog.Error("parser error", "hostname", ctx.hostname, "step", stepName, "parser", step.Parser, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] parser %q error: %v\n", stepName, step.Parser, err)
					recordStepFailure(ctx, stepName, fmt.Sprintf("parser %q error: %v", step.Parser, err))
					break
				}
				validationOutput = parsedOutput
				writeSessionf(ctx.sessionLog, "[step:%s] parser %q output:\n%s\n", stepName, step.Parser, parsedOutput)
				if err := saveStepArtifact(ctx, step, stepName, attempt, "parsed", parsedOutput); err != nil {
					*ctx.runFailed = true
					slog.Error("error saving parsed command output", "hostname", ctx.hostname, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] output error: %v\n", stepName, err)
				}
				if !ctx.jsonOut {
					fmt.Printf("parser output for %s step=%s parser=%s:\n%s\n", ctx.hostname, stepName, step.Parser, parsedOutput)
				}
				if registerParserOutput(ctx.variables, step, validationOutput) {
					slog.Info("registered parser output", "hostname", ctx.hostname, "step", stepName, "variable", strings.TrimSpace(step.Register), "value", validationOutput)
				}
			}

			validations := stepValidations(step)
			if len(validations) == 0 {
				break
			}

			results, overall, verr := runStepValidations(validationOutput, validations, ctx.variables)
			if verr != nil {
				*ctx.runFailed = true
				slog.Error("validation error", "hostname", ctx.hostname, "step", stepName, "error", verr)
			}

			finalResult = overall
			finalValidationResults = results

			for idx, vres := range results {
				if !ctx.jsonOut {
					jb, _ := json.MarshalIndent(vres, "", "  ")
					fmt.Printf("validation result for %s step=%s validation=%d:\n%s\n", ctx.hostname, stepName, idx+1, string(jb))
				}
				jb, _ := json.MarshalIndent(vres, "", "  ")
				writeSessionf(ctx.sessionLog, "[step:%s] validation result %d:\n%s\n", stepName, idx+1, string(jb))
				*ctx.aggregated = append(*ctx.aggregated, deviceValidation{Hostname: ctx.hostname, IP: ctx.ip, Result: vres})
			}

			for _, vres := range results {
				if step.Register != "" && vres.RawExtract != "" {
					ctx.variables[step.Register] = vres.RawExtract
					slog.Info("registered variable", "hostname", ctx.hostname, "step", stepName, "variable", step.Register, "value", vres.RawExtract)
					break
				}
			}

			retryCfg := step.Retry
			if retryCfg != nil && retryCfg.UntilPass && finalResult.Status == "fail" {
				if retryCfg.MaxAttempts > 0 && attempt >= retryCfg.MaxAttempts {
					slog.Warn("step reached max attempts", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "max_attempts", retryCfg.MaxAttempts)
					break
				}

				interval := time.Duration(retryCfg.IntervalSeconds) * time.Second
				if interval <= 0 {
					interval = 60 * time.Second
				}
				slog.Info("retrying step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "interval", interval, "attempt", attempt+1)
				time.Sleep(interval)
				continue
			}

			break
		}

		if len(stepValidations(step)) > 0 {
			if isFailureResult(finalResult) {
				if err := appendFailureLog(ctx, stepName, finalResult, finalValidationResults); err != nil {
					*ctx.runFailed = true
					slog.Error("error writing failure log", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] failed to write failure log: %v\n", stepName, err)
				}
			}

			action := validationActionForResult(step, finalResult)
			outcome, err := executeValidationAction(ctx, client, action, stepName)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("validation action failed", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] validation action failed: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("validation action failed: %v", err))
				break
			}
			if outcome.RunFailed {
				*ctx.runFailed = true
			}
			if outcome.StopDevice {
				stopDeviceSteps = true
				slog.Info("stopping remaining SSH steps after validation action", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
				break
			}
		}
	}
	return stopDeviceSteps
}

func sanitizeLogName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		isSafe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if isSafe {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}

	sanitized := strings.Trim(b.String(), "_")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

func outputEnabled(config Config, devices []DeviceConfig) bool {
	if config.Output.SaveRaw || config.Output.SaveParsed || strings.TrimSpace(config.Output.SummaryFile) != "" {
		return true
	}
	for _, device := range devices {
		for _, step := range device.Steps {
			if step.Output != nil && (step.Output.SaveRaw != nil || step.Output.SaveParsed != nil) {
				return true
			}
		}
	}
	return false
}

func prepareRunOutput(config OutputConfig, runID string) (string, error) {
	directory := strings.TrimSpace(config.Directory)
	if directory == "" {
		directory = "artifacts"
	}
	runDir := filepath.Join(directory, runID)
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	return runDir, nil
}

func stepOutputEnabled(global bool, override *bool) bool {
	if override != nil {
		return *override
	}
	return global
}

func atomicWriteFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".network-collector-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func saveStepArtifact(ctx *stepExecutionContext, step StepConfig, stepName string, attempt int, kind, content string) error {
	if ctx == nil || strings.TrimSpace(ctx.runDir) == "" {
		return nil
	}
	enabled := ctx.output.SaveRaw
	extension := "raw.txt"
	var override *bool
	if step.Output != nil {
		override = step.Output.SaveRaw
	}
	if kind == "parsed" {
		enabled = ctx.output.SaveParsed
		extension = "parsed.json"
		if step.Output != nil {
			override = step.Output.SaveParsed
		}
	}
	if !stepOutputEnabled(enabled, override) {
		return nil
	}

	deviceDir := fmt.Sprintf("%03d-%s", ctx.deviceIndex+1, sanitizeLogName(ctx.hostname))
	ctx.artifactSeq++
	filename := fmt.Sprintf("%s.artifact-%03d.attempt-%03d.%s", sanitizeLogName(stepName), ctx.artifactSeq, attempt, extension)
	path := filepath.Join(ctx.runDir, deviceDir, filename)
	if err := atomicWriteFile(path, []byte(content)); err != nil {
		return fmt.Errorf("failed to save %s output: %w", kind, err)
	}
	if ctx.artifacts != nil {
		*ctx.artifacts = append(*ctx.artifacts, outputArtifact{
			Hostname: ctx.hostname, IP: ctx.ip, Step: stepName, Attempt: attempt, Kind: kind, Path: path,
		})
	}
	return nil
}

func writeRunSummary(config OutputConfig, runDir string, summary runSummary) (string, error) {
	filename := strings.TrimSpace(config.SummaryFile)
	if filename == "" {
		return "", nil
	}
	path := filename
	if !filepath.IsAbs(path) {
		path = filepath.Join(runDir, path)
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := atomicWriteFile(path, encoded); err != nil {
		return "", err
	}
	return path, nil
}

func formatSessionBanner(playbookName, hostname string, started time.Time) string {
	title := strings.TrimSpace(playbookName)
	if title == "" {
		title = "Network Collector Session"
	}

	width := 78
	line := strings.Repeat("=", width)
	return fmt.Sprintf(
		"%s\n%s\n%s\nHostname: %s\nStarted:  %s\n%s\n\n",
		line,
		centerASCII(title, width),
		line,
		strings.TrimSpace(hostname),
		started.Format(time.RFC3339),
		line,
	)
}

func centerASCII(value string, width int) string {
	if len(value) >= width {
		return value
	}
	left := (width - len(value)) / 2
	return strings.Repeat(" ", left) + value
}

func openSessionLog(hostname, playbookName string, started time.Time) (*os.File, string, error) {
	if err := os.MkdirAll("session_logs", 0755); err != nil {
		return nil, "", fmt.Errorf("failed to create session log directory: %w", err)
	}
	if err := ensureFailureLog(failureLogPath()); err != nil {
		return nil, "", err
	}

	filename := fmt.Sprintf("%s_%s.log", sanitizeLogName(hostname), started.Format("20060102_150405"))
	path := "session_logs/" + filename
	file, err := os.Create(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create session log file: %w", err)
	}

	if _, err := file.WriteString(formatSessionBanner(playbookName, hostname, started)); err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("failed to write session log banner: %w", err)
	}

	return file, path, nil
}

func failureLogPath() string {
	return filepath.Join("session_logs", "FAILURES.txt")
}

func ensureFailureLog(path string) error {
	if strings.TrimSpace(path) == "" {
		path = failureLogPath()
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create failure log file: %w", err)
	}
	return file.Close()
}

func formatFailureLogEntry(ctx *stepExecutionContext, stepName string, overall validation.ValidationResult, results []validation.ValidationResult) string {
	return formatFailureRecord(ctx.hostname, ctx.ip, stepName, overall, results)
}

func formatFailureRecord(hostname, ip, stepName string, overall validation.ValidationResult, results []validation.ValidationResult) string {
	var b strings.Builder
	b.WriteString(strings.Repeat("=", 78))
	b.WriteByte('\n')
	b.WriteString(fmt.Sprintf("Time:     %s\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	b.WriteString(fmt.Sprintf("IP:       %s\n", ip))
	if strings.TrimSpace(stepName) != "" {
		b.WriteString(fmt.Sprintf("Step:     %s\n", stepName))
	}
	b.WriteString(fmt.Sprintf("Status:   %s\n", overall.Status))
	if strings.TrimSpace(overall.Message) != "" {
		b.WriteString(fmt.Sprintf("Message:  %s\n", overall.Message))
	}

	failed := make([]validation.ValidationResult, 0, len(results))
	for _, result := range results {
		if isFailureResult(result) {
			failed = append(failed, result)
		}
	}
	if len(failed) > 0 {
		b.WriteString("Validation results:\n")
		for idx, result := range failed {
			jb, _ := json.MarshalIndent(result, "  ", "  ")
			b.WriteString(fmt.Sprintf("  [%d]\n%s\n", idx+1, string(jb)))
		}
	}
	b.WriteByte('\n')
	return b.String()
}

func appendFailureRecord(path, hostname, ip, stepName, status, message string, results []validation.ValidationResult) error {
	failureLogMu.Lock()
	defer failureLogMu.Unlock()

	if strings.TrimSpace(path) == "" {
		path = failureLogPath()
	}
	if strings.TrimSpace(status) == "" {
		status = "error"
	}
	overall := validation.ValidationResult{
		Pass:      false,
		Status:    status,
		Message:   strings.TrimSpace(message),
		Timestamp: time.Now(),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create failure log directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open failure log file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(formatFailureRecord(hostname, ip, stepName, overall, results)); err != nil {
		return fmt.Errorf("failed to write failure log entry: %w", err)
	}
	return nil
}

func appendFailureLog(ctx *stepExecutionContext, stepName string, overall validation.ValidationResult, results []validation.ValidationResult) error {
	if ctx == nil {
		return nil
	}
	path := strings.TrimSpace(ctx.failureLog)
	if path == "" {
		path = failureLogPath()
	}
	return appendFailureRecord(path, ctx.hostname, ctx.ip, stepName, overall.Status, overall.Message, results)
}

func appendFailureMessage(ctx *stepExecutionContext, stepName, status, message string) error {
	if ctx == nil {
		return nil
	}
	return appendFailureRecord(ctx.failureLog, ctx.hostname, ctx.ip, stepName, status, message, nil)
}

func writeSessionf(writer io.Writer, format string, args ...interface{}) {
	if writer == nil {
		return
	}
	_, _ = fmt.Fprintf(writer, format, args...)
}

func logStepMessage(ctx *stepExecutionContext, stepName, messageTemplate string) error {
	if strings.TrimSpace(messageTemplate) == "" {
		return nil
	}
	message, err := renderTemplate(messageTemplate, ctx.variables)
	if err != nil {
		return err
	}
	writeSessionf(ctx.sessionLog, "[step:%s] message: %s\n", stepName, message)
	if !ctx.jsonOut {
		fmt.Printf("device=%s step=%s message=%q\n", ctx.hostname, stepName, message)
	}
	return nil
}

func sshOptionsForDevice(device DeviceConfig) []ssh.Option {
	opts := []ssh.Option{}
	if device.Timeout > 0 {
		opts = append(opts, ssh.WithConnectionTimeout(time.Duration(device.Timeout)*time.Second))
	}
	if device.OperationTimeout > 0 {
		opts = append(opts, ssh.WithOperationTimeout(time.Duration(device.OperationTimeout)*time.Second))
	}
	return opts
}

func init() {
	viper.AutomaticEnv()
	if err := viper.BindEnv("fail_on_fail", "FAIL_ON_FAIL"); err != nil {
		slog.Error("error binding environment variable", "key", "fail_on_fail", "env", "FAIL_ON_FAIL", "error", err)
		os.Exit(1)
	}
}

const maxConfigImportDepth = 20

func mergeConfigMaps(destination, source map[string]interface{}) map[string]interface{} {
	if destination == nil {
		destination = map[string]interface{}{}
	}
	for key, sourceValue := range source {
		if key == "imports" {
			continue
		}
		destinationValue, exists := destination[key]
		if !exists {
			destination[key] = sourceValue
			continue
		}

		sourceMap, sourceIsMap := sourceValue.(map[string]interface{})
		destinationMap, destinationIsMap := destinationValue.(map[string]interface{})
		if sourceIsMap && destinationIsMap {
			destination[key] = mergeConfigMaps(destinationMap, sourceMap)
			continue
		}
		sourceSlice, sourceIsSlice := sourceValue.([]interface{})
		destinationSlice, destinationIsSlice := destinationValue.([]interface{})
		if sourceIsSlice && destinationIsSlice {
			destination[key] = append(destinationSlice, sourceSlice...)
			continue
		}
		destination[key] = sourceValue
	}
	return destination
}

func configImports(value interface{}) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	switch imports := value.(type) {
	case string:
		return []string{imports}, nil
	case []interface{}:
		result := make([]string, 0, len(imports))
		for _, item := range imports {
			path, ok := item.(string)
			if !ok || strings.TrimSpace(path) == "" {
				return nil, fmt.Errorf("imports entries must be non-empty file paths")
			}
			result = append(result, path)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("imports must be a file path or list of file paths")
	}
}

func expandConfigImport(importingFile, configuredPath string) ([]string, error) {
	path := strings.TrimSpace(configuredPath)
	if path == "" {
		return nil, fmt.Errorf("import path cannot be empty")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(importingFile), path)
	}
	if strings.ContainsAny(path, "*?[") {
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, fmt.Errorf("invalid import pattern %q: %w", configuredPath, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("import pattern %q matched no files", configuredPath)
		}
		return matches, nil
	}
	return []string{path}, nil
}

func loadConfigMap(path string, depth int, loaded, active map[string]bool) (map[string]interface{}, error) {
	if depth > maxConfigImportDepth {
		return nil, fmt.Errorf("config imports exceed maximum depth of %d", maxConfigImportDepth)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolutePath = filepath.Clean(absolutePath)
	if active[absolutePath] {
		return nil, fmt.Errorf("config import cycle detected at %q", absolutePath)
	}
	if loaded[absolutePath] {
		return nil, fmt.Errorf("config file imported more than once: %q", absolutePath)
	}

	content, err := os.ReadFile(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config %q: %w", absolutePath, err)
	}
	current := map[string]interface{}{}
	if err := yaml.Unmarshal(content, &current); err != nil {
		return nil, fmt.Errorf("failed to parse config %q: %w", absolutePath, err)
	}
	imports, err := configImports(current["imports"])
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", absolutePath, err)
	}

	active[absolutePath] = true
	defer delete(active, absolutePath)
	merged := map[string]interface{}{}
	for _, configuredImport := range imports {
		paths, err := expandConfigImport(absolutePath, configuredImport)
		if err != nil {
			return nil, fmt.Errorf("config %q: %w", absolutePath, err)
		}
		for _, importPath := range paths {
			imported, err := loadConfigMap(importPath, depth+1, loaded, active)
			if err != nil {
				return nil, err
			}
			merged = mergeConfigMaps(merged, imported)
		}
	}
	delete(current, "imports")
	merged = mergeConfigMaps(merged, current)
	loaded[absolutePath] = true
	return merged, nil
}

func loadConfig(configFile string) (Config, bool, error) {
	configMap, err := loadConfigMap(configFile, 0, map[string]bool{}, map[string]bool{})
	if err != nil {
		return Config{}, false, err
	}
	settings := viper.New()
	settings.AutomaticEnv()
	if err := settings.BindEnv("fail_on_fail", "FAIL_ON_FAIL"); err != nil {
		return Config{}, false, err
	}
	if err := settings.MergeConfigMap(configMap); err != nil {
		return Config{}, false, err
	}
	var config Config
	if err := settings.Unmarshal(&config, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		stringToBoolDecodeHook,
	))); err != nil {
		return Config{}, false, err
	}
	return config, settings.GetBool("fail_on_fail"), nil
}

func validateExecutionConfig(cfg ExecutionConfig) error {
	if cfg.MaxParallel < 0 {
		return fmt.Errorf("execution.max_parallel must be greater than or equal to 0")
	}
	if cfg.StartIntervalSeconds < 0 {
		return fmt.Errorf("execution.start_interval_seconds must be greater than or equal to 0")
	}
	if cfg.CanaryCount < 0 {
		return fmt.Errorf("execution.canary_count must be greater than or equal to 0")
	}
	if cfg.FailureThreshold < 0 {
		return fmt.Errorf("execution.failure_threshold must be greater than or equal to 0")
	}
	return nil
}

func runSSHDevice(index int, device DeviceConfig, config Config, username, password string, jsonOut bool, parsers map[string]ParserModuleConfig, variables map[string]string, runDir string) deviceRunResult {
	result := deviceRunResult{index: index}
	hostname := strings.TrimSpace(device.Hostname)
	ip := strings.TrimSpace(device.IP)
	deviceType := strings.TrimSpace(device.Type)

	if hostname == "" || ip == "" || deviceType == "" {
		result.failed = true
		slog.Warn("skipping invalid SSH entry", "hostname", hostname, "ip", ip, "type", deviceType)
		if err := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", "skipping invalid SSH entry", nil); err != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", err)
		}
		return result
	}

	steps := device.Steps
	if len(steps) == 0 && strings.TrimSpace(device.Command) != "" {
		steps = []StepConfig{{
			Name: "default", Command: strings.TrimSpace(device.Command), Parser: strings.TrimSpace(device.Parser),
			Validation: device.Validation, Validations: device.Validations,
		}}
	}
	if len(steps) == 0 {
		result.failed = true
		slog.Warn("skipping SSH device with no steps or command", "hostname", hostname, "ip", ip)
		if err := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", "skipping SSH device with no steps or command", nil); err != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", err)
		}
		return result
	}

	started := time.Now()
	sessionLog, sessionLogPath, err := openSessionLog(hostname, config.NamePlaybook, started)
	if err != nil {
		result.failed = true
		slog.Error("error creating session log", "hostname", hostname, "ip", ip, "error", err)
		return result
	}
	slog.Info("recording SSH session", "hostname", hostname, "ip", ip, "path", sessionLogPath)

	opts := sshOptionsForDevice(device)
	channelLog := io.Writer(sessionLog)
	if !jsonOut {
		channelLog = io.MultiWriter(os.Stdout, sessionLog)
	}
	opts = append(opts, ssh.WithChannelLog(channelLog))

	client := ssh.NewClient(opts...)
	if err := client.Connect(ip, username, password, deviceType); err != nil {
		result.failed = true
		slog.Error("error connecting to SSH device", "hostname", hostname, "ip", ip, "error", err)
		writeSessionf(sessionLog, "ERROR: failed to connect to %s (%s): %v\n", hostname, ip, err)
		if ferr := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", fmt.Sprintf("failed to connect to %s (%s): %v", hostname, ip, err), nil); ferr != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", ferr)
		}
		_ = sessionLog.Close()
		return result
	}

	ctx := stepExecutionContext{
		hostname: hostname, ip: ip, deviceType: deviceType, username: username, password: password,
		opts: opts, jsonOut: jsonOut, sessionLog: sessionLog, failureLog: failureLogPath(),
		variables: variables, aggregated: &result.aggregated, runFailed: &result.failed, parsers: parsers,
		output: config.Output, runDir: runDir, deviceIndex: index, artifacts: &result.artifacts,
	}
	if executeSteps(&ctx, &client, steps) {
		slog.Warn("stopped remaining SSH steps for device", "hostname", hostname, "ip", ip)
	}
	for _, deviceValidation := range result.aggregated {
		if deviceValidation.Result.Status == "fail" || deviceValidation.Result.Status == "error" {
			result.failed = true
			break
		}
	}
	if err := closeSSHClient(client); err != nil {
		result.failed = true
		slog.Error("error closing SSH connection", "hostname", hostname, "ip", ip, "error", err)
		writeSessionf(sessionLog, "ERROR: failed to close SSH connection: %v\n", err)
		if ferr := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", fmt.Sprintf("failed to close SSH connection: %v", err), nil); ferr != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", ferr)
		}
	}
	writeSessionf(sessionLog, "\nSession complete: %s\n", time.Now().Format(time.RFC3339))
	if err := sessionLog.Close(); err != nil {
		result.failed = true
		slog.Error("error closing session log", "hostname", hostname, "ip", ip, "path", sessionLogPath, "error", err)
	}
	return result
}

func runDeviceBatch(devices []DeviceConfig, offset int, cfg ExecutionConfig, lastStart *time.Time, runner func(int, DeviceConfig) deviceRunResult) ([]deviceRunResult, int, bool) {
	maxParallel := cfg.MaxParallel
	if maxParallel == 0 {
		maxParallel = 1
	}
	interval := time.Duration(cfg.StartIntervalSeconds) * time.Second
	results := make([]deviceRunResult, 0, len(devices))
	completed := make(chan deviceRunResult, len(devices))
	active, failures, next := 0, 0, 0
	stopped := false

	receive := func() {
		result := <-completed
		active--
		if result.failed {
			failures++
		}
		results = append(results, result)
	}

	for next < len(devices) {
		if cfg.FailureThreshold > 0 && failures >= cfg.FailureThreshold {
			stopped = true
			break
		}
		if active >= maxParallel {
			receive()
			continue
		}

		if !lastStart.IsZero() && interval > 0 {
			wait := time.Until(lastStart.Add(interval))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case result := <-completed:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					active--
					if result.failed {
						failures++
					}
					results = append(results, result)
					continue
				case <-timer.C:
				}
			}
		}

		index := offset + next
		device := devices[next]
		next++
		active++
		*lastStart = time.Now()
		slog.Info("starting scheduled device", "hostname", device.Hostname, "ip", device.IP, "active", active, "max_parallel", maxParallel)
		go func() { completed <- runner(index, device) }()
	}
	for active > 0 {
		receive()
	}
	return results, failures, stopped
}

func runScheduledDevices(devices []DeviceConfig, cfg ExecutionConfig, runner func(int, DeviceConfig) deviceRunResult) ([]deviceRunResult, bool) {
	canaryCount := cfg.CanaryCount
	if canaryCount > len(devices) {
		canaryCount = len(devices)
	}
	allResults := make([]deviceRunResult, 0, len(devices))
	lastStart := time.Time{}
	totalFailures := 0

	if canaryCount > 0 {
		canaryCfg := cfg
		canaryCfg.FailureThreshold = 0
		results, failures, _ := runDeviceBatch(devices[:canaryCount], 0, canaryCfg, &lastStart, runner)
		allResults = append(allResults, results...)
		totalFailures += failures
		if failures > 0 {
			slog.Error("canary stage failed; remaining devices will not be started", "canary_failures", failures)
			return allResults, true
		}
	}

	remainingCfg := cfg
	if cfg.FailureThreshold > 0 {
		remainingCfg.FailureThreshold = cfg.FailureThreshold - totalFailures
	}
	results, _, stopped := runDeviceBatch(devices[canaryCount:], canaryCount, remainingCfg, &lastStart, runner)
	allResults = append(allResults, results...)
	if stopped {
		slog.Error("failure threshold reached; remaining devices will not be started", "failure_threshold", cfg.FailureThreshold)
	}
	return allResults, stopped
}

func main() {
	// CLI flags
	var jsonOut bool
	var showVersion bool
	var cliFailOnFail bool
	var cliCredsInput bool
	var configFile string
	var cliInventoryFile string
	var cliParsersFile string
	flag.StringVar(&configFile, "config", "config.yaml", "path to config file")
	flag.StringVar(&cliInventoryFile, "inventory", "", "path to inventory file")
	flag.StringVar(&cliParsersFile, "parsers", "", "path to parser module file")
	flag.BoolVar(&jsonOut, "json", false, "emit machine-readable JSON only")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&cliFailOnFail, "fail-on-fail", false, "exit non-zero if any validation fails or errors")
	flag.BoolVar(&cliCredsInput, "creds_input", false, "prompt for username and password interactively")
	flag.Parse()
	if showVersion {
		fmt.Printf("network-collector %s\n", version)
		return
	}

	config, failOnFail, err := loadConfig(configFile)
	if err != nil {
		slog.Error("error reading config", "config_file", configFile, "error", err)
		os.Exit(1)
	}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on-fail" {
			failOnFail = cliFailOnFail
		}
	})

	username, password, err := credentials.ResolveCredentials(cliCredsInput, nil, nil)
	if err != nil {
		slog.Error("error reading credentials", "error", err)
		os.Exit(1)
	}
	if username == "" || password == "" {
		slog.Error("missing required credentials", "required", "NET_USER,NET_PASSWORD")
		os.Exit(1)
	}

	if strings.TrimSpace(cliInventoryFile) != "" {
		config.InventoryFile = cliInventoryFile
	}
	if strings.TrimSpace(cliParsersFile) != "" {
		config.ParsersFile = cliParsersFile
	}

	inventory, err := loadOptionalInventory(config.InventoryFile, configFile)
	if err != nil {
		slog.Error("error reading inventory", "inventory_file", config.InventoryFile, "error", err)
		os.Exit(1)
	}

	sshDevices, err := resolveInventoryDevices(config.SSH, inventory)
	if err != nil {
		slog.Error("error resolving SSH inventory", "error", err)
		os.Exit(1)
	}

	parserConfig, err := loadOptionalParsers(config.ParsersFile, configFile)
	if err != nil {
		slog.Error("error reading parser modules", "parsers_file", config.ParsersFile, "error", err)
		os.Exit(1)
	}
	parsers := map[string]ParserModuleConfig{}
	if parserConfig != nil && parserConfig.Parsers != nil {
		parsers = parserConfig.Parsers
	}

	runStarted := time.Now()
	runID := "run-" + runStarted.Format("20060102T150405.000000000")
	runDir := ""
	if outputEnabled(config, sshDevices) {
		runDir, err = prepareRunOutput(config.Output, runID)
		if err != nil {
			slog.Error("error preparing structured output", "error", err)
			os.Exit(1)
		}
		slog.Info("recording structured output", "run_id", runID, "directory", runDir)
	}

	if err := validateExecutionConfig(config.Execution); err != nil {
		slog.Error("invalid execution configuration", "error", err)
		os.Exit(1)
	}

	variableStates := make(map[string]*deviceVariableState)
	for index, device := range sshDevices {
		key := variableScopeKey(device.Hostname, device.IP)
		state, exists := variableStates[key]
		if !exists {
			state = &deviceVariableState{variables: map[string]string{}}
			state.cond = sync.NewCond(&state.mu)
			variableStates[key] = state
		}
		state.order = append(state.order, index)
	}
	runner := func(index int, device DeviceConfig) deviceRunResult {
		state := variableStates[variableScopeKey(device.Hostname, device.IP)]
		state.mu.Lock()
		for state.next < len(state.order) && state.order[state.next] != index {
			state.cond.Wait()
		}
		result := runSSHDevice(index, device, config, username, password, jsonOut, parsers, state.variables, runDir)
		state.next++
		state.cond.Broadcast()
		state.mu.Unlock()
		return result
	}
	deviceResults, schedulingStopped := runScheduledDevices(sshDevices, config.Execution, runner)
	runFailed := schedulingStopped
	resultsByIndex := make(map[int]deviceRunResult, len(deviceResults))
	for _, result := range deviceResults {
		resultsByIndex[result.index] = result
		if result.failed {
			runFailed = true
		}
	}
	var aggregated []deviceValidation
	var artifacts []outputArtifact
	for index := range sshDevices {
		if result, ok := resultsByIndex[index]; ok {
			aggregated = append(aggregated, result.aggregated...)
			artifacts = append(artifacts, result.artifacts...)
		}
	}
	if runDir != "" {
		summaryPath, err := writeRunSummary(config.Output, runDir, runSummary{
			RunID: runID, Playbook: config.NamePlaybook, StartedAt: runStarted, CompletedAt: time.Now(),
			Failed: runFailed, Validations: aggregated, Artifacts: artifacts,
		})
		if err != nil {
			runFailed = true
			slog.Error("error writing run summary", "error", err)
		} else if summaryPath != "" {
			slog.Info("wrote run summary", "path", summaryPath)
		}
	}

	// Emit aggregated JSON if requested
	if jsonOut {
		out, _ := json.MarshalIndent(aggregated, "", "  ")
		fmt.Println(string(out))
	}

	// Exit non-zero if any validation failed or errored and flag set
	if failOnFail {
		if runFailed {
			os.Exit(2)
		}
		for _, dv := range aggregated {
			if dv.Result.Status == "fail" || dv.Result.Status == "error" {
				os.Exit(2)
			}
		}
	}
}
