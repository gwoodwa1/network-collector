package main

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/kcajme/network-collector/pkg/validation"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// reuse lightweight structs to parse config.yaml for tests
type testDevice struct {
	Hostname   string                 `yaml:"hostname"`
	IP         string                 `yaml:"ip"`
	Type       string                 `yaml:"type"`
	Command    string                 `yaml:"cmd"`
	Validation map[string]interface{} `yaml:"validation"`
}

type testConfig struct {
	SSH []testDevice `yaml:"ssh"`
}

func TestValidationIntegration(t *testing.T) {
	b, err := ioutil.ReadFile("../../config.yaml")
	if err != nil {
		t.Fatalf("failed reading config.yaml: %v", err)
	}
	var c testConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	// ensure viper is using same file for consistency
	viper.SetConfigFile("../../config.yaml")
	_ = viper.ReadInConfig()

	for _, d := range c.SSH {
		if d.Validation == nil {
			continue
		}
		// construct rule
		rule := validation.ValidationRule{
			Extractor:    toString(d.Validation["extractor"]),
			Pattern:      toString(d.Validation["pattern"]),
			JSONPath:     toString(d.Validation["json_path"]),
			Condition:    toString(d.Validation["condition"]),
			Expected:     d.Validation["expected"],
			ExpectedType: toString(d.Validation["expected_type"]),
		}

		// craft a sample output that should pass for the examples we added
		var sample string
		if rule.Pattern != "" && contains(rule.Pattern, "Total routes") {
			sample = "Total routes: 120"
		} else if rule.Pattern != "" && contains(rule.Pattern, "System state") {
			sample = "System state: RUNNING"
		} else if rule.Pattern != "" && contains(rule.Pattern, "Total memory") {
			sample = "Total memory: 100MB"
		} else {
			// default fallback to the expected as string
			sample = toString(rule.Expected)
		}

		res, err := validation.ValidateOutput(sample, rule)
		if err != nil {
			t.Fatalf("validation execution error for %s: %v", d.Hostname, err)
		}
		if !res.Pass {
			t.Fatalf("expected validation pass for %s, got: %+v", d.Hostname, res)
		}
	}
}

func TestStepVariableRegistrationAndInterpolation(t *testing.T) {
	vars := map[string]string{}

	output := "Install ID: 14"
	rule := validation.ValidationRule{
		Extractor:    "regex",
		Pattern:      `Install ID:\s+(\d+)`,
		Condition:    "eq",
		Expected:     14,
		ExpectedType: "int",
	}

	res, err := validation.ValidateOutput(output, rule)
	if err != nil {
		t.Fatalf("validation execution error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected validation pass, got: %+v", res)
	}
	if res.RawExtract != "14" {
		t.Fatalf("expected RawExtract 14, got %q", res.RawExtract)
	}

	vars["install_id"] = res.RawExtract

	cmd, err := renderTemplate("show install active {{install_id}}", vars)
	if err != nil {
		t.Fatalf("renderTemplate failed: %v", err)
	}
	if cmd != "show install active 14" {
		t.Fatalf("unexpected rendered command: %q", cmd)
	}

	expected, err := renderExpectedValue("{{install_id}}", vars)
	if err != nil {
		t.Fatalf("renderExpectedValue failed: %v", err)
	}
	if expected != "14" {
		t.Fatalf("unexpected rendered expected value: %#v", expected)
	}

	pattern, err := renderTemplate(`Package ID:\s+{{install_id}}`, vars)
	if err != nil {
		t.Fatalf("renderTemplate failed for pattern: %v", err)
	}
	if pattern != `Package ID:\s+14` {
		t.Fatalf("unexpected rendered pattern: %q", pattern)
	}
}

func TestTemplateMissingVariableReturnsError(t *testing.T) {
	vars := map[string]string{}
	_, err := renderTemplate("show install active {{install_id}}", vars)
	if err == nil {
		t.Fatal("expected error for missing variable, got nil")
	}
	if !strings.Contains(err.Error(), "undefined variables") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func contains(s, sub string) bool {
	return s != "" && sub != "" && (len(s) >= len(sub)) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
