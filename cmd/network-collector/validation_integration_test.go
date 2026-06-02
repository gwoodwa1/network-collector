package main

import (
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kcajme/network-collector/pkg/validation"
	"github.com/mitchellh/mapstructure"
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

func TestWaitDuration(t *testing.T) {
	wait, err := waitDuration(5)
	if err != nil {
		t.Fatalf("waitDuration returned error: %v", err)
	}
	if wait != 5*time.Second {
		t.Fatalf("expected 5s wait, got %v", wait)
	}

	wait, err = waitDuration(0)
	if err != nil {
		t.Fatalf("waitDuration returned error for zero wait: %v", err)
	}
	if wait != 0 {
		t.Fatalf("expected zero wait, got %v", wait)
	}

	_, err = waitDuration(-1)
	if err == nil {
		t.Fatal("expected error for negative wait_seconds, got nil")
	}
}

func TestShouldReturnToPrompt(t *testing.T) {
	if !shouldReturnToPrompt(nil) {
		t.Fatal("expected unset return_to_prompt to default to true")
	}

	value := true
	if !shouldReturnToPrompt(&value) {
		t.Fatal("expected true return_to_prompt to require a prompt")
	}

	value = false
	if shouldReturnToPrompt(&value) {
		t.Fatal("expected false return_to_prompt to allow no prompt")
	}
}

func TestDeviceConfigOperationTimeoutDecode(t *testing.T) {
	input := map[string]interface{}{
		"hostname":          "device-ios-01",
		"ip":                "192.0.2.1",
		"type":              "cisco_ios",
		"timeout":           20,
		"operation_timeout": 120,
		"cmd":               "show install request",
	}

	var device DeviceConfig
	if err := mapstructure.Decode(input, &device); err != nil {
		t.Fatalf("failed to decode device config: %v", err)
	}
	if device.Timeout != 20 {
		t.Fatalf("expected connection timeout 20, got %d", device.Timeout)
	}
	if device.OperationTimeout != 120 {
		t.Fatalf("expected operation timeout 120, got %d", device.OperationTimeout)
	}
}

func TestConfigYAMLDecodeWithSSHProbe(t *testing.T) {
	input := `
name_playbook: Software Upgrade on Cisco IOS
ssh:
  - hostname: router-01
    ip: 192.0.2.1
    type: cisco_ios
    steps:
      - name: wait-for-reboot
        wait_seconds: 600
        ssh_probe:
          port: 22
          interval_seconds: 30
          max_attempts: 40
          timeout_seconds: 5
          post_wait_seconds: 120
`

	var config Config
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		t.Fatalf("failed to decode config with ssh_probe: %v", err)
	}
	if config.NamePlaybook != "Software Upgrade on Cisco IOS" {
		t.Fatalf("unexpected playbook name: %q", config.NamePlaybook)
	}
	if len(config.SSH) != 1 || len(config.SSH[0].Steps) != 1 {
		t.Fatalf("unexpected SSH step shape: %+v", config.SSH)
	}
	probe := config.SSH[0].Steps[0].SSHProbe
	if probe == nil {
		t.Fatal("expected ssh_probe to decode")
	}
	if probe.Port != 22 || probe.IntervalSeconds != 30 || probe.MaxAttempts != 40 || probe.TimeoutSeconds != 5 || probe.PostWaitSeconds != 120 {
		t.Fatalf("unexpected ssh_probe config: %+v", probe)
	}
}

func TestSessionLogFormatting(t *testing.T) {
	if got := sanitizeLogName("router 01/lab"); got != "router_01_lab" {
		t.Fatalf("unexpected sanitized log name: %q", got)
	}
	if got := sanitizeLogName("   "); got != "unknown" {
		t.Fatalf("expected unknown for blank log name, got %q", got)
	}

	started := time.Date(2026, 6, 2, 18, 30, 0, 0, time.UTC)
	banner := formatSessionBanner("Software Upgrade on Cisco IOS", "router-01", started)
	if !strings.Contains(banner, "Software Upgrade on Cisco IOS") {
		t.Fatalf("expected banner to contain playbook title, got %q", banner)
	}
	if !strings.Contains(banner, "Hostname: router-01") {
		t.Fatalf("expected banner to contain hostname, got %q", banner)
	}
	if !strings.Contains(banner, "Started:  2026-06-02T18:30:00Z") {
		t.Fatalf("expected banner to contain timestamp, got %q", banner)
	}
}

func TestResolveSSHProbeConfig(t *testing.T) {
	probe, err := resolveSSHProbeConfig(nil)
	if err != nil {
		t.Fatalf("resolveSSHProbeConfig returned error: %v", err)
	}
	if probe.Port != 22 {
		t.Fatalf("expected default SSH probe port 22, got %d", probe.Port)
	}
	if probe.Interval != 30*time.Second {
		t.Fatalf("expected default SSH probe interval 30s, got %v", probe.Interval)
	}
	if probe.Attempts != 20 {
		t.Fatalf("expected default SSH probe attempts 20, got %d", probe.Attempts)
	}
	if probe.Timeout != 5*time.Second {
		t.Fatalf("expected default SSH probe timeout 5s, got %v", probe.Timeout)
	}
	if probe.PostWait != 0 {
		t.Fatalf("expected default SSH probe post wait 0s, got %v", probe.PostWait)
	}

	probe, err = resolveSSHProbeConfig(&SSHProbeConfig{
		Port:            2222,
		IntervalSeconds: 10,
		MaxAttempts:     3,
		TimeoutSeconds:  2,
		PostWaitSeconds: 120,
	})
	if err != nil {
		t.Fatalf("resolveSSHProbeConfig returned error for custom config: %v", err)
	}
	if probe.Port != 2222 || probe.Interval != 10*time.Second || probe.Attempts != 3 || probe.Timeout != 2*time.Second || probe.PostWait != 120*time.Second {
		t.Fatalf("unexpected custom SSH probe config: %+v", probe)
	}

	_, err = resolveSSHProbeConfig(&SSHProbeConfig{PostWaitSeconds: -1})
	if err == nil {
		t.Fatal("expected error for negative SSH probe post wait, got nil")
	}
}

func TestWaitForSSHPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener address: %v", err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("failed to parse listener port: %v", err)
	}

	err = waitForSSHPort("127.0.0.1", &SSHProbeConfig{
		Port:            portNumber,
		IntervalSeconds: 1,
		MaxAttempts:     1,
		TimeoutSeconds:  1,
	})
	if err != nil {
		t.Fatalf("waitForSSHPort returned error: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("expected probe connection to be accepted")
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
