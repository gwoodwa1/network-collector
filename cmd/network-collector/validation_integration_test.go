package main

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/validation"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// reuse lightweight structs to parse config.yaml for tests
type testDevice struct {
	Hostname   string                 `yaml:"hostname"`
	Host       string                 `yaml:"host"`
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
		} else if rule.Pattern != "" && contains(rule.Pattern, "address-family ipv4 unicast overload") {
			sample = "address-family ipv4 unicast overload"
		} else {
			// default fallback to the expected as string
			sample = toString(rule.Expected)
		}

		res, err := validation.ValidateOutput(sample, rule)
		if err != nil {
			t.Fatalf("validation execution error for %s: %v", testDeviceName(d), err)
		}
		if !res.Pass {
			t.Fatalf("expected validation pass for %s, got: %+v", testDeviceName(d), res)
		}
	}
}

func testDeviceName(d testDevice) string {
	if strings.TrimSpace(d.Hostname) != "" {
		return d.Hostname
	}
	return d.Host
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

func TestRunStepValidationsRequiresAllRulesToPass(t *testing.T) {
	output := `{"active_packages":["disk0:mini","disk0:fpd"],"profile":"Default Profile"}`
	rules := []ValidationConfig{
		{
			Extractor:    "gjson",
			JSONPath:     "active_packages.#",
			Condition:    "eq",
			Expected:     2,
			ExpectedType: "int",
		},
		{
			Extractor:    "gjson",
			JSONPath:     "profile",
			Condition:    "contains",
			Expected:     "Default",
			ExpectedType: "string",
		},
	}

	results, overall, err := runStepValidations(output, rules, map[string]string{})
	if err != nil {
		t.Fatalf("runStepValidations returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected two validation results, got %d", len(results))
	}
	if !overall.Pass || overall.Status != "pass" {
		t.Fatalf("expected overall pass, got %+v", overall)
	}
}

func TestRunStepValidationsFailsWhenAnyRuleFails(t *testing.T) {
	output := `{"active_packages":["disk0:mini"],"profile":"Default Profile"}`
	rules := []ValidationConfig{
		{
			Extractor:    "gjson",
			JSONPath:     "active_packages.#",
			Condition:    "eq",
			Expected:     2,
			ExpectedType: "int",
		},
		{
			Extractor:    "gjson",
			JSONPath:     "profile",
			Condition:    "contains",
			Expected:     "Default",
			ExpectedType: "string",
		},
	}

	results, overall, err := runStepValidations(output, rules, map[string]string{})
	if err != nil {
		t.Fatalf("runStepValidations returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected two validation results, got %d", len(results))
	}
	if overall.Pass || overall.Status != "fail" {
		t.Fatalf("expected overall fail, got %+v", overall)
	}
}

func TestStepValidationsKeepsBackwardCompatibleSingleValidation(t *testing.T) {
	step := StepConfig{
		Validation: &ValidationConfig{Extractor: "regex", Pattern: `Version:\s+(\S+)`},
		Validations: []ValidationConfig{
			{Extractor: "gjson", JSONPath: "active_packages.#"},
		},
	}

	validations := stepValidations(step)
	if len(validations) != 2 {
		t.Fatalf("expected single validation plus validations list, got %d", len(validations))
	}
	if validations[0].Extractor != "regex" || validations[1].Extractor != "gjson" {
		t.Fatalf("unexpected validations order: %+v", validations)
	}
}

func TestRegisterParserOutputStoresParsedJSON(t *testing.T) {
	vars := map[string]string{}
	parsed := `{"descriptions":["Power Group redundancy lost."],"groups":["Environ"],"locations":["0"]}`

	registered := registerParserOutput(vars, StepConfig{Register: " baseline_alarms "}, parsed)
	if !registered {
		t.Fatalf("expected parser output to be registered")
	}
	if vars["baseline_alarms"] != parsed {
		t.Fatalf("unexpected registered value: %q", vars["baseline_alarms"])
	}
}

func TestRegisterParserOutputSkipsEmptyRegister(t *testing.T) {
	vars := map[string]string{}

	registered := registerParserOutput(vars, StepConfig{}, `{"locations":["0"]}`)
	if registered {
		t.Fatalf("did not expect parser output to be registered")
	}
	if len(vars) != 0 {
		t.Fatalf("unexpected variables: %+v", vars)
	}
}

func TestParsedAlarmBaselineCanRenderFinalComparison(t *testing.T) {
	vars := map[string]string{}
	baseline := `{"descriptions":["Power Group redundancy lost."],"groups":["Environ"],"locations":["0"],"set_times":["02/26/2026 15:05:05 GMT"],"severities":["Major"]}`

	if !registerParserOutput(vars, StepConfig{Register: "baseline_alarms"}, baseline) {
		t.Fatalf("expected baseline alarms to be registered")
	}

	expected, err := renderExpectedValue("{{baseline_alarms}}", vars)
	if err != nil {
		t.Fatalf("renderExpectedValue failed: %v", err)
	}
	if expected != baseline {
		t.Fatalf("unexpected rendered baseline: %#v", expected)
	}

	rules := []ValidationConfig{{
		Extractor:    "gjson",
		JSONPath:     "@this",
		Condition:    "eq",
		Expected:     "{{baseline_alarms}}",
		ExpectedType: "string",
	}}
	results, overall, err := runStepValidations(baseline, rules, vars)
	if err != nil {
		t.Fatalf("runStepValidations returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one validation result, got %d", len(results))
	}
	if !overall.Pass {
		t.Fatalf("expected final alarm comparison to pass, got %+v from %+v", overall, results[0])
	}
}

func TestVariableScopeKeyMatchesSameDeviceOnly(t *testing.T) {
	first := variableScopeKey(" router-1 ", " 192.0.2.1 ")
	second := variableScopeKey("router-1", "192.0.2.1")
	other := variableScopeKey("router-1", "192.0.2.2")

	if first != second {
		t.Fatalf("expected whitespace-normalized device keys to match")
	}
	if first == other {
		t.Fatalf("expected different device IPs to have separate variable scopes")
	}
}

func TestResolveInventoryDevicesPreservesInlineDevice(t *testing.T) {
	devices := []DeviceConfig{{
		Hostname: "router-01",
		IP:       "192.0.2.1",
		Type:     "cisco_ios",
		Command:  "show version",
	}}

	resolved, err := resolveInventoryDevices(devices, nil)
	if err != nil {
		t.Fatalf("resolveInventoryDevices returned error: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("expected one resolved device, got %d", len(resolved))
	}
	if resolved[0].Hostname != "router-01" || resolved[0].IP != "192.0.2.1" || resolved[0].Type != "cisco_ios" {
		t.Fatalf("unexpected resolved inline device: %+v", resolved[0])
	}
}

func TestResolveInventoryDevicesExpandsHostAndGroup(t *testing.T) {
	inventory := &InventoryConfig{
		Hosts: []InventoryHostConfig{
			{Name: "router-01", IP: "192.0.2.1", Type: "cisco_ios", Timeout: 20},
			{Name: "router-02", IP: "192.0.2.2", Type: "cisco_ios", Timeout: 30},
		},
		Groups: map[string]InventoryGroupConfig{
			"ios": {Hosts: []string{"router-01", "router-02"}},
		},
	}

	devices := []DeviceConfig{{
		Group:            "ios",
		OperationTimeout: 120,
		Command:          "show version",
	}}

	resolved, err := resolveInventoryDevices(devices, inventory)
	if err != nil {
		t.Fatalf("resolveInventoryDevices returned error: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected two resolved devices, got %d", len(resolved))
	}
	if resolved[0].Hostname != "router-01" || resolved[0].IP != "192.0.2.1" || resolved[0].Type != "cisco_ios" {
		t.Fatalf("unexpected first resolved device: %+v", resolved[0])
	}
	if resolved[1].Hostname != "router-02" || resolved[1].IP != "192.0.2.2" || resolved[1].Type != "cisco_ios" {
		t.Fatalf("unexpected second resolved device: %+v", resolved[1])
	}
	if resolved[0].Timeout != 20 || resolved[0].OperationTimeout != 120 {
		t.Fatalf("expected inventory timeout and config operation timeout, got %+v", resolved[0])
	}
}

func TestResolveInventoryDevicesMissingHostReturnsError(t *testing.T) {
	devices := []DeviceConfig{{
		Host:    "missing-router",
		Command: "show version",
	}}

	_, err := resolveInventoryDevices(devices, &InventoryConfig{})
	if err == nil {
		t.Fatal("expected error for missing inventory host, got nil")
	}
	if !strings.Contains(err.Error(), "missing-router") {
		t.Fatalf("expected error to mention missing host, got %v", err)
	}
}

func TestLoadOptionalInventoryMissingDefaultDoesNotError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("name_playbook: test\n"), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	inventory, err := loadOptionalInventory("", configPath)
	if err != nil {
		t.Fatalf("loadOptionalInventory returned error: %v", err)
	}
	if inventory != nil {
		t.Fatalf("expected nil inventory for missing default, got %+v", inventory)
	}
}

func TestLoadInventoryRelativeToConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("name_playbook: test\n"), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	inventoryPath := filepath.Join(dir, "inventory.yaml")
	input := []byte(`
hosts:
  - name: router-01
    ip: 192.0.2.1
    type: cisco_ios
groups:
  ios:
    hosts:
      - router-01
`)
	if err := os.WriteFile(inventoryPath, input, 0644); err != nil {
		t.Fatalf("failed to write temp inventory: %v", err)
	}

	inventory, err := loadOptionalInventory("", configPath)
	if err != nil {
		t.Fatalf("loadOptionalInventory returned error: %v", err)
	}
	if inventory == nil || len(inventory.Hosts) != 1 || inventory.Hosts[0].Name != "router-01" {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
}

func TestParseOutputWithRegexModule(t *testing.T) {
	output := `RP/0/RSP0/CPU0:router(admin)# show install active summary
Mon Jun 22 23:41:19.509 PST
Default Profile:
  SDRs:
    Owner
  Active Packages:
    disk0:comp-asr9k-mini-3.9.0.12I
    disk0:asr9k-fpd-3.9.0.12I
    disk0:asr9k-k9sec-3.9.0.12I
`

	parsers := map[string]ParserModuleConfig{
		"xr_install_active_summary": {
			Type: "regex",
			Fields: map[string]ParserFieldConfig{
				"active_packages": {
					Pattern:  `(?m)^\s+(disk0:\S+)`,
					Group:    1,
					Repeated: true,
				},
				"profile": {
					Pattern: `(?m)^(.+ Profile):`,
					Group:   1,
				},
			},
		},
	}

	parsed, err := parseOutputWithModule(output, "xr_install_active_summary", parsers)
	if err != nil {
		t.Fatalf("parseOutputWithModule returned error: %v", err)
	}

	rule := validation.ValidationRule{
		Extractor:    "gjson",
		JSONPath:     "active_packages.#",
		Condition:    "eq",
		Expected:     3,
		ExpectedType: "int",
	}
	res, err := validation.ValidateOutput(parsed, rule)
	if err != nil {
		t.Fatalf("validation returned error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected gjson validation to pass against parsed output, got %+v from %s", res, parsed)
	}
}

func TestXRShowAlarmsBriefSystemActiveParser(t *testing.T) {
	output := `RP/0/RSP1/CPU0:alice-b2bc-1#show alarms brief system active
Wed Jun  3 15:26:30.339 BST

Active Alarms
--------------------------------------------------------------------------------
Location        Severity     Group       Set Time                   Description
--------------------------------------------------------------------------------
0/FT0-FH2       Major        Environ     02/12/2026 10:11:26 GMT    Power Module Error (PM_VIN_VOLT_OOR).
0/FT0-FH2       Major        Environ     02/12/2026 10:11:26 GMT    Power Module Error (PM_NO_INPUT_DETECTED).
0/FT0-FH2       Major        Environ     02/12/2026 10:11:26 GMT    Power Module Output Disabled (PM_OUTPUT_EN_PI_HI).
0/FT0-FH2       Major        Environ     02/12/2026 10:11:26 GMT    Power Module Error (PM_VIN_A_VOLT_OOR).
0/RSP1/CPU0     Major        Software    01/09/2026 23:56:40 BST    One Or More Fabricq ASICs Offline
Hu0/0/0/31      Critical     Software    05/07/2026 19:30:03 BST    HW_OPTICS: RX POWER LANE-0 Low Alarm
Hu0/0/0/31      Critical     Software    05/07/2026 19:30:03 BST    HW_OPTICS: RX POWER LANE-1 Low Alarm
`

	parsers, err := loadParsers("../../parsers.yaml", "")
	if err != nil {
		t.Fatalf("failed to load parsers.yaml: %v", err)
	}
	parsed, err := parseOutputWithModule(output, "xr_show_alarms_brief_system_active", parsers.Parsers)
	if err != nil {
		t.Fatalf("parseOutputWithModule returned error: %v", err)
	}

	tests := []validation.ValidationRule{
		{
			Extractor:    "gjson",
			JSONPath:     "locations.#",
			Condition:    "eq",
			Expected:     7,
			ExpectedType: "int",
		},
		{
			Extractor:    "gjson",
			JSONPath:     "severities.5",
			Condition:    "eq",
			Expected:     "Critical",
			ExpectedType: "string",
		},
		{
			Extractor:    "gjson",
			JSONPath:     "descriptions.4",
			Condition:    "contains",
			Expected:     "Fabricq ASICs Offline",
			ExpectedType: "string",
		},
	}
	for _, rule := range tests {
		res, err := validation.ValidateOutput(parsed, rule)
		if err != nil {
			t.Fatalf("validation returned error for %s: %v", rule.JSONPath, err)
		}
		if !res.Pass {
			t.Fatalf("expected validation pass for %s, got %+v from %s", rule.JSONPath, res, parsed)
		}
	}
}

func TestLoadParsersRelativeToConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("name_playbook: test\n"), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	parserPath := filepath.Join(dir, "parsers.yaml")
	input := []byte(`
parsers:
  sample:
    type: regex
    fields:
      value:
        pattern: 'Value:\s+(\S+)'
        group: 1
`)
	if err := os.WriteFile(parserPath, input, 0644); err != nil {
		t.Fatalf("failed to write temp parsers: %v", err)
	}

	parsers, err := loadOptionalParsers("", configPath)
	if err != nil {
		t.Fatalf("loadOptionalParsers returned error: %v", err)
	}
	if parsers == nil || parsers.Parsers["sample"].Fields["value"].Pattern == "" {
		t.Fatalf("unexpected parsers: %+v", parsers)
	}
}

func TestConfigYAMLDecodeWithInventoryRefs(t *testing.T) {
	input := `
name_playbook: Inventory Playbook
inventory_file: inventory.yaml
parsers_file: parsers.yaml
ssh:
  - host: router-01
    parser: sample
    cmd: show version
    validations:
      - extractor: gjson
        json_path: active_packages.#
        condition: gte
        expected: 1
        expected_type: int
  - group: ios
    steps:
      - name: show-clock
        cmd: show clock
`

	var config Config
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		t.Fatalf("failed to decode config with inventory refs: %v", err)
	}
	if config.InventoryFile != "inventory.yaml" {
		t.Fatalf("unexpected inventory file: %q", config.InventoryFile)
	}
	if config.ParsersFile != "parsers.yaml" {
		t.Fatalf("unexpected parsers file: %q", config.ParsersFile)
	}
	if len(config.SSH) != 2 {
		t.Fatalf("expected two ssh entries, got %d", len(config.SSH))
	}
	if config.SSH[0].Host != "router-01" || config.SSH[0].Parser != "sample" {
		t.Fatalf("unexpected host ref: %+v", config.SSH[0])
	}
	if len(config.SSH[0].Validations) != 1 {
		t.Fatalf("expected one validation in validations list, got %+v", config.SSH[0].Validations)
	}
	if config.SSH[1].Group != "ios" || len(config.SSH[1].Steps) != 1 {
		t.Fatalf("unexpected group ref: %+v", config.SSH[1])
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

func TestReturnToPromptDecodeAcceptsNo(t *testing.T) {
	input := map[string]interface{}{
		"name":             "confirm-reload",
		"cmd":              "yes",
		"return_to_prompt": "no",
	}

	var step StepConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToBoolDecodeHook,
		),
		Result: &step,
	})
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}
	if err := decoder.Decode(input); err != nil {
		t.Fatalf("failed to decode return_to_prompt: %v", err)
	}
	if step.ReturnToPrompt == nil {
		t.Fatal("expected return_to_prompt to decode")
	}
	if *step.ReturnToPrompt {
		t.Fatal("expected return_to_prompt: no to decode as false")
	}
}

func TestValidationActionSelectionAndExit(t *testing.T) {
	step := StepConfig{
		OnPass: &ValidationActionConfig{Action: "exit", Message: "already upgraded"},
		OnFail: &ValidationActionConfig{Action: "fail", Message: "upgrade check failed"},
	}

	passAction := validationActionForResult(step, validation.ValidationResult{Status: "pass"})
	if passAction == nil || passAction.Action != "exit" {
		t.Fatalf("expected pass action exit, got %+v", passAction)
	}

	failAction := validationActionForResult(step, validation.ValidationResult{Status: "fail"})
	if failAction == nil || failAction.Action != "fail" {
		t.Fatalf("expected fail action fail, got %+v", failAction)
	}

	var log bytes.Buffer
	ctx := stepExecutionContext{
		hostname:   "router-01",
		jsonOut:    true,
		sessionLog: &log,
		variables:  map[string]string{},
	}
	outcome, err := executeValidationAction(&ctx, nil, passAction, "check-version")
	if err != nil {
		t.Fatalf("executeValidationAction returned error: %v", err)
	}
	if !outcome.StopDevice || outcome.RunFailed {
		t.Fatalf("unexpected action outcome: %+v", outcome)
	}
	if !strings.Contains(log.String(), "already upgraded") {
		t.Fatalf("expected action message in log, got %q", log.String())
	}
}

func TestValidationActionMessageOnlyContinues(t *testing.T) {
	action := &ValidationActionConfig{Message: "already checked {{image}}"}
	var log bytes.Buffer
	ctx := stepExecutionContext{
		hostname:   "router-01",
		jsonOut:    true,
		sessionLog: &log,
		variables:  map[string]string{"image": "17.9.4"},
	}

	outcome, err := executeValidationAction(&ctx, nil, action, "check-version")
	if err != nil {
		t.Fatalf("executeValidationAction returned error: %v", err)
	}
	if outcome.StopDevice || outcome.RunFailed {
		t.Fatalf("unexpected action outcome: %+v", outcome)
	}
	if !strings.Contains(log.String(), "already checked 17.9.4") {
		t.Fatalf("expected action message in log, got %q", log.String())
	}
}

func TestStepMessageOnlyLogsAndContinues(t *testing.T) {
	var log bytes.Buffer
	aggregated := []deviceValidation{}
	runFailed := false
	ctx := stepExecutionContext{
		hostname:   "router-01",
		jsonOut:    true,
		sessionLog: &log,
		variables:  map[string]string{"image": "17.9.4"},
		aggregated: &aggregated,
		runFailed:  &runFailed,
	}

	stopped := executeSteps(&ctx, nil, []StepConfig{{
		Name:    "announce",
		Message: "target image {{image}} is already active",
	}})
	if stopped {
		t.Fatal("expected message-only step to continue")
	}
	if runFailed {
		t.Fatal("expected message-only step not to mark run failed")
	}
	if !strings.Contains(log.String(), "target image 17.9.4 is already active") {
		t.Fatalf("expected step message in log, got %q", log.String())
	}
}

func TestValidationActionNoopContinues(t *testing.T) {
	ctx := stepExecutionContext{
		hostname:  "router-01",
		jsonOut:   true,
		variables: map[string]string{},
	}
	outcome, err := executeValidationAction(&ctx, nil, &ValidationActionConfig{Action: "noop"}, "check-version")
	if err != nil {
		t.Fatalf("executeValidationAction returned error: %v", err)
	}
	if outcome.StopDevice || outcome.RunFailed {
		t.Fatalf("unexpected action outcome: %+v", outcome)
	}
}

func TestStepDecodeWithValidationActions(t *testing.T) {
	input := `
name: check-current-version
cmd: show version
validation:
  extractor: regex
  pattern: 'Version\s+(\S+)'
  condition: eq
  expected: 17.9.4
  expected_type: string
on_pass:
  message: already running requested image
on_fail:
  action: none
  message: target image not active; continuing upgrade flow
`

	var step StepConfig
	if err := yaml.Unmarshal([]byte(input), &step); err != nil {
		t.Fatalf("failed to decode step with validation actions: %v", err)
	}
	if step.OnPass == nil || step.OnPass.Message != "already running requested image" {
		t.Fatalf("unexpected on_pass action: %+v", step.OnPass)
	}
	if step.OnFail == nil || step.OnFail.Action != "none" {
		t.Fatalf("unexpected on_fail action: %+v", step.OnFail)
	}
}

func TestStepDecodeWithMessage(t *testing.T) {
	input := `
name: announce
message: target image is already active
`

	var step StepConfig
	if err := yaml.Unmarshal([]byte(input), &step); err != nil {
		t.Fatalf("failed to decode step message: %v", err)
	}
	if step.Message != "target image is already active" {
		t.Fatalf("unexpected step message: %q", step.Message)
	}
}

func TestStepDecodeWithNestedValidationActionSteps(t *testing.T) {
	input := `
name: check-current-version
cmd: show version
validation:
  extractor: regex
  pattern: 'Version\s+(\S+)'
  condition: eq
  expected: 17.9.4
  expected_type: string
on_fail:
  message: running upgrade path
  steps:
    - name: collect-install-state
      cmd: show install summary
      validation:
        extractor: regex
        pattern: 'State:\s+(\S+)'
        condition: eq
        expected: READY
        expected_type: string
    - name: perform-upgrade
      cmd: install add file flash:image.bin activate commit
`

	var step StepConfig
	if err := yaml.Unmarshal([]byte(input), &step); err != nil {
		t.Fatalf("failed to decode step with nested validation action steps: %v", err)
	}
	if step.OnFail == nil || len(step.OnFail.Steps) != 2 {
		t.Fatalf("expected two nested on_fail steps, got %+v", step.OnFail)
	}
	nested := step.OnFail.Steps[0]
	if nested.Name != "collect-install-state" || nested.Validation == nil {
		t.Fatalf("unexpected nested validation step: %+v", nested)
	}
}

func TestStepDecodeWithCommandAction(t *testing.T) {
	input := `
name: check-current-version
cmd: show version
validation:
  extractor: regex
  pattern: 'Version\s+(\S+)'
  condition: eq
  expected: 17.9.4
  expected_type: string
on_fail:
  cmd: show install summary
`

	var step StepConfig
	if err := yaml.Unmarshal([]byte(input), &step); err != nil {
		t.Fatalf("failed to decode step with command action: %v", err)
	}
	if step.OnFail == nil || step.OnFail.Command != "show install summary" {
		t.Fatalf("unexpected on_fail action: %+v", step.OnFail)
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

func TestAppendFailureLogWritesFinalFailureEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "FAILURES.txt")
	ctx := stepExecutionContext{
		hostname:   "router-01",
		ip:         "192.0.2.1",
		failureLog: path,
	}
	overall := validation.ValidationResult{
		Pass:    false,
		Status:  "fail",
		Message: "one or more validations failed",
	}
	results := []validation.ValidationResult{
		{
			Pass:          true,
			Status:        "pass",
			Extractor:     "regex",
			PatternOrPath: `Version:\s+(\S+)`,
			RawExtract:    "17.9.4",
			Expected:      "17.9.4",
			Condition:     "eq",
			Message:       "values equal",
		},
		{
			Pass:          false,
			Status:        "fail",
			Extractor:     "gjson",
			PatternOrPath: "active_packages.#",
			RawExtract:    "2",
			Expected:      3,
			ExpectedType:  "int",
			Condition:     "eq",
			Message:       "values differ",
		},
	}

	if err := appendFailureLog(&ctx, "check-install", overall, results); err != nil {
		t.Fatalf("appendFailureLog returned error: %v", err)
	}
	if err := appendFailureLog(&ctx, "check-install-again", overall, results); err != nil {
		t.Fatalf("second appendFailureLog returned error: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read failure log: %v", err)
	}
	log := string(b)
	for _, want := range []string{
		"Hostname: router-01",
		"IP:       192.0.2.1",
		"Step:     check-install",
		"Status:   fail",
		`"pattern_or_path": "active_packages.#"`,
		"Step:     check-install-again",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("expected failure log to contain %q, got %q", want, log)
		}
	}
	if strings.Contains(log, `"pattern_or_path": "Version:\\s+(\\S+)"`) {
		t.Fatalf("expected passing validation result to be omitted, got %q", log)
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

func TestRunScheduledDevicesHonorsMaxParallel(t *testing.T) {
	devices := make([]DeviceConfig, 8)
	var active int32
	var peak int32
	runner := func(index int, device DeviceConfig) deviceRunResult {
		current := atomic.AddInt32(&active, 1)
		for {
			seen := atomic.LoadInt32(&peak)
			if current <= seen || atomic.CompareAndSwapInt32(&peak, seen, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return deviceRunResult{index: index}
	}

	results, stopped := runScheduledDevices(devices, ExecutionConfig{MaxParallel: 3}, runner)
	if stopped {
		t.Fatal("scheduler unexpectedly stopped")
	}
	if len(results) != len(devices) {
		t.Fatalf("expected %d results, got %d", len(devices), len(results))
	}
	if got := atomic.LoadInt32(&peak); got != 3 {
		t.Fatalf("expected peak concurrency 3, got %d", got)
	}
}

func TestRunScheduledDevicesStopsAfterCanaryFailure(t *testing.T) {
	devices := make([]DeviceConfig, 5)
	var mu sync.Mutex
	var started []int
	runner := func(index int, device DeviceConfig) deviceRunResult {
		mu.Lock()
		started = append(started, index)
		mu.Unlock()
		return deviceRunResult{index: index, failed: index == 0}
	}

	results, stopped := runScheduledDevices(devices, ExecutionConfig{MaxParallel: 2, CanaryCount: 1}, runner)
	if !stopped {
		t.Fatal("expected failed canary to stop scheduling")
	}
	if len(results) != 1 || len(started) != 1 || started[0] != 0 {
		t.Fatalf("expected only canary device to start, results=%d started=%v", len(results), started)
	}
}

func TestRunScheduledDevicesStopsAtFailureThreshold(t *testing.T) {
	devices := make([]DeviceConfig, 5)
	runner := func(index int, device DeviceConfig) deviceRunResult {
		return deviceRunResult{index: index, failed: true}
	}

	results, stopped := runScheduledDevices(devices, ExecutionConfig{MaxParallel: 1, FailureThreshold: 2}, runner)
	if !stopped {
		t.Fatal("expected failure threshold to stop scheduling")
	}
	if len(results) != 2 {
		t.Fatalf("expected two failed devices to run, got %d", len(results))
	}
}

func TestValidateExecutionConfig(t *testing.T) {
	valid := ExecutionConfig{MaxParallel: 4, StartIntervalSeconds: 120, CanaryCount: 1, FailureThreshold: 2}
	if err := validateExecutionConfig(valid); err != nil {
		t.Fatalf("valid execution config rejected: %v", err)
	}
	if err := validateExecutionConfig(ExecutionConfig{StartIntervalSeconds: -1}); err == nil {
		t.Fatal("expected negative start interval to be rejected")
	}
}

func TestStructuredOutputArtifactsAndSummary(t *testing.T) {
	runDir := filepath.Join(t.TempDir(), "run-test")
	artifacts := []outputArtifact{}
	ctx := &stepExecutionContext{
		hostname: "router-01", ip: "192.0.2.10", deviceIndex: 0, runDir: runDir,
		output: OutputConfig{SaveRaw: true, SaveParsed: true}, artifacts: &artifacts,
	}
	step := StepConfig{Name: "show-interfaces"}
	if err := saveStepArtifact(ctx, step, step.Name, 1, "raw", "raw output\n"); err != nil {
		t.Fatalf("failed to save raw artifact: %v", err)
	}
	if err := saveStepArtifact(ctx, step, step.Name, 1, "parsed", `{"records":[]}`); err != nil {
		t.Fatalf("failed to save parsed artifact: %v", err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("expected two artifacts, got %d", len(artifacts))
	}
	for _, artifact := range artifacts {
		if _, err := os.Stat(artifact.Path); err != nil {
			t.Fatalf("artifact %q was not written: %v", artifact.Path, err)
		}
	}

	summaryPath, err := writeRunSummary(OutputConfig{SummaryFile: "results.json"}, runDir, runSummary{
		RunID: "run-test", StartedAt: time.Now(), CompletedAt: time.Now(), Artifacts: artifacts,
	})
	if err != nil {
		t.Fatalf("failed to write summary: %v", err)
	}
	content, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("failed to read summary: %v", err)
	}
	if !strings.Contains(string(content), `"run_id": "run-test"`) {
		t.Fatalf("unexpected summary: %s", content)
	}
}

func TestStepOutputOverride(t *testing.T) {
	disabled := false
	artifacts := []outputArtifact{}
	ctx := &stepExecutionContext{
		hostname: "router-01", runDir: t.TempDir(), output: OutputConfig{SaveRaw: true}, artifacts: &artifacts,
	}
	step := StepConfig{Output: &StepOutputConfig{SaveRaw: &disabled}}
	if err := saveStepArtifact(ctx, step, "secret", 1, "raw", "sensitive"); err != nil {
		t.Fatalf("saveStepArtifact returned error: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("expected step override to suppress raw artifact, got %+v", artifacts)
	}
}

func TestExecuteRepeatRunsFiniteCount(t *testing.T) {
	var log bytes.Buffer
	runFailed := false
	ctx := &stepExecutionContext{
		hostname: "router-01", ip: "192.0.2.10", jsonOut: true,
		sessionLog: &log, variables: map[string]string{}, runFailed: &runFailed,
	}
	sleeps := 0
	stopped := executeRepeat(ctx, nil, RepeatConfig{
		Count: 3, IntervalSeconds: 10,
		Steps: []StepConfig{{Name: "note", Message: "collecting"}},
	}, "monitor", 1, func(duration time.Duration) {
		if duration != 10*time.Second {
			t.Fatalf("unexpected repeat interval: %s", duration)
		}
		sleeps++
	})
	if stopped || runFailed {
		t.Fatalf("repeat unexpectedly stopped or failed: stopped=%v failed=%v", stopped, runFailed)
	}
	if sleeps != 2 {
		t.Fatalf("expected two sleeps between three iterations, got %d", sleeps)
	}
	if got := strings.Count(log.String(), "[step:note] message: collecting"); got != 3 {
		t.Fatalf("expected three iteration log entries, got %d: %s", got, log.String())
	}
}

func TestExecuteRepeatStopsOnFailureByDefault(t *testing.T) {
	var log bytes.Buffer
	runFailed := false
	ctx := &stepExecutionContext{
		hostname: "router-01", ip: "192.0.2.10", jsonOut: true,
		sessionLog: &log, failureLog: filepath.Join(t.TempDir(), "failures.txt"),
		variables: map[string]string{}, runFailed: &runFailed,
	}
	sleeps := 0
	stopped := executeRepeat(ctx, nil, RepeatConfig{
		Count: 3, IntervalSeconds: 10,
		Steps: []StepConfig{{Name: "invalid-empty-step"}},
	}, "monitor", 1, func(time.Duration) { sleeps++ })
	if stopped {
		t.Fatal("failed iteration should stop the repeat block, not the whole device")
	}
	if !runFailed {
		t.Fatal("expected failed iteration to mark the run failed")
	}
	if sleeps != 0 {
		t.Fatalf("expected no wait after stopping on first failure, got %d", sleeps)
	}
}

func TestValidateRepeatConfigSafetyLimits(t *testing.T) {
	valid := RepeatConfig{Count: 10, IntervalSeconds: 120, Steps: []StepConfig{{Message: "collect"}}}
	if err := validateRepeatConfig(valid, 1); err != nil {
		t.Fatalf("valid repeat rejected: %v", err)
	}
	invalid := []RepeatConfig{
		{Count: 0, IntervalSeconds: 1, Steps: []StepConfig{{Message: "collect"}}},
		{Count: maxRepeatCount + 1, IntervalSeconds: 1, Steps: []StepConfig{{Message: "collect"}}},
		{Count: 2, IntervalSeconds: 0, Steps: []StepConfig{{Message: "collect"}}},
		{Count: 2, IntervalSeconds: 1},
		{Count: 2, IntervalSeconds: 1, Steps: []StepConfig{{Name: "unbounded", Retry: &RetryConfig{UntilPass: true}}}},
	}
	for _, config := range invalid {
		if err := validateRepeatConfig(config, 1); err == nil {
			t.Fatalf("unsafe repeat config accepted: %+v", config)
		}
	}
	if err := validateRepeatConfig(valid, maxRepeatDepth+1); err == nil {
		t.Fatal("expected excessive repeat nesting to be rejected")
	}
}

func TestLoadConfigComposesImports(t *testing.T) {
	dir := t.TempDir()
	rolesDir := filepath.Join(dir, "roles")
	if err := os.MkdirAll(rolesDir, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(rolesDir, "10-ntp.yaml"): `
execution:
  max_parallel: 2
  start_interval_seconds: 30
ssh:
  - host: router-01
    cmd: show ntp status
`,
		filepath.Join(rolesDir, "20-platform.yaml"): `
ssh:
  - host: router-02
    cmd: show platform
`,
		filepath.Join(dir, "config.yaml"): `
imports:
  - roles/*.yaml
name_playbook: composed playbook
inventory_file: inventory.yaml
execution:
  max_parallel: 4
ssh:
  - host: router-03
    cmd: show version
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	config, failOnFail, err := loadConfig(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if failOnFail {
		t.Fatal("fail_on_fail unexpectedly enabled")
	}
	if config.NamePlaybook != "composed playbook" || config.Execution.MaxParallel != 4 || config.Execution.StartIntervalSeconds != 30 {
		t.Fatalf("unexpected merged config: %+v", config)
	}
	if len(config.SSH) != 3 || config.SSH[0].Host != "router-01" || config.SSH[1].Host != "router-02" || config.SSH[2].Host != "router-03" {
		t.Fatalf("unexpected imported SSH order: %+v", config.SSH)
	}
}

func TestLoadConfigRejectsImportCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yaml")
	b := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(a, []byte("imports: [b.yaml]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("imports: [a.yaml]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(a); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected import cycle error, got %v", err)
	}
}

func TestLoadConfigRejectsDuplicateImport(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared.yaml")
	root := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(shared, []byte("ssh: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("imports: [shared.yaml, shared.yaml]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(root); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate import error, got %v", err)
	}
}

func TestModularExampleLoads(t *testing.T) {
	configPath := filepath.Join("..", "..", "examples", "modular", "config.yaml")
	config, _, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load modular example: %v", err)
	}
	if len(config.SSH) != 2 || config.SSH[0].Group != "xr" || config.SSH[1].Group != "xr" {
		t.Fatalf("unexpected modular example workflows: %+v", config.SSH)
	}
	inventory, err := loadOptionalInventory(config.InventoryFile, configPath)
	if err != nil || inventory == nil || len(inventory.Hosts) != 1 {
		t.Fatalf("failed to load modular example inventory: inventory=%+v error=%v", inventory, err)
	}
	parsers, err := loadOptionalParsers(config.ParsersFile, configPath)
	if err != nil || parsers == nil || parsers.Parsers["xr_show_ntp_status"].Template == "" {
		t.Fatalf("failed to load modular example parsers: parsers=%+v error=%v", parsers, err)
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
