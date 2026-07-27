package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sequenceNETCONFExecutor struct {
	configs []NETCONFStepConfig
	outputs []string
}

type sequenceSSHEnsureExecutor struct {
	commands []string
	outputs  []string
	errors   []error
}

func (executor *sequenceSSHEnsureExecutor) Execute(command string) (string, error) {
	executor.commands = append(executor.commands, command)
	var output string
	if len(executor.outputs) > 0 {
		output = executor.outputs[0]
		executor.outputs = executor.outputs[1:]
	}
	var err error
	if len(executor.errors) > 0 {
		err = executor.errors[0]
		executor.errors = executor.errors[1:]
	}
	return output, err
}

func (executor *sequenceNETCONFExecutor) ExecuteNETCONF(config NETCONFStepConfig) (string, error) {
	executor.configs = append(executor.configs, config)
	if len(executor.outputs) == 0 {
		return "", nil
	}
	output := executor.outputs[0]
	executor.outputs = executor.outputs[1:]
	return output, nil
}

func interfaceReply(name, description string, enabled bool) string {
	return `<rpc-reply><data><interfaces xmlns="http://openconfig.net/yang/interfaces"><interface><name>` +
		xmlText(name) + `</name><config><name>` + xmlText(name) + `</name><description>` + xmlText(description) +
		`</description><enabled>` + map[bool]string{true: "true", false: "false"}[enabled] +
		`</enabled></config></interface></interfaces></data></rpc-reply>`
}

func TestEnsureInterfaceIsIdempotent(t *testing.T) {
	description := "customer handoff"
	executor := &sequenceNETCONFExecutor{outputs: []string{interfaceReply("Ethernet4", description, true)}}
	ctx, failed := interactionContext(t, nil)
	ctx.netconf = executor

	stopped := executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "Ethernet4", State: "enabled", Description: &description,
		},
	}})

	if stopped || *failed {
		t.Fatalf("ensure step failed: stopped=%v failed=%v", stopped, *failed)
	}
	if len(executor.configs) != 1 || executor.configs[0].Operation != "rpc" {
		t.Fatalf("in-sync ensure should only discover state: %+v", executor.configs)
	}
}

func TestEnsureInterfaceCheckModeReportsWithoutEditing(t *testing.T) {
	description := "new description"
	executor := &sequenceNETCONFExecutor{outputs: []string{interfaceReply("Ethernet4", "old description", false)}}
	ctx, failed := interactionContext(t, nil)
	ctx.netconf = executor
	ctx.checkMode = true

	if executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "Ethernet4", State: "enabled", Description: &description,
		},
	}}) || *failed {
		t.Fatalf("check-mode ensure failed: failed=%v", *failed)
	}
	if len(executor.configs) != 1 {
		t.Fatalf("check mode sent a mutation: %+v", executor.configs)
	}
}

func TestEnsureInterfaceAppliesAndVerifies(t *testing.T) {
	description := `customer & core`
	executor := &sequenceNETCONFExecutor{outputs: []string{
		interfaceReply("Ethernet4", "old", false),
		"<rpc-reply><ok/></rpc-reply>",
		interfaceReply("Ethernet4", description, true),
	}}
	ctx, failed := interactionContext(t, nil)
	ctx.netconf = executor

	if executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "Ethernet4", State: "enabled", Description: &description,
		},
	}}) || *failed {
		t.Fatalf("apply ensure failed: failed=%v configs=%+v", *failed, executor.configs)
	}
	if len(executor.configs) != 3 || executor.configs[1].Operation != "edit-config" || executor.configs[1].Target != "running" {
		t.Fatalf("ensure did not discover, edit, and verify: %+v", executor.configs)
	}
	if !strings.Contains(executor.configs[1].Payload, "customer &amp; core") {
		t.Fatalf("ensure payload was not XML escaped: %s", executor.configs[1].Payload)
	}
}

func TestCheckModeSkipsImperativeAndMutatingNETCONFSteps(t *testing.T) {
	executor := &sequenceNETCONFExecutor{outputs: []string{"<rpc-reply><data/></rpc-reply>"}}
	ctx, failed := interactionContext(t, nil)
	ctx.netconf = executor
	ctx.checkMode = true

	steps := []StepConfig{
		{Name: "ssh-change", Command: "configure terminal"},
		{Name: "netconf-change", NETCONF: &NETCONFStepConfig{Operation: "edit-config", Target: "running", Payload: "<config/>"}},
		{Name: "unknown-rpc", NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: "<request-reboot/>"}},
		{Name: "safe-get", NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: "<get/>"}},
	}
	if executeSteps(ctx, nil, steps) || *failed {
		t.Fatalf("check mode failed: failed=%v", *failed)
	}
	if len(executor.configs) != 1 || executor.configs[0].Payload != "<get/>" {
		t.Fatalf("check mode should execute only the unambiguously read-only RPC: %+v", executor.configs)
	}
}

func TestValidateEnsureConfig(t *testing.T) {
	for _, config := range []EnsureConfig{
		{},
		{Resource: "route", Name: "x", State: "enabled"},
		{Resource: "interface", Name: "Ethernet4", State: "present"},
		{Resource: "interface", Name: "Ethernet4", State: "enabled", Transport: "ssh"},
		{Resource: "interface", Name: "Ethernet4", State: "enabled", Target: "candidate"},
	} {
		if _, err := validateEnsureConfig(config); err == nil {
			t.Fatalf("invalid ensure configuration accepted: %+v", config)
		}
	}
}

func iosXRInterfaceOutput(name, state, description string) string {
	output := name + " is " + state + ", line protocol is down\n"
	if description != "" {
		output += "  Description: " + description + "\n"
	}
	return output
}

func readEnsureFixture(t *testing.T, name string) string {
	t.Helper()
	return readPlatformEnsureFixture(t, "iosxr", name)
}

func readPlatformEnsureFixture(t *testing.T, platform, name string) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", "ensure", platform, name))
	if err != nil {
		t.Fatalf("read ensure fixture %s: %v", name, err)
	}
	return string(payload)
}

func TestSSHEnsureInterfaceCheckModeDiscoversAndPreviews(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{outputs: []string{
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "administratively down", "old description"),
	}}
	ctx, failed := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.checkMode = true
	ctx.sshEnsure = executor
	description := "new core uplink"

	if executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
			RequireState: "disabled", Description: &description, Transport: "ssh",
		},
	}}) || *failed {
		t.Fatalf("SSH interface check failed: failed=%v", *failed)
	}
	if len(executor.commands) != 1 || executor.commands[0] != "show interfaces HundredGigE0/0/0/0" {
		t.Fatalf("check mode sent more than safe discovery: %+v", executor.commands)
	}
}

func TestSSHEnsureInterfacePlanIncludesExactApplyAndRollbackCommands(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{outputs: []string{
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "administratively down", "old description"),
	}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.checkMode = true
	description := "new core uplink"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		`"action": "would-change"`,
		`"commands"`,
		`description new core uplink`,
		`no shutdown`,
		`"rollback_commands"`,
		`description old description`,
		`shutdown`,
	} {
		if !strings.Contains(output, wanted) {
			t.Fatalf("SSH interface plan missing %q:\n%s", wanted, output)
		}
	}
}

func TestSSHEnsureInterfaceAppliesAndVerifies(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{outputs: []string{
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "administratively down", "old description"),
		"Commit complete",
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "up", "new core uplink"),
	}}
	ctx, failed := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.sshEnsure = executor
	description := "new core uplink"

	if executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
			RequireState: "disabled", Description: &description, Transport: "ssh",
		},
	}}) || *failed {
		t.Fatalf("SSH interface apply failed: failed=%v commands=%+v", *failed, executor.commands)
	}
	if len(executor.commands) != 3 ||
		!strings.Contains(executor.commands[1], "description new core uplink") ||
		!strings.Contains(executor.commands[1], "no shutdown") ||
		executor.commands[2] != "show interfaces HundredGigE0/0/0/0" {
		t.Fatalf("SSH interface did not discover, apply, and verify: %+v", executor.commands)
	}
}

func TestSSHEnsureInterfaceVerificationFailureRollsBackAndRemainsFailed(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{outputs: []string{
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "administratively down", "old description"),
		"Commit complete",
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "administratively down", "new core uplink"),
		"Rollback commit complete",
	}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	description := "new core uplink"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh", RollbackOnFailure: true,
	})
	if err == nil || !strings.Contains(err.Error(), "automatic rollback completed") {
		t.Fatalf("verification failure did not remain failed after rollback: %v", err)
	}
	if len(executor.commands) != 4 ||
		!strings.Contains(executor.commands[3], "description old description") ||
		!strings.Contains(executor.commands[3], "shutdown") {
		t.Fatalf("exact prior interface state was not restored: %+v", executor.commands)
	}
	if !strings.Contains(output, `"action": "rolled-back"`) ||
		!strings.Contains(output, `"rollback_status": "succeeded"`) {
		t.Fatalf("rollback audit state missing from plan: %s", output)
	}
}

func TestSSHEnsureRollbackFailureIsReported(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{
		outputs: []string{
			iosXRInterfaceOutput("HundredGigE0/0/0/0", "administratively down", "old description"),
			"partial apply",
			"rollback rejected",
		},
		errors: []error{nil, errors.New("apply timed out"), errors.New("rollback commit rejected")},
	}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	description := "new core uplink"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh", RollbackOnFailure: true,
	})
	if err == nil || !strings.Contains(err.Error(), "automatic rollback failed") {
		t.Fatalf("rollback failure was not returned: %v", err)
	}
	if !strings.Contains(output, `"action": "rollback-failed"`) ||
		!strings.Contains(output, `"rollback_status": "failed"`) ||
		!strings.Contains(output, "rollback commit rejected") {
		t.Fatalf("rollback failure audit state missing: %s", output)
	}
}

func TestSSHEnsureInterfaceIsIdempotent(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{outputs: []string{
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "up", "core uplink"),
	}}
	ctx, failed := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.sshEnsure = executor
	description := "core uplink"
	if executeSteps(ctx, nil, []StepConfig{{
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
			Description: &description, Transport: "ssh",
		},
	}}) || *failed {
		t.Fatalf("idempotent SSH interface ensure failed: %v", *failed)
	}
	if len(executor.commands) != 1 {
		t.Fatalf("in-sync SSH interface sent a mutation: %+v", executor.commands)
	}
}

func TestSSHEnsureInterfaceRequireStateRefusesActivePortChange(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{outputs: []string{
		iosXRInterfaceOutput("HundredGigE0/0/0/0", "up", "unexpected service"),
	}}
	ctx, failed := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.sshEnsure = executor
	description := "new core uplink"
	if !executeSteps(ctx, nil, []StepConfig{{
		Name: "guarded-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
			RequireState: "disabled", Description: &description, Transport: "ssh",
		},
	}}) || !*failed {
		t.Fatalf("active interface should fail the require_state gate: failed=%v", *failed)
	}
	if len(executor.commands) != 1 {
		t.Fatalf("require_state failure sent a mutation: %+v", executor.commands)
	}
}

func TestParseIOSXRInterfaceDownMeansAdminEnabled(t *testing.T) {
	state, err := parseIOSXRInterfaceState(
		readEnsureFixture(t, "interface-operationally-down.txt"),
		"HundredGigE0/0/0/0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.Enabled == nil || !*state.Enabled {
		t.Fatalf("operationally down IOS XR interface should remain administratively enabled: %+v", state)
	}
}

func TestParseIOSXRInterfaceFixtures(t *testing.T) {
	tests := []struct {
		name            string
		fixture         string
		enabled         bool
		wantDescription bool
	}{
		{name: "administratively down", fixture: "interface-administratively-down.txt", enabled: false, wantDescription: true},
		{name: "operationally down", fixture: "interface-operationally-down.txt", enabled: true, wantDescription: true},
		{name: "up without description", fixture: "interface-up-no-description.txt", enabled: true, wantDescription: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := parseIOSXRInterfaceState(readEnsureFixture(t, test.fixture), "HundredGigE0/0/0/0")
			if err != nil {
				t.Fatal(err)
			}
			if state.Enabled == nil || *state.Enabled != test.enabled || (state.Description != nil) != test.wantDescription {
				t.Fatalf("unexpected state from %s: %+v", test.fixture, state)
			}
		})
	}
	if _, err := parseIOSXRInterfaceState(readEnsureFixture(t, "interface-not-found.txt"), "HundredGigE0/0/0/99"); err == nil {
		t.Fatal("not-found fixture was accepted as an interface")
	}
}

func TestEOSInterfaceFixturesAndCommands(t *testing.T) {
	disabled, err := parseEOSInterfaceState(
		readPlatformEnsureFixture(t, "eos", "interface-administratively-down.txt"),
		"Ethernet3",
	)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled == nil || *disabled.Enabled || disabled.Description == nil || *disabled.Description != "Example customer handoff" {
		t.Fatalf("unexpected disabled EOS interface: %+v", disabled)
	}
	enabled, err := parseEOSInterfaceState(
		readPlatformEnsureFixture(t, "eos", "interface-up-no-description.txt"),
		"Ethernet3",
	)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.Enabled == nil || !*enabled.Enabled || enabled.Description != nil {
		t.Fatalf("unexpected enabled EOS interface: %+v", enabled)
	}
	description := "new customer handoff"
	commands := eosInterfaceCommands("Ethernet3", true, &description)
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "description new customer handoff") ||
		!strings.Contains(joined, "no shutdown") ||
		strings.Contains(joined, "commit") ||
		commands[len(commands)-1] != "write memory" {
		t.Fatalf("unexpected EOS interface commands: %+v", commands)
	}
}

func TestEOSInterfaceEnsureCheckAndApply(t *testing.T) {
	disabled := readPlatformEnsureFixture(t, "eos", "interface-administratively-down.txt")
	enabled := strings.Replace(disabled, "is administratively down, line protocol is down (disabled)", "is up, line protocol is up (connected)", 1)
	enabled = strings.Replace(enabled, "Example customer handoff", "new customer handoff", 1)
	executor := &sequenceSSHEnsureExecutor{outputs: []string{disabled, "Copy completed successfully", enabled}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "arista_eos"
	description := "new customer handoff"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "Ethernet3", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 || !strings.Contains(executor.commands[1], "write memory") ||
		strings.Contains(executor.commands[1], "commit") || !strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("EOS ensure did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
}

func TestIOSXEInterfaceFixturesAndEnsure(t *testing.T) {
	disabled := readPlatformEnsureFixture(t, "iosxe", "interface-administratively-down.txt")
	state, err := parseIOSXEInterfaceState(disabled, "GigabitEthernet1")
	if err != nil || state.Enabled == nil || *state.Enabled || state.Description == nil {
		t.Fatalf("unexpected IOS-XE disabled state: state=%+v error=%v", state, err)
	}
	enabledFixture := strings.Replace(disabled, "is administratively down, line protocol is down", "is up, line protocol is up", 1)
	enabledFixture = strings.Replace(enabledFixture, "Example customer handoff", "new customer handoff", 1)
	executor := &sequenceSSHEnsureExecutor{outputs: []string{disabled, "Building configuration...\n[OK]", enabledFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxe"
	description := "new customer handoff"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "GigabitEthernet1", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 || !strings.Contains(executor.commands[1], "write memory") ||
		strings.Contains(executor.commands[1], "commit") || !strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("IOS-XE ensure did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
	upNoDescription, err := parseIOSXEInterfaceState(
		readPlatformEnsureFixture(t, "iosxe", "interface-up-no-description.txt"),
		"GigabitEthernet1",
	)
	if err != nil || upNoDescription.Enabled == nil || !*upNoDescription.Enabled || upNoDescription.Description != nil {
		t.Fatalf("unexpected IOS-XE enabled state: state=%+v error=%v", upNoDescription, err)
	}
}

func TestNXOSInterfaceFixturesAndEnsure(t *testing.T) {
	disabled := readPlatformEnsureFixture(t, "nxos", "interface-administratively-down.txt")
	state, err := parseNXOSInterfaceState(disabled, "Ethernet1/3")
	if err != nil || state.Enabled == nil || *state.Enabled || state.Description == nil ||
		*state.Description != "Example customer handoff" {
		t.Fatalf("unexpected NX-OS disabled state: state=%+v error=%v", state, err)
	}
	enabledFixture := strings.Replace(
		disabled,
		"is administratively down, line protocol is down (Administratively down)",
		"is up, line protocol is up (connected)",
		1,
	)
	enabledFixture = strings.Replace(enabledFixture, "Example customer handoff", "new customer handoff", 1)
	executor := &sequenceSSHEnsureExecutor{outputs: []string{disabled, "Copy complete.", enabledFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_nxos"
	description := "new customer handoff"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "Ethernet1/3", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 ||
		!strings.Contains(executor.commands[1], "copy running-config startup-config") ||
		strings.Contains(executor.commands[1], "write memory") ||
		strings.Contains(executor.commands[1], "commit") ||
		!strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("NX-OS ensure did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
	upNoDescription, err := parseNXOSInterfaceState(
		readPlatformEnsureFixture(t, "nxos", "interface-up-no-description.txt"),
		"Ethernet1/3",
	)
	if err != nil || upNoDescription.Enabled == nil || !*upNoDescription.Enabled || upNoDescription.Description != nil {
		t.Fatalf("unexpected NX-OS enabled state: state=%+v error=%v", upNoDescription, err)
	}
}

func TestJunosInterfaceFixturesAndEnsure(t *testing.T) {
	disabled := readPlatformEnsureFixture(t, "junos", "interface-administratively-down.txt")
	state, err := parseJunosInterfaceState(disabled, "ge-0/0/3")
	if err != nil || state.Enabled == nil || *state.Enabled || state.Description == nil ||
		*state.Description != "Example customer handoff" {
		t.Fatalf("unexpected Junos disabled state: state=%+v error=%v", state, err)
	}
	enabledFixture := strings.Replace(disabled, "down  down", "up    up", 1)
	enabledFixture = strings.Replace(enabledFixture, `"Example customer handoff"`, `"new customer handoff"`, 1)
	enabledFixture = strings.Replace(enabledFixture, "set interfaces ge-0/0/3 disable\n", "", 1)
	executor := &sequenceSSHEnsureExecutor{outputs: []string{disabled, "commit complete", enabledFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "juniper_junos"
	description := "new customer handoff"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "ge-0/0/3", State: "enabled",
		RequireState: "disabled", Description: &description, Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 ||
		executor.commands[0] != "show interfaces ge-0/0/3 terse\nshow configuration interfaces ge-0/0/3 | display set" ||
		!strings.Contains(executor.commands[1], `set interfaces ge-0/0/3 description "new customer handoff"`) ||
		!strings.Contains(executor.commands[1], "delete interfaces ge-0/0/3 disable") ||
		!strings.Contains(executor.commands[1], "commit and-quit") ||
		strings.Contains(executor.commands[1], "write memory") ||
		!strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("Junos ensure did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
	upNoDescription, err := parseJunosInterfaceState(
		readPlatformEnsureFixture(t, "junos", "interface-up-no-description.txt"),
		"ge-0/0/3",
	)
	if err != nil || upNoDescription.Enabled == nil || !*upNoDescription.Enabled || upNoDescription.Description != nil {
		t.Fatalf("unexpected Junos enabled state: state=%+v error=%v", upNoDescription, err)
	}
}

func TestParseIOSXRStaticRoutesSeparatesVRFs(t *testing.T) {
	iosXRStaticRouteFixture := readEnsureFixture(t, "static-routes.txt")
	defaultRoute := parseIOSXRStaticRoutes(iosXRStaticRouteFixture, "198.51.100.0/24", "")
	if len(defaultRoute.NextHops) != 1 || defaultRoute.NextHops[0] != "192.0.2.1" {
		t.Fatalf("unexpected default route state: %+v", defaultRoute)
	}
	customerRoute := parseIOSXRStaticRoutes(iosXRStaticRouteFixture, "203.0.113.0/24", "CUSTOMER-A")
	if len(customerRoute.NextHops) != 2 || customerRoute.NextHops[0] != "192.0.2.10" || customerRoute.NextHops[1] != "192.0.2.11" {
		t.Fatalf("unexpected customer route state: %+v", customerRoute)
	}
	customerBRoute := parseIOSXRStaticRoutes(iosXRStaticRouteFixture, "203.0.113.0/24", "CUSTOMER-B")
	if len(customerBRoute.NextHops) != 1 || customerBRoute.NextHops[0] != "192.0.2.20" {
		t.Fatalf("unexpected second VRF route state: %+v", customerBRoute)
	}
	if wrongVRF := parseIOSXRStaticRoutes(iosXRStaticRouteFixture, "203.0.113.0/24", "CUSTOMER-C"); len(wrongVRF.NextHops) != 0 {
		t.Fatalf("route leaked across VRFs: %+v", wrongVRF)
	}
}

func TestSSHEnsureStaticRouteCheckModePreviewsExactPath(t *testing.T) {
	iosXRStaticRouteFixture := readEnsureFixture(t, "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{iosXRStaticRouteFixture}}
	ctx, failed := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.checkMode = true
	ctx.sshEnsure = executor

	if executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-route",
		Ensure: &EnsureConfig{
			Resource: "static_route", Prefix: "203.0.114.0/24", NextHop: "192.0.2.10",
			VRF: "CUSTOMER-A", State: "present", Transport: "ssh",
		},
	}}) || *failed {
		t.Fatalf("SSH route check failed: %v", *failed)
	}
	if len(executor.commands) != 1 || executor.commands[0] != "show running-config router static" {
		t.Fatalf("check mode sent more than route discovery: %+v", executor.commands)
	}
}

func TestSSHEnsureStaticRoutePresentIsIdempotentAndPreservesECMP(t *testing.T) {
	iosXRStaticRouteFixture := readEnsureFixture(t, "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{iosXRStaticRouteFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.113.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "present", Transport: "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 1 || !strings.Contains(output, `"changed": false`) {
		t.Fatalf("existing exact route should be idempotent: commands=%+v output=%s", executor.commands, output)
	}
	if !strings.Contains(output, `"192.0.2.11"`) {
		t.Fatalf("ECMP peer was not preserved in current state: %s", output)
	}
}

func TestSSHEnsureStaticRouteAbsentPlanRemovesOnlyExactNextHop(t *testing.T) {
	iosXRStaticRouteFixture := readEnsureFixture(t, "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{iosXRStaticRouteFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.checkMode = true
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.113.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "absent", Transport: "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, `no 203.0.113.0/24 192.0.2.10`) ||
		!strings.Contains(output, `"192.0.2.11"`) {
		t.Fatalf("route removal plan did not target only the exact path: %s", output)
	}
}

func TestSSHEnsureStaticRouteAppliesAndVerifies(t *testing.T) {
	iosXRStaticRouteFixture := readEnsureFixture(t, "static-routes.txt")
	verifiedFixture := strings.Replace(iosXRStaticRouteFixture, "   203.0.113.0/24 192.0.2.10", "   203.0.114.0/24 192.0.2.10\n   203.0.113.0/24 192.0.2.10", 1)
	executor := &sequenceSSHEnsureExecutor{outputs: []string{iosXRStaticRouteFixture, "Commit complete", verifiedFixture}}
	ctx, failed := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxr"
	ctx.sshEnsure = executor

	if executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-route",
		Ensure: &EnsureConfig{
			Resource: "static_route", Prefix: "203.0.114.0/24", NextHop: "192.0.2.10",
			VRF: "CUSTOMER-A", State: "present", Transport: "ssh",
		},
	}}) || *failed {
		t.Fatalf("SSH route apply failed: failed=%v commands=%+v", *failed, executor.commands)
	}
	if len(executor.commands) != 3 ||
		!strings.Contains(executor.commands[1], "vrf CUSTOMER-A") ||
		!strings.Contains(executor.commands[1], "203.0.114.0/24 192.0.2.10") ||
		executor.commands[2] != "show running-config router static" {
		t.Fatalf("SSH route did not discover, apply, and verify: %+v", executor.commands)
	}
}

func TestParseEOSStaticRoutesSeparatesVRFsAndPreservesECMP(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "eos", "static-routes.txt")
	defaultRoute := parseEOSStaticRoutes(fixture, "198.51.100.0/24", "")
	if len(defaultRoute.NextHops) != 1 || defaultRoute.NextHops[0] != "192.0.2.1" {
		t.Fatalf("unexpected EOS default route: %+v", defaultRoute)
	}
	customerRoute := parseEOSStaticRoutes(fixture, "203.0.113.0/24", "CUSTOMER-A")
	if len(customerRoute.NextHops) != 2 || customerRoute.NextHops[0] != "192.0.2.10" || customerRoute.NextHops[1] != "192.0.2.11" {
		t.Fatalf("unexpected EOS customer route: %+v", customerRoute)
	}
	customerBRoute := parseEOSStaticRoutes(fixture, "203.0.113.0/24", "CUSTOMER-B")
	if len(customerBRoute.NextHops) != 1 || customerBRoute.NextHops[0] != "192.0.2.20" {
		t.Fatalf("EOS route leaked across VRFs: %+v", customerBRoute)
	}
}

func TestEOSStaticRouteEnsureCheckApplyAndVerify(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "eos", "static-routes.txt")
	verifiedFixture := fixture + "ip route vrf CUSTOMER-A 203.0.114.0/24 192.0.2.10\n"
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture, "Copy completed successfully", verifiedFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "arista_eos"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.114.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "present", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 ||
		executor.commands[0] != "show running-config | include ^ip route" ||
		!strings.Contains(executor.commands[1], "ip route vrf CUSTOMER-A 203.0.114.0/24 192.0.2.10") ||
		!strings.Contains(executor.commands[1], "write memory") ||
		strings.Contains(executor.commands[1], "commit") ||
		!strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("EOS route did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
}

func TestEOSStaticRouteAbsentPlanTargetsExactNextHop(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "eos", "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "arista_eos"
	ctx.checkMode = true
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.113.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "absent", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 1 ||
		!strings.Contains(output, `no ip route vrf CUSTOMER-A 203.0.113.0/24 192.0.2.10`) ||
		!strings.Contains(output, `"192.0.2.11"`) {
		t.Fatalf("EOS route removal plan was not exact: commands=%+v output=%s", executor.commands, output)
	}
}

func TestIOSXEStaticRouteParsingAndMaskRendering(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "iosxe", "static-routes.txt")
	customerRoute := parseIOSXEStaticRoutes(fixture, "203.0.113.0/24", "CUSTOMER-A")
	if len(customerRoute.NextHops) != 2 || customerRoute.NextHops[0] != "192.0.2.10" || customerRoute.NextHops[1] != "192.0.2.11" {
		t.Fatalf("unexpected IOS-XE VRF route: %+v", customerRoute)
	}
	cidrRoute := parseIOSXEStaticRoutes(fixture, "192.0.2.128/25", "")
	if len(cidrRoute.NextHops) != 1 || cidrRoute.NextHops[0] != "198.51.100.1" {
		t.Fatalf("IOS-XE CIDR route was not normalized: %+v", cidrRoute)
	}
	network, mask := iosXEPrefixParts("203.0.114.0/24")
	if network != "203.0.114.0" || mask != "255.255.255.0" {
		t.Fatalf("unexpected IOS-XE prefix rendering: network=%s mask=%s", network, mask)
	}
}

func TestIOSXEStaticRouteEnsureCheckApplyAndVerify(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "iosxe", "static-routes.txt")
	verifiedFixture := fixture + "ip route vrf CUSTOMER-A 203.0.114.0 255.255.255.0 192.0.2.10\n"
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture, "Building configuration...\n[OK]", verifiedFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxe"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.114.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "present", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 ||
		executor.commands[0] != "show running-config | include ^ip route" ||
		!strings.Contains(executor.commands[1], "ip route vrf CUSTOMER-A 203.0.114.0 255.255.255.0 192.0.2.10") ||
		!strings.Contains(executor.commands[1], "write memory") ||
		!strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("IOS-XE route did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
}

func TestIOSXEStaticRouteAbsentPlanIsExact(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "iosxe", "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_iosxe"
	ctx.checkMode = true
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.113.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "absent", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 1 ||
		!strings.Contains(output, `no ip route vrf CUSTOMER-A 203.0.113.0 255.255.255.0 192.0.2.10`) ||
		!strings.Contains(output, `"192.0.2.11"`) {
		t.Fatalf("IOS-XE route removal plan was not exact: commands=%+v output=%s", executor.commands, output)
	}
}

func TestNXOSStaticRouteParsingAndVRFCommands(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "nxos", "static-routes.txt")
	customerRoute := parseNXOSStaticRoutes(fixture, "203.0.113.0/24", "CUSTOMER-A")
	if len(customerRoute.NextHops) != 2 ||
		customerRoute.NextHops[0] != "192.0.2.10" ||
		customerRoute.NextHops[1] != "192.0.2.11" {
		t.Fatalf("unexpected NX-OS VRF route: %+v", customerRoute)
	}
	defaultRoute := parseNXOSStaticRoutes(fixture, "192.0.2.128/25", "")
	if len(defaultRoute.NextHops) != 1 || defaultRoute.NextHops[0] != "198.51.100.1" {
		t.Fatalf("NX-OS parser did not return to the default VRF: %+v", defaultRoute)
	}
	commands := nxOSStaticRouteCommands("203.0.114.0/24", "192.0.2.10", "CUSTOMER-A", true)
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "vrf context CUSTOMER-A\n ip route 203.0.114.0/24 192.0.2.10") ||
		commands[len(commands)-1] != "copy running-config startup-config" {
		t.Fatalf("unexpected NX-OS VRF route commands: %+v", commands)
	}
}

func TestNXOSStaticRouteEnsureCheckApplyAndVerify(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "nxos", "static-routes.txt")
	verifiedFixture := fixture + "\nvrf context CUSTOMER-A\n  ip route 203.0.114.0/24 192.0.2.10\n"
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture, "Copy complete.", verifiedFixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_nxos"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.114.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "present", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 ||
		executor.commands[0] != "show running-config" ||
		!strings.Contains(executor.commands[1], "vrf context CUSTOMER-A") ||
		!strings.Contains(executor.commands[1], "ip route 203.0.114.0/24 192.0.2.10") ||
		!strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("NX-OS route did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
}

func TestNXOSStaticRouteAbsentPlanIsExact(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "nxos", "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "cisco_nxos"
	ctx.checkMode = true
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.113.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "absent", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 1 ||
		!strings.Contains(output, `no ip route 203.0.113.0/24 192.0.2.10`) ||
		!strings.Contains(output, `"192.0.2.11"`) {
		t.Fatalf("NX-OS route removal plan was not exact: commands=%+v output=%s", executor.commands, output)
	}
}

func TestJunosStaticRouteParsingAndEnsure(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "junos", "static-routes.txt")
	customerRoute := parseJunosStaticRoutes(fixture, "203.0.113.0/24", "CUSTOMER-A")
	if len(customerRoute.NextHops) != 2 ||
		customerRoute.NextHops[0] != "192.0.2.10" ||
		customerRoute.NextHops[1] != "192.0.2.11" {
		t.Fatalf("unexpected Junos VRF route: %+v", customerRoute)
	}
	verified := fixture + "set routing-instances CUSTOMER-A routing-options static route 203.0.114.0/24 next-hop 192.0.2.10\n"
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture, "commit complete", verified}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "juniper_junos"
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.114.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "present", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 3 ||
		!strings.Contains(executor.commands[1], "set routing-instances CUSTOMER-A routing-options static route 203.0.114.0/24 next-hop 192.0.2.10") ||
		!strings.Contains(executor.commands[1], "commit and-quit") ||
		!strings.Contains(output, `"action": "changed"`) {
		t.Fatalf("Junos route did not discover, apply, and verify: commands=%+v output=%s", executor.commands, output)
	}
}

func TestJunosStaticRouteAbsentPlanIsExact(t *testing.T) {
	fixture := readPlatformEnsureFixture(t, "junos", "static-routes.txt")
	executor := &sequenceSSHEnsureExecutor{outputs: []string{fixture}}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "juniper_junos"
	ctx.checkMode = true
	output, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "static_route", Prefix: "203.0.113.0/24", NextHop: "192.0.2.10",
		VRF: "CUSTOMER-A", State: "absent", Transport: "ssh", RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 1 ||
		!strings.Contains(output, "delete routing-instances CUSTOMER-A routing-options static route 203.0.113.0/24 next-hop 192.0.2.10") ||
		!strings.Contains(output, `"192.0.2.11"`) {
		t.Fatalf("Junos route removal plan was not exact: commands=%+v output=%s", executor.commands, output)
	}
}

func TestSSHEnsureRejectsUnsupportedPlatformAndUnsafeValues(t *testing.T) {
	executor := &sequenceSSHEnsureExecutor{}
	ctx, _ := interactionContext(t, nil)
	ctx.deviceType = "unsupported_os"
	if _, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "Ethernet1", State: "enabled", Transport: "ssh",
	}); err == nil || !strings.Contains(err.Error(), "currently supported: cisco_iosxr, arista_eos, cisco_iosxe, cisco_nxos, juniper_junos") {
		t.Fatalf("unsupported platform was accepted: %v", err)
	}
	ctx.deviceType = "cisco_iosxr"
	if _, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "Ethernet1\nshutdown", State: "enabled", Transport: "ssh",
	}); err == nil {
		t.Fatal("unsafe interface value was accepted")
	}
	injectedDescription := "uplink; shutdown"
	if _, _, err := executeSSHEnsureStep(ctx, executor, EnsureConfig{
		Resource: "interface", Name: "Ethernet1", State: "enabled",
		Description: &injectedDescription, Transport: "ssh",
	}); err == nil {
		t.Fatal("unsafe description value was accepted")
	}
}

func TestCheckModeSSHNeedDetectionOnlyConnectsForSSHEnsure(t *testing.T) {
	workflows := map[string]WorkflowConfig{
		"ensure-route": {Steps: []StepConfig{{Ensure: &EnsureConfig{Resource: "static_route", Transport: "ssh"}}}},
	}
	if stepsNeedSSHInCheck([]StepConfig{{Use: "ensure-route"}}, workflows, map[string]bool{}) != true {
		t.Fatal("nested SSH ensure was not detected in check mode")
	}
	if stepsNeedSSHInCheck([]StepConfig{{Command: "show version"}}, nil, map[string]bool{}) {
		t.Fatal("generic SSH command should not open a check-mode SSH connection")
	}
}
