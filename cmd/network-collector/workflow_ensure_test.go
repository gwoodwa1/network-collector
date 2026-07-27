package main

import (
	"strings"
	"testing"
)

type sequenceNETCONFExecutor struct {
	configs []NETCONFStepConfig
	outputs []string
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
