package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

type fakeNETCONFStepExecutor struct {
	configs []NETCONFStepConfig
	output  string
	err     error
}

func TestNETCONFWorkflowStepLoadsAndRendersPayloadFile(t *testing.T) {
	directory := t.TempDir()
	payloadPath := filepath.Join(directory, "interface.xml")
	if err := os.WriteFile(payloadPath, []byte(`<config><interface><name>{{interface}}</name></interface></config>`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, failed := interactionContext(t, map[string]string{"interface": "Ethernet4"})
	ctx.configBaseDir = directory
	executor := &fakeNETCONFStepExecutor{output: "<ok/>"}
	ctx.netconf = executor
	var client *ssh.Client
	step := StepConfig{
		Name: "file-payload",
		NETCONF: &NETCONFStepConfig{
			Operation:   "edit-config",
			Target:      "running",
			PayloadFile: "interface.xml",
		},
	}

	if executeSteps(ctx, &client, []StepConfig{step}) || *failed {
		t.Fatalf("NETCONF payload_file step failed: failed=%v", *failed)
	}
	if len(executor.configs) != 1 || executor.configs[0].Payload != `<config><interface><name>Ethernet4</name></interface></config>` {
		t.Fatalf("NETCONF payload_file was not loaded and rendered: %+v", executor.configs)
	}
}

func (executor *fakeNETCONFStepExecutor) ExecuteNETCONF(config NETCONFStepConfig) (string, error) {
	executor.configs = append(executor.configs, config)
	return executor.output, executor.err
}

func TestNETCONFWorkflowStepRendersAndValidatesWithoutSSH(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{
		"table":  "CUST3100.inet.0",
		"prefix": "203.0.113.0/24",
	})
	executor := &fakeNETCONFStepExecutor{
		output: "<route-information><rt-destination>203.0.113.0/24</rt-destination></route-information>",
	}
	ctx.netconf = executor
	var client *ssh.Client
	step := StepConfig{
		Name: "route-check",
		NETCONF: &NETCONFStepConfig{
			Operation: "rpc",
			Payload:   "<get-route-information><table>{{table}}</table><destination>{{prefix}}</destination></get-route-information>",
		},
		Validation: &ValidationConfig{
			Extractor: "regex",
			Pattern:   `<rt-destination>([^<]+)</rt-destination>`,
			Condition: "eq",
			Expected:  "{{prefix}}",
		},
	}

	if executeSteps(ctx, &client, []StepConfig{step}) || *failed {
		t.Fatalf("NETCONF-only step failed: failed=%v", *failed)
	}
	if client != nil {
		t.Fatal("NETCONF-only step unexpectedly created an SSH client")
	}
	if len(executor.configs) != 1 || !strings.Contains(executor.configs[0].Payload, "CUST3100.inet.0") || !strings.Contains(executor.configs[0].Payload, "203.0.113.0/24") {
		t.Fatalf("NETCONF payload was not rendered: %+v", executor.configs)
	}
	if stepsNeedSSH([]StepConfig{step}, nil, map[string]bool{}) {
		t.Fatal("NETCONF-only step was classified as requiring SSH")
	}
}

func TestValidateNETCONFOperations(t *testing.T) {
	tests := []struct {
		name   string
		config NETCONFStepConfig
		want   string
	}{
		{name: "rpc payload", config: NETCONFStepConfig{Operation: "rpc"}, want: "payload or netconf.payload_file is required"},
		{name: "edit target", config: NETCONFStepConfig{Operation: "edit-config", Target: "startup", Payload: "<config/>"}, want: "unsupported"},
		{name: "commit payload", config: NETCONFStepConfig{Operation: "commit", Payload: "<commit/>"}, want: "does not support payload"},
		{name: "commit payload file", config: NETCONFStepConfig{Operation: "commit", PayloadFile: "commit.xml"}, want: "does not support payload"},
		{name: "commit timeout", config: NETCONFStepConfig{Operation: "commit", ConfirmTimeoutSeconds: 30}, want: "confirmed must be true"},
		{name: "discard fields", config: NETCONFStepConfig{Operation: "discard-changes", Target: "candidate"}, want: "does not support"},
		{name: "unknown", config: NETCONFStepConfig{Operation: "copy-config"}, want: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateNETCONFStep(test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateNETCONFStep() error=%v want substring %q", err, test.want)
			}
		})
	}
	for _, config := range []NETCONFStepConfig{
		{Operation: "rpc", Payload: "<get/>"},
		{Operation: "edit-config", Target: "candidate", Payload: "<config/>"},
		{Operation: "commit"},
		{Operation: "commit", Confirmed: true, ConfirmTimeoutSeconds: 30},
		{Operation: "discard-changes"},
	} {
		if err := validateNETCONFStep(config); err != nil {
			t.Fatalf("valid NETCONF operation rejected: config=%+v error=%v", config, err)
		}
	}
}

func TestRenderNETCONFStepRejectsPayloadAndPayloadFile(t *testing.T) {
	_, err := renderNETCONFStep(NETCONFStepConfig{
		Operation:   "rpc",
		Payload:     "<get/>",
		PayloadFile: "get.xml",
	}, nil, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("renderNETCONFStep() error=%v, want mutual exclusion error", err)
	}
}
