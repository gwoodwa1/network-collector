package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightRejectsUndefinedVariableBeforeSteps(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		IP:       "192.0.2.10",
		Steps: []StepConfig{{
			Name:    "configure-interface",
			Command: "interface {{interface_name}}",
		}},
	}

	err := preflightDeviceVariables(device, nil, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), `undefined variable "interface_name"`) {
		t.Fatalf("expected undefined-variable error, got %v", err)
	}
	if !strings.Contains(err.Error(), "edge-01/configure-interface cmd") {
		t.Fatalf("expected device and step path, got %v", err)
	}
}

func TestPreflightRejectsEmptyReferencedVariable(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{{
			Name:    "configure-interface",
			Command: "interface {{interface_name}}",
		}},
	}

	err := preflightDeviceVariables(device, nil, map[string]string{"interface_name": " \t"})
	if err == nil || !strings.Contains(err.Error(), `empty variable "interface_name"`) {
		t.Fatalf("expected empty-variable error, got %v", err)
	}
}

func TestPreflightRejectsRegisteredDeviceOutputInCommands(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{
			{Name: "discover", Command: "show interface", Register: "interface_state"},
			{Name: "use-result", Command: "inspect {{interface_state}}"},
		},
	}

	err := preflightDeviceVariables(device, nil, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), `cannot interpolate tainted device output variable "interface_state"`) {
		t.Fatalf("expected tainted command interpolation to fail, got %v", err)
	}
}

func TestPreflightRejectsRegisteredDeviceOutputInNETCONFPayload(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{
			{Name: "discover", Command: "show interface", Register: "interface_name"},
			{Name: "use-result", NETCONF: &NETCONFStepConfig{
				Operation: "edit-config",
				Payload:   "<interface><name>{{interface_name}}</name></interface>",
			}},
		},
	}

	err := preflightDeviceVariables(device, nil, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), `cannot interpolate tainted device output variable "interface_name"`) {
		t.Fatalf("expected adversarial registered output to be rejected before NETCONF rendering, got %v", err)
	}
}

func TestPreflightAllowsRegisteredDeviceOutputInMessages(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{
			{Name: "discover", Command: "show interface", Register: "interface_state"},
			{Name: "describe-result", Message: "observed {{interface_state}}"},
		},
	}

	if err := preflightDeviceVariables(device, nil, map[string]string{}); err != nil {
		t.Fatalf("expected tainted output to remain usable as non-executable data: %v", err)
	}
}

func TestPreflightRejectsReferenceBeforeRegister(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{
			{Name: "use-result", Command: "inspect {{interface_state}}"},
			{Name: "discover", Command: "show interface", Register: "interface_state"},
		},
	}

	err := preflightDeviceVariables(device, nil, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), `undefined variable "interface_state"`) {
		t.Fatalf("expected reference-before-register failure, got %v", err)
	}
}

func TestPreflightScopesForeachVariables(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{{
			Name: "interfaces",
			Foreach: &ForeachConfig{
				From:  "monitored_interfaces",
				Item:  "interface",
				Index: "position",
				Steps: []StepConfig{{
					Name:    "inspect",
					Command: "show interface {{interface}} position {{position}} at {{site}}",
				}},
			},
		}},
	}
	vars := map[string]string{
		"monitored_interfaces": `["Ethernet1","Ethernet2"]`,
		"site":                 "london",
	}

	if err := preflightDeviceVariables(device, nil, vars); err != nil {
		t.Fatalf("expected foreach variables to be in scope: %v", err)
	}
}

func TestPreflightScopesGNMIEventVariables(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{{
			Name: "monitor",
			GNMISubscribe: &GNMISubscribeConfig{
				Paths: []string{"/interfaces/interface/state"},
				Triggers: []GNMITriggerConfig{{
					Name: "interface-change",
					Steps: []StepConfig{{
						Name:    "record-event",
						Message: "{{gnmi_event_path}} changed to {{gnmi_event_value}}",
					}},
				}},
			},
		}},
	}

	if err := preflightDeviceVariables(device, nil, nil); err != nil {
		t.Fatalf("expected gNMI event bindings to be in trigger scope: %v", err)
	}
}

func TestPreflightValidatesWorkflowParametersAndNestedReferences(t *testing.T) {
	workflows := map[string]WorkflowConfig{
		"turn-up": {
			Parameters: []string{"interface"},
			Steps: []StepConfig{{
				Name:    "configure",
				Command: "interface {{interface}} description {{description}}",
			}},
		},
	}
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{{
			Name: "invoke-turn-up",
			Use:  "turn-up",
			With: map[string]interface{}{"interface": "{{interface_name}}"},
		}},
	}

	err := preflightDeviceVariables(device, workflows, map[string]string{"interface_name": "Ethernet1"})
	if err == nil || !strings.Contains(err.Error(), `undefined variable "description"`) {
		t.Fatalf("expected nested workflow reference failure, got %v", err)
	}
}

func TestPreflightChecksInventoryValuesPerDevice(t *testing.T) {
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{{
			Name:    "configure",
			Command: "interface {{interface_name}} description {{description}}",
		}},
	}
	defaults := map[string]string{"description": "core uplink"}
	vars, err := mergeInventoryVariables(defaults, map[string]interface{}{"interface_name": "Ethernet7"})
	if err != nil {
		t.Fatal(err)
	}

	if err := preflightDeviceVariables(device, nil, vars); err != nil {
		t.Fatalf("expected host inventory variable to satisfy preflight: %v", err)
	}
}

func TestPreflightRejectsEmptyWorkflowArgument(t *testing.T) {
	workflows := map[string]WorkflowConfig{
		"turn-up": {
			Parameters: []string{"interface"},
			Steps:      []StepConfig{{Name: "configure", Command: "interface {{interface}}"}},
		},
	}
	device := DeviceConfig{
		Hostname: "edge-01",
		Steps: []StepConfig{{
			Name: "invoke-turn-up",
			Use:  "turn-up",
			With: map[string]interface{}{"interface": ""},
		}},
	}

	err := preflightDeviceVariables(device, workflows, nil)
	if err == nil || !strings.Contains(err.Error(), `workflow parameter "interface"`) {
		t.Fatalf("expected empty workflow parameter failure, got %v", err)
	}
}

func TestWorkflowOperationExamplesPassVariablePreflight(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "examples", "workflow-operations", "*", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		parent := filepath.Base(filepath.Dir(path))
		if parent == "inventory" || parent == "parsers" || parent == "vars" {
			continue
		}
		t.Run(parent+"/"+filepath.Base(path), func(t *testing.T) {
			config, _, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := loadOptionalInventory(config.InventoryFile, path)
			if err != nil {
				t.Fatal(err)
			}
			sshDevices, err := resolveInventoryDevices(config.SSH, inventory)
			if err != nil {
				t.Fatal(err)
			}
			netconfDevices, err := resolveInventoryDevices(config.NETCONF, inventory)
			if err != nil {
				t.Fatal(err)
			}
			defaults, err := configVariables(config.Vars)
			if err != nil {
				t.Fatal(err)
			}
			for _, device := range append(sshDevices, netconfDevices...) {
				vars, err := mergeInventoryVariables(defaults, device.InventoryVars)
				if err != nil {
					t.Fatal(err)
				}
				if err := preflightDeviceVariables(device, config.Workflows, vars); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
