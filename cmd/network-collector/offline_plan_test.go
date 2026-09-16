package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildOfflinePlanIsStructuralAndMarksRuntimeBranches(t *testing.T) {
	config := Config{
		NamePlaybook: "safe upgrade",
		Workflows: map[string]WorkflowConfig{
			"verify": {Steps: []StepConfig{{Name: "show-version", Command: "show version"}}},
		},
	}
	devices := []DeviceConfig{{
		Hostname: "edge-1",
		IP:       "192.0.2.10",
		Type:     "iosxr",
		Groups:   []string{"core", "blue"},
		Steps: []StepConfig{
			{Name: "precheck", Use: "verify"},
			{Name: "upgrade", Block: &BlockConfig{
				Steps:  []StepConfig{{Name: "apply", Command: "install add file secret-image.bin"}},
				Rescue: []StepConfig{{Name: "restore", Command: "install rollback"}},
			}},
		}},
	}

	plan := buildOfflinePlan(config, devices)
	if plan.ConnectionsOpened != 0 || plan.DeviceCount != 1 {
		t.Fatalf("unexpected offline plan summary: %#v", plan)
	}
	if !strings.HasPrefix(plan.ResolutionDigest, "sha256:") {
		t.Fatalf("expected SHA-256 resolution digest, got %q", plan.ResolutionDigest)
	}
	if got, want := plan.Devices[0].Groups, []string{"blue", "core"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("groups were not represented deterministically: got %v want %v", got, want)
	}

	steps := plan.Devices[0].Steps
	if len(steps) != 5 {
		t.Fatalf("got %d plan steps, want 5: %#v", len(steps), steps)
	}
	if steps[1].Path != "precheck/workflow:verify/show-version" || steps[1].Conditional {
		t.Fatalf("workflow expansion is incorrect: %#v", steps[1])
	}
	if steps[4].Path != "upgrade/rescue/restore" || !steps[4].Conditional || steps[4].Reason != "block failure" {
		t.Fatalf("rescue branch must be shown as conditional: %#v", steps[4])
	}

	rendered := renderOfflinePlan(plan)
	if strings.Contains(rendered, "secret-image.bin") || strings.Contains(rendered, "install rollback") {
		t.Fatalf("offline plan must not expose command content: %s", rendered)
	}
}

func TestNetworkCollectorSchemaIsJSONAndExposesCoreDefinitions(t *testing.T) {
	encoded, err := json.Marshal(networkCollectorSchema())
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	if decoded["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected schema dialect: %#v", decoded["$schema"])
	}
	definitions, ok := decoded["$defs"].(map[string]interface{})
	if !ok || definitions["step"] == nil || definitions["device"] == nil {
		t.Fatalf("schema does not expose core definitions: %#v", decoded["$defs"])
	}
}
