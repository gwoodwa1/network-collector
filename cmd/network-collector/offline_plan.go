package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// offlinePlan is intentionally structural: device output, registered values,
// approvals, foreach.from and validation outcomes are runtime data. Instead of
// pretending to predict one path, it exposes those branches as conditional
// nodes. It contains no credentials, commands, payloads, or variable values.
type offlinePlan struct {
	FormatVersion     int                 `json:"format_version"`
	Playbook          string              `json:"playbook,omitempty"`
	DeviceCount       int                 `json:"device_count"`
	ConnectionsOpened int                 `json:"connections_opened"`
	ResolutionDigest  string              `json:"resolution_digest"`
	Devices           []offlinePlanDevice `json:"devices"`
}

type offlinePlanDevice struct {
	Hostname string            `json:"hostname"`
	IP       string            `json:"ip"`
	Platform string            `json:"platform,omitempty"`
	Groups   []string          `json:"groups,omitempty"`
	Steps    []offlinePlanStep `json:"steps"`
}

type offlinePlanStep struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Execution   string `json:"execution"`
	Conditional bool   `json:"conditional,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

func buildOfflinePlan(config Config, devices []DeviceConfig) offlinePlan {
	plan := offlinePlan{FormatVersion: 1, Playbook: strings.TrimSpace(config.NamePlaybook), DeviceCount: len(devices), ConnectionsOpened: 0}
	for _, device := range devices {
		steps := device.Steps
		if len(steps) == 0 && strings.TrimSpace(device.Command) != "" {
			steps = []StepConfig{{Name: "default", Command: device.Command, Parser: device.Parser, Validation: device.Validation, Validations: device.Validations}}
		}
		entry := offlinePlanDevice{Hostname: strings.TrimSpace(device.Hostname), IP: strings.TrimSpace(device.IP), Platform: strings.TrimSpace(device.Type), Groups: append([]string(nil), device.Groups...)}
		if entry.Hostname == "" {
			entry.Hostname = entry.IP
		}
		sort.Strings(entry.Groups)
		entry.Steps = appendPlanSteps(nil, steps, config.Workflows, "", false, "")
		plan.Devices = append(plan.Devices, entry)
	}
	// Struct-only JSON has stable field ordering. The digest binds the selected
	// device set and conditional graph without serialising secrets or values.
	canonical := plan
	canonical.ResolutionDigest = ""
	encoded, _ := json.Marshal(canonical)
	sum := sha256.Sum256(encoded)
	plan.ResolutionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return plan
}

func appendPlanSteps(result []offlinePlanStep, steps []StepConfig, workflows map[string]WorkflowConfig, prefix string, inheritedConditional bool, inheritedReason string) []offlinePlanStep {
	for index, step := range steps {
		name := strings.TrimSpace(step.Name)
		if name == "" {
			name = fmt.Sprintf("step-%d", index+1)
		}
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		conditional, reason := inheritedConditional, inheritedReason
		if step.When != nil {
			conditional, reason = true, "when condition"
		}
		kind := planStepKind(step)
		result = append(result, offlinePlanStep{Path: path, Kind: kind, Execution: planStepExecution(step), Conditional: conditional, Reason: reason})

		if use := strings.TrimSpace(step.Use); use != "" {
			if workflow, ok := workflows[use]; ok {
				result = appendPlanSteps(result, workflow.Steps, workflows, path+"/workflow:"+use, conditional, reason)
			}
		}
		if step.Repeat != nil {
			result = appendPlanSteps(result, step.Repeat.Steps, workflows, path+"/repeat", true, "repeat count/runtime result")
		}
		if step.Foreach != nil {
			result = appendPlanSteps(result, step.Foreach.Steps, workflows, path+"/foreach", true, "foreach items/runtime value")
		}
		if step.Parallel != nil {
			result = appendPlanSteps(result, step.Parallel.Steps, workflows, path+"/parallel", true, "parallel branch")
		}
		if step.Block != nil {
			result = appendPlanSteps(result, step.Block.Steps, workflows, path+"/block", conditional, reason)
			result = appendPlanSteps(result, step.Block.Rescue, workflows, path+"/rescue", true, "block failure")
			result = appendPlanSteps(result, step.Block.Rollback, workflows, path+"/rollback", true, "block failure or explicit rollback")
			result = appendPlanSteps(result, step.Block.Always, workflows, path+"/always", true, "block completion")
		}
		for _, action := range []*ValidationActionConfig{step.OnPass, step.OnFail} {
			if action != nil {
				result = appendPlanSteps(result, action.Steps, workflows, path+"/validation-action", true, "validation result")
			}
		}
		if step.GNMISubscribe != nil {
			for triggerIndex, trigger := range step.GNMISubscribe.Triggers {
				result = appendPlanSteps(result, trigger.Steps, workflows, fmt.Sprintf("%s/gnmi-trigger-%d", path, triggerIndex+1), true, "gNMI event trigger")
			}
		}
	}
	return result
}

func planStepKind(step StepConfig) string {
	switch {
	case step.Approval != nil:
		return "approval"
	case step.Facts != nil:
		return "facts"
	case step.Ensure != nil:
		return "ensure"
	case step.NETCONF != nil:
		return "netconf"
	case step.GNMISubscribe != nil:
		return "gnmi_subscribe"
	case step.SSHProbe != nil:
		return "ssh_probe"
	case step.WaitSeconds > 0:
		return "wait"
	case step.Use != "":
		return "workflow"
	case step.Foreach != nil:
		return "foreach"
	case step.Repeat != nil:
		return "repeat"
	case step.Block != nil:
		return "block"
	case step.Parallel != nil:
		return "parallel"
	case step.Command != "":
		return "ssh_command"
	default:
		return "control"
	}
}

func planStepExecution(step StepConfig) string {
	switch planStepKind(step) {
	case "ensure", "netconf", "ssh_command", "facts", "gnmi_subscribe", "ssh_probe":
		return "runtime transport operation"
	case "approval":
		return "runtime operator decision"
	case "wait":
		return "runtime delay"
	default:
		return "control flow"
	}
}

func renderOfflinePlan(plan offlinePlan) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Offline plan (%d device(s), zero connections)\n", plan.DeviceCount)
	if plan.Playbook != "" {
		fmt.Fprintf(&output, "Playbook: %s\n", plan.Playbook)
	}
	fmt.Fprintf(&output, "Resolution digest: %s\n", plan.ResolutionDigest)
	for _, device := range plan.Devices {
		fmt.Fprintf(&output, "\nDevice %s (%s)", device.Hostname, device.IP)
		if device.Platform != "" {
			fmt.Fprintf(&output, " [%s]", device.Platform)
		}
		output.WriteString("\n")
		for _, step := range device.Steps {
			marker := ""
			if step.Conditional {
				marker = " [conditional: " + step.Reason + "]"
			}
			fmt.Fprintf(&output, "  - %s (%s)%s\n", step.Path, step.Kind, marker)
		}
	}
	return output.String()
}

// networkCollectorSchema is a deliberately permissive JSON Schema: it gives
// editors useful completion for the public DSL while Go preflight remains the
// authoritative source of semantic checks (imports, variable flow and safety).
func networkCollectorSchema() map[string]interface{} {
	step := map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{
			"name": map[string]string{"type": "string"}, "cmd": map[string]string{"type": "string"}, "parser": map[string]string{"type": "string"},
			"message": map[string]string{"type": "string"}, "register": map[string]string{"type": "string"}, "when": map[string]interface{}{"$ref": "#/$defs/when"},
			"wait_seconds": map[string]interface{}{"type": "integer", "minimum": 0}, "ssh_probe": map[string]interface{}{"$ref": "#/$defs/ssh_probe"},
			"approval": map[string]interface{}{"$ref": "#/$defs/approval"}, "validation": map[string]interface{}{"$ref": "#/$defs/validation"},
			"steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}},
			"use":   map[string]string{"type": "string"}, "with": map[string]interface{}{"type": "object"},
			"netconf": map[string]interface{}{"$ref": "#/$defs/netconf"}, "ensure": map[string]interface{}{"$ref": "#/$defs/ensure"},
			"facts": map[string]interface{}{"$ref": "#/$defs/facts"}, "gnmi_subscribe": map[string]interface{}{"$ref": "#/$defs/gnmi_subscribe"},
			"foreach": map[string]interface{}{"$ref": "#/$defs/foreach"}, "repeat": map[string]interface{}{"$ref": "#/$defs/repeat"},
			"block": map[string]interface{}{"$ref": "#/$defs/block"}, "parallel": map[string]interface{}{"$ref": "#/$defs/parallel"},
		},
	}
	return map[string]interface{}{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "Network Collector playbook", "type": "object",
		"properties": map[string]interface{}{
			"name_playbook": map[string]string{"type": "string"}, "imports": map[string]interface{}{"oneOf": []interface{}{map[string]string{"type": "string"}, map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}}},
			"inventory_file": map[string]string{"type": "string"}, "parsers_file": map[string]string{"type": "string"}, "vars": map[string]interface{}{"type": "object"},
			"fail_on_fail": map[string]string{"type": "boolean"}, "security_mode": map[string]interface{}{"enum": []string{"production", "permissive"}},
			"execution": map[string]interface{}{"$ref": "#/$defs/execution"}, "schedule": map[string]interface{}{"$ref": "#/$defs/schedule"},
			"output": map[string]interface{}{"$ref": "#/$defs/output"}, "report": map[string]interface{}{"$ref": "#/$defs/report"},
			"ssh_security": map[string]interface{}{"$ref": "#/$defs/ssh_security"}, "credentials": map[string]interface{}{"$ref": "#/$defs/credentials"},
			"ssh": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/device"}}, "netconf": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/device"}},
			"workflows": map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"$ref": "#/$defs/workflow"}},
		},
		"$defs": map[string]interface{}{
			"device":   map[string]interface{}{"type": "object", "properties": map[string]interface{}{"hostname": map[string]string{"type": "string"}, "ip": map[string]string{"type": "string"}, "type": map[string]string{"type": "string"}, "groups": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}, "steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}, "cmd": map[string]string{"type": "string"}, "ssh_security": map[string]interface{}{"$ref": "#/$defs/ssh_security"}}},
			"workflow": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"parameters": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}, "steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}}},
			"step":     step, "when": map[string]interface{}{"type": "object", "required": []string{"variable", "condition"}, "properties": map[string]interface{}{"variable": map[string]string{"type": "string"}, "condition": map[string]string{"type": "string"}, "expected": map[string]interface{}{}}},
			"netconf":        map[string]interface{}{"type": "object", "properties": map[string]interface{}{"operation": map[string]string{"type": "string"}, "target": map[string]string{"type": "string"}, "payload": map[string]string{"type": "string"}, "payload_file": map[string]string{"type": "string"}}},
			"ensure":         map[string]interface{}{"type": "object", "required": []string{"resource", "state"}, "properties": map[string]interface{}{"resource": map[string]string{"type": "string"}, "state": map[string]string{"type": "string"}, "name": map[string]string{"type": "string"}, "prefix": map[string]string{"type": "string"}, "next_hop": map[string]string{"type": "string"}, "vrf": map[string]string{"type": "string"}}},
			"facts":          map[string]interface{}{"type": "object", "properties": map[string]interface{}{"format": map[string]string{"type": "string"}, "subsets": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}, "transports": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}}},
			"gnmi_subscribe": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"paths": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}, "mode": map[string]string{"type": "string"}}},
			"foreach":        map[string]interface{}{"type": "object", "properties": map[string]interface{}{"from": map[string]string{"type": "string"}, "items": map[string]interface{}{"type": "array"}, "steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}}},
			"repeat":         map[string]interface{}{"type": "object", "properties": map[string]interface{}{"count": map[string]string{"type": "integer"}, "steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}}},
			"block":          map[string]interface{}{"type": "object", "properties": map[string]interface{}{"steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}, "rescue": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}, "rollback": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}, "always": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}}},
			"parallel":       map[string]interface{}{"type": "object", "properties": map[string]interface{}{"max_parallel": map[string]string{"type": "integer"}, "steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/$defs/step"}}}},
			"validation":     map[string]interface{}{"type": "object", "properties": map[string]interface{}{"extractor": map[string]string{"type": "string"}, "pattern": map[string]string{"type": "string"}, "json_path": map[string]string{"type": "string"}, "condition": map[string]string{"type": "string"}, "expected": map[string]interface{}{}}},
			"approval":       map[string]interface{}{"type": "object", "properties": map[string]interface{}{"message": map[string]string{"type": "string"}, "timeout_seconds": map[string]interface{}{"type": "integer", "minimum": 0}}},
			"ssh_probe":      map[string]interface{}{"type": "object", "properties": map[string]interface{}{"port": map[string]string{"type": "integer"}, "interval_seconds": map[string]string{"type": "integer"}, "max_attempts": map[string]string{"type": "integer"}, "timeout_seconds": map[string]string{"type": "integer"}}},
			"execution":      map[string]interface{}{"type": "object", "properties": map[string]interface{}{"max_parallel": map[string]string{"type": "integer"}, "start_interval_seconds": map[string]string{"type": "integer"}, "canary_count": map[string]string{"type": "integer"}, "failure_threshold": map[string]string{"type": "integer"}}},
			"schedule":       map[string]interface{}{"type": "object", "properties": map[string]interface{}{"count": map[string]string{"type": "integer"}, "interval_seconds": map[string]string{"type": "integer"}}},
			"output":         map[string]interface{}{"type": "object", "properties": map[string]interface{}{"directory": map[string]string{"type": "string"}, "save_raw": map[string]string{"type": "boolean"}, "save_parsed": map[string]string{"type": "boolean"}, "summary_file": map[string]string{"type": "string"}, "events_file": map[string]string{"type": "string"}}},
			"report":         map[string]interface{}{"type": "object", "properties": map[string]interface{}{"enabled": map[string]string{"type": "boolean"}, "format": map[string]string{"type": "string"}, "template": map[string]string{"type": "string"}, "output": map[string]string{"type": "string"}, "title": map[string]string{"type": "string"}}},
			"ssh_security":   map[string]interface{}{"type": "object", "properties": map[string]interface{}{"profile": map[string]string{"type": "string"}, "host_key_policy": map[string]string{"type": "string"}, "known_hosts_file": map[string]string{"type": "string"}}},
			"credentials":    map[string]interface{}{"type": "object", "properties": map[string]interface{}{"provider": map[string]string{"type": "string"}, "file": map[string]string{"type": "string"}, "timeout_seconds": map[string]string{"type": "integer"}, "rsa_token": map[string]string{"type": "boolean"}}},
		},
	}
}
