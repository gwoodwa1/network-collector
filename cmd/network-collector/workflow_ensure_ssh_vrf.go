package main

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type sshVRFState struct {
	Exists             bool     `json:"exists"`
	RouteDistinguisher string   `json:"route_distinguisher,omitempty"`
	ImportRouteTargets []string `json:"import_route_targets"`
	ExportRouteTargets []string `json:"export_route_targets"`
	Dependencies       []string `json:"dependencies,omitempty"`
}

func executeSSHVRFEnsure(
	ctx *stepExecutionContext,
	executor sshEnsureCommandExecutor,
	platform string,
	config EnsureConfig,
) (string, string, error) {
	if platform != "cisco_iosxr" {
		return "", "", fmt.Errorf("SSH vrf ensure is not supported for platform %q; currently supported: cisco_iosxr", platform)
	}
	name := strings.TrimSpace(config.Name)
	if err := validateCLIIdentifier(name, "ensure.name"); err != nil {
		return "", "", err
	}
	if config.Cascade {
		return "", "", fmt.Errorf("ensure.cascade is not yet supported for SSH vrf resources; dependent configuration is always refused")
	}
	if strings.TrimSpace(config.Prefix) != "" || strings.TrimSpace(config.NextHop) != "" ||
		strings.TrimSpace(config.VRF) != "" || strings.TrimSpace(config.RequireState) != "" ||
		config.Description != nil || strings.TrimSpace(config.Target) != "" {
		return "", "", fmt.Errorf("ensure vrf does not use prefix, next_hop, vrf, require_state, description, or target")
	}
	present, err := desiredVRFPresent(config.State)
	if err != nil {
		return "", "", err
	}
	desired := sshVRFState{
		Exists:             present,
		RouteDistinguisher: strings.TrimSpace(config.Attributes.RouteDistinguisher),
		ImportRouteTargets: normalizedRouteTargets(config.Attributes.ImportRouteTargets),
		ExportRouteTargets: normalizedRouteTargets(config.Attributes.ExportRouteTargets),
	}
	if present {
		if err := validateRouteTarget(desired.RouteDistinguisher, "ensure.attributes.route_distinguisher"); err != nil {
			return "", "", err
		}
		for _, target := range append(append([]string{}, desired.ImportRouteTargets...), desired.ExportRouteTargets...) {
			if err := validateRouteTarget(target, "ensure.attributes route target"); err != nil {
				return "", "", err
			}
		}
	}

	discoveryCommand := "show running-config"
	output, err := executor.Execute(discoveryCommand)
	display := fmt.Sprintf("ensure vrf %s state=%s transport=ssh", name, strings.ToLower(strings.TrimSpace(config.State)))
	if err != nil {
		return output, display, fmt.Errorf("discover VRF %q over SSH: %w", name, err)
	}
	current := parseIOSXRVRFState(output, name)
	if !present && current.Exists && len(current.Dependencies) > 0 {
		return output, display, fmt.Errorf(
			"VRF %q has dependent configuration (%s); refusing deletion",
			name, strings.Join(current.Dependencies, ", "),
		)
	}
	changed := !sshVRFMatches(current, desired)
	apply := iosXRVRFCommands(name, current, desired)
	rollback := iosXRVRFCommands(name, desired, current)
	if !changed {
		apply, rollback = nil, nil
	}
	plan := sshEnsurePlan{
		Resource: "vrf", Platform: platform, Current: current, Desired: desired,
		Changed: changed, Check: ctx.checkMode, DiscoveryCommands: []string{discoveryCommand},
		Commands: apply, RollbackCommands: rollback, RollbackOnFailure: config.RollbackOnFailure, Action: "none",
	}
	if !changed {
		return marshalSSHEnsurePlan(plan), display, nil
	}
	if ctx.checkMode {
		plan.Action = "would-change"
		return marshalSSHEnsurePlan(plan), display, nil
	}
	applyOutput, err := executor.Execute(strings.Join(apply, "\n"))
	if err != nil {
		return failSSHEnsure(executor, plan, display, applyOutput, fmt.Errorf("apply VRF %q over SSH: %w", name, err))
	}
	verifyOutput, err := executor.Execute(discoveryCommand)
	if err != nil {
		return failSSHEnsure(executor, plan, display, verifyOutput, fmt.Errorf("verify VRF %q over SSH: %w", name, err))
	}
	verified := parseIOSXRVRFState(verifyOutput, name)
	if !sshVRFMatches(verified, desired) {
		return failSSHEnsure(
			executor,
			plan,
			display,
			verifyOutput,
			fmt.Errorf("VRF %q did not reach desired SSH state", name),
		)
	}
	plan.Action = "changed"
	plan.Verified = verified
	return marshalSSHEnsurePlan(plan), display, nil
}

func desiredVRFPresent(state string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "present":
		return true, nil
	case "absent":
		return false, nil
	default:
		return false, fmt.Errorf("SSH vrf ensure.state must be present or absent")
	}
}

func validateRouteTarget(value, field string) error {
	if err := validateCLIIdentifier(value, field); err != nil {
		return err
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return fmt.Errorf("%s must use ASN:number or IPv4:number form", field)
	}
	if address := net.ParseIP(parts[0]); address == nil || address.To4() == nil {
		if _, err := strconv.ParseUint(parts[0], 10, 32); err != nil {
			return fmt.Errorf("%s must use ASN:number or IPv4:number form", field)
		}
	}
	if _, err := strconv.ParseUint(parts[1], 10, 32); err != nil {
		return fmt.Errorf("%s must use ASN:number or IPv4:number form", field)
	}
	return nil
}

func normalizedRouteTargets(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func parseIOSXRVRFState(output, name string) sshVRFState {
	state := sshVRFState{ImportRouteTargets: []string{}, ExportRouteTargets: []string{}}
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	inVRF := false
	targetMode := ""
	targetIndent := -1
	topLevel := ""
	dependencies := map[string]struct{}{}
	targetPattern := regexp.MustCompile(`^[A-Za-z0-9_.-]+:[0-9]+$`)

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := leadingSpaces(raw)
		if indent == 0 && trimmed != "!" {
			topLevel = trimmed
		}
		if !inVRF && indent == 0 && trimmed == "vrf "+name {
			inVRF = true
			state.Exists = true
			targetMode, targetIndent = "", -1
			continue
		}
		if inVRF {
			if indent == 0 {
				inVRF = false
				targetMode, targetIndent = "", -1
				if trimmed != "!" {
					topLevel = trimmed
				}
			} else {
				if targetMode != "" && indent <= targetIndent {
					targetMode, targetIndent = "", -1
				}
				switch {
				case strings.HasPrefix(trimmed, "rd "):
					state.RouteDistinguisher = strings.TrimSpace(strings.TrimPrefix(trimmed, "rd "))
				case trimmed == "import route-target":
					targetMode, targetIndent = "import", indent
				case trimmed == "export route-target":
					targetMode, targetIndent = "export", indent
				case targetMode != "" && targetPattern.MatchString(trimmed):
					if targetMode == "import" {
						state.ImportRouteTargets = append(state.ImportRouteTargets, trimmed)
					} else {
						state.ExportRouteTargets = append(state.ExportRouteTargets, trimmed)
					}
				}
				continue
			}
		}
		if indent > 0 && trimmed == "vrf "+name && topLevel != "vrf "+name {
			dependencies[topLevel] = struct{}{}
		}
	}
	state.ImportRouteTargets = normalizedRouteTargets(state.ImportRouteTargets)
	state.ExportRouteTargets = normalizedRouteTargets(state.ExportRouteTargets)
	for dependency := range dependencies {
		state.Dependencies = append(state.Dependencies, dependency)
	}
	sort.Strings(state.Dependencies)
	return state
}

func sshVRFMatches(current, desired sshVRFState) bool {
	if current.Exists != desired.Exists {
		return false
	}
	if !desired.Exists {
		return true
	}
	return current.RouteDistinguisher == desired.RouteDistinguisher &&
		stringSlicesEqual(current.ImportRouteTargets, desired.ImportRouteTargets) &&
		stringSlicesEqual(current.ExportRouteTargets, desired.ExportRouteTargets)
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func iosXRVRFCommands(name string, current, desired sshVRFState) []string {
	if current.Exists && !desired.Exists {
		return []string{"configure terminal", "no vrf " + name, "commit", "end"}
	}
	if !desired.Exists {
		return nil
	}
	commands := []string{"configure terminal", "vrf " + name}
	if current.RouteDistinguisher != desired.RouteDistinguisher {
		if desired.RouteDistinguisher == "" {
			commands = append(commands, " no rd")
		} else {
			commands = append(commands, " rd "+desired.RouteDistinguisher)
		}
	}
	importChanges := iosXRRouteTargetChanges(current.ImportRouteTargets, desired.ImportRouteTargets)
	exportChanges := iosXRRouteTargetChanges(current.ExportRouteTargets, desired.ExportRouteTargets)
	if len(importChanges) > 0 || len(exportChanges) > 0 {
		commands = append(commands, " address-family ipv4 unicast")
	}
	if len(importChanges) > 0 {
		commands = append(commands, "  import route-target")
		for _, change := range importChanges {
			commands = append(commands, "   "+change)
		}
		commands = append(commands, "  !")
	}
	if len(exportChanges) > 0 {
		commands = append(commands, "  export route-target")
		for _, change := range exportChanges {
			commands = append(commands, "   "+change)
		}
		commands = append(commands, "  !")
	}
	return append(commands, "commit", "end")
}

func iosXRRouteTargetChanges(current, desired []string) []string {
	changes := []string{}
	for _, target := range current {
		if !containsString(desired, target) {
			changes = append(changes, "no "+target)
		}
	}
	for _, target := range desired {
		if !containsString(current, target) {
			changes = append(changes, target)
		}
	}
	return changes
}
