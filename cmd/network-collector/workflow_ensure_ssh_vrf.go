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
	ControlPlaneExists bool     `json:"control_plane_exists,omitempty"`
	PlatformContext    string   `json:"platform_context,omitempty"`
	RouteDistinguisher string   `json:"route_distinguisher,omitempty"`
	ImportRouteTargets []string `json:"import_route_targets"`
	ExportRouteTargets []string `json:"export_route_targets"`
	Dependencies       []string `json:"dependencies,omitempty"`
}

type sshVRFPlatformAdapter struct {
	parse    func(string, string) sshVRFState
	commands func(string, sshVRFState, sshVRFState) []string
}

func executeSSHVRFEnsure(
	ctx *stepExecutionContext,
	executor sshEnsureCommandExecutor,
	platform string,
	config EnsureConfig,
) (string, string, error) {
	adapter, err := sshVRFAdapter(platform)
	if err != nil {
		return "", "", err
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
	current := adapter.parse(output, name)
	desired.PlatformContext = current.PlatformContext
	if platform == "arista_eos" && present {
		desired.ControlPlaneExists = true
		if current.PlatformContext == "" {
			return output, display, fmt.Errorf("EOS VRF %q requires an existing router bgp instance for RD and route targets", name)
		}
	}
	if !present && current.Exists && len(current.Dependencies) > 0 {
		return output, display, fmt.Errorf(
			"VRF %q has dependent configuration (%s); refusing deletion",
			name, strings.Join(current.Dependencies, ", "),
		)
	}
	changed := !sshVRFMatches(current, desired)
	apply := adapter.commands(name, current, desired)
	rollback := adapter.commands(name, desired, current)
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
	verified := adapter.parse(verifyOutput, name)
	verified.PlatformContext = desired.PlatformContext
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

func sshVRFAdapter(platform string) (sshVRFPlatformAdapter, error) {
	switch platform {
	case "cisco_iosxr":
		return sshVRFPlatformAdapter{parse: parseIOSXRVRFState, commands: iosXRVRFCommands}, nil
	case "arista_eos":
		return sshVRFPlatformAdapter{parse: parseEOSVRFState, commands: eosVRFCommands}, nil
	case "cisco_iosxe":
		return sshVRFPlatformAdapter{parse: parseIOSXEVRFState, commands: iosXEVRFCommands}, nil
	default:
		return sshVRFPlatformAdapter{}, fmt.Errorf(
			"SSH vrf ensure is not supported for platform %q; currently supported: cisco_iosxr, arista_eos, cisco_iosxe",
			platform,
		)
	}
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

func parseEOSVRFState(output, name string) sshVRFState {
	state := sshVRFState{ImportRouteTargets: []string{}, ExportRouteTargets: []string{}}
	inBGPVRF := false
	bgpVRFIndent := -1
	topLevel := ""
	dependencies := map[string]struct{}{}
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := leadingSpaces(raw)
		if indent == 0 && trimmed != "!" {
			topLevel = trimmed
			if strings.HasPrefix(trimmed, "router bgp ") {
				state.PlatformContext = strings.TrimSpace(strings.TrimPrefix(trimmed, "router bgp "))
			}
		}
		if indent == 0 && trimmed == "vrf instance "+name {
			state.Exists = true
		}
		if strings.HasPrefix(trimmed, "ip route vrf "+name+" ") {
			dependencies["ip route vrf "+name] = struct{}{}
		}
		if indent > 0 && trimmed == "vrf "+name && strings.HasPrefix(topLevel, "router bgp ") {
			inBGPVRF = true
			bgpVRFIndent = indent
			state.Exists = true
			state.ControlPlaneExists = true
			continue
		}
		if inBGPVRF {
			if indent <= bgpVRFIndent {
				inBGPVRF = false
			} else {
				fields := strings.Fields(trimmed)
				switch {
				case len(fields) == 2 && fields[0] == "rd":
					state.RouteDistinguisher = fields[1]
				case len(fields) == 4 && fields[0] == "route-target" &&
					fields[1] == "import" && fields[2] == "vpn-ipv4":
					state.ImportRouteTargets = append(state.ImportRouteTargets, fields[3])
				case len(fields) == 4 && fields[0] == "route-target" &&
					fields[1] == "export" && fields[2] == "vpn-ipv4":
					state.ExportRouteTargets = append(state.ExportRouteTargets, fields[3])
				case trimmed != "!":
					dependencies["router bgp "+state.PlatformContext+" vrf "+name] = struct{}{}
				}
				continue
			}
		}
		if indent > 0 && trimmed == "vrf "+name && strings.HasPrefix(topLevel, "interface ") {
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

func parseIOSXEVRFState(output, name string) sshVRFState {
	state := sshVRFState{ImportRouteTargets: []string{}, ExportRouteTargets: []string{}}
	inVRF := false
	topLevel := ""
	dependencies := map[string]struct{}{}
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := leadingSpaces(raw)
		if indent == 0 && trimmed != "!" {
			topLevel = trimmed
		}
		if !inVRF && indent == 0 && trimmed == "vrf definition "+name {
			inVRF = true
			state.Exists = true
			continue
		}
		if inVRF {
			if indent == 0 {
				inVRF = false
				if trimmed != "!" {
					topLevel = trimmed
				}
			} else {
				fields := strings.Fields(trimmed)
				switch {
				case len(fields) == 2 && fields[0] == "rd":
					state.RouteDistinguisher = fields[1]
				case len(fields) == 3 && fields[0] == "route-target" && fields[1] == "import":
					state.ImportRouteTargets = append(state.ImportRouteTargets, fields[2])
				case len(fields) == 3 && fields[0] == "route-target" && fields[1] == "export":
					state.ExportRouteTargets = append(state.ExportRouteTargets, fields[2])
				}
				continue
			}
		}
		if strings.HasPrefix(trimmed, "ip route vrf "+name+" ") {
			dependencies["ip route vrf "+name] = struct{}{}
		}
		if indent > 0 && (trimmed == "vrf forwarding "+name || trimmed == "ip vrf forwarding "+name) {
			dependencies[topLevel] = struct{}{}
		}
		if indent > 0 && trimmed == "address-family ipv4 vrf "+name {
			dependencies[topLevel+" address-family ipv4 vrf "+name] = struct{}{}
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
		current.ControlPlaneExists == desired.ControlPlaneExists &&
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

func eosVRFCommands(name string, current, desired sshVRFState) []string {
	asn := desired.PlatformContext
	if asn == "" {
		asn = current.PlatformContext
	}
	if current.Exists && !desired.Exists {
		commands := []string{"configure terminal"}
		if current.ControlPlaneExists {
			commands = append(commands, "router bgp "+asn, " no vrf "+name, "exit")
		}
		return append(commands, "no vrf instance "+name, "end", "write memory")
	}
	if !desired.Exists {
		return nil
	}
	commands := []string{"configure terminal"}
	if !current.Exists {
		commands = append(commands, "vrf instance "+name, "exit")
	}
	if current.ControlPlaneExists && !desired.ControlPlaneExists {
		commands = append(commands, "router bgp "+asn, " no vrf "+name)
		return append(commands, "end", "write memory")
	}
	commands = append(commands, "router bgp "+asn, " vrf "+name)
	if current.RouteDistinguisher != desired.RouteDistinguisher {
		if desired.RouteDistinguisher == "" {
			commands = append(commands, "  no rd")
		} else {
			commands = append(commands, "  rd "+desired.RouteDistinguisher)
		}
	}
	for _, change := range eosRouteTargetChanges("import", current.ImportRouteTargets, desired.ImportRouteTargets) {
		commands = append(commands, "  "+change)
	}
	for _, change := range eosRouteTargetChanges("export", current.ExportRouteTargets, desired.ExportRouteTargets) {
		commands = append(commands, "  "+change)
	}
	return append(commands, "end", "write memory")
}

func eosRouteTargetChanges(direction string, current, desired []string) []string {
	changes := []string{}
	for _, target := range current {
		if !containsString(desired, target) {
			changes = append(changes, "no route-target "+direction+" vpn-ipv4 "+target)
		}
	}
	for _, target := range desired {
		if !containsString(current, target) {
			changes = append(changes, "route-target "+direction+" vpn-ipv4 "+target)
		}
	}
	return changes
}

func iosXEVRFCommands(name string, current, desired sshVRFState) []string {
	if current.Exists && !desired.Exists {
		return []string{"configure terminal", "no vrf definition " + name, "end", "write memory"}
	}
	if !desired.Exists {
		return nil
	}
	commands := []string{"configure terminal", "vrf definition " + name}
	if current.RouteDistinguisher != desired.RouteDistinguisher {
		if desired.RouteDistinguisher == "" {
			commands = append(commands, " no rd")
		} else {
			commands = append(commands, " rd "+desired.RouteDistinguisher)
		}
	}
	importChanges := iosXERouteTargetChanges("import", current.ImportRouteTargets, desired.ImportRouteTargets)
	exportChanges := iosXERouteTargetChanges("export", current.ExportRouteTargets, desired.ExportRouteTargets)
	if len(importChanges) > 0 || len(exportChanges) > 0 {
		commands = append(commands, " address-family ipv4")
		for _, change := range importChanges {
			commands = append(commands, "  "+change)
		}
		for _, change := range exportChanges {
			commands = append(commands, "  "+change)
		}
		commands = append(commands, " exit-address-family")
	}
	return append(commands, "end", "write memory")
}

func iosXERouteTargetChanges(direction string, current, desired []string) []string {
	changes := []string{}
	for _, target := range current {
		if !containsString(desired, target) {
			changes = append(changes, "no route-target "+direction+" "+target)
		}
	}
	for _, target := range desired {
		if !containsString(current, target) {
			changes = append(changes, "route-target "+direction+" "+target)
		}
	}
	return changes
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
