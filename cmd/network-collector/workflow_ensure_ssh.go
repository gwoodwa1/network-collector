package main

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

type sshEnsurePlan struct {
	Resource          string      `json:"resource"`
	Platform          string      `json:"platform"`
	Current           interface{} `json:"current"`
	Desired           interface{} `json:"desired"`
	Changed           bool        `json:"changed"`
	Check             bool        `json:"check"`
	DiscoveryCommands []string    `json:"discovery_commands"`
	Commands          []string    `json:"commands,omitempty"`
	RollbackCommands  []string    `json:"rollback_commands,omitempty"`
	Action            string      `json:"action"`
	Verified          interface{} `json:"verified,omitempty"`
}

type sshInterfaceState struct {
	Exists      bool    `json:"exists"`
	Enabled     *bool   `json:"enabled,omitempty"`
	Description *string `json:"description,omitempty"`
}

type sshStaticRouteState struct {
	Prefix   string   `json:"prefix"`
	VRF      string   `json:"vrf"`
	NextHops []string `json:"next_hops"`
}

func executeSSHEnsureStep(ctx *stepExecutionContext, executor sshEnsureCommandExecutor, config EnsureConfig) (string, string, error) {
	if executor == nil {
		return "", "", fmt.Errorf("SSH executor is not configured")
	}
	platform, err := normalizeSSHEnsurePlatform(ctx.deviceType)
	if err != nil {
		return "", "", err
	}

	switch normalizeEnsureResource(config.Resource) {
	case "interface":
		return executeSSHInterfaceEnsure(ctx, executor, platform, config)
	case "static_route":
		return executeSSHStaticRouteEnsure(ctx, executor, platform, config)
	default:
		return "", "", fmt.Errorf("SSH ensure.resource must be interface or static_route")
	}
}

func normalizeEnsureResource(resource string) string {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "route", "static-route", "static_route":
		return "static_route"
	default:
		return strings.ToLower(strings.TrimSpace(resource))
	}
}

func normalizeSSHEnsurePlatform(platform string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "cisco_iosxr", "iosxr", "ios-xr":
		return "cisco_iosxr", nil
	default:
		return "", fmt.Errorf("SSH declarative ensure is not supported for platform %q; currently supported: cisco_iosxr", platform)
	}
}

func executeSSHInterfaceEnsure(ctx *stepExecutionContext, executor sshEnsureCommandExecutor, platform string, config EnsureConfig) (string, string, error) {
	name := strings.TrimSpace(config.Name)
	if err := validateCLIIdentifier(name, "ensure.name"); err != nil {
		return "", "", err
	}
	desiredEnabled, err := desiredInterfaceEnabled(config.State)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(config.Target) != "" {
		return "", "", fmt.Errorf("ensure.target is not used with SSH interface resources")
	}
	if config.Description != nil {
		if err := validateCLIDescription(*config.Description); err != nil {
			return "", "", err
		}
	}

	discoveryCommand := "show interfaces " + name
	output, err := executor.Execute(discoveryCommand)
	if err != nil {
		return output, "ensure interface " + name, fmt.Errorf("discover interface %q over SSH: %w", name, err)
	}
	current, err := parseIOSXRInterfaceState(output, name)
	if err != nil {
		return output, "ensure interface " + name, err
	}
	desired := sshInterfaceState{Exists: true, Enabled: &desiredEnabled, Description: config.Description}
	changed := !sshInterfaceMatches(current, desiredEnabled, config.Description)
	var requiredEnabled *bool
	if strings.TrimSpace(config.RequireState) != "" {
		requiredValue, requireErr := desiredInterfaceEnabled(config.RequireState)
		if requireErr != nil {
			return output, "ensure interface " + name, fmt.Errorf("ensure.require_state: %w", requireErr)
		}
		requiredEnabled = &requiredValue
	}
	if changed && requiredEnabled != nil {
		if current.Enabled == nil || *current.Enabled != *requiredEnabled {
			return output, "ensure interface " + name, fmt.Errorf(
				"interface %q current state is %s; require_state is %s, refusing change",
				name, interfaceStateLabel(current.Enabled), interfaceStateLabel(requiredEnabled),
			)
		}
	}
	apply := iosXRInterfaceCommands(name, desiredEnabled, config.Description)
	rollbackDescription := current.Description
	if config.Description != nil && rollbackDescription == nil {
		empty := ""
		rollbackDescription = &empty
	}
	rollback := iosXRInterfaceCommands(name, boolValue(current.Enabled), rollbackDescription)
	if !changed {
		apply, rollback = nil, nil
	}
	plan := sshEnsurePlan{
		Resource: "interface", Platform: platform, Current: current, Desired: desired,
		Changed: changed, Check: ctx.checkMode, DiscoveryCommands: []string{discoveryCommand},
		Commands: apply, RollbackCommands: rollback, Action: "none",
	}
	display := fmt.Sprintf("ensure interface %s state=%s transport=ssh", name, strings.ToLower(strings.TrimSpace(config.State)))
	if !changed {
		return marshalSSHEnsurePlan(plan), display, nil
	}
	if ctx.checkMode {
		plan.Action = "would-change"
		return marshalSSHEnsurePlan(plan), display, nil
	}
	applyOutput, err := executor.Execute(strings.Join(apply, "\n"))
	if err != nil {
		return applyOutput, display, fmt.Errorf("apply interface %q over SSH: %w", name, err)
	}
	verifyOutput, err := executor.Execute(discoveryCommand)
	if err != nil {
		return verifyOutput, display, fmt.Errorf("verify interface %q over SSH: %w", name, err)
	}
	verified, err := parseIOSXRInterfaceState(verifyOutput, name)
	if err != nil {
		return verifyOutput, display, err
	}
	if !sshInterfaceMatches(verified, desiredEnabled, config.Description) {
		return verifyOutput, display, fmt.Errorf("interface %q did not reach desired SSH state", name)
	}
	plan.Action = "changed"
	plan.Verified = verified
	return marshalSSHEnsurePlan(plan), display, nil
}

func desiredInterfaceEnabled(state string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "enabled", "up":
		return true, nil
	case "disabled", "down":
		return false, nil
	default:
		return false, fmt.Errorf("SSH interface ensure.state must be enabled or disabled")
	}
}

func parseIOSXRInterfaceState(output, name string) (sshInterfaceState, error) {
	linePattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + ` is (.*?), line protocol is .*?\r?$`)
	match := linePattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return sshInterfaceState{}, fmt.Errorf("interface %q was not found in IOS XR show output", name)
	}
	enabled := !strings.EqualFold(strings.TrimSpace(match[1]), "administratively down")
	state := sshInterfaceState{Exists: true, Enabled: &enabled}
	descriptionPattern := regexp.MustCompile(`(?mi)^[ \t]*Description:[ \t]*(.*?)[ \t]*\r?$`)
	if descriptionMatch := descriptionPattern.FindStringSubmatch(output); len(descriptionMatch) == 2 {
		description := strings.TrimSpace(descriptionMatch[1])
		state.Description = &description
	}
	return state, nil
}

func sshInterfaceMatches(current sshInterfaceState, enabled bool, description *string) bool {
	if !current.Exists || current.Enabled == nil || *current.Enabled != enabled {
		return false
	}
	return description == nil || ensureDescriptionMatches(current.Description, *description)
}

func iosXRInterfaceCommands(name string, enabled bool, description *string) []string {
	commands := []string{"configure terminal", "interface " + name}
	if description != nil {
		if *description == "" {
			commands = append(commands, " no description")
		} else {
			commands = append(commands, " description "+*description)
		}
	}
	if enabled {
		commands = append(commands, " no shutdown")
	} else {
		commands = append(commands, " shutdown")
	}
	return append(commands, "commit", "end")
}

func executeSSHStaticRouteEnsure(ctx *stepExecutionContext, executor sshEnsureCommandExecutor, platform string, config EnsureConfig) (string, string, error) {
	prefix := strings.TrimSpace(config.Prefix)
	if prefix == "" {
		prefix = strings.TrimSpace(config.Name)
	}
	prefixIP, parsedPrefix, err := net.ParseCIDR(prefix)
	if err != nil {
		return "", "", fmt.Errorf("ensure.prefix must be a valid IP prefix: %w", err)
	}
	if prefixIP.To4() == nil {
		return "", "", fmt.Errorf("SSH static_route currently supports only IPv4 prefixes")
	}
	prefix = parsedPrefix.String()
	nextHop := strings.TrimSpace(config.NextHop)
	if parsedNextHop := net.ParseIP(nextHop); parsedNextHop == nil || parsedNextHop.To4() == nil {
		return "", "", fmt.Errorf("ensure.next_hop must be a valid IPv4 address")
	}
	vrf := strings.TrimSpace(config.VRF)
	if vrf != "" {
		if err := validateCLIIdentifier(vrf, "ensure.vrf"); err != nil {
			return "", "", err
		}
	}
	if config.Description != nil {
		return "", "", fmt.Errorf("ensure.description is not supported for SSH static_route resources")
	}
	if strings.TrimSpace(config.RequireState) != "" {
		return "", "", fmt.Errorf("ensure.require_state is supported only for SSH interface resources")
	}
	if strings.TrimSpace(config.Target) != "" {
		return "", "", fmt.Errorf("ensure.target is not used with SSH static_route resources")
	}
	present, err := desiredRoutePresent(config.State)
	if err != nil {
		return "", "", err
	}

	discoveryCommand := "show running-config router static"
	output, err := executor.Execute(discoveryCommand)
	if err != nil {
		return output, "ensure static route " + prefix, fmt.Errorf("discover static route %q over SSH: %w", prefix, err)
	}
	current := parseIOSXRStaticRoutes(output, prefix, vrf)
	exactExists := containsString(current.NextHops, nextHop)
	changed := exactExists != present
	desired := map[string]interface{}{"prefix": prefix, "vrf": vrf, "next_hop": nextHop, "present": present}
	apply := iosXRStaticRouteCommands(prefix, nextHop, vrf, present)
	rollback := iosXRStaticRouteCommands(prefix, nextHop, vrf, !present)
	if !changed {
		apply, rollback = nil, nil
	}
	plan := sshEnsurePlan{
		Resource: "static_route", Platform: platform, Current: current, Desired: desired,
		Changed: changed, Check: ctx.checkMode, DiscoveryCommands: []string{discoveryCommand},
		Commands: apply, RollbackCommands: rollback, Action: "none",
	}
	display := fmt.Sprintf("ensure static route %s via %s vrf=%s state=%s transport=ssh", prefix, nextHop, routeVRFLabel(vrf), strings.ToLower(strings.TrimSpace(config.State)))
	if !changed {
		return marshalSSHEnsurePlan(plan), display, nil
	}
	if ctx.checkMode {
		plan.Action = "would-change"
		return marshalSSHEnsurePlan(plan), display, nil
	}
	applyOutput, err := executor.Execute(strings.Join(apply, "\n"))
	if err != nil {
		return applyOutput, display, fmt.Errorf("apply static route %q over SSH: %w", prefix, err)
	}
	verifyOutput, err := executor.Execute(discoveryCommand)
	if err != nil {
		return verifyOutput, display, fmt.Errorf("verify static route %q over SSH: %w", prefix, err)
	}
	verified := parseIOSXRStaticRoutes(verifyOutput, prefix, vrf)
	if containsString(verified.NextHops, nextHop) != present {
		return verifyOutput, display, fmt.Errorf("static route %q via %s did not reach desired SSH state", prefix, nextHop)
	}
	plan.Action = "changed"
	plan.Verified = verified
	return marshalSSHEnsurePlan(plan), display, nil
}

func desiredRoutePresent(state string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "present":
		return true, nil
	case "absent":
		return false, nil
	default:
		return false, fmt.Errorf("SSH static_route ensure.state must be present or absent")
	}
}

func parseIOSXRStaticRoutes(output, wantedPrefix, wantedVRF string) sshStaticRouteState {
	state := sshStaticRouteState{Prefix: wantedPrefix, VRF: wantedVRF, NextHops: []string{}}
	inStatic := false
	currentVRF := ""
	vrfIndent := -1
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := leadingSpaces(raw)
		if trimmed == "router static" {
			inStatic = true
			currentVRF, vrfIndent = "", -1
			continue
		}
		if !inStatic {
			continue
		}
		if indent == 0 && trimmed != "!" {
			break
		}
		if currentVRF != "" && indent <= vrfIndent && !strings.HasPrefix(trimmed, "vrf ") {
			currentVRF, vrfIndent = "", -1
		}
		if strings.HasPrefix(trimmed, "vrf ") {
			currentVRF = strings.TrimSpace(strings.TrimPrefix(trimmed, "vrf "))
			vrfIndent = indent
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || fields[0] != wantedPrefix || currentVRF != wantedVRF {
			continue
		}
		if net.ParseIP(fields[1]) != nil && !containsString(state.NextHops, fields[1]) {
			state.NextHops = append(state.NextHops, fields[1])
		}
	}
	sort.Strings(state.NextHops)
	return state
}

func iosXRStaticRouteCommands(prefix, nextHop, vrf string, present bool) []string {
	commands := []string{"configure terminal", "router static"}
	if vrf != "" {
		commands = append(commands, " vrf "+vrf, "  address-family ipv4 unicast")
		routeIndent := "   "
		if !present {
			commands = append(commands, routeIndent+"no "+prefix+" "+nextHop)
		} else {
			commands = append(commands, routeIndent+prefix+" "+nextHop)
		}
	} else {
		commands = append(commands, " address-family ipv4 unicast")
		routeIndent := "  "
		if !present {
			commands = append(commands, routeIndent+"no "+prefix+" "+nextHop)
		} else {
			commands = append(commands, routeIndent+prefix+" "+nextHop)
		}
	}
	return append(commands, "commit", "end")
}

func routeVRFLabel(vrf string) string {
	if vrf == "" {
		return "default"
	}
	return vrf
}

func validateCLIIdentifier(value, field string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
	if !valid.MatchString(value) {
		return fmt.Errorf("%s contains unsupported CLI characters", field)
	}
	return nil
}

func validateCLIDescription(value string) error {
	if strings.ContainsAny(value, "\r\n;") {
		return fmt.Errorf("ensure.description contains unsupported CLI control characters")
	}
	for _, character := range value {
		if character < 0x20 && character != '\t' {
			return fmt.Errorf("ensure.description contains unsupported CLI control characters")
		}
	}
	return nil
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func interfaceStateLabel(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "enabled"
	}
	return "disabled"
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func leadingSpaces(value string) int {
	return len(value) - len(strings.TrimLeft(value, " "))
}

func marshalSSHEnsurePlan(plan sshEnsurePlan) string {
	encoded, _ := json.MarshalIndent(plan, "", "  ")
	return string(encoded)
}
