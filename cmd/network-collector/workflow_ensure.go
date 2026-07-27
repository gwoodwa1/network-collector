package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

type interfaceEnsureState struct {
	Exists      bool    `json:"exists"`
	Enabled     *bool   `json:"enabled,omitempty"`
	Description *string `json:"description,omitempty"`
}

type sshEnsureCommandExecutor interface {
	Execute(string) (string, error)
}

func executeEnsureStep(ctx *stepExecutionContext, sshExecutor sshEnsureCommandExecutor, config EnsureConfig) (string, string, error) {
	rendered, err := renderEnsureConfig(config, ctx.variables)
	if err != nil {
		return "", "", err
	}
	if strings.EqualFold(strings.TrimSpace(rendered.Transport), "ssh") {
		return executeSSHEnsureStep(ctx, sshExecutor, rendered)
	}
	desiredEnabled, err := validateEnsureConfig(rendered)
	if err != nil {
		return "", "", err
	}
	if ctx.netconf == nil {
		return "", "", fmt.Errorf("NETCONF executor is not configured")
	}
	if strings.TrimSpace(rendered.Target) == "" {
		rendered.Target = "running"
	}

	display := fmt.Sprintf("ensure interface %s state=%s", rendered.Name, rendered.State)
	currentXML, err := ctx.netconf.ExecuteNETCONF(NETCONFStepConfig{
		Operation: "rpc",
		Payload:   interfaceGetPayload(rendered.Name),
	})
	if err != nil {
		return currentXML, display, fmt.Errorf("discover interface %q: %w", rendered.Name, err)
	}
	current, err := parseInterfaceEnsureState(currentXML, rendered.Name)
	if err != nil {
		return currentXML, display, fmt.Errorf("parse interface %q state: %w", rendered.Name, err)
	}
	inSync := current.Exists && current.Enabled != nil && *current.Enabled == desiredEnabled
	if rendered.Description != nil {
		inSync = inSync && ensureDescriptionMatches(current.Description, *rendered.Description)
	}

	report := map[string]interface{}{
		"resource": "interface",
		"name":     rendered.Name,
		"current":  current,
		"desired": map[string]interface{}{
			"enabled":     desiredEnabled,
			"description": rendered.Description,
		},
		"changed": !inSync,
		"check":   ctx.checkMode,
	}
	if inSync {
		return marshalEnsureReport(report), display, nil
	}

	payload := interfaceEditPayload(rendered.Name, desiredEnabled, rendered.Description)
	report["payload"] = payload
	if ctx.checkMode {
		report["action"] = "would-change"
		return marshalEnsureReport(report), display, nil
	}

	editOutput, err := ctx.netconf.ExecuteNETCONF(NETCONFStepConfig{
		Operation: "edit-config",
		Target:    rendered.Target,
		Payload:   payload,
	})
	if err != nil {
		return editOutput, display, fmt.Errorf("apply interface %q state: %w", rendered.Name, err)
	}
	verifyXML, err := ctx.netconf.ExecuteNETCONF(NETCONFStepConfig{
		Operation: "rpc",
		Payload:   interfaceGetPayload(rendered.Name),
	})
	if err != nil {
		return verifyXML, display, fmt.Errorf("verify interface %q: %w", rendered.Name, err)
	}
	verified, err := parseInterfaceEnsureState(verifyXML, rendered.Name)
	if err != nil {
		return verifyXML, display, fmt.Errorf("parse verified interface %q state: %w", rendered.Name, err)
	}
	if !interfaceEnsureMatches(verified, desiredEnabled, rendered.Description) {
		return verifyXML, display, fmt.Errorf("interface %q did not reach desired state", rendered.Name)
	}
	report["action"] = "changed"
	report["verified"] = verified
	return marshalEnsureReport(report), display, nil
}

func renderEnsureConfig(config EnsureConfig, vars map[string]string) (EnsureConfig, error) {
	var err error
	for label, target := range map[string]*string{
		"resource":      &config.Resource,
		"name":          &config.Name,
		"prefix":        &config.Prefix,
		"next_hop":      &config.NextHop,
		"vrf":           &config.VRF,
		"state":         &config.State,
		"require_state": &config.RequireState,
		"transport":     &config.Transport,
		"target":        &config.Target,
	} {
		*target, err = renderTemplate(strings.TrimSpace(*target), vars)
		if err != nil {
			return EnsureConfig{}, fmt.Errorf("render ensure.%s: %w", label, err)
		}
	}
	if config.Description != nil {
		rendered, renderErr := renderTemplate(*config.Description, vars)
		if renderErr != nil {
			return EnsureConfig{}, fmt.Errorf("render ensure.description: %w", renderErr)
		}
		config.Description = &rendered
	}
	config.Attributes.RouteDistinguisher, err = renderTemplate(strings.TrimSpace(config.Attributes.RouteDistinguisher), vars)
	if err != nil {
		return EnsureConfig{}, fmt.Errorf("render ensure.attributes.route_distinguisher: %w", err)
	}
	for label, targets := range map[string]*[]string{
		"import_route_targets": &config.Attributes.ImportRouteTargets,
		"export_route_targets": &config.Attributes.ExportRouteTargets,
	} {
		for index := range *targets {
			(*targets)[index], err = renderTemplate(strings.TrimSpace((*targets)[index]), vars)
			if err != nil {
				return EnsureConfig{}, fmt.Errorf("render ensure.attributes.%s[%d]: %w", label, index, err)
			}
		}
	}
	return config, nil
}

func validateEnsureConfig(config EnsureConfig) (bool, error) {
	if !strings.EqualFold(config.Resource, "interface") {
		return false, fmt.Errorf("ensure.resource must be interface")
	}
	if strings.TrimSpace(config.Name) == "" {
		return false, fmt.Errorf("ensure.name is required")
	}
	if strings.TrimSpace(config.RequireState) != "" {
		return false, fmt.Errorf("ensure.require_state is currently supported only for SSH interfaces")
	}
	if config.RollbackOnFailure {
		return false, fmt.Errorf("ensure.rollback_on_failure is currently supported only for SSH resources")
	}
	if !ensureAttributesEmpty(config.Attributes) || config.Cascade {
		return false, fmt.Errorf("ensure.attributes and ensure.cascade are currently supported only for SSH vrf resources")
	}
	if strings.TrimSpace(config.Prefix) != "" || strings.TrimSpace(config.NextHop) != "" || strings.TrimSpace(config.VRF) != "" {
		return false, fmt.Errorf("ensure.prefix, next_hop, and vrf are supported only for SSH static_route resources")
	}
	transport := strings.ToLower(strings.TrimSpace(config.Transport))
	if transport == "" {
		transport = "netconf"
	}
	if transport != "netconf" {
		return false, fmt.Errorf("ensure.transport must be netconf")
	}
	target := strings.ToLower(strings.TrimSpace(config.Target))
	if target == "" {
		target = "running"
		config.Target = target
	}
	if target != "running" {
		return false, fmt.Errorf("ensure.target currently supports only running")
	}
	switch strings.ToLower(strings.TrimSpace(config.State)) {
	case "enabled", "up":
		return true, nil
	case "disabled", "down":
		return false, nil
	default:
		return false, fmt.Errorf("ensure.state must be enabled or disabled")
	}
}

func interfaceEnsureMatches(current interfaceEnsureState, enabled bool, description *string) bool {
	if !current.Exists || current.Enabled == nil || *current.Enabled != enabled {
		return false
	}
	return description == nil || ensureDescriptionMatches(current.Description, *description)
}

func ensureDescriptionMatches(current *string, desired string) bool {
	return (current == nil && desired == "") || (current != nil && *current == desired)
}

func interfaceGetPayload(name string) string {
	return "<get><filter type=\"subtree\"><interfaces xmlns=\"http://openconfig.net/yang/interfaces\"><interface><name>" +
		xmlText(name) +
		"</name><config><description/><enabled/></config></interface></interfaces></filter></get>"
}

func interfaceEditPayload(name string, enabled bool, description *string) string {
	var descriptionXML string
	if description != nil {
		descriptionXML = "<description>" + xmlText(*description) + "</description>"
	}
	return fmt.Sprintf(
		"<config><interfaces xmlns=\"http://openconfig.net/yang/interfaces\"><interface><name>%s</name><config><name>%s</name>%s<enabled>%t</enabled></config></interface></interfaces></config>",
		xmlText(name), xmlText(name), descriptionXML, enabled,
	)
}

func xmlText(value string) string {
	var output bytes.Buffer
	_ = xml.EscapeText(&output, []byte(value))
	return output.String()
}

func marshalEnsureReport(report map[string]interface{}) string {
	encoded, _ := json.MarshalIndent(report, "", "  ")
	return string(encoded)
}

func parseInterfaceEnsureState(payload, wantedName string) (interfaceEnsureState, error) {
	decoder := xml.NewDecoder(strings.NewReader(payload))
	var stack []string
	var state interfaceEnsureState
	var interfaceDepth int
	var found bool
	var name, configEnabled, configDescription string

	reset := func() {
		name, configEnabled, configDescription = "", "", ""
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return interfaceEnsureState{}, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			stack = append(stack, value.Name.Local)
			if value.Name.Local == "interface" && interfaceDepth == 0 {
				interfaceDepth = len(stack)
				reset()
			}
		case xml.CharData:
			if interfaceDepth == 0 {
				continue
			}
			text := strings.TrimSpace(string(value))
			if text == "" || len(stack) == 0 {
				continue
			}
			element := stack[len(stack)-1]
			inConfig := stackContainsAfter(stack, interfaceDepth, "config")
			switch {
			case element == "name" && name == "":
				name = text
			case element == "enabled" && inConfig:
				configEnabled = text
			case element == "description" && inConfig:
				configDescription = text
			}
		case xml.EndElement:
			if interfaceDepth > 0 && value.Name.Local == "interface" && len(stack) == interfaceDepth {
				if name == wantedName {
					found = true
					state.Exists = true
					if configEnabled != "" {
						enabled, parseErr := parseEnsureBool(configEnabled)
						if parseErr != nil {
							return interfaceEnsureState{}, parseErr
						}
						state.Enabled = &enabled
					}
					if configDescription != "" {
						description := configDescription
						state.Description = &description
					}
				}
				interfaceDepth = 0
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if !found {
		return interfaceEnsureState{}, nil
	}
	return state, nil
}

func stackContainsAfter(stack []string, depth int, wanted string) bool {
	for index := depth; index < len(stack); index++ {
		if stack[index] == wanted {
			return true
		}
	}
	return false
}

func parseEnsureBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid enabled value %q", value)
	}
}
