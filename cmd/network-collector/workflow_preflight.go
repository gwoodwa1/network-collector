package main

import (
	"fmt"
	"sort"
	"strings"
)

type preflightVariable struct {
	value   string
	dynamic bool
}

type preflightScope map[string]preflightVariable

func newPreflightScope(values map[string]string) preflightScope {
	scope := make(preflightScope, len(values))
	for name, value := range values {
		scope[name] = preflightVariable{value: value}
	}
	return scope
}

func clonePreflightScope(scope preflightScope) preflightScope {
	cloned := make(preflightScope, len(scope))
	for name, value := range scope {
		cloned[name] = value
	}
	return cloned
}

func mergePreflightOutputs(target, base, branch preflightScope) {
	for name, value := range branch {
		if original, exists := base[name]; exists && original == value {
			continue
		}
		target[name] = value
	}
}

func preflightDeviceVariables(device DeviceConfig, workflows map[string]WorkflowConfig, values map[string]string) error {
	steps := device.Steps
	if len(steps) == 0 && strings.TrimSpace(device.Command) != "" {
		steps = []StepConfig{{
			Name: "default", Command: strings.TrimSpace(device.Command), Parser: strings.TrimSpace(device.Parser),
			Validation: device.Validation, Validations: device.Validations,
		}}
	}
	label := strings.TrimSpace(device.Hostname)
	if label == "" {
		label = strings.TrimSpace(device.IP)
	}
	if label == "" {
		label = "unnamed device"
	}
	if err := preflightSteps(steps, workflows, newPreflightScope(values), label, 0); err != nil {
		return fmt.Errorf("device %s: %w", label, err)
	}
	return nil
}

func preflightLocalVariables(steps []StepConfig, workflows map[string]WorkflowConfig, values map[string]string) error {
	if err := preflightSteps(steps, workflows, newPreflightScope(values), "local", 0); err != nil {
		return fmt.Errorf("local steps: %w", err)
	}
	return nil
}

func preflightSteps(steps []StepConfig, workflows map[string]WorkflowConfig, scope preflightScope, path string, depth int) error {
	if depth > maxWorkflowDepth {
		return fmt.Errorf("%s: nesting exceeds %d control levels", path, maxWorkflowDepth)
	}
	for index, step := range steps {
		name := strings.TrimSpace(step.Name)
		if name == "" {
			name = fmt.Sprintf("step-%d", index+1)
		}
		stepPath := path + "/" + name
		if err := preflightStep(step, workflows, scope, stepPath, depth); err != nil {
			return err
		}
	}
	return nil
}

func preflightStep(step StepConfig, workflows map[string]WorkflowConfig, scope preflightScope, path string, depth int) error {
	if step.When != nil {
		if err := requirePreflightVariable(scope, step.When.Variable, path+" when.variable"); err != nil {
			return err
		}
		if err := checkTemplateValue(step.When.Expected, scope, path+" when.expected"); err != nil {
			return err
		}
	}
	if err := checkTemplateString(step.Message, scope, path+" message"); err != nil {
		return err
	}
	if err := checkTemplateString(step.Command, scope, path+" cmd"); err != nil {
		return err
	}
	if step.Approval != nil {
		if err := checkTemplateString(step.Approval.Message, scope, path+" approval.message"); err != nil {
			return err
		}
	}
	if step.Local != nil {
		if err := preflightLocalCommand(*step.Local, scope, path); err != nil {
			return err
		}
	}
	if step.NETCONF != nil {
		for field, value := range map[string]string{
			"operation": step.NETCONF.Operation, "target": step.NETCONF.Target, "source": step.NETCONF.Source,
			"payload": step.NETCONF.Payload, "payload_file": step.NETCONF.PayloadFile,
			"persist": step.NETCONF.Persist, "persist_id": step.NETCONF.PersistID,
		} {
			if err := checkTemplateString(value, scope, path+" netconf."+field); err != nil {
				return err
			}
		}
	}
	if step.Ensure != nil {
		if err := preflightEnsure(*step.Ensure, scope, path); err != nil {
			return err
		}
	}
	if step.Drift != nil {
		driftScope := clonePreflightScope(scope)
		driftScope["hostname"] = preflightVariable{dynamic: true}
		driftScope["ip"] = preflightVariable{dynamic: true}
		if err := checkTemplateString(step.Drift.Baseline, driftScope, path+" drift.baseline"); err != nil {
			return err
		}
	}

	// A step registers its output before its validation actions execute.
	if register := strings.TrimSpace(step.Register); register != "" {
		scope[register] = preflightVariable{dynamic: true}
	}
	for index, validation := range stepValidations(step) {
		validationPath := fmt.Sprintf("%s validation[%d]", path, index+1)
		if err := checkTemplateString(validation.Pattern, scope, validationPath+".pattern"); err != nil {
			return err
		}
		if err := checkTemplateString(validation.JSONPath, scope, validationPath+".json_path"); err != nil {
			return err
		}
		if err := checkTemplateValue(validation.Expected, scope, validationPath+".expected"); err != nil {
			return err
		}
	}
	for label, action := range map[string]*ValidationActionConfig{"on_pass": step.OnPass, "on_fail": step.OnFail} {
		if action == nil {
			continue
		}
		if err := checkTemplateString(action.Message, scope, path+" "+label+".message"); err != nil {
			return err
		}
		if err := checkTemplateString(action.Command, scope, path+" "+label+".cmd"); err != nil {
			return err
		}
		branch := clonePreflightScope(scope)
		if err := preflightSteps(action.Steps, workflows, branch, path+"/"+label, depth+1); err != nil {
			return err
		}
		mergePreflightOutputs(scope, scope, branch)
	}

	if strings.TrimSpace(step.Use) != "" {
		if err := preflightWorkflow(step, workflows, scope, path, depth+1); err != nil {
			return err
		}
	}
	if step.Repeat != nil {
		branch := clonePreflightScope(scope)
		if err := preflightSteps(step.Repeat.Steps, workflows, branch, path+"/repeat", depth+1); err != nil {
			return err
		}
		mergePreflightOutputs(scope, scope, branch)
	}
	if step.Foreach != nil {
		if err := preflightForeach(*step.Foreach, workflows, scope, path, depth+1); err != nil {
			return err
		}
	}
	if step.Block != nil {
		if err := preflightSteps(step.Block.Steps, workflows, scope, path+"/block/steps", depth+1); err != nil {
			return err
		}
		for _, branchConfig := range []struct {
			label string
			steps []StepConfig
		}{
			{label: "rescue", steps: step.Block.Rescue},
			{label: "rollback", steps: step.Block.Rollback},
			{label: "always", steps: step.Block.Always},
		} {
			branch := clonePreflightScope(scope)
			if err := preflightSteps(branchConfig.steps, workflows, branch, path+"/block/"+branchConfig.label, depth+1); err != nil {
				return err
			}
			mergePreflightOutputs(scope, scope, branch)
		}
	}
	if step.Parallel != nil {
		base := clonePreflightScope(scope)
		for index, nested := range step.Parallel.Steps {
			branch := clonePreflightScope(base)
			if err := preflightSteps([]StepConfig{nested}, workflows, branch, fmt.Sprintf("%s/parallel[%d]", path, index+1), depth+1); err != nil {
				return err
			}
			mergePreflightOutputs(scope, base, branch)
		}
	}
	if step.GNMISubscribe != nil {
		for index, trigger := range step.GNMISubscribe.Triggers {
			branch := clonePreflightScope(scope)
			for _, name := range []string{
				"gnmi_event", "gnmi_event_type", "gnmi_event_path", "gnmi_event_value",
				"gnmi_metric_value", "gnmi_baseline_value", "gnmi_threshold_value",
			} {
				branch[name] = preflightVariable{dynamic: true}
			}
			if err := preflightSteps(trigger.Steps, workflows, branch, fmt.Sprintf("%s/gnmi_trigger[%d]", path, index+1), depth+1); err != nil {
				return err
			}
			for _, name := range []string{
				"gnmi_event", "gnmi_event_type", "gnmi_event_path", "gnmi_event_value",
				"gnmi_metric_value", "gnmi_baseline_value", "gnmi_threshold_value",
			} {
				delete(branch, name)
			}
			mergePreflightOutputs(scope, scope, branch)
		}
	}
	return nil
}

func preflightWorkflow(step StepConfig, workflows map[string]WorkflowConfig, scope preflightScope, path string, depth int) error {
	name := strings.TrimSpace(step.Use)
	workflow, exists := workflows[name]
	if !exists {
		return fmt.Errorf("%s: unknown workflow %q", path, name)
	}
	allowed := make(map[string]bool, len(workflow.Parameters))
	bindings := make(preflightScope, len(workflow.Parameters))
	for _, rawParameter := range workflow.Parameters {
		parameter := strings.TrimSpace(rawParameter)
		allowed[parameter] = true
		value, exists := step.With[parameter]
		if !exists {
			return fmt.Errorf("%s: workflow %q missing parameter %q", path, name, parameter)
		}
		if err := validateVariableNotEmpty(value, parameter); err != nil {
			return fmt.Errorf("%s: workflow parameter %q: %w", path, parameter, err)
		}
		if err := checkTemplateValue(value, scope, path+" with."+parameter); err != nil {
			return err
		}
		text, err := variableString(value)
		if err != nil {
			return fmt.Errorf("%s: workflow parameter %q: %w", path, parameter, err)
		}
		bindings[parameter] = preflightVariable{value: text, dynamic: valueHasDynamicReference(value, scope)}
	}
	for parameter := range step.With {
		if !allowed[parameter] {
			return fmt.Errorf("%s: workflow %q has no parameter %q", path, name, parameter)
		}
	}
	nested := clonePreflightScope(scope)
	for parameter, value := range bindings {
		nested[parameter] = value
	}
	if err := preflightSteps(workflow.Steps, workflows, nested, path+"/workflow:"+name, depth); err != nil {
		return err
	}
	for parameter := range bindings {
		delete(nested, parameter)
	}
	mergePreflightOutputs(scope, scope, nested)
	return nil
}

func preflightForeach(config ForeachConfig, workflows map[string]WorkflowConfig, scope preflightScope, path string, depth int) error {
	if len(config.Items) > 0 && strings.TrimSpace(config.From) != "" {
		return fmt.Errorf("%s: foreach cannot define both items and from", path)
	}
	if from := strings.TrimSpace(config.From); from != "" {
		if err := requirePreflightVariable(scope, from, path+" foreach.from"); err != nil {
			return err
		}
	} else {
		if config.Items == nil {
			return fmt.Errorf("%s: foreach requires items or from", path)
		}
		for index, item := range config.Items {
			if err := validateVariableNotEmpty(item, fmt.Sprintf("items[%d]", index)); err != nil {
				return fmt.Errorf("%s foreach: %w", path, err)
			}
			if err := checkTemplateValue(item, scope, fmt.Sprintf("%s foreach.items[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	itemName, indexName := strings.TrimSpace(config.Item), strings.TrimSpace(config.Index)
	if itemName == "" {
		itemName = "item"
	}
	if indexName == "" {
		indexName = "index"
	}
	nested := clonePreflightScope(scope)
	nested[itemName] = preflightVariable{dynamic: true}
	nested[indexName] = preflightVariable{value: "0"}
	if err := preflightSteps(config.Steps, workflows, nested, path+"/foreach", depth); err != nil {
		return err
	}
	delete(nested, itemName)
	delete(nested, indexName)
	mergePreflightOutputs(scope, scope, nested)
	return nil
}

func preflightLocalCommand(config LocalCommandConfig, scope preflightScope, path string) error {
	local := clonePreflightScope(scope)
	names := make([]string, 0, len(config.Inputs))
	for name := range config.Inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := checkTemplateString(config.Inputs[name], scope, path+" local.inputs."+name); err != nil {
			return err
		}
		local[name] = preflightVariable{dynamic: true}
	}
	if err := checkTemplateString(config.Command, local, path+" local.command"); err != nil {
		return err
	}
	for index, arg := range config.Args {
		if err := checkTemplateString(arg, local, fmt.Sprintf("%s local.args[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func preflightEnsure(config EnsureConfig, scope preflightScope, path string) error {
	fields := map[string]string{
		"name": config.Name, "prefix": config.Prefix, "next_hop": config.NextHop,
		"vrf": config.VRF, "state": config.State, "require_state": config.RequireState,
		"transport": config.Transport, "target": config.Target,
		"attributes.route_distinguisher": config.Attributes.RouteDistinguisher,
	}
	if config.Description != nil {
		fields["description"] = *config.Description
	}
	for field, value := range fields {
		if err := checkTemplateString(value, scope, path+" ensure."+field); err != nil {
			return err
		}
	}
	for index, target := range config.Attributes.ImportRouteTargets {
		if err := checkTemplateString(target, scope, fmt.Sprintf("%s ensure.attributes.import_route_targets[%d]", path, index)); err != nil {
			return err
		}
	}
	for index, target := range config.Attributes.ExportRouteTargets {
		if err := checkTemplateString(target, scope, fmt.Sprintf("%s ensure.attributes.export_route_targets[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func requirePreflightVariable(scope preflightScope, rawName, location string) error {
	name := strings.TrimSpace(rawName)
	if name == "" {
		return fmt.Errorf("%s cannot be empty", location)
	}
	value, exists := scope[name]
	if !exists {
		return fmt.Errorf("%s references undefined variable %q", location, name)
	}
	if !value.dynamic && strings.TrimSpace(value.value) == "" {
		return fmt.Errorf("%s references empty variable %q", location, name)
	}
	return nil
}

func checkTemplateValue(value interface{}, scope preflightScope, location string) error {
	text, err := variableString(value)
	if err != nil {
		return fmt.Errorf("%s: %w", location, err)
	}
	return checkTemplateString(text, scope, location)
}

func checkTemplateString(input string, scope preflightScope, location string) error {
	seen := map[string]bool{}
	for _, match := range templateVariablePattern.FindAllStringSubmatch(input, -1) {
		if len(match) < 2 || seen[match[1]] {
			continue
		}
		seen[match[1]] = true
		if err := requirePreflightVariable(scope, match[1], location); err != nil {
			return err
		}
	}
	return nil
}

func valueHasDynamicReference(value interface{}, scope preflightScope) bool {
	text, err := variableString(value)
	if err != nil {
		return true
	}
	for _, match := range templateVariablePattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 && scope[match[1]].dynamic {
			return true
		}
	}
	return false
}
