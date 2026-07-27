package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func effectiveSSHSecurity(global SSHSecurityConfig, device *SSHSecurityConfig) SSHSecurityConfig {
	resolved := global
	if device == nil {
		return resolved
	}
	if strings.TrimSpace(device.Profile) != "" {
		resolved.Profile = device.Profile
	}
	if strings.TrimSpace(device.HostKeyPolicy) != "" {
		resolved.HostKeyPolicy = device.HostKeyPolicy
	}
	if strings.TrimSpace(device.KnownHostsFile) != "" {
		resolved.KnownHostsFile = device.KnownHostsFile
	}
	return resolved
}

func validateSSHSecurity(config SSHSecurityConfig) error {
	profile := strings.ToLower(strings.TrimSpace(config.Profile))
	if profile == "" {
		profile = "compatibility"
	}
	if profile != "compatibility" && profile != "auto" && profile != "modern" && profile != "legacy" {
		return fmt.Errorf("ssh_security.profile must be compatibility, auto, modern, or legacy")
	}
	policy := strings.ToLower(strings.TrimSpace(config.HostKeyPolicy))
	if policy == "" {
		policy = "insecure"
	}
	if policy != "insecure" && policy != "known_hosts" {
		return fmt.Errorf("ssh_security.host_key_policy must be insecure or known_hosts")
	}
	return nil
}

type sshSecuritySummary struct {
	Compatibility int
	Auto          int
	Modern        int
	Legacy        int
	Insecure      int
	Verified      int
}

func summarizeSSHSecurity(global SSHSecurityConfig, devices []DeviceConfig) sshSecuritySummary {
	summary := sshSecuritySummary{}
	for _, device := range devices {
		security := effectiveSSHSecurity(global, device.SSHSecurity)
		profile := strings.ToLower(strings.TrimSpace(security.Profile))
		if profile == "" {
			profile = "compatibility"
		}
		switch profile {
		case "auto":
			summary.Auto++
		case "modern":
			summary.Modern++
		case "legacy":
			summary.Legacy++
		default:
			summary.Compatibility++
		}
		policy := strings.ToLower(strings.TrimSpace(security.HostKeyPolicy))
		if policy == "known_hosts" {
			summary.Verified++
		} else {
			summary.Insecure++
		}
	}
	return summary
}

func logSSHSecuritySummary(global SSHSecurityConfig, devices []DeviceConfig) {
	if len(devices) == 0 {
		return
	}
	summary := summarizeSSHSecurity(global, devices)
	args := []interface{}{"devices", len(devices), "compatibility", summary.Compatibility, "auto", summary.Auto, "modern", summary.Modern, "legacy", summary.Legacy, "host_key_insecure", summary.Insecure, "host_key_verified", summary.Verified}
	if summary.Insecure > 0 || summary.Compatibility > 0 || summary.Legacy > 0 {
		slog.Warn("SSH security policy summary; configure ssh_security explicitly for stricter policy", args...)
		return
	}
	slog.Info("SSH security policy summary", args...)
}

func sshOptionsForDevice(device DeviceConfig, globalSecurity SSHSecurityConfig) []ssh.Option {
	opts := []ssh.Option{}
	if device.Timeout > 0 {
		opts = append(opts, ssh.WithConnectionTimeout(time.Duration(device.Timeout)*time.Second))
	}
	if device.OperationTimeout > 0 {
		opts = append(opts, ssh.WithOperationTimeout(time.Duration(device.OperationTimeout)*time.Second))
	}
	security := effectiveSSHSecurity(globalSecurity, device.SSHSecurity)
	opts = append(opts, ssh.WithSecurityProfile(security.Profile), ssh.WithHostKeyPolicy(security.HostKeyPolicy, security.KnownHostsFile))
	return opts
}

func init() {
	viper.AutomaticEnv()
	if err := viper.BindEnv("fail_on_fail", "FAIL_ON_FAIL"); err != nil {
		slog.Error("error binding environment variable", "key", "fail_on_fail", "env", "FAIL_ON_FAIL", "error", err)
		os.Exit(1)
	}
}

const maxConfigImportDepth = 20

func mergeConfigMaps(destination, source map[string]interface{}) map[string]interface{} {
	if destination == nil {
		destination = map[string]interface{}{}
	}
	for key, sourceValue := range source {
		if key == "imports" {
			continue
		}
		destinationValue, exists := destination[key]
		if !exists {
			destination[key] = sourceValue
			continue
		}

		sourceMap, sourceIsMap := sourceValue.(map[string]interface{})
		destinationMap, destinationIsMap := destinationValue.(map[string]interface{})
		if sourceIsMap && destinationIsMap {
			destination[key] = mergeConfigMaps(destinationMap, sourceMap)
			continue
		}
		sourceSlice, sourceIsSlice := sourceValue.([]interface{})
		destinationSlice, destinationIsSlice := destinationValue.([]interface{})
		if sourceIsSlice && destinationIsSlice {
			destination[key] = append(destinationSlice, sourceSlice...)
			continue
		}
		destination[key] = sourceValue
	}
	return destination
}

func configImports(value interface{}) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	switch imports := value.(type) {
	case string:
		return []string{imports}, nil
	case []interface{}:
		result := make([]string, 0, len(imports))
		for _, item := range imports {
			path, ok := item.(string)
			if !ok || strings.TrimSpace(path) == "" {
				return nil, fmt.Errorf("imports entries must be non-empty file paths")
			}
			result = append(result, path)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("imports must be a file path or list of file paths")
	}
}

func loadVariableFile(path string) (map[string]interface{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read variable file %q: %w", path, err)
	}
	values := map[string]interface{}{}
	if err := yaml.Unmarshal(content, &values); err != nil {
		return nil, fmt.Errorf("failed to parse variable file %q: %w", path, err)
	}
	if wrapped, ok := values["vars"].(map[string]interface{}); ok {
		if len(values) != 1 {
			return nil, fmt.Errorf("variable file %q cannot mix a vars wrapper with other keys", path)
		}
		values = wrapped
	}
	return values, nil
}

func mergeConfigVariables(current map[string]interface{}, configPath string) error {
	files, err := configImports(current["vars_files"])
	if err != nil {
		return fmt.Errorf("vars_files: %w", err)
	}
	merged := map[string]interface{}{}
	for _, configuredPath := range files {
		paths, err := expandConfigImport(configPath, configuredPath)
		if err != nil {
			return fmt.Errorf("vars_files: %w", err)
		}
		for _, path := range paths {
			values, err := loadVariableFile(path)
			if err != nil {
				return err
			}
			merged = mergeConfigMaps(merged, values)
		}
	}
	if inline, exists := current["vars"]; exists {
		inlineMap, ok := inline.(map[string]interface{})
		if !ok {
			return fmt.Errorf("vars must be a map")
		}
		merged = mergeConfigMaps(merged, inlineMap)
	}
	if len(merged) > 0 {
		current["vars"] = merged
	}
	delete(current, "vars_files")
	return nil
}

func configVariables(values map[string]interface{}) (map[string]string, error) {
	variables := make(map[string]string, len(values))
	validName := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	for name, value := range values {
		if !validName.MatchString(name) {
			return nil, fmt.Errorf("variable name %q must be a valid template variable", name)
		}
		if err := validateVariableNotEmpty(value, name); err != nil {
			return nil, fmt.Errorf("variable %q: %w", name, err)
		}
		text, err := variableString(value)
		if err != nil {
			return nil, fmt.Errorf("variable %q: %w", name, err)
		}
		variables[name] = text
	}
	return variables, nil
}

func validateVariableNotEmpty(value interface{}, path string) error {
	if value == nil {
		return fmt.Errorf("%s is null", path)
	}
	current := reflect.ValueOf(value)
	for current.Kind() == reflect.Interface || current.Kind() == reflect.Pointer {
		if current.IsNil() {
			return fmt.Errorf("%s is null", path)
		}
		current = current.Elem()
	}
	switch current.Kind() {
	case reflect.String:
		if strings.TrimSpace(current.String()) == "" {
			return fmt.Errorf("%s is blank", path)
		}
	case reflect.Slice, reflect.Array:
		if current.Len() == 0 {
			return fmt.Errorf("%s is an empty list", path)
		}
		for index := 0; index < current.Len(); index++ {
			if err := validateVariableNotEmpty(current.Index(index).Interface(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if current.Len() == 0 {
			return fmt.Errorf("%s is an empty map", path)
		}
		iterator := current.MapRange()
		for iterator.Next() {
			key := fmt.Sprint(iterator.Key().Interface())
			if err := validateVariableNotEmpty(iterator.Value().Interface(), path+"."+key); err != nil {
				return err
			}
		}
	}
	return nil
}

func mergeInventoryVariables(base map[string]string, inventory map[string]interface{}) (map[string]string, error) {
	merged := cloneVariables(base)
	overrides, err := configVariables(inventory)
	if err != nil {
		return nil, err
	}
	for name, value := range overrides {
		merged[name] = value
	}
	return merged, nil
}

func expandConfigImport(importingFile, configuredPath string) ([]string, error) {
	path := strings.TrimSpace(configuredPath)
	if path == "" {
		return nil, fmt.Errorf("import path cannot be empty")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(importingFile), path)
	}
	if strings.ContainsAny(path, "*?[") {
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, fmt.Errorf("invalid import pattern %q: %w", configuredPath, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("import pattern %q matched no files", configuredPath)
		}
		return matches, nil
	}
	return []string{path}, nil
}

func loadConfigMap(path string, depth int, loaded, active map[string]bool) (map[string]interface{}, error) {
	if depth > maxConfigImportDepth {
		return nil, fmt.Errorf("config imports exceed maximum depth of %d", maxConfigImportDepth)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolutePath = filepath.Clean(absolutePath)
	if active[absolutePath] {
		return nil, fmt.Errorf("config import cycle detected at %q", absolutePath)
	}
	if loaded[absolutePath] {
		return nil, fmt.Errorf("config file imported more than once: %q", absolutePath)
	}

	content, err := os.ReadFile(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config %q: %w", absolutePath, err)
	}
	current := map[string]interface{}{}
	if err := yaml.Unmarshal(content, &current); err != nil {
		return nil, fmt.Errorf("failed to parse config %q: %w", absolutePath, err)
	}
	if err := mergeConfigVariables(current, absolutePath); err != nil {
		return nil, fmt.Errorf("config %q: %w", absolutePath, err)
	}
	imports, err := configImports(current["imports"])
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", absolutePath, err)
	}

	active[absolutePath] = true
	defer delete(active, absolutePath)
	merged := map[string]interface{}{}
	for _, configuredImport := range imports {
		paths, err := expandConfigImport(absolutePath, configuredImport)
		if err != nil {
			return nil, fmt.Errorf("config %q: %w", absolutePath, err)
		}
		for _, importPath := range paths {
			imported, err := loadConfigMap(importPath, depth+1, loaded, active)
			if err != nil {
				return nil, err
			}
			merged = mergeConfigMaps(merged, imported)
		}
	}
	delete(current, "imports")
	merged = mergeConfigMaps(merged, current)
	loaded[absolutePath] = true
	return merged, nil
}

func loadConfig(configFile string) (Config, bool, error) {
	configMap, err := loadConfigMap(configFile, 0, map[string]bool{}, map[string]bool{})
	if err != nil {
		return Config{}, false, err
	}
	settings := viper.New()
	settings.AutomaticEnv()
	if err := settings.BindEnv("fail_on_fail", "FAIL_ON_FAIL"); err != nil {
		return Config{}, false, err
	}
	if err := settings.MergeConfigMap(configMap); err != nil {
		return Config{}, false, err
	}
	var config Config
	if err := settings.Unmarshal(&config, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		stringToBoolDecodeHook,
	))); err != nil {
		return Config{}, false, err
	}
	if err := rejectRemovedLocalExecution(config); err != nil {
		return Config{}, false, err
	}
	if _, err := configVariables(config.Vars); err != nil {
		return Config{}, false, err
	}
	absolutePath, err := filepath.Abs(configFile)
	if err != nil {
		return Config{}, false, fmt.Errorf("resolve config path: %w", err)
	}
	config.baseDir = filepath.Dir(absolutePath)
	return config, settings.GetBool("fail_on_fail"), nil
}

func rejectRemovedLocalExecution(config Config) error {
	provider := strings.ToLower(strings.TrimSpace(config.Credentials.Provider))
	if config.Credentials.RemovedCommand != nil || provider == "command" || provider == "exec" {
		return fmt.Errorf("credentials.command is unsupported: workbook-controlled process execution has been removed")
	}
	if config.Credentials.Hashicorp.RemovedBinary != nil {
		return fmt.Errorf("credentials.hashicorp.binary is unsupported: executable selection is fixed to the approved vault CLI")
	}
	if config.Credentials.OnePassword.RemovedBinary != nil {
		return fmt.Errorf("credentials.onepassword.binary is unsupported: executable selection is fixed to the approved op CLI")
	}
	if config.RemovedLocalSteps != nil {
		return fmt.Errorf("local_steps is unsupported: arbitrary local execution has been removed; use a Go-native processor")
	}
	for index, device := range config.SSH {
		if err := rejectRemovedLocalSteps(device.Steps, fmt.Sprintf("ssh[%d].steps", index)); err != nil {
			return err
		}
	}
	for index, device := range config.NETCONF {
		if err := rejectRemovedLocalSteps(device.Steps, fmt.Sprintf("netconf[%d].steps", index)); err != nil {
			return err
		}
	}
	for name, workflow := range config.Workflows {
		if err := rejectRemovedLocalSteps(workflow.Steps, fmt.Sprintf("workflows.%s.steps", name)); err != nil {
			return err
		}
	}
	return nil
}

func rejectRemovedLocalSteps(steps []StepConfig, path string) error {
	for index, step := range steps {
		stepPath := fmt.Sprintf("%s[%d]", path, index)
		if name := strings.TrimSpace(step.Name); name != "" {
			stepPath += "(" + name + ")"
		}
		if step.RemovedLocal != nil {
			return fmt.Errorf("%s.local is unsupported: arbitrary local execution has been removed; use a Go-native processor", stepPath)
		}
		nested := []struct {
			name  string
			steps []StepConfig
		}{
			{"repeat.steps", stepsFromRepeat(step.Repeat)},
			{"foreach.steps", stepsFromForeach(step.Foreach)},
			{"parallel.steps", stepsFromParallel(step.Parallel)},
			{"block.steps", stepsFromBlock(step.Block, "steps")},
			{"block.rescue", stepsFromBlock(step.Block, "rescue")},
			{"block.rollback", stepsFromBlock(step.Block, "rollback")},
			{"block.always", stepsFromBlock(step.Block, "always")},
			{"on_pass.steps", stepsFromAction(step.OnPass)},
			{"on_fail.steps", stepsFromAction(step.OnFail)},
		}
		if step.GNMISubscribe != nil {
			for triggerIndex, trigger := range step.GNMISubscribe.Triggers {
				nested = append(nested, struct {
					name  string
					steps []StepConfig
				}{
					fmt.Sprintf("gnmi_subscribe.triggers[%d].steps", triggerIndex),
					trigger.Steps,
				})
			}
		}
		for _, child := range nested {
			if err := rejectRemovedLocalSteps(child.steps, stepPath+"."+child.name); err != nil {
				return err
			}
		}
	}
	return nil
}

func stepsFromRepeat(value *RepeatConfig) []StepConfig {
	if value == nil {
		return nil
	}
	return value.Steps
}

func stepsFromForeach(value *ForeachConfig) []StepConfig {
	if value == nil {
		return nil
	}
	return value.Steps
}

func stepsFromParallel(value *ParallelConfig) []StepConfig {
	if value == nil {
		return nil
	}
	return value.Steps
}

func stepsFromBlock(value *BlockConfig, phase string) []StepConfig {
	if value == nil {
		return nil
	}
	switch phase {
	case "steps":
		return value.Steps
	case "rescue":
		return value.Rescue
	case "rollback":
		return value.Rollback
	default:
		return value.Always
	}
}

func stepsFromAction(value *ValidationActionConfig) []StepConfig {
	if value == nil {
		return nil
	}
	return value.Steps
}

func validateExecutionConfig(cfg ExecutionConfig) error {
	if cfg.MaxParallel < 0 {
		return fmt.Errorf("execution.max_parallel must be greater than or equal to 0")
	}
	if cfg.StartIntervalSeconds < 0 {
		return fmt.Errorf("execution.start_interval_seconds must be greater than or equal to 0")
	}
	if cfg.CanaryCount < 0 {
		return fmt.Errorf("execution.canary_count must be greater than or equal to 0")
	}
	if cfg.FailureThreshold < 0 {
		return fmt.Errorf("execution.failure_threshold must be greater than or equal to 0")
	}
	return nil
}

func validateScheduleConfig(cfg ScheduleConfig) error {
	if cfg.Count < 0 {
		return fmt.Errorf("schedule.count must be greater than or equal to 0")
	}
	if cfg.IntervalSeconds < 0 {
		return fmt.Errorf("schedule.interval_seconds must be greater than or equal to 0")
	}
	if cfg.Count > 1000 {
		return fmt.Errorf("schedule.count must not exceed 1000")
	}
	if cfg.Count > 1 && cfg.IntervalSeconds < 1 {
		return fmt.Errorf("schedule.interval_seconds must be at least 1 when count is greater than 1")
	}
	return nil
}
