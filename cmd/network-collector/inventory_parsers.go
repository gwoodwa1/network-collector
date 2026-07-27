package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drift"
	"github.com/gwoodwa1/network-collector/pkg/textfsm"
	"github.com/gwoodwa1/network-collector/pkg/validation"
	"gopkg.in/yaml.v3"
)

func cloneDeviceConfig(device DeviceConfig) DeviceConfig {
	device.Host = ""
	device.Hosts = nil
	device.Group = ""
	device.Groups = nil
	return device
}

func inventoryHostKey(host InventoryHostConfig) string {
	name := strings.TrimSpace(host.Name)
	if name != "" {
		return name
	}
	return strings.TrimSpace(host.Hostname)
}

func inventoryHostIP(host InventoryHostConfig) string {
	ip := strings.TrimSpace(host.IP)
	if ip != "" {
		return ip
	}
	return strings.TrimSpace(host.Address)
}

func applyInventoryHost(device DeviceConfig, host InventoryHostConfig) DeviceConfig {
	resolved := cloneDeviceConfig(device)
	name := inventoryHostKey(host)
	if strings.TrimSpace(resolved.Hostname) == "" {
		resolved.Hostname = name
	}
	if strings.TrimSpace(resolved.IP) == "" {
		resolved.IP = inventoryHostIP(host)
	}
	if strings.TrimSpace(resolved.Type) == "" {
		resolved.Type = strings.TrimSpace(host.Type)
	}
	if resolved.Timeout == 0 {
		resolved.Timeout = host.Timeout
	}
	if resolved.OperationTimeout == 0 {
		resolved.OperationTimeout = host.OperationTimeout
	}
	if resolved.SSHSecurity == nil && host.SSHSecurity != nil {
		copied := *host.SSHSecurity
		resolved.SSHSecurity = &copied
	}
	if resolved.GNMI == nil && host.GNMI != nil {
		copied := *host.GNMI
		resolved.GNMI = &copied
	}
	if strings.TrimSpace(resolved.CredentialProfile) == "" {
		resolved.CredentialProfile = strings.TrimSpace(host.CredentialProfile)
	}
	resolved.InventoryVars = cloneInterfaceMap(host.Vars)
	resolved.Labels = cloneLabels(host.Labels)
	for key, value := range device.Labels {
		resolved.Labels[key] = value
	}
	return resolved
}

func cloneInterfaceMap(values map[string]interface{}) map[string]interface{} {
	cloned := make(map[string]interface{}, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func resolveInventoryPath(inventoryFile, configFile string) string {
	path := strings.TrimSpace(inventoryFile)
	if path == "" {
		path = "inventory.yaml"
	}
	if !filepath.IsAbs(path) && strings.TrimSpace(configFile) != "" {
		path = filepath.Join(filepath.Dir(configFile), path)
	}
	return path
}

func loadInventory(inventoryFile, configFile string) (*InventoryConfig, error) {
	path := resolveInventoryPath(inventoryFile, configFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var inventory InventoryConfig
	if err := yaml.Unmarshal(b, &inventory); err != nil {
		return nil, err
	}
	inventory.baseDir = filepath.Dir(path)
	for index := range inventory.Hosts {
		resolveGNMICertificatePaths(inventory.Hosts[index].GNMI, inventory.baseDir)
	}
	return &inventory, nil
}

func resolveGNMICertificatePaths(config *GNMIConnectionConfig, baseDir string) {
	if config == nil {
		return
	}
	for _, value := range []*string{&config.CAFile, &config.CertFile, &config.KeyFile} {
		path := strings.TrimSpace(*value)
		if path != "" && !filepath.IsAbs(path) {
			*value = filepath.Clean(filepath.Join(baseDir, path))
		}
	}
}

func loadOptionalInventory(inventoryFile, configFile string) (*InventoryConfig, error) {
	explicit := strings.TrimSpace(inventoryFile) != ""
	path := resolveInventoryPath(inventoryFile, configFile)
	if !explicit {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	}
	return loadInventory(inventoryFile, configFile)
}

func resolveParsersPath(parsersFile, configFile string) string {
	path := strings.TrimSpace(parsersFile)
	if path == "" {
		path = "parsers.yaml"
	}
	if !filepath.IsAbs(path) && strings.TrimSpace(configFile) != "" {
		path = filepath.Join(filepath.Dir(configFile), path)
	}
	return path
}

func loadParsers(parsersFile, configFile string) (*ParsersConfig, error) {
	path := resolveParsersPath(parsersFile, configFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var parsers ParsersConfig
	if err := yaml.Unmarshal(b, &parsers); err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(path)
	for name, parser := range parsers.Parsers {
		parser.baseDir = baseDir
		parsers.Parsers[name] = parser
	}
	return &parsers, nil
}

func loadOptionalParsers(parsersFile, configFile string) (*ParsersConfig, error) {
	explicit := strings.TrimSpace(parsersFile) != ""
	path := resolveParsersPath(parsersFile, configFile)
	if !explicit {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	}
	return loadParsers(parsersFile, configFile)
}

func parserGroupIndex(field ParserFieldConfig, submatchCount int) int {
	if field.Group > 0 {
		return field.Group
	}
	if submatchCount > 1 {
		return 1
	}
	return 0
}

func coerceParsedValue(value string, valueType string) (interface{}, error) {
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "", "string":
		return value, nil
	case "int":
		i, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		return i, nil
	default:
		return nil, fmt.Errorf("unsupported parser field type: %s", valueType)
	}
}

func parseWithRegexModule(output string, parser ParserModuleConfig) (string, error) {
	parsed := map[string]interface{}{}
	for fieldName, field := range parser.Fields {
		if strings.TrimSpace(field.Pattern) == "" {
			return "", fmt.Errorf("parser field %q missing pattern", fieldName)
		}

		re, err := regexp.Compile(field.Pattern)
		if err != nil {
			return "", fmt.Errorf("parser field %q has invalid regex: %w", fieldName, err)
		}

		if field.Repeated {
			values := []interface{}{}
			for _, match := range re.FindAllStringSubmatch(output, -1) {
				group := parserGroupIndex(field, len(match))
				if group >= len(match) {
					return "", fmt.Errorf("parser field %q group %d not found", fieldName, group)
				}
				value, err := coerceParsedValue(match[group], field.Type)
				if err != nil {
					return "", fmt.Errorf("parser field %q failed to coerce value: %w", fieldName, err)
				}
				values = append(values, value)
			}
			parsed[fieldName] = values
			continue
		}

		match := re.FindStringSubmatch(output)
		if len(match) == 0 {
			parsed[fieldName] = ""
			continue
		}
		group := parserGroupIndex(field, len(match))
		if group >= len(match) {
			return "", fmt.Errorf("parser field %q group %d not found", fieldName, group)
		}
		value, err := coerceParsedValue(match[group], field.Type)
		if err != nil {
			return "", fmt.Errorf("parser field %q failed to coerce value: %w", fieldName, err)
		}
		parsed[fieldName] = value
	}

	b, err := json.Marshal(parsed)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseWithRegexRecords(output string, parser ParserModuleConfig) (string, error) {
	if strings.TrimSpace(parser.Pattern) == "" {
		return "", fmt.Errorf("regex_records parser missing pattern")
	}
	re, err := regexp.Compile(parser.Pattern)
	if err != nil {
		return "", fmt.Errorf("regex_records parser has invalid regex: %w", err)
	}

	records := make([]map[string]interface{}, 0)
	for _, match := range re.FindAllStringSubmatch(output, -1) {
		record := make(map[string]interface{}, len(parser.Fields))
		for fieldName, field := range parser.Fields {
			group := parserGroupIndex(field, len(match))
			if group >= len(match) {
				return "", fmt.Errorf("parser field %q group %d not found", fieldName, group)
			}
			value, err := coerceParsedValue(match[group], field.Type)
			if err != nil {
				return "", fmt.Errorf("parser field %q failed to coerce value: %w", fieldName, err)
			}
			record[fieldName] = value
		}
		records = append(records, record)
	}

	root := strings.TrimSpace(parser.Root)
	if root == "" {
		root = "records"
	}
	encoded, err := json.Marshal(map[string]interface{}{root: records})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func parseWithTextFSM(output string, parser ParserModuleConfig) (string, error) {
	templatePath := strings.TrimSpace(parser.Template)
	if templatePath == "" {
		return "", fmt.Errorf("textfsm parser missing template")
	}
	if !filepath.IsAbs(templatePath) {
		templatePath = filepath.Join(parser.baseDir, templatePath)
	}
	templateBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read TextFSM template %q: %w", templatePath, err)
	}

	result, err := textfsm.Parse(output, templateBytes, parser.Root)
	if err != nil {
		return "", fmt.Errorf("template %q: %w", templatePath, err)
	}
	return result, nil
}

func parseOutputWithModule(output, parserName string, parsers map[string]ParserModuleConfig) (string, error) {
	parserName = strings.TrimSpace(parserName)
	if parserName == "" {
		return output, nil
	}
	parser, ok := parsers[parserName]
	if !ok {
		return "", fmt.Errorf("parser %q not found", parserName)
	}

	switch strings.ToLower(strings.TrimSpace(parser.Type)) {
	case "", "regex":
		return parseWithRegexModule(output, parser)
	case "regex_records":
		return parseWithRegexRecords(output, parser)
	case "textfsm":
		return parseWithTextFSM(output, parser)
	default:
		return "", fmt.Errorf("unsupported parser type %q for parser %q", parser.Type, parserName)
	}
}

func applyDriftCheck(ctx *stepExecutionContext, step StepConfig, stepName, current string) error {
	if step.Drift == nil {
		return nil
	}
	vars := cloneVariables(ctx.variables)
	vars["hostname"] = ctx.hostname
	vars["ip"] = ctx.ip
	baselinePath, err := renderTemplate(strings.TrimSpace(step.Drift.Baseline), vars)
	if err != nil {
		return fmt.Errorf("render drift baseline: %w", err)
	}
	if baselinePath == "" {
		return fmt.Errorf("drift.baseline cannot be empty")
	}
	updateBaseline := step.Drift.UpdateBaseline
	if strings.EqualFold(baselinePath, "previous") {
		directory := strings.TrimSpace(ctx.output.Directory)
		if directory == "" {
			directory = "artifacts"
		}
		baselinePath = filepath.Join(directory, ".baselines", sanitizeLogName(ctx.hostname), sanitizeLogName(stepName)+".json")
		updateBaseline = true
	}
	baseline, err := os.ReadFile(baselinePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read drift baseline: %w", err)
	}
	if os.IsNotExist(err) {
		if !updateBaseline {
			return fmt.Errorf("drift baseline %q does not exist", baselinePath)
		}
		if err := atomicWriteFile(baselinePath, append([]byte(current), '\n')); err != nil {
			return fmt.Errorf("create drift baseline: %w", err)
		}
		baseline = []byte(current)
	}
	report, err := drift.Compare(baseline, []byte(current), step.Drift.Ignore)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	writeSessionf(ctx.sessionLog, "[step:%s] drift result:\n%s\n", stepName, encoded)
	if err := saveStepArtifact(ctx, step, stepName, 1, "drift", string(encoded)); err != nil {
		return err
	}
	status := "pass"
	message := "no structured drift detected"
	if report.Changed {
		message = fmt.Sprintf("structured drift detected: %d change(s)", len(report.Changes))
		if step.Drift.FailOnChange {
			status = "fail"
		}
	}
	result := validation.ValidationResult{Pass: status == "pass", Status: status, Extractor: "drift", PatternOrPath: baselinePath, Message: message, Timestamp: time.Now()}
	*ctx.aggregated = append(*ctx.aggregated, deviceValidation{Hostname: ctx.hostname, IP: ctx.ip, Result: result})
	ctx.events.emit(lifecycleEvent{Type: "validation.completed", Hostname: ctx.hostname, IP: ctx.ip, Step: stepName, Data: map[string]interface{}{"status": status, "pass": status == "pass", "kind": "drift", "changed": report.Changed, "changes": len(report.Changes)}})
	if report.Changed && step.Drift.FailOnChange {
		*ctx.runFailed = true
	}
	if updateBaseline && report.Changed {
		if err := atomicWriteFile(baselinePath, append([]byte(current), '\n')); err != nil {
			return fmt.Errorf("update drift baseline: %w", err)
		}
	}
	return nil
}

func inventoryIndex(inventory *InventoryConfig) (map[string]InventoryHostConfig, error) {
	index := map[string]InventoryHostConfig{}
	if inventory == nil {
		return index, nil
	}

	for _, host := range inventory.Hosts {
		key := inventoryHostKey(host)
		if key == "" {
			return nil, fmt.Errorf("inventory host missing name or hostname")
		}
		if inventoryHostIP(host) == "" {
			return nil, fmt.Errorf("inventory host %q missing ip or address", key)
		}
		if _, exists := index[key]; exists {
			return nil, fmt.Errorf("duplicate inventory host %q", key)
		}
		if _, err := configVariables(host.Vars); err != nil {
			return nil, fmt.Errorf("inventory host %q vars: %w", key, err)
		}
		index[key] = host
	}
	return index, nil
}

func inventoryTargets(device DeviceConfig) []string {
	targets := []string{}
	if strings.TrimSpace(device.Host) != "" {
		targets = append(targets, strings.TrimSpace(device.Host))
	}
	for _, host := range device.Hosts {
		if strings.TrimSpace(host) != "" {
			targets = append(targets, strings.TrimSpace(host))
		}
	}
	return targets
}

func inventoryGroupNames(device DeviceConfig) []string {
	groups := []string{}
	if strings.TrimSpace(device.Group) != "" {
		groups = append(groups, strings.TrimSpace(device.Group))
	}
	for _, group := range device.Groups {
		if strings.TrimSpace(group) != "" {
			groups = append(groups, strings.TrimSpace(group))
		}
	}
	return groups
}

func resolveInventoryDevices(devices []DeviceConfig, inventory *InventoryConfig) ([]DeviceConfig, error) {
	hostIndex, err := inventoryIndex(inventory)
	if err != nil {
		return nil, err
	}

	var resolved []DeviceConfig
	for _, device := range devices {
		targets := inventoryTargets(device)
		for _, groupName := range inventoryGroupNames(device) {
			if inventory == nil || inventory.Groups == nil {
				return nil, fmt.Errorf("inventory group %q requested but no inventory groups are loaded", groupName)
			}
			group, ok := inventory.Groups[groupName]
			if !ok {
				return nil, fmt.Errorf("inventory group %q not found", groupName)
			}
			for _, host := range group.Hosts {
				if strings.TrimSpace(host) != "" {
					targets = append(targets, strings.TrimSpace(host))
				}
			}
		}

		if len(targets) == 0 {
			resolved = append(resolved, cloneDeviceConfig(device))
			continue
		}

		for _, target := range targets {
			host, ok := hostIndex[target]
			if !ok {
				return nil, fmt.Errorf("inventory host %q not found", target)
			}
			resolved = append(resolved, applyInventoryHost(device, host))
		}
	}
	return resolved, nil
}
