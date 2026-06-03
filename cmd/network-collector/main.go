package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/ssh"
	"github.com/kcajme/network-collector/pkg/validation"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type RetryConfig struct {
	IntervalSeconds int  `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	MaxAttempts     int  `mapstructure:"max_attempts" yaml:"max_attempts"`
	UntilPass       bool `mapstructure:"until_pass" yaml:"until_pass"`
}

type SSHProbeConfig struct {
	Port            int `mapstructure:"port" yaml:"port"`
	IntervalSeconds int `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	MaxAttempts     int `mapstructure:"max_attempts" yaml:"max_attempts"`
	TimeoutSeconds  int `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	PostWaitSeconds int `mapstructure:"post_wait_seconds" yaml:"post_wait_seconds"`
}

type ValidationActionConfig struct {
	Action  string       `mapstructure:"action" yaml:"action"`
	Command string       `mapstructure:"cmd" yaml:"cmd"`
	Message string       `mapstructure:"message" yaml:"message"`
	Steps   []StepConfig `mapstructure:"steps" yaml:"steps"`
}

type StepConfig struct {
	Name           string                  `mapstructure:"name" yaml:"name"`
	Command        string                  `mapstructure:"cmd" yaml:"cmd"`
	WaitSeconds    int                     `mapstructure:"wait_seconds" yaml:"wait_seconds"`
	ReturnToPrompt *bool                   `mapstructure:"return_to_prompt" yaml:"return_to_prompt"`
	SSHProbe       *SSHProbeConfig         `mapstructure:"ssh_probe" yaml:"ssh_probe"`
	Validation     *ValidationConfig       `mapstructure:"validation" yaml:"validation"`
	Retry          *RetryConfig            `mapstructure:"retry" yaml:"retry"`
	Register       string                  `mapstructure:"register" yaml:"register"`
	OnPass         *ValidationActionConfig `mapstructure:"on_pass" yaml:"on_pass"`
	OnFail         *ValidationActionConfig `mapstructure:"on_fail" yaml:"on_fail"`
}

type DeviceConfig struct {
	Hostname         string            `mapstructure:"hostname" yaml:"hostname"`
	IP               string            `mapstructure:"ip" yaml:"ip"`
	Host             string            `mapstructure:"host" yaml:"host"`
	Hosts            []string          `mapstructure:"hosts" yaml:"hosts"`
	Group            string            `mapstructure:"group" yaml:"group"`
	Groups           []string          `mapstructure:"groups" yaml:"groups"`
	Type             string            `mapstructure:"type" yaml:"type"`
	Timeout          int               `mapstructure:"timeout" yaml:"timeout"`
	OperationTimeout int               `mapstructure:"operation_timeout" yaml:"operation_timeout"`
	Steps            []StepConfig      `mapstructure:"steps" yaml:"steps"`
	Command          string            `mapstructure:"cmd" yaml:"cmd"`
	Validation       *ValidationConfig `mapstructure:"validation" yaml:"validation"`
}

type ValidationConfig struct {
	Extractor    string      `mapstructure:"extractor" yaml:"extractor"`
	Pattern      string      `mapstructure:"pattern" yaml:"pattern"`
	JSONPath     string      `mapstructure:"json_path" yaml:"json_path"`
	Condition    string      `mapstructure:"condition" yaml:"condition"`
	Expected     interface{} `mapstructure:"expected" yaml:"expected"`
	ExpectedType string      `mapstructure:"expected_type" yaml:"expected_type"`
}

type Config struct {
	NamePlaybook  string         `mapstructure:"name_playbook" yaml:"name_playbook"`
	InventoryFile string         `mapstructure:"inventory_file" yaml:"inventory_file"`
	SSH           []DeviceConfig `mapstructure:"ssh" yaml:"ssh"`
}

type InventoryHostConfig struct {
	Name             string `yaml:"name"`
	Hostname         string `yaml:"hostname"`
	IP               string `yaml:"ip"`
	Address          string `yaml:"address"`
	Type             string `yaml:"type"`
	Timeout          int    `yaml:"timeout"`
	OperationTimeout int    `yaml:"operation_timeout"`
}

type InventoryGroupConfig struct {
	Hosts []string `yaml:"hosts"`
}

type InventoryConfig struct {
	Hosts  []InventoryHostConfig           `yaml:"hosts"`
	Groups map[string]InventoryGroupConfig `yaml:"groups"`
}

type deviceValidation struct {
	Hostname string                      `json:"hostname"`
	IP       string                      `json:"ip"`
	Result   validation.ValidationResult `json:"result"`
}

type stepExecutionContext struct {
	hostname   string
	ip         string
	deviceType string
	username   string
	password   string
	opts       []ssh.Option
	jsonOut    bool
	sessionLog io.Writer
	variables  map[string]string
	aggregated *[]deviceValidation
	runFailed  *bool
}

func renderTemplate(input string, vars map[string]string) (string, error) {
	re := regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
	missing := map[string]bool{}

	output := re.ReplaceAllStringFunc(input, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		name := parts[1]
		value, ok := vars[name]
		if !ok {
			missing[name] = true
			return match
		}
		return value
	})

	if len(missing) > 0 {
		keys := make([]string, 0, len(missing))
		for key := range missing {
			keys = append(keys, key)
		}
		return output, fmt.Errorf("undefined variables: %s", strings.Join(keys, ", "))
	}

	return output, nil
}

func renderExpectedValue(expected interface{}, vars map[string]string) (interface{}, error) {
	if s, ok := expected.(string); ok && strings.Contains(s, "{{") {
		rendered, err := renderTemplate(s, vars)
		if err != nil {
			return nil, err
		}
		return rendered, nil
	}
	return expected, nil
}

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
	return resolved
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
	return &inventory, nil
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

func waitDuration(waitSeconds int) (time.Duration, error) {
	if waitSeconds < 0 {
		return 0, fmt.Errorf("wait_seconds must be greater than or equal to 0")
	}
	return time.Duration(waitSeconds) * time.Second, nil
}

func shouldReturnToPrompt(returnToPrompt *bool) bool {
	return returnToPrompt == nil || *returnToPrompt
}

func validationActionForResult(step StepConfig, result validation.ValidationResult) *ValidationActionConfig {
	if result.Status == "pass" {
		return step.OnPass
	}
	if result.Status == "fail" || result.Status == "error" {
		return step.OnFail
	}
	return nil
}

func stringToBoolDecodeHook(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
	if from.Kind() != reflect.String || to.Kind() != reflect.Bool {
		return data, nil
	}

	switch strings.ToLower(strings.TrimSpace(data.(string))) {
	case "yes", "y":
		return true, nil
	case "no", "n":
		return false, nil
	default:
		value, err := strconv.ParseBool(strings.TrimSpace(data.(string)))
		if err != nil {
			return data, nil
		}
		return value, nil
	}
}

type resolvedSSHProbe struct {
	Port     int
	Interval time.Duration
	Attempts int
	Timeout  time.Duration
	PostWait time.Duration
}

func resolveSSHProbeConfig(cfg *SSHProbeConfig) (resolvedSSHProbe, error) {
	probe := resolvedSSHProbe{
		Port:     22,
		Interval: 30 * time.Second,
		Attempts: 20,
		Timeout:  5 * time.Second,
	}
	if cfg == nil {
		return probe, nil
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return probe, fmt.Errorf("ssh_probe.port must be between 1 and 65535")
	}
	if cfg.Port > 0 {
		probe.Port = cfg.Port
	}
	if cfg.IntervalSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.interval_seconds must be greater than or equal to 0")
	}
	if cfg.IntervalSeconds > 0 {
		probe.Interval = time.Duration(cfg.IntervalSeconds) * time.Second
	}
	if cfg.MaxAttempts < 0 {
		return probe, fmt.Errorf("ssh_probe.max_attempts must be greater than or equal to 0")
	}
	if cfg.MaxAttempts > 0 {
		probe.Attempts = cfg.MaxAttempts
	}
	if cfg.TimeoutSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.timeout_seconds must be greater than or equal to 0")
	}
	if cfg.TimeoutSeconds > 0 {
		probe.Timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	if cfg.PostWaitSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.post_wait_seconds must be greater than or equal to 0")
	}
	if cfg.PostWaitSeconds > 0 {
		probe.PostWait = time.Duration(cfg.PostWaitSeconds) * time.Second
	}
	return probe, nil
}

func sshProbeAddress(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

func waitForSSHPort(host string, cfg *SSHProbeConfig) error {
	probe, err := resolveSSHProbeConfig(cfg)
	if err != nil {
		return err
	}

	address := sshProbeAddress(host, probe.Port)
	var lastErr error
	for attempt := 1; attempt <= probe.Attempts; attempt++ {
		conn, err := net.DialTimeout("tcp", address, probe.Timeout)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		if attempt < probe.Attempts {
			time.Sleep(probe.Interval)
		}
	}
	return fmt.Errorf("ssh probe failed for %s after %d attempts: %w", address, probe.Attempts, lastErr)
}

func closeSSHClient(client *ssh.Client) error {
	if client == nil {
		return nil
	}
	return client.Close()
}

type validationActionOutcome struct {
	StopDevice bool
	RunFailed  bool
}

func executeValidationAction(ctx *stepExecutionContext, client **ssh.Client, action *ValidationActionConfig, stepName string) (validationActionOutcome, error) {
	if action == nil {
		return validationActionOutcome{}, nil
	}

	if strings.TrimSpace(action.Message) != "" {
		message, err := renderTemplate(action.Message, ctx.variables)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action message: %w", err)
		}
		writeSessionf(ctx.sessionLog, "[step:%s] action: %s\n", stepName, message)
		if !ctx.jsonOut {
			fmt.Printf("device=%s step=%s action=%q\n", ctx.hostname, stepName, message)
		}
	}

	actionName := strings.ToLower(strings.TrimSpace(action.Action))
	if actionName == "" && strings.TrimSpace(action.Command) != "" {
		actionName = "cmd"
	}
	if actionName == "" && len(action.Steps) > 0 {
		actionName = "steps"
	}

	switch actionName {
	case "", "none", "noop", "no_op":
		return validationActionOutcome{}, nil
	case "exit", "stop":
		return validationActionOutcome{StopDevice: true}, nil
	case "fail":
		return validationActionOutcome{StopDevice: true, RunFailed: true}, nil
	case "cmd", "command", "run":
		if client == nil || *client == nil {
			return validationActionOutcome{}, fmt.Errorf("cannot run validation action command without an active SSH session")
		}
		cmd, err := renderTemplate(strings.TrimSpace(action.Command), ctx.variables)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action command: %w", err)
		}
		if cmd == "" {
			return validationActionOutcome{}, fmt.Errorf("validation action command cannot be empty")
		}
		output, err := (*client).Execute(cmd)
		if err != nil {
			return validationActionOutcome{}, err
		}
		writeSessionf(ctx.sessionLog, "\n[step:%s] action command=%q\n%s\n", stepName, cmd, output)
		if !ctx.jsonOut {
			fmt.Printf("device=%s step=%s action_command=%q\n%s\n", ctx.hostname, stepName, cmd, output)
		}
		if len(action.Steps) == 0 {
			return validationActionOutcome{}, nil
		}
		fallthrough
	case "steps":
		if len(action.Steps) == 0 {
			return validationActionOutcome{}, nil
		}
		if executeSteps(ctx, client, action.Steps) {
			return validationActionOutcome{StopDevice: true}, nil
		}
		return validationActionOutcome{}, nil
	default:
		return validationActionOutcome{}, fmt.Errorf("unsupported validation action: %s", action.Action)
	}
}

func executeSteps(ctx *stepExecutionContext, client **ssh.Client, steps []StepConfig) bool {
	stopDeviceSteps := false
	for _, step := range steps {
		stepName := strings.TrimSpace(step.Name)
		if stepName == "" {
			stepName = "unnamed"
		}

		wait, err := waitDuration(step.WaitSeconds)
		if err != nil {
			*ctx.runFailed = true
			slog.Error("invalid wait step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			continue
		}
		if wait > 0 {
			slog.Info("waiting before step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "duration", wait)
			writeSessionf(ctx.sessionLog, "\n[step:%s] waiting %s\n", stepName, wait)
			time.Sleep(wait)
		}

		if step.SSHProbe != nil {
			probe, err := resolveSSHProbeConfig(step.SSHProbe)
			if err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("invalid SSH probe step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				break
			}

			if err := closeSSHClient(*client); err != nil {
				slog.Warn("error closing stale SSH connection before probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] warning: failed to close stale SSH connection before probe: %v\n", stepName, err)
			}
			*client = nil

			slog.Info("probing SSH port", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			writeSessionf(ctx.sessionLog, "\n[step:%s] probing SSH port on %s\n", stepName, ctx.ip)
			if err := waitForSSHPort(ctx.ip, step.SSHProbe); err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("SSH probe failed", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] SSH probe failed: %v\n", stepName, err)
				break
			}
			writeSessionf(ctx.sessionLog, "[step:%s] SSH probe succeeded\n", stepName)

			if probe.PostWait > 0 {
				slog.Info("waiting after successful SSH probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "duration", probe.PostWait)
				writeSessionf(ctx.sessionLog, "[step:%s] waiting %s after successful SSH probe\n", stepName, probe.PostWait)
				time.Sleep(probe.PostWait)
			}

			*client = ssh.NewClient(ctx.opts...)
			if err := (*client).Connect(ctx.ip, ctx.username, ctx.password, ctx.deviceType); err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("error reconnecting to SSH device after probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] failed to reconnect after SSH probe: %v\n", stepName, err)
				break
			}
			writeSessionf(ctx.sessionLog, "[step:%s] SSH session re-established\n", stepName)
		}

		cmd, err := renderTemplate(strings.TrimSpace(step.Command), ctx.variables)
		if err != nil {
			*ctx.runFailed = true
			slog.Error("error rendering command", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			continue
		}
		if cmd == "" {
			if wait > 0 || step.SSHProbe != nil {
				continue
			}
			*ctx.runFailed = true
			slog.Warn("skipping empty step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			continue
		}

		var finalResult validation.ValidationResult
		attempt := 0
		for {
			attempt++

			if client == nil || *client == nil {
				*ctx.runFailed = true
				slog.Error("cannot execute step without an active SSH session", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
				writeSessionf(ctx.sessionLog, "\n[step:%s] command error: no active SSH session\n", stepName)
				break
			}

			output, err := (*client).Execute(cmd)
			if err != nil {
				if !shouldReturnToPrompt(step.ReturnToPrompt) {
					slog.Info("step did not return to prompt as configured", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "\n[step:%s] command did not return to prompt as configured: %v\n", stepName, err)
					if err := closeSSHClient(*client); err != nil {
						slog.Warn("error closing SSH connection after no-prompt step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
						writeSessionf(ctx.sessionLog, "[step:%s] warning: failed to close SSH connection after no-prompt step: %v\n", stepName, err)
					}
					*client = nil
					break
				}
				*ctx.runFailed = true
				slog.Error("error executing step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "\n[step:%s] command error: %v\n", stepName, err)
				break
			}

			writeSessionf(ctx.sessionLog, "\n[step:%s] device=%s command=%q\n%s\n", stepName, ctx.hostname, cmd, output)
			if !ctx.jsonOut {
				fmt.Printf("device=%s step=%s command=%q\n%s\n", ctx.hostname, stepName, cmd, output)
			}

			if step.Validation == nil {
				break
			}

			pattern, err := renderTemplate(step.Validation.Pattern, ctx.variables)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("error rendering validation pattern", "hostname", ctx.hostname, "step", stepName, "error", err)
				break
			}

			jsonPath, err := renderTemplate(step.Validation.JSONPath, ctx.variables)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("error rendering validation json_path", "hostname", ctx.hostname, "step", stepName, "error", err)
				break
			}

			expected, err := renderExpectedValue(step.Validation.Expected, ctx.variables)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("error rendering validation expected value", "hostname", ctx.hostname, "step", stepName, "error", err)
				break
			}

			rule := validation.ValidationRule{
				Extractor:    step.Validation.Extractor,
				Pattern:      pattern,
				JSONPath:     jsonPath,
				Condition:    step.Validation.Condition,
				Expected:     expected,
				ExpectedType: step.Validation.ExpectedType,
			}

			vres, verr := validation.ValidateOutput(output, rule)
			if verr != nil {
				*ctx.runFailed = true
				slog.Error("validation error", "hostname", ctx.hostname, "step", stepName, "error", verr)
			}

			finalResult = vres

			if !ctx.jsonOut {
				jb, _ := json.MarshalIndent(vres, "", "  ")
				fmt.Printf("validation result for %s step=%s:\n%s\n", ctx.hostname, stepName, string(jb))
			}
			jb, _ := json.MarshalIndent(vres, "", "  ")
			writeSessionf(ctx.sessionLog, "[step:%s] validation result:\n%s\n", stepName, string(jb))

			if step.Register != "" && vres.RawExtract != "" {
				ctx.variables[step.Register] = vres.RawExtract
				slog.Info("registered variable", "hostname", ctx.hostname, "step", stepName, "variable", step.Register, "value", vres.RawExtract)
			}

			retryCfg := step.Retry
			if retryCfg != nil && retryCfg.UntilPass && finalResult.Status == "fail" {
				if retryCfg.MaxAttempts > 0 && attempt >= retryCfg.MaxAttempts {
					slog.Warn("step reached max attempts", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "max_attempts", retryCfg.MaxAttempts)
					break
				}

				interval := time.Duration(retryCfg.IntervalSeconds) * time.Second
				if interval <= 0 {
					interval = 60 * time.Second
				}
				slog.Info("retrying step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "interval", interval, "attempt", attempt+1)
				time.Sleep(interval)
				continue
			}

			break
		}

		if step.Validation != nil {
			*ctx.aggregated = append(*ctx.aggregated, deviceValidation{Hostname: ctx.hostname, IP: ctx.ip, Result: finalResult})

			action := validationActionForResult(step, finalResult)
			outcome, err := executeValidationAction(ctx, client, action, stepName)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("validation action failed", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] validation action failed: %v\n", stepName, err)
				break
			}
			if outcome.RunFailed {
				*ctx.runFailed = true
			}
			if outcome.StopDevice {
				stopDeviceSteps = true
				slog.Info("stopping remaining SSH steps after validation action", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
				break
			}
		}
	}
	return stopDeviceSteps
}

func sanitizeLogName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		isSafe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if isSafe {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}

	sanitized := strings.Trim(b.String(), "_")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

func formatSessionBanner(playbookName, hostname string, started time.Time) string {
	title := strings.TrimSpace(playbookName)
	if title == "" {
		title = "Network Collector Session"
	}

	width := 78
	line := strings.Repeat("=", width)
	return fmt.Sprintf(
		"%s\n%s\n%s\nHostname: %s\nStarted:  %s\n%s\n\n",
		line,
		centerASCII(title, width),
		line,
		strings.TrimSpace(hostname),
		started.Format(time.RFC3339),
		line,
	)
}

func centerASCII(value string, width int) string {
	if len(value) >= width {
		return value
	}
	left := (width - len(value)) / 2
	return strings.Repeat(" ", left) + value
}

func openSessionLog(hostname, playbookName string, started time.Time) (*os.File, string, error) {
	if err := os.MkdirAll("session_logs", 0755); err != nil {
		return nil, "", fmt.Errorf("failed to create session log directory: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.log", sanitizeLogName(hostname), started.Format("20060102_150405"))
	path := "session_logs/" + filename
	file, err := os.Create(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create session log file: %w", err)
	}

	if _, err := file.WriteString(formatSessionBanner(playbookName, hostname, started)); err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("failed to write session log banner: %w", err)
	}

	return file, path, nil
}

func writeSessionf(writer io.Writer, format string, args ...interface{}) {
	if writer == nil {
		return
	}
	_, _ = fmt.Fprintf(writer, format, args...)
}

func sshOptionsForDevice(device DeviceConfig) []ssh.Option {
	opts := []ssh.Option{}
	if device.Timeout > 0 {
		opts = append(opts, ssh.WithConnectionTimeout(time.Duration(device.Timeout)*time.Second))
	}
	if device.OperationTimeout > 0 {
		opts = append(opts, ssh.WithOperationTimeout(time.Duration(device.OperationTimeout)*time.Second))
	}
	return opts
}

func init() {
	viper.AutomaticEnv()
	if err := viper.BindEnv("fail_on_fail", "FAIL_ON_FAIL"); err != nil {
		slog.Error("error binding environment variable", "key", "fail_on_fail", "env", "FAIL_ON_FAIL", "error", err)
		os.Exit(1)
	}
}

func loadConfig(configFile string) {
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("unable to read config file", "config_file", configFile, "error", err)
	}
}

func main() {
	// CLI flags
	var jsonOut bool
	var cliFailOnFail bool
	var configFile string
	var cliInventoryFile string
	flag.StringVar(&configFile, "config", "config.yaml", "path to config file")
	flag.StringVar(&cliInventoryFile, "inventory", "", "path to inventory file")
	flag.BoolVar(&jsonOut, "json", false, "emit machine-readable JSON only")
	flag.BoolVar(&cliFailOnFail, "fail-on-fail", false, "exit non-zero if any validation fails or errors")
	flag.Parse()

	loadConfig(configFile)
	failOnFail := viper.GetBool("fail_on_fail")
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on-fail" {
			failOnFail = cliFailOnFail
		}
	})

	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		slog.Error("missing required environment variables", "required", "NET_USER,NET_PASSWORD")
		os.Exit(1)
	}

	var config Config
	if err := viper.Unmarshal(&config, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		stringToBoolDecodeHook,
	))); err != nil {
		slog.Error("error reading config", "error", err)
		os.Exit(1)
	}
	if strings.TrimSpace(cliInventoryFile) != "" {
		config.InventoryFile = cliInventoryFile
	}

	inventory, err := loadOptionalInventory(config.InventoryFile, configFile)
	if err != nil {
		slog.Error("error reading inventory", "inventory_file", config.InventoryFile, "error", err)
		os.Exit(1)
	}

	sshDevices, err := resolveInventoryDevices(config.SSH, inventory)
	if err != nil {
		slog.Error("error resolving SSH inventory", "error", err)
		os.Exit(1)
	}

	var aggregated []deviceValidation
	runFailed := false

	for _, device := range sshDevices {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		deviceType := strings.TrimSpace(device.Type)

		if hostname == "" || ip == "" || deviceType == "" {
			runFailed = true
			slog.Warn("skipping invalid SSH entry", "hostname", hostname, "ip", ip, "type", deviceType)
			continue
		}

		steps := device.Steps
		if len(steps) == 0 && strings.TrimSpace(device.Command) != "" {
			steps = []StepConfig{{
				Name:       "default",
				Command:    strings.TrimSpace(device.Command),
				Validation: device.Validation,
			}}
		}

		if len(steps) == 0 {
			runFailed = true
			slog.Warn("skipping SSH device with no steps or command", "hostname", hostname, "ip", ip)
			continue
		}

		started := time.Now()
		sessionLog, sessionLogPath, err := openSessionLog(hostname, config.NamePlaybook, started)
		if err != nil {
			runFailed = true
			slog.Error("error creating session log", "hostname", hostname, "ip", ip, "error", err)
			continue
		}
		slog.Info("recording SSH session", "hostname", hostname, "ip", ip, "path", sessionLogPath)

		opts := sshOptionsForDevice(device)
		channelLog := io.Writer(sessionLog)
		if !jsonOut {
			channelLog = io.MultiWriter(os.Stdout, sessionLog)
		}
		opts = append(opts, ssh.WithChannelLog(channelLog))

		client := ssh.NewClient(opts...)
		if err := client.Connect(ip, username, password, deviceType); err != nil {
			runFailed = true
			slog.Error("error connecting to SSH device", "hostname", hostname, "ip", ip, "error", err)
			writeSessionf(sessionLog, "ERROR: failed to connect to %s (%s): %v\n", hostname, ip, err)
			_ = sessionLog.Close()
			continue
		}

		ctx := stepExecutionContext{
			hostname:   hostname,
			ip:         ip,
			deviceType: deviceType,
			username:   username,
			password:   password,
			opts:       opts,
			jsonOut:    jsonOut,
			sessionLog: sessionLog,
			variables:  map[string]string{},
			aggregated: &aggregated,
			runFailed:  &runFailed,
		}
		stopDeviceSteps := executeSteps(&ctx, &client, steps)
		if stopDeviceSteps {
			slog.Warn("stopped remaining SSH steps for device", "hostname", hostname, "ip", ip)
		}

		if err := closeSSHClient(client); err != nil {
			runFailed = true
			slog.Error("error closing SSH connection", "hostname", hostname, "ip", ip, "error", err)
			writeSessionf(sessionLog, "ERROR: failed to close SSH connection: %v\n", err)
		}
		writeSessionf(sessionLog, "\nSession complete: %s\n", time.Now().Format(time.RFC3339))
		if err := sessionLog.Close(); err != nil {
			runFailed = true
			slog.Error("error closing session log", "hostname", hostname, "ip", ip, "path", sessionLogPath, "error", err)
		}
	}

	// Emit aggregated JSON if requested
	if jsonOut {
		out, _ := json.MarshalIndent(aggregated, "", "  ")
		fmt.Println(string(out))
	}

	// Exit non-zero if any validation failed or errored and flag set
	if failOnFail {
		if runFailed {
			os.Exit(2)
		}
		for _, dv := range aggregated {
			if dv.Result.Status == "fail" || dv.Result.Status == "error" {
				os.Exit(2)
			}
		}
	}
}
