package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/ssh"
	"github.com/kcajme/network-collector/pkg/validation"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
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
	Action  string `mapstructure:"action" yaml:"action"`
	Command string `mapstructure:"cmd" yaml:"cmd"`
	Message string `mapstructure:"message" yaml:"message"`
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
	NamePlaybook string         `mapstructure:"name_playbook" yaml:"name_playbook"`
	SSH          []DeviceConfig `mapstructure:"ssh" yaml:"ssh"`
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

func executeValidationAction(client *ssh.Client, action *ValidationActionConfig, vars map[string]string, writer io.Writer, jsonOut bool, hostname, stepName string) (validationActionOutcome, error) {
	if action == nil {
		return validationActionOutcome{}, nil
	}

	if strings.TrimSpace(action.Message) != "" {
		message, err := renderTemplate(action.Message, vars)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action message: %w", err)
		}
		writeSessionf(writer, "[step:%s] action: %s\n", stepName, message)
		if !jsonOut {
			fmt.Printf("device=%s step=%s action=%q\n", hostname, stepName, message)
		}
	}

	actionName := strings.ToLower(strings.TrimSpace(action.Action))
	if actionName == "" && strings.TrimSpace(action.Command) != "" {
		actionName = "cmd"
	}

	switch actionName {
	case "exit", "stop":
		return validationActionOutcome{StopDevice: true}, nil
	case "fail":
		return validationActionOutcome{StopDevice: true, RunFailed: true}, nil
	case "cmd", "command", "run":
		if client == nil {
			return validationActionOutcome{}, fmt.Errorf("cannot run validation action command without an active SSH session")
		}
		cmd, err := renderTemplate(strings.TrimSpace(action.Command), vars)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action command: %w", err)
		}
		if cmd == "" {
			return validationActionOutcome{}, fmt.Errorf("validation action command cannot be empty")
		}
		output, err := client.Execute(cmd)
		if err != nil {
			return validationActionOutcome{}, err
		}
		writeSessionf(writer, "\n[step:%s] action command=%q\n%s\n", stepName, cmd, output)
		if !jsonOut {
			fmt.Printf("device=%s step=%s action_command=%q\n%s\n", hostname, stepName, cmd, output)
		}
		return validationActionOutcome{}, nil
	default:
		if actionName == "" {
			return validationActionOutcome{}, fmt.Errorf("validation action requires action or cmd")
		}
		return validationActionOutcome{}, fmt.Errorf("unsupported validation action: %s", action.Action)
	}
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
	flag.StringVar(&configFile, "config", "config.yaml", "path to config file")
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

	type deviceValidation struct {
		Hostname string                      `json:"hostname"`
		IP       string                      `json:"ip"`
		Result   validation.ValidationResult `json:"result"`
	}

	var aggregated []deviceValidation
	runFailed := false

	for _, device := range config.SSH {
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

		variables := map[string]string{}
		stopDeviceSteps := false
		for _, step := range steps {
			stepName := strings.TrimSpace(step.Name)
			if stepName == "" {
				stepName = "unnamed"
			}

			wait, err := waitDuration(step.WaitSeconds)
			if err != nil {
				runFailed = true
				slog.Error("invalid wait step", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
				continue
			}
			if wait > 0 {
				slog.Info("waiting before step", "hostname", hostname, "ip", ip, "step", stepName, "duration", wait)
				writeSessionf(sessionLog, "\n[step:%s] waiting %s\n", stepName, wait)
				time.Sleep(wait)
			}

			if step.SSHProbe != nil {
				probe, err := resolveSSHProbeConfig(step.SSHProbe)
				if err != nil {
					runFailed = true
					stopDeviceSteps = true
					slog.Error("invalid SSH probe step", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					break
				}

				if err := closeSSHClient(client); err != nil {
					slog.Warn("error closing stale SSH connection before probe", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					writeSessionf(sessionLog, "[step:%s] warning: failed to close stale SSH connection before probe: %v\n", stepName, err)
				}
				client = nil

				slog.Info("probing SSH port", "hostname", hostname, "ip", ip, "step", stepName)
				writeSessionf(sessionLog, "\n[step:%s] probing SSH port on %s\n", stepName, ip)
				if err := waitForSSHPort(ip, step.SSHProbe); err != nil {
					runFailed = true
					stopDeviceSteps = true
					slog.Error("SSH probe failed", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					writeSessionf(sessionLog, "[step:%s] SSH probe failed: %v\n", stepName, err)
					break
				}
				writeSessionf(sessionLog, "[step:%s] SSH probe succeeded\n", stepName)

				if probe.PostWait > 0 {
					slog.Info("waiting after successful SSH probe", "hostname", hostname, "ip", ip, "step", stepName, "duration", probe.PostWait)
					writeSessionf(sessionLog, "[step:%s] waiting %s after successful SSH probe\n", stepName, probe.PostWait)
					time.Sleep(probe.PostWait)
				}

				client = ssh.NewClient(opts...)
				if err := client.Connect(ip, username, password, deviceType); err != nil {
					runFailed = true
					stopDeviceSteps = true
					slog.Error("error reconnecting to SSH device after probe", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					writeSessionf(sessionLog, "[step:%s] failed to reconnect after SSH probe: %v\n", stepName, err)
					break
				}
				writeSessionf(sessionLog, "[step:%s] SSH session re-established\n", stepName)
			}

			cmd, err := renderTemplate(strings.TrimSpace(step.Command), variables)
			if err != nil {
				runFailed = true
				slog.Error("error rendering command", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
				continue
			}
			if cmd == "" {
				if wait > 0 || step.SSHProbe != nil {
					continue
				}
				runFailed = true
				slog.Warn("skipping empty step", "hostname", hostname, "ip", ip, "step", stepName)
				continue
			}

			var finalResult validation.ValidationResult
			attempt := 0
			for {
				attempt++

				output, err := client.Execute(cmd)
				if err != nil {
					if !shouldReturnToPrompt(step.ReturnToPrompt) {
						slog.Info("step did not return to prompt as configured", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
						writeSessionf(sessionLog, "\n[step:%s] command did not return to prompt as configured: %v\n", stepName, err)
						if err := closeSSHClient(client); err != nil {
							slog.Warn("error closing SSH connection after no-prompt step", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
							writeSessionf(sessionLog, "[step:%s] warning: failed to close SSH connection after no-prompt step: %v\n", stepName, err)
						}
						client = nil
						break
					}
					runFailed = true
					slog.Error("error executing step", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					writeSessionf(sessionLog, "\n[step:%s] command error: %v\n", stepName, err)
					break
				}

				writeSessionf(sessionLog, "\n[step:%s] device=%s command=%q\n%s\n", stepName, hostname, cmd, output)
				if !jsonOut {
					fmt.Printf("device=%s step=%s command=%q\n%s\n", hostname, stepName, cmd, output)
				}

				if step.Validation == nil {
					break
				}

				pattern, err := renderTemplate(step.Validation.Pattern, variables)
				if err != nil {
					runFailed = true
					slog.Error("error rendering validation pattern", "hostname", hostname, "step", stepName, "error", err)
					break
				}

				jsonPath, err := renderTemplate(step.Validation.JSONPath, variables)
				if err != nil {
					runFailed = true
					slog.Error("error rendering validation json_path", "hostname", hostname, "step", stepName, "error", err)
					break
				}

				expected, err := renderExpectedValue(step.Validation.Expected, variables)
				if err != nil {
					runFailed = true
					slog.Error("error rendering validation expected value", "hostname", hostname, "step", stepName, "error", err)
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
					runFailed = true
					slog.Error("validation error", "hostname", hostname, "step", stepName, "error", verr)
				}

				finalResult = vres

				if !jsonOut {
					jb, _ := json.MarshalIndent(vres, "", "  ")
					fmt.Printf("validation result for %s step=%s:\n%s\n", hostname, stepName, string(jb))
				}
				jb, _ := json.MarshalIndent(vres, "", "  ")
				writeSessionf(sessionLog, "[step:%s] validation result:\n%s\n", stepName, string(jb))

				if step.Register != "" && vres.RawExtract != "" {
					variables[step.Register] = vres.RawExtract
					slog.Info("registered variable", "hostname", hostname, "step", stepName, "variable", step.Register, "value", vres.RawExtract)
				}

				retryCfg := step.Retry
				if retryCfg != nil && retryCfg.UntilPass && finalResult.Status == "fail" {
					if retryCfg.MaxAttempts > 0 && attempt >= retryCfg.MaxAttempts {
						slog.Warn("step reached max attempts", "hostname", hostname, "ip", ip, "step", stepName, "max_attempts", retryCfg.MaxAttempts)
						break
					}

					interval := time.Duration(retryCfg.IntervalSeconds) * time.Second
					if interval <= 0 {
						interval = 60 * time.Second
					}
					slog.Info("retrying step", "hostname", hostname, "ip", ip, "step", stepName, "interval", interval, "attempt", attempt+1)
					time.Sleep(interval)
					continue
				}

				break
			}

			if step.Validation != nil {
				aggregated = append(aggregated, deviceValidation{Hostname: hostname, IP: ip, Result: finalResult})

				action := validationActionForResult(step, finalResult)
				outcome, err := executeValidationAction(client, action, variables, sessionLog, jsonOut, hostname, stepName)
				if err != nil {
					runFailed = true
					slog.Error("validation action failed", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					writeSessionf(sessionLog, "[step:%s] validation action failed: %v\n", stepName, err)
					break
				}
				if outcome.RunFailed {
					runFailed = true
				}
				if outcome.StopDevice {
					stopDeviceSteps = true
					slog.Info("stopping remaining SSH steps after validation action", "hostname", hostname, "ip", ip, "step", stepName)
					break
				}
			}
		}
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
