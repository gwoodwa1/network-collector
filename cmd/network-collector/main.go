package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/ssh"
	"github.com/kcajme/network-collector/pkg/validation"
	"github.com/spf13/viper"
)

type RetryConfig struct {
	IntervalSeconds int  `mapstructure:"interval_seconds"`
	MaxAttempts     int  `mapstructure:"max_attempts"`
	UntilPass       bool `mapstructure:"until_pass"`
}

type SSHProbeConfig struct {
	Port            int `mapstructure:"port"`
	IntervalSeconds int `mapstructure:"interval_seconds"`
	MaxAttempts     int `mapstructure:"max_attempts"`
	TimeoutSeconds  int `mapstructure:"timeout_seconds"`
	PostWaitSeconds int `mapstructure:"post_wait_seconds"`
}

type StepConfig struct {
	Name           string            `mapstructure:"name"`
	Command        string            `mapstructure:"cmd"`
	WaitSeconds    int               `mapstructure:"wait_seconds"`
	ReturnToPrompt *bool             `mapstructure:"return_to_prompt"`
	SSHProbe       *SSHProbeConfig   `mapstructure:"ssh_probe"`
	Validation     *ValidationConfig `mapstructure:"validation"`
	Retry          *RetryConfig      `mapstructure:"retry"`
	Register       string            `mapstructure:"register"`
}

type DeviceConfig struct {
	Hostname   string            `mapstructure:"hostname"`
	IP         string            `mapstructure:"ip"`
	Type       string            `mapstructure:"type"`
	Timeout    int               `mapstructure:"timeout"`
	Steps      []StepConfig      `mapstructure:"steps"`
	Command    string            `mapstructure:"cmd"`
	Validation *ValidationConfig `mapstructure:"validation"`
}

type ValidationConfig struct {
	Extractor    string      `mapstructure:"extractor"`
	Pattern      string      `mapstructure:"pattern"`
	JSONPath     string      `mapstructure:"json_path"`
	Condition    string      `mapstructure:"condition"`
	Expected     interface{} `mapstructure:"expected"`
	ExpectedType string      `mapstructure:"expected_type"`
}

type Config struct {
	SSH []DeviceConfig `mapstructure:"ssh"`
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
	if err := viper.Unmarshal(&config); err != nil {
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

		opts := []ssh.Option{}
		if device.Timeout > 0 {
			opts = append(opts, ssh.WithConnectionTimeout(time.Duration(device.Timeout)*time.Second))
		}

		client := ssh.NewClient(opts...)
		if err := client.Connect(ip, username, password, deviceType); err != nil {
			runFailed = true
			slog.Error("error connecting to SSH device", "hostname", hostname, "ip", ip, "error", err)
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
				}
				client = nil

				slog.Info("probing SSH port", "hostname", hostname, "ip", ip, "step", stepName)
				if err := waitForSSHPort(ip, step.SSHProbe); err != nil {
					runFailed = true
					stopDeviceSteps = true
					slog.Error("SSH probe failed", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					break
				}

				if probe.PostWait > 0 {
					slog.Info("waiting after successful SSH probe", "hostname", hostname, "ip", ip, "step", stepName, "duration", probe.PostWait)
					time.Sleep(probe.PostWait)
				}

				client = ssh.NewClient(opts...)
				if err := client.Connect(ip, username, password, deviceType); err != nil {
					runFailed = true
					stopDeviceSteps = true
					slog.Error("error reconnecting to SSH device after probe", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					break
				}
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
						if err := closeSSHClient(client); err != nil {
							slog.Warn("error closing SSH connection after no-prompt step", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
						}
						client = nil
						break
					}
					runFailed = true
					slog.Error("error executing step", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
					break
				}

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
			}
		}
		if stopDeviceSteps {
			slog.Warn("stopped remaining SSH steps for device", "hostname", hostname, "ip", ip)
		}

		if err := client.Close(); err != nil {
			runFailed = true
			slog.Error("error closing SSH connection", "hostname", hostname, "ip", ip, "error", err)
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
