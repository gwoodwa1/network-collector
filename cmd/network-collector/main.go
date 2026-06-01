package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
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

type StepConfig struct {
	Name       string            `mapstructure:"name"`
	Command    string            `mapstructure:"cmd"`
	Validation *ValidationConfig `mapstructure:"validation"`
	Retry      *RetryConfig      `mapstructure:"retry"`
	Register   string            `mapstructure:"register"`
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

func init() {
	viper.AutomaticEnv()
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
	var failOnFail bool
	var configFile string
	flag.StringVar(&configFile, "config", "config.yaml", "path to config file")
	flag.BoolVar(&jsonOut, "json", false, "emit machine-readable JSON only")
	flag.BoolVar(&failOnFail, "fail-on-fail", false, "exit non-zero if any validation fails or errors")
	flag.Parse()

	loadConfig(configFile)

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

	for _, device := range config.SSH {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		deviceType := strings.TrimSpace(device.Type)

		if hostname == "" || ip == "" || deviceType == "" {
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
			slog.Warn("skipping SSH device with no steps or command", "hostname", hostname, "ip", ip)
			continue
		}

		opts := []ssh.Option{}
		if device.Timeout > 0 {
			opts = append(opts, ssh.WithConnectionTimeout(time.Duration(device.Timeout)*time.Second))
		}

		client := ssh.NewClient(opts...)
		if err := client.Connect(ip, username, password, deviceType); err != nil {
			slog.Error("error connecting to SSH device", "hostname", hostname, "ip", ip, "error", err)
			continue
		}
		defer func(c *ssh.Client, h, i string) {
			if err := c.Close(); err != nil {
				slog.Error("error closing SSH connection", "hostname", h, "ip", i, "error", err)
			}
		}(client, hostname, ip)

		variables := map[string]string{}
		for _, step := range steps {
			stepName := strings.TrimSpace(step.Name)
			if stepName == "" {
				stepName = "unnamed"
			}

			cmd, err := renderTemplate(strings.TrimSpace(step.Command), variables)
			if err != nil {
				slog.Error("error rendering command", "hostname", hostname, "ip", ip, "step", stepName, "error", err)
				continue
			}
			if cmd == "" {
				slog.Warn("skipping empty step", "hostname", hostname, "ip", ip, "step", stepName)
				continue
			}

			var finalResult validation.ValidationResult
			attempt := 0
			for {
				attempt++

				output, err := client.Execute(cmd)
				if err != nil {
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
					slog.Error("error rendering validation pattern", "hostname", hostname, "step", stepName, "error", err)
					break
				}

				jsonPath, err := renderTemplate(step.Validation.JSONPath, variables)
				if err != nil {
					slog.Error("error rendering validation json_path", "hostname", hostname, "step", stepName, "error", err)
					break
				}

				expected, err := renderExpectedValue(step.Validation.Expected, variables)
				if err != nil {
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
	}

	// Emit aggregated JSON if requested
	if jsonOut {
		out, _ := json.MarshalIndent(aggregated, "", "  ")
		fmt.Println(string(out))
	}

	// Exit non-zero if any validation failed or errored and flag set
	if failOnFail {
		for _, dv := range aggregated {
			if dv.Result.Status == "fail" || dv.Result.Status == "error" {
				os.Exit(2)
			}
		}
	}
}
