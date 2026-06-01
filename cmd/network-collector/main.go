package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/ssh"
	"github.com/kcajme/network-collector/pkg/validation"
	"github.com/spf13/viper"
)

type DeviceConfig struct {
	Hostname   string            `mapstructure:"hostname"`
	IP         string            `mapstructure:"ip"`
	Type       string            `mapstructure:"type"`
	Command    string            `mapstructure:"cmd"`
	Timeout    int               `mapstructure:"timeout"`
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

func init() {
	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("warning: unable to read config file: %v", err)
	}
}

func main() {
	// CLI flags
	var jsonOut bool
	var failOnFail bool
	flag.BoolVar(&jsonOut, "json", false, "emit machine-readable JSON only")
	flag.BoolVar(&failOnFail, "fail-on-fail", false, "exit non-zero if any validation fails or errors")
	flag.Parse()

	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		log.Fatal("NET_USER and NET_PASSWORD must be set in the environment")
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	type deviceValidation struct {
		Hostname string                      `json:"hostname"`
		IP       string                      `json:"ip"`
		Result   validation.ValidationResult `json:"result"`
	}

	var aggregated []deviceValidation

	for _, sshConfig := range config.SSH {
		hostname := strings.TrimSpace(sshConfig.Hostname)
		ip := strings.TrimSpace(sshConfig.IP)
		deviceType := strings.TrimSpace(sshConfig.Type)
		command := strings.TrimSpace(sshConfig.Command)

		if hostname == "" || ip == "" || deviceType == "" {
			log.Printf("skipping invalid SSH entry: hostname=%q ip=%q type=%q", hostname, ip, deviceType)
			continue
		}
		if command == "" {
			log.Printf("skipping SSH device %s (%s): no command provided", hostname, ip)
			continue
		}

		opts := []ssh.Option{}
		if sshConfig.Timeout > 0 {
			opts = append(opts, ssh.WithConnectionTimeout(time.Duration(sshConfig.Timeout)*time.Second))
		}

		client := ssh.NewClient(opts...)
		if err := client.Connect(ip, username, password, deviceType); err != nil {
			log.Printf("error connecting to %s (%s): %v", hostname, ip, err)
			continue
		}

		output, err := client.Execute(command)
		if err != nil {
			log.Printf("error executing command on %s (%s): %v", hostname, ip, err)
		} else if !jsonOut {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}

		if err := client.Close(); err != nil {
			log.Printf("error closing SSH connection for %s (%s): %v", hostname, ip, err)
		}

		// Run validation if provided
		if sshConfig.Validation != nil {
			rule := validation.ValidationRule{
				Extractor:    sshConfig.Validation.Extractor,
				Pattern:      sshConfig.Validation.Pattern,
				JSONPath:     sshConfig.Validation.JSONPath,
				Condition:    sshConfig.Validation.Condition,
				Expected:     sshConfig.Validation.Expected,
				ExpectedType: sshConfig.Validation.ExpectedType,
			}

			vres, verr := validation.ValidateOutput(output, rule)
			if verr != nil {
				log.Printf("validation error for %s (%s): %v", hostname, ip, verr)
			}

			// collect aggregated result
			aggregated = append(aggregated, deviceValidation{Hostname: hostname, IP: ip, Result: vres})

			if !jsonOut {
				// Print JSON result for machine-readable consumption
				jb, _ := json.MarshalIndent(vres, "", "  ")
				fmt.Printf("validation result for %s (%s):\n%s\n", hostname, ip, string(jb))
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
