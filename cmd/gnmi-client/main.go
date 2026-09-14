package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/credentials"
	"github.com/gwoodwa1/network-collector/pkg/drivers/gnmi"
	"github.com/spf13/viper"
)

type GNMIConfig struct {
	Hostname string `mapstructure:"hostname"`
	IP       string `mapstructure:"ip"`
	Path     string `mapstructure:"path"`
	// Insecure is plaintext gRPC. It is intentionally opt-in for controlled
	// lab/testing use only; TLS certificate verification is the default.
	Insecure bool `mapstructure:"insecure"`
	// SkipTLS is retained only for older config files. It has the same
	// plaintext meaning as Insecure and should be migrated to insecure.
	SkipTLS    bool                 `mapstructure:"skip_tls"`
	CAFile     string               `mapstructure:"ca_file"`
	CertFile   string               `mapstructure:"cert_file"`
	KeyFile    string               `mapstructure:"key_file"`
	ServerName string               `mapstructure:"server_name"`
	Timeout    int                  `mapstructure:"timeout"`
	Subscribe  *GNMISubscribeConfig `mapstructure:"subscribe"`
}

type GNMISubscribeConfig struct {
	Paths                 []string `mapstructure:"paths"`
	Mode                  string   `mapstructure:"mode"`
	StreamMode            string   `mapstructure:"stream_mode"`
	SampleIntervalSeconds int      `mapstructure:"sample_interval_seconds"`
	DurationSeconds       int      `mapstructure:"duration_seconds"`
	MaxUpdates            int      `mapstructure:"max_updates"`
}

type GNMIConfigSet struct {
	GNMI []GNMIConfig `mapstructure:"gnmi"`
}

func init() {
	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("unable to read config file", "error", err)
	}
}

func main() {
	var promptForCreds bool
	var insecureForTesting bool
	flag.BoolVar(&promptForCreds, "creds_input", false, "prompt for username and password interactively")
	flag.BoolVar(&insecureForTesting, "insecure", false, "use plaintext gNMI for controlled testing only; overrides TLS for every configured device")
	flag.Parse()

	username, password, err := credentials.ResolveCredentials(promptForCreds, nil, nil)
	if err != nil {
		slog.Error("error reading credentials", "error", err)
		os.Exit(1)
	}
	if username == "" || password == "" {
		slog.Error("missing required credentials", "required", "NET_USER,NET_PASSWORD")
		os.Exit(1)
	}

	var config GNMIConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		slog.Error("error reading config", "error", err)
		os.Exit(1)
	}

	for _, device := range config.GNMI {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		gnmiPath := strings.TrimSpace(device.Path)

		if hostname == "" || ip == "" || (gnmiPath == "" && device.Subscribe == nil) {
			slog.Warn("skipping invalid gNMI entry", "hostname", hostname, "ip", ip, "path", gnmiPath)
			continue
		}

		opts, err := optionsForDevice(device, insecureForTesting)
		if err != nil {
			slog.Error("invalid gNMI TLS configuration", "hostname", hostname, "ip", ip, "error", err)
			continue
		}

		client := &gnmi.GNMIClient{}
		if err := client.Connect(ip, username, password, opts...); err != nil {
			slog.Error("error connecting to gNMI device", "hostname", hostname, "ip", ip, "error", err)
			continue
		}
		var output string
		if device.Subscribe != nil {
			output, err = client.Subscribe(context.Background(), gnmi.Subscription{Paths: device.Subscribe.Paths, Mode: device.Subscribe.Mode, StreamMode: device.Subscribe.StreamMode, SampleInterval: time.Duration(device.Subscribe.SampleIntervalSeconds) * time.Second, Duration: time.Duration(device.Subscribe.DurationSeconds) * time.Second, MaxUpdates: device.Subscribe.MaxUpdates})
		} else {
			output, err = client.Execute(gnmiPath)
		}
		if err != nil {
			slog.Error("error executing gNMI path", "hostname", hostname, "ip", ip, "error", err)
		} else {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}

		if err := client.Close(); err != nil {
			slog.Error("error closing gNMI client", "hostname", hostname, "ip", ip, "error", err)
		}
	}
}

func optionsForDevice(device GNMIConfig, forceInsecure bool) ([]gnmi.Option, error) {
	caFile, certFile := strings.TrimSpace(device.CAFile), strings.TrimSpace(device.CertFile)
	keyFile, serverName := strings.TrimSpace(device.KeyFile), strings.TrimSpace(device.ServerName)
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("cert_file and key_file must be configured together")
	}
	insecure := forceInsecure || device.Insecure || device.SkipTLS
	if insecure && (caFile != "" || certFile != "" || keyFile != "" || serverName != "") {
		return nil, fmt.Errorf("insecure plaintext mode cannot be combined with TLS certificate settings")
	}
	opts := []gnmi.Option{gnmi.WithInsecure(insecure)}
	if insecure {
		slog.Warn("using plaintext gNMI for testing", "hostname", strings.TrimSpace(device.Hostname))
	} else {
		// Empty CAFile deliberately means the host trust store; verification is
		// still enabled. CAFile is for a private router CA and cert/key enable mTLS.
		opts = append(opts, gnmi.WithTLSCredentials(caFile, certFile, keyFile, serverName))
	}
	if device.Timeout > 0 {
		opts = append(opts, gnmi.WithGNMITimeout(time.Duration(device.Timeout)*time.Second))
	}
	return opts, nil
}
