package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/gnmi"
	"github.com/spf13/viper"
)

type GNMIConfig struct {
	Hostname string `mapstructure:"hostname"`
	IP       string `mapstructure:"ip"`
	Path     string `mapstructure:"path"`
	SkipTLS  bool   `mapstructure:"skip_tls"`
	Timeout  int    `mapstructure:"timeout"`
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
	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		slog.Error("missing required environment variables", "required", "NET_USER,NET_PASSWORD")
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

		if hostname == "" || ip == "" || gnmiPath == "" {
			slog.Warn("skipping invalid gNMI entry", "hostname", hostname, "ip", ip, "path", gnmiPath)
			continue
		}

		opts := []gnmi.Option{}
		if device.SkipTLS {
			opts = append(opts, gnmi.WithSkipTLS())
		}
		if device.Timeout > 0 {
			opts = append(opts, gnmi.WithGNMITimeout(time.Duration(device.Timeout)*time.Second))
		}

		client := &gnmi.GNMIClient{}
		if err := client.Connect(ip, username, password, opts...); err != nil {
			slog.Error("error connecting to gNMI device", "hostname", hostname, "ip", ip, "error", err)
			continue
		}
		defer func(c *gnmi.GNMIClient, h, i string) {
			if err := c.Close(); err != nil {
				slog.Error("error closing gNMI client", "hostname", h, "ip", i, "error", err)
			}
		}(client, hostname, ip)
		output, err := client.Execute(gnmiPath)
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
