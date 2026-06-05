package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/aristahttp"
	"github.com/spf13/viper"
)

type HTTPConfig struct {
	Hostname string `mapstructure:"hostname"`
	IP       string `mapstructure:"ip"`
	Command  string `mapstructure:"cmd"`
	SkipTLS  bool   `mapstructure:"skip_tls"`
	Timeout  int    `mapstructure:"timeout"`
}

type HTTPConfigSet struct {
	HTTP []HTTPConfig `mapstructure:"http"`
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

	var config HTTPConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		slog.Error("error reading config", "error", err)
		os.Exit(1)
	}

	for _, device := range config.HTTP {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		command := strings.TrimSpace(device.Command)

		if hostname == "" || ip == "" || command == "" {
			slog.Warn("skipping invalid HTTP entry", "hostname", hostname, "ip", ip, "command", command)
			continue
		}

		opts := []aristahttp.Option{}
		if device.SkipTLS {
			opts = append(opts, aristahttp.WithSkipTLS())
		}
		if device.Timeout > 0 {
			opts = append(opts, aristahttp.WithRequestTimeout(time.Duration(device.Timeout)*time.Second))
		}

		client := aristahttp.AristaHTTP{}
		if err := client.Connect(ip, username, password, opts...); err != nil {
			slog.Error("error connecting to HTTP device", "hostname", hostname, "ip", ip, "error", err)
			continue
		}
		defer func(c *aristahttp.AristaHTTP, h, i string) {
			if err := c.Close(); err != nil {
				slog.Error("error closing HTTP client", "hostname", h, "ip", i, "error", err)
			}
		}(&client, hostname, ip)

		output, err := client.Execute(command)
		if err != nil {
			slog.Error("error executing command", "hostname", hostname, "ip", ip, "error", err)
		} else {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}
	}
}
