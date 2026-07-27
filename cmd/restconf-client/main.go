package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/credentials"
	"github.com/gwoodwa1/network-collector/pkg/drivers/restconf"
	"github.com/spf13/viper"
)

type RESTCONFConfig struct {
	Hostname string `mapstructure:"hostname"`
	IP       string `mapstructure:"ip"`
	Port     int    `mapstructure:"port"`
	Method   string `mapstructure:"method"`
	Endpoint string `mapstructure:"endpoint"`
	SkipTLS  bool   `mapstructure:"skip_tls"`
	Timeout  int    `mapstructure:"timeout"`
}

type RESTCONFConfigSet struct {
	RESTCONF []RESTCONFConfig `mapstructure:"restconf"`
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
	flag.BoolVar(&promptForCreds, "creds_input", false, "prompt for username and password interactively")
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

	var config RESTCONFConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		slog.Error("error reading config", "error", err)
		os.Exit(1)
	}

	for _, device := range config.RESTCONF {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		method := strings.TrimSpace(device.Method)
		endpoint := strings.TrimSpace(device.Endpoint)

		if hostname == "" || ip == "" || method == "" || endpoint == "" || device.Port <= 0 {
			slog.Warn("skipping invalid RESTCONF entry", "hostname", hostname, "ip", ip, "port", device.Port, "method", method, "endpoint", endpoint)
			continue
		}

		opts := []restconf.Option{}
		if device.SkipTLS {
			opts = append(opts, restconf.WithSkipTLSVerification())
		}
		if device.Timeout > 0 {
			opts = append(opts, restconf.WithRequestTimeout(time.Duration(device.Timeout)*time.Second))
		}

		baseURL := fmt.Sprintf("https://%s:%d/restconf", ip, device.Port)
		client := &restconf.RESTCONFClient{}
		if err := client.Connect(baseURL, username, password, opts...); err != nil {
			slog.Error("error connecting to RESTCONF device", "hostname", hostname, "ip", ip, "error", err)
			continue
		}
		defer func(c *restconf.RESTCONFClient, h, i string) {
			if err := c.Close(); err != nil {
				slog.Error("error closing RESTCONF client", "hostname", h, "ip", i, "error", err)
			}
		}(client, hostname, ip)
		output, err := client.Execute(method, endpoint)
		if err != nil {
			slog.Error("error executing RESTCONF request", "hostname", hostname, "ip", ip, "error", err)
		} else {
			fmt.Printf("RESTCONF output for %s (%s):\n%s\n", hostname, ip, output)
		}
	}
}
