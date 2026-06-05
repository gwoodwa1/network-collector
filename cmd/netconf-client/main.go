package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
	"github.com/spf13/viper"
)

type NetconfConfig struct {
	Hostname string `mapstructure:"hostname"`
	IP       string `mapstructure:"ip"`
	RPC      string `mapstructure:"rpc"`
	Timeout  int    `mapstructure:"timeout"`
}

type NetconfConfigSet struct {
	Netconf []NetconfConfig `mapstructure:"netconf"`
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

	var config NetconfConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		slog.Error("error reading config", "error", err)
		os.Exit(1)
	}

	for _, device := range config.Netconf {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		rpc := strings.TrimSpace(device.RPC)

		if hostname == "" || ip == "" || rpc == "" {
			slog.Warn("skipping invalid NETCONF entry", "hostname", hostname, "ip", ip, "rpc", rpc)
			continue
		}

		opts := []netconf.Option{}
		if device.Timeout > 0 {
			opts = append(opts, netconf.WithNetconfTimeouts(time.Duration(device.Timeout)*time.Second, time.Duration(device.Timeout)*time.Second))
		}

		client := &netconf.ScrapligoNETCONF{}
		if err := client.Connect(ip, username, password, opts...); err != nil {
			slog.Error("error connecting to NETCONF device", "hostname", hostname, "ip", ip, "error", err)
			continue
		}

		output, err := client.Execute(rpc)
		if err != nil {
			slog.Error("error executing RPC", "hostname", hostname, "ip", ip, "error", err)
		} else {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}

		if err := client.Close(); err != nil {
			slog.Error("error closing NETCONF client", "hostname", hostname, "ip", ip, "error", err)
		}
	}
}
