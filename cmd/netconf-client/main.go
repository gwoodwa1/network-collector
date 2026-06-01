package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/netconf"
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
		log.Printf("warning: unable to read config file: %v", err)
	}
}

func main() {
	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		log.Fatal("NET_USER and NET_PASSWORD must be set in the environment")
	}

	var config NetconfConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	for _, device := range config.Netconf {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		rpc := strings.TrimSpace(device.RPC)

		if hostname == "" || ip == "" || rpc == "" {
			log.Printf("skipping invalid NETCONF entry: hostname=%q ip=%q rpc=%q", hostname, ip, rpc)
			continue
		}

		opts := []netconf.Option{}
		if device.Timeout > 0 {
			opts = append(opts, netconf.WithNetconfTimeouts(time.Duration(device.Timeout)*time.Second, time.Duration(device.Timeout)*time.Second))
		}

		client := &netconf.ScrapligoNETCONF{}
		if err := client.Connect(ip, username, password, opts...); err != nil {
			log.Printf("error connecting to %s (%s): %v", hostname, ip, err)
			continue
		}

		output, err := client.Execute(rpc)
		if err != nil {
			log.Printf("error executing RPC on %s (%s): %v", hostname, ip, err)
		} else {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}

		if err := client.Close(); err != nil {
			log.Printf("error closing NETCONF client for %s (%s): %v", hostname, ip, err)
		}
	}
}
