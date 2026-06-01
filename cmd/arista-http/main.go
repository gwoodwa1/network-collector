package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/aristahttp"
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
		log.Printf("warning: unable to read config file: %v", err)
	}
}

func main() {
	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		log.Fatal("NET_USER and NET_PASSWORD must be set in the environment")
	}

	var config HTTPConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	for _, device := range config.HTTP {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		command := strings.TrimSpace(device.Command)

		if hostname == "" || ip == "" || command == "" {
			log.Printf("skipping invalid HTTP entry: hostname=%q ip=%q command=%q", hostname, ip, command)
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
			log.Printf("error connecting to %s (%s): %v", hostname, ip, err)
			continue
		}
		defer func(c *aristahttp.AristaHTTP, h, i string) {
			if err := c.Close(); err != nil {
				log.Printf("error closing HTTP client for %s (%s): %v", h, i, err)
			}
		}(&client, hostname, ip)

		output, err := client.Execute(command)
		if err != nil {
			log.Printf("error executing command on %s (%s): %v", hostname, ip, err)
		} else {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}
	}
}
