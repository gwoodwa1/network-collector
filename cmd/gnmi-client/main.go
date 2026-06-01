package main

import (
	"fmt"
	"log"
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
		log.Printf("warning: unable to read config file: %v", err)
	}
}

func main() {
	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		log.Fatal("NET_USER and NET_PASSWORD must be set in the environment")
	}

	var config GNMIConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	for _, device := range config.GNMI {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		gnmiPath := strings.TrimSpace(device.Path)

		if hostname == "" || ip == "" || gnmiPath == "" {
			log.Printf("skipping invalid gNMI entry: hostname=%q ip=%q path=%q", hostname, ip, gnmiPath)
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
			log.Printf("error connecting to %s (%s): %v", hostname, ip, err)
			continue
		}		defer func(c *gnmi.GNMIClient, h, i string) {
			if err := c.Close(); err != nil {
				log.Printf("error closing gNMI client for %s (%s): %v", h, i, err)
			}
		}(&client, hostname, ip)
		output, err := client.Execute(gnmiPath)
		if err != nil {
			log.Printf("error executing gNMI path on %s (%s): %v", hostname, ip, err)
		} else {
			fmt.Printf("output for %s (%s):\n%s\n", hostname, ip, output)
		}

		if err := client.Close(); err != nil {
			log.Printf("error closing gNMI client for %s (%s): %v", hostname, ip, err)
		}
	}
}
