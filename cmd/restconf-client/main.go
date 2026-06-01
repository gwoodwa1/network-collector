package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers/restconf"
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
		log.Printf("warning: unable to read config file: %v", err)
	}
}

func main() {
	username := strings.TrimSpace(viper.GetString("NET_USER"))
	password := strings.TrimSpace(viper.GetString("NET_PASSWORD"))

	if username == "" || password == "" {
		log.Fatal("NET_USER and NET_PASSWORD must be set in the environment")
	}

	var config RESTCONFConfigSet
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	for _, device := range config.RESTCONF {
		hostname := strings.TrimSpace(device.Hostname)
		ip := strings.TrimSpace(device.IP)
		method := strings.TrimSpace(device.Method)
		endpoint := strings.TrimSpace(device.Endpoint)

		if hostname == "" || ip == "" || method == "" || endpoint == "" || device.Port <= 0 {
			log.Printf("skipping invalid RESTCONF entry: hostname=%q ip=%q port=%d method=%q endpoint=%q", hostname, ip, device.Port, method, endpoint)
			continue
		}

		opts := []restconf.Option{}
		if device.SkipTLS {
			opts = append(opts, restconf.WithSkipTLS())
		}
		if device.Timeout > 0 {
			opts = append(opts, restconf.WithRequestTimeout(time.Duration(device.Timeout)*time.Second))
		}

		baseURL := fmt.Sprintf("https://%s:%d/restconf", ip, device.Port)
		client := &restconf.RESTCONFClient{}
		if err := client.Connect(baseURL, username, password, opts...); err != nil {
			log.Printf("error connecting to %s (%s): %v", hostname, ip, err)
			continue
		}

		output, err := client.Execute(method, endpoint)
		if err != nil {
			log.Printf("error executing RESTCONF request on %s (%s): %v", hostname, ip, err)
		} else {
			fmt.Printf("RESTCONF output for %s (%s):\n%s\n", hostname, ip, output)
		}

		if err := client.Close(); err != nil {
			log.Printf("error closing RESTCONF client for %s (%s): %v", hostname, ip, err)
		}
	}
}
