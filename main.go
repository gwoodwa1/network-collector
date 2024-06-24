package main

import (
	"fmt"
	"github.com/gwoodwa1/network-collector/drivers"
	//"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"log"
)

type DeviceConfig struct {
	Hostname string `mapstructure:"hostname"`
	IP       string `mapstructure:"ip"`
	Type     string `mapstructure:"type"`
	Command  string `mapstructure:"cmd"`
	GNMIPath string `mapstructure:"path"`
	RPC      string `mapstructure:"rpc"`
	Port     int    `mapstructure:"port"`
	SkipTLS  bool   `mapstructure:"skip_tls"`
	Method   string `mapstructure:"method"`
	Endpoint string `mapstructure:"endpoint"`
}

type Config struct {
	SSH      []DeviceConfig `mapstructure:"ssh"`
	HTTP     []DeviceConfig `mapstructure:"http"`
	Netconf  []DeviceConfig `mapstructure:"netconf"`
	GNMI     []DeviceConfig `mapstructure:"gnmi"`
	RESTCONF []DeviceConfig `mapstructure:"restconf"`
}

func init() {
	// Set the file name of the configurations file
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath("./")
	// Load the .env file using godotenv

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}
}

func main() {
	username := viper.GetString("NET_USER")
	password := viper.GetString("NET_PASSWORD")

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		wrappedErr := fmt.Errorf("error decoding config: %w", err)
		log.Fatal(wrappedErr)
		return
	}

	for _, sshConfig := range config.SSH {
		if sshConfig.Command == "" {
			log.Printf("No CLI Command Provided %s (%s):\n", sshConfig.Hostname, sshConfig.IP)
			continue // If there's an error, skip to the next iteration
		}
		ssh := &drivers.ScrapligoSSH{}
		err := ssh.Connect(sshConfig.IP, username, password, sshConfig.Type)
		if err != nil {
			log.Printf("Error connecting to %s (%s): %v\n", sshConfig.Hostname, sshConfig.IP, err)
			continue // If there's an error, skip to the next iteration
		}

		output, err := ssh.Execute(sshConfig.Command)
		if err != nil {
			log.Printf("Error executing command on %s (%s): %v\n", sshConfig.Hostname, sshConfig.IP, err)
		} else {
			log.Printf("Output for %s (%s):\n%s\n", sshConfig.Hostname, sshConfig.IP, output)
		}
		if err := ssh.Close(); err != nil {
			log.Printf("Error closing SSH connection: %v", err)
		}
	}

	// Example using AristaHTTP

	for _, httpConfig := range config.HTTP {

		opts := []drivers.Option{}
		if httpConfig.SkipTLS {
			opts = append(opts, drivers.WithSkipTLS())
		}

		http := drivers.AristaHTTP{}

		err := http.Connect(httpConfig.IP, username, password, opts...)
		if err != nil {
			log.Printf("HTTP Connect Error %s: %v\n", httpConfig.IP, err)
			continue
		}

		output, err := http.Execute(httpConfig.Command)
		if err != nil {
			log.Printf("HTTP Error executing command on %s: %v\n", httpConfig.IP, err)
		} else {
			log.Printf("HTTP Output for %s: %s\n", httpConfig.IP, output)
		}

	}

	// Example using ScrapligoNETCONF
	for _, netconfConfig := range config.Netconf {
		netconfAPI := &drivers.ScrapligoNETCONF{}
		err := netconfAPI.Connect(netconfConfig.IP, username, password)
		if err != nil {
			log.Printf("NETCONF Error connecting to %s (%s): %v\n", netconfConfig.Hostname, netconfConfig.IP, err)
			continue
		}

		// Use the RPC field from the configuration
		netconfRPC, err := netconfAPI.Execute(netconfConfig.RPC)
		if err != nil {
			log.Printf("NETCONF Error executing RPC on %s (%s): %v\n", netconfConfig.Hostname, netconfConfig.IP, err)
		} else {
			log.Printf("NETCONF Output for %s (%s):\n%s\n", netconfConfig.Hostname, netconfConfig.IP, netconfRPC)
		}
		if err := netconfAPI.Close(); err != nil {
			log.Printf("Error closing SSH connection: %v", err)
		}
		// Example using GNMI
		for _, gnmiConfig := range config.GNMI {

			gnmi := &drivers.GNMIClient{}

			err := gnmi.Connect(gnmiConfig.IP, username, password, drivers.WithSkipTLS())
			if err != nil {
				log.Printf("Error connecting to device: %v", err)
			}
			rsp, err := gnmi.Execute(gnmiConfig.GNMIPath)
			if err != nil {
				log.Printf("Error exectuting path statement: %v", err)
			}
			fmt.Println(rsp)
			gnmi.Close()
		}
	}
	// Example using RESTCONF
	for _, restconfConfig := range config.RESTCONF {
		restconf := &drivers.RESTCONFClient{}

		opts := []drivers.Option{}
		if restconfConfig.SkipTLS {
			opts = append(opts, drivers.WithSkipTLS())
		}

		err := restconf.Connect(fmt.Sprintf("https://%s:%d/restconf", restconfConfig.IP, restconfConfig.Port), username, password, opts...)
		if err != nil {
			log.Printf("Error connecting to RESTCONF device %s (%s): %v", restconfConfig.Hostname, restconfConfig.IP, err)
			continue
		}
		rsp, err := restconf.Execute(restconfConfig.Method, restconfConfig.Endpoint)
		if err != nil {
			log.Printf("Error executing RESTCONF request on %s (%s): %v", restconfConfig.Hostname, restconfConfig.IP, err)
		} else {
			fmt.Printf("RESTCONF Output for %s (%s):\n%s\n", restconfConfig.Hostname, restconfConfig.IP, rsp)
		}
		restconf.Close()
	}
}
