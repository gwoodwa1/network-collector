package main

import (
	"strings"
	"testing"
)

func TestEOSAndJunosFactParsers(t *testing.T) {
	config, err := loadParsers("../../parsers.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, output, contains string }{
		{"eos_facts_system", "Arista DCS-7280SR\nSoftware image version: 4.32.1F\nHostname: eos-leaf-01\n", `"HOSTNAME":"eos-leaf-01"`},
		{"eos_facts_platform", "1  48  48 port 10G SFP+  DCS-7280SR  Ok\n", `"NODE":"1"`},
		{"eos_facts_interfaces", "Et1  core uplink  connected  10  full  10G\n", `"INTERFACE":"Et1"`},
		{"eos_facts_lldp", "Interface name: Ethernet1\nChassis ID: 0011.2233.4455\nPort ID: Ethernet49\nPort Description: spine uplink\nSystem Name: spine-01\n", `"SYSTEM_NAME":"spine-01"`},
		{"eos_facts_bgp", "192.0.2.2 4 65002 12 10 0 0 0 1d02h 42\n", `"REMOTE_AS":"65002"`},
		{"junos_facts_system", "Hostname: junos-edge-01\nModel: qfx5120-48y\nJunos: 23.4R2-S1.2\n", `"HOSTNAME":"junos-edge-01"`},
		{"junos_facts_platform", "FPC 0 REV 20 750-083726 QFX5120-48Y FPC\n", `"NODE":"FPC 0"`},
		{"junos_facts_interfaces", "xe-0/0/0 up up inet 192.0.2.1/31\n", `"INTERFACE":"xe-0/0/0"`},
		{"junos_facts_lldp", "Local interface : xe-0/0/0\nChassis ID : 0011.2233.4455\nPort ID : Ethernet49\nPort description : spine uplink\nSystem name : spine-01\n", `"SYSTEM_NAME":"spine-01"`},
		{"junos_facts_bgp", "192.0.2.2 65002 10 12 0 0 1d2h Establ 1/1/1/0\n", `"REMOTE_AS":"65002"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parseOutputWithModule(test.output, test.name, config.Parsers)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(parsed, test.contains) {
				t.Fatalf("parsed output %s does not contain %s", parsed, test.contains)
			}
		})
	}
}
