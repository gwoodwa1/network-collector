package main

import (
	"strings"
	"testing"
)

func boolPointer(value bool) *bool {
	return &value
}

func TestSecurityModeDefaultsToProduction(t *testing.T) {
	mode, err := validateSecurityPolicy(Config{}, []DeviceConfig{{Hostname: "router"}})
	if err != nil {
		t.Fatal(err)
	}
	if mode != securityModeProduction {
		t.Fatalf("got mode %q, want %q", mode, securityModeProduction)
	}
}

func TestProductionSecurityRejectsInsecureTransports(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		devices []DeviceConfig
		want    string
	}{
		{
			name:    "legacy SSH",
			devices: []DeviceConfig{{Hostname: "router", SSHSecurity: &SSHSecurityConfig{Profile: "legacy"}}},
			want:    "requires modern",
		},
		{
			name:    "insecure host key",
			devices: []DeviceConfig{{Hostname: "router", SSHSecurity: &SSHSecurityConfig{HostKeyPolicy: "insecure"}}},
			want:    "disables SSH host-key verification",
		},
		{
			name:    "plaintext gNMI inventory",
			devices: []DeviceConfig{{Hostname: "router", GNMI: &GNMIConnectionConfig{Insecure: boolPointer(true)}}},
			want:    "plaintext gNMI",
		},
		{
			name:    "unverified gNMI certificate",
			devices: []DeviceConfig{{Hostname: "router", GNMI: &GNMIConnectionConfig{SkipVerify: boolPointer(true)}}},
			want:    "disables gNMI certificate verification",
		},
		{
			name: "nested legacy gNMI step",
			config: Config{Workflows: map[string]WorkflowConfig{
				"monitor": {Steps: []StepConfig{{Parallel: &ParallelConfig{Steps: []StepConfig{{
					Name: "telemetry", GNMISubscribe: &GNMISubscribeConfig{SkipTLS: true},
				}}}}}},
			}},
			want: "uses legacy gNMI skip_tls",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateSecurityPolicy(test.config, test.devices)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPermissiveSecurityAllowsExplicitLegacyConfiguration(t *testing.T) {
	config := Config{
		SecurityMode: securityModePermissive,
		Workflows: map[string]WorkflowConfig{
			"monitor": {Steps: []StepConfig{{GNMISubscribe: &GNMISubscribeConfig{SkipTLS: true}}}},
		},
	}
	devices := []DeviceConfig{{
		Hostname:    "legacy-router",
		SSHSecurity: &SSHSecurityConfig{Profile: "legacy", HostKeyPolicy: "insecure"},
		GNMI:        &GNMIConnectionConfig{Insecure: boolPointer(true), SkipVerify: boolPointer(true)},
	}}
	mode, err := validateSecurityPolicy(config, devices)
	if err != nil {
		t.Fatal(err)
	}
	if mode != securityModePermissive {
		t.Fatalf("got mode %q, want permissive", mode)
	}
}

func TestRSATokenReuseIsExplicitAndBounded(t *testing.T) {
	if _, err := validateRSATokenReuse(CredentialProviderConfig{}, true, 2); err == nil {
		t.Fatal("default RSA reuse accepted more than one device")
	}
	maxDevices, err := validateRSATokenReuse(CredentialProviderConfig{RSATokenReuseMaxDevices: 3}, true, 3)
	if err != nil {
		t.Fatal(err)
	}
	if maxDevices != 3 {
		t.Fatalf("got maximum %d, want 3", maxDevices)
	}
	if _, err := validateRSATokenReuse(CredentialProviderConfig{RSATokenReuseMaxDevices: maxRSATokenReuseDevices + 1}, true, 1); err == nil {
		t.Fatal("RSA reuse above hard maximum was accepted")
	}
	if _, err := validateRSATokenReuse(CredentialProviderConfig{RSATokenReuseMaxDevices: 2}, false, 1); err == nil {
		t.Fatal("RSA reuse setting without RSA token mode was accepted")
	}
}
