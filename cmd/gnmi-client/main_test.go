package main

import (
	"testing"

	"github.com/gwoodwa1/network-collector/pkg/drivers/gnmi"
)

func configuredClient(t *testing.T, device GNMIConfig, forceInsecure bool) *gnmi.GNMIClient {
	t.Helper()
	opts, err := optionsForDevice(device, forceInsecure)
	if err != nil {
		t.Fatal(err)
	}
	client := &gnmi.GNMIClient{}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func TestGNMIClientDefaultsToVerifiedTLS(t *testing.T) {
	client := configuredClient(t, GNMIConfig{Hostname: "router"}, false)
	if client.Insecure || client.SkipVerify {
		t.Fatalf("default security flags = %+v", client.TLSConfig)
	}
}

func TestGNMIClientConfiguresPrivateCAAndMutualTLS(t *testing.T) {
	client := configuredClient(t, GNMIConfig{CAFile: "ca.pem", CertFile: "client.pem", KeyFile: "client.key", ServerName: "router.example.net"}, false)
	if client.Insecure || client.CAFile != "ca.pem" || client.CertFile != "client.pem" || client.KeyFile != "client.key" || client.ServerName != "router.example.net" {
		t.Fatalf("TLS configuration = %+v", client.TLSConfig)
	}
}

func TestGNMIClientInsecureModeIsExplicit(t *testing.T) {
	client := configuredClient(t, GNMIConfig{Insecure: true}, false)
	if !client.Insecure {
		t.Fatal("insecure config did not enable plaintext")
	}
	client = configuredClient(t, GNMIConfig{}, true)
	if !client.Insecure {
		t.Fatal("testing flag did not enable plaintext")
	}
}

func TestGNMIClientRejectsAmbiguousTLSConfiguration(t *testing.T) {
	for _, device := range []GNMIConfig{{CertFile: "client.pem"}, {Insecure: true, CAFile: "ca.pem"}} {
		if _, err := optionsForDevice(device, false); err == nil {
			t.Fatalf("configuration %+v was accepted", device)
		}
	}
}
