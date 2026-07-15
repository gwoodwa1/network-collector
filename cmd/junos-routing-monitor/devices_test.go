package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDeviceSpecsValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - hostname: pe-router-1
    table: CUSTOMER-A.inet.0
    interfaces: [ae0, ae1]
    neighbors: [198.51.100.101]
  - hostname: pe-router-2
    interfaces:
      - ae10
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	specs, interval, _, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if interval != 0 {
		t.Fatalf("expected zero interval when unset, got %v", interval)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d: %+v", len(specs), specs)
	}
	if specs[0].Hostname != "pe-router-1" || specs[0].Table != "CUSTOMER-A.inet.0" {
		t.Fatalf("unexpected first spec: %+v", specs[0])
	}
	if len(specs[0].Interfaces) != 2 || specs[0].Interfaces[0] != "ae0" || specs[0].Interfaces[1] != "ae1" {
		t.Fatalf("unexpected interfaces: %+v", specs[0].Interfaces)
	}
	if len(specs[0].Neighbors) != 1 || specs[0].Neighbors[0] != "198.51.100.101" {
		t.Fatalf("unexpected neighbors: %+v", specs[0].Neighbors)
	}
	if specs[1].Hostname != "pe-router-2" || specs[1].Table != "" {
		t.Fatalf("unexpected second spec: %+v", specs[1])
	}
}

// TestDeviceSpecTablesMergesLegacySingularAndPlural proves the legacy
// singular "table" field and the "tables" list are merged and deduplicated,
// mirroring xr-routing-monitor's vrf/vrfs alias handling.
func TestDeviceSpecTablesMergesLegacySingularAndPlural(t *testing.T) {
	spec := deviceSpec{Table: "CUSTOMER-A.inet.0", Tables: []string{"CUSTOMER-B.inet.0", "CUSTOMER-A.inet.0", ""}}
	got := spec.tables()
	if len(got) != 2 || got[0] != "CUSTOMER-A.inet.0" || got[1] != "CUSTOMER-B.inet.0" {
		t.Fatalf("expected [CUSTOMER-A.inet.0 CUSTOMER-B.inet.0], got %v", got)
	}
}

func TestLoadDeviceSpecsMissingHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - table: CUSTOMER-A.inet.0
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a device spec missing hostname")
	}
}

func TestLoadDeviceSpecsMissingFile(t *testing.T) {
	if _, _, _, err := loadDeviceSpecs(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a missing devices file")
	}
}

func TestLoadDeviceSpecsInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(path, []byte("devices: [this is not valid: yaml:"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoadDeviceSpecsInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `interval: 30s

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, interval, _, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if interval != 30*time.Second {
		t.Fatalf("expected 30s interval, got %v", interval)
	}
}

func TestLoadDeviceSpecsInvalidInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `interval: not-a-duration

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for an invalid interval")
	}
}

func TestLoadDeviceSpecsNegativeInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `interval: -30s

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a negative interval instead of it being silently discarded")
	}
}

func TestLoadDeviceSpecsCommandOverrideRequiresPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `commands:
  route_command: "show route summary table"

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a route_command override missing its placeholder")
	}
}

func TestLoadDeviceSpecsCommandOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `commands:
  bgp_command: show bgp summary logical-system all
  route_command: "show route summary table %s"
  default_route_command: 'show route table %s 0/0 exact extensive | match "Protocol next hop:"'
  interface_command: 'show interfaces %s | match "Description:|Input :|Output:"'

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, commands, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if commands.BGPCommand != "show bgp summary logical-system all" {
		t.Fatalf("unexpected bgp command override: %q", commands.BGPCommand)
	}
	spec := resolveCollectionSpec(commands)
	if spec.RouteCommand != "show route summary table %s" {
		t.Fatalf("unexpected resolved route command: %q", spec.RouteCommand)
	}
	if spec.DefaultRouteCommand != `show route table %s 0/0 exact extensive | match "Protocol next hop:"` {
		t.Fatalf("unexpected resolved default route command: %q", spec.DefaultRouteCommand)
	}
}

// TestLoadDeviceSpecsDefaultRouteCommandOverrideRequiresPlaceholder mirrors
// TestLoadDeviceSpecsCommandOverrideRequiresPlaceholder for the
// default_route_command field specifically, since it was added after that
// validation path already existed for route_command/interface_command.
func TestLoadDeviceSpecsDefaultRouteCommandOverrideRequiresPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `commands:
  default_route_command: "show route table 0/0 exact extensive"

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a default_route_command override missing its placeholder")
	}
}
