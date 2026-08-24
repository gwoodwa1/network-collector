package main

import (
	"os"
	"path/filepath"
	"strings"
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

	specs, interval, _, _, err := loadDeviceSpecs(path)
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

	if _, _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a device spec missing hostname")
	}
}

func TestLoadDeviceSpecsMissingFile(t *testing.T) {
	if _, _, _, _, err := loadDeviceSpecs(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a missing devices file")
	}
}

func TestLoadDeviceSpecsInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(path, []byte("devices: [this is not valid: yaml:"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoadDeviceSpecsRejectsYAMLAnchors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := "devices:\n  - &device\n    hostname: router-1\n  - *device\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadDeviceSpecs(path); err == nil ||
		!strings.Contains(err.Error(), "anchors and aliases") {
		t.Fatalf("Junos device YAML anchors were not rejected: %v", err)
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
	_, interval, _, _, err := loadDeviceSpecs(path)
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
	if _, _, _, _, err := loadDeviceSpecs(path); err == nil {
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
	if _, _, _, _, err := loadDeviceSpecs(path); err == nil {
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
	if _, _, _, _, err := loadDeviceSpecs(path); err == nil {
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
	_, _, commands, _, err := loadDeviceSpecs(path)
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
	if _, _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a default_route_command override missing its placeholder")
	}
}

func boolPtr(b bool) *bool { return &b }

// TestResolveNetconfSnapshotNilFallsBackToFallback proves configured==nil
// (unset) is distinguishable from an explicit false — a plain bool can't
// represent that on its own, mirroring xr-routing-monitor's
// resolveHubTopInterfaces nil-vs-explicit-zero convention.
func TestResolveNetconfSnapshotNilFallsBackToFallback(t *testing.T) {
	if got := resolveNetconfSnapshot(nil, true); got != true {
		t.Fatalf("expected nil to fall back to fallback=true, got %v", got)
	}
	if got := resolveNetconfSnapshot(nil, false); got != false {
		t.Fatalf("expected nil to fall back to fallback=false, got %v", got)
	}
}

func TestResolveNetconfSnapshotExplicitOverridesFallback(t *testing.T) {
	if got := resolveNetconfSnapshot(boolPtr(false), true); got != false {
		t.Fatalf("expected explicit false to override fallback=true, got %v", got)
	}
	if got := resolveNetconfSnapshot(boolPtr(true), false); got != true {
		t.Fatalf("expected explicit true to override fallback=false, got %v", got)
	}
}

// TestDeviceSpecResolvedNetconfSnapshotPerDeviceOverride proves a
// per-device netconf_snapshot value wins over the fleet-wide default in
// either direction.
func TestDeviceSpecResolvedNetconfSnapshotPerDeviceOverride(t *testing.T) {
	unset := deviceSpec{}
	if got := unset.resolvedNetconfSnapshot(true); got != true {
		t.Fatalf("expected an unset per-device value to use the fleet default, got %v", got)
	}
	optOut := deviceSpec{NetconfSnapshot: boolPtr(false)}
	if got := optOut.resolvedNetconfSnapshot(true); got != false {
		t.Fatalf("expected an explicit per-device false to override a true fleet default, got %v", got)
	}
	optIn := deviceSpec{NetconfSnapshot: boolPtr(true)}
	if got := optIn.resolvedNetconfSnapshot(false); got != true {
		t.Fatalf("expected an explicit per-device true to override a false fleet default, got %v", got)
	}
}

// TestLoadDeviceSpecsNetconfSnapshotFleetDefaultAndPerDeviceOverride proves
// the --devices YAML file's top-level netconf_snapshot is returned
// distinctly from unset (nil), and that a per-device override round-trips
// through deviceSpec.
func TestLoadDeviceSpecsNetconfSnapshotFleetDefaultAndPerDeviceOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `netconf_snapshot: true

devices:
  - hostname: pe-router-1
  - hostname: pe-router-2
    netconf_snapshot: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	specs, _, _, netconfSnapshotDefault, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if netconfSnapshotDefault == nil || *netconfSnapshotDefault != true {
		t.Fatalf("expected the fleet-wide netconf_snapshot default to be true, got %v", netconfSnapshotDefault)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0].resolvedNetconfSnapshot(*netconfSnapshotDefault) != true {
		t.Fatalf("expected pe-router-1 (no override) to inherit the fleet default")
	}
	if specs[1].resolvedNetconfSnapshot(*netconfSnapshotDefault) != false {
		t.Fatalf("expected pe-router-2's explicit override to win over the fleet default")
	}
}

func TestLoadDeviceSpecsNoNetconfSnapshotFieldReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, netconfSnapshotDefault, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if netconfSnapshotDefault != nil {
		t.Fatalf("expected nil when the file has no top-level netconf_snapshot, got %v", *netconfSnapshotDefault)
	}
}
