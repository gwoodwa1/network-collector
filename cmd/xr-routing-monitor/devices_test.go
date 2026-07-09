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
    vrf: CUSTOMER-A-INTERNET
    interfaces: [BE45, BE46]
    neighbors: [198.51.100.101]
  - hostname: pe-router-2
    interfaces:
      - BE10
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	specs, interval, gatewayPrefix, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if interval != 0 {
		t.Fatalf("expected zero interval when unset, got %v", interval)
	}
	if gatewayPrefix != "" {
		t.Fatalf("expected empty gateway prefix when unset, got %q", gatewayPrefix)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d: %+v", len(specs), specs)
	}
	if specs[0].Hostname != "pe-router-1" || specs[0].VRF != "CUSTOMER-A-INTERNET" {
		t.Fatalf("unexpected first spec: %+v", specs[0])
	}
	if len(specs[0].Interfaces) != 2 || specs[0].Interfaces[0] != "BE45" || specs[0].Interfaces[1] != "BE46" {
		t.Fatalf("unexpected interfaces: %+v", specs[0].Interfaces)
	}
	if len(specs[0].Neighbors) != 1 || specs[0].Neighbors[0] != "198.51.100.101" {
		t.Fatalf("unexpected neighbors: %+v", specs[0].Neighbors)
	}
	if specs[1].Hostname != "pe-router-2" || specs[1].VRF != "" {
		t.Fatalf("unexpected second spec: %+v", specs[1])
	}
}

func TestLoadDeviceSpecsMissingHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - vrf: CUSTOMER-A-INTERNET
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

func TestLoadDeviceSpecsCustomerGatewayPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `customer_gateway_prefix: 10.99.99.

devices:
  - hostname: pe-router-1
    auto_detect_vrf: true
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	specs, _, gatewayPrefix, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gatewayPrefix != "10.99.99." {
		t.Fatalf("expected gateway prefix 10.99.99., got %q", gatewayPrefix)
	}
	if !specs[0].AutoDetectVRF {
		t.Fatal("expected auto_detect_vrf to be true")
	}
}

// TestLoadDeviceSpecsAutoDetectVRFRequiresGatewayPrefix guards against a
// devices file that requests auto-detection for a device but forgets the
// document-level gateway prefix it depends on — without this check, that
// device would silently onboard with no VRFs monitored instead of erroring.
func TestLoadDeviceSpecsAutoDetectVRFRequiresGatewayPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - hostname: pe-router-1
    auto_detect_vrf: true
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for auto_detect_vrf without a top-level customer_gateway_prefix")
	}
}

func TestDeviceSpecVRFsMergesLegacySingularAndPluralFields(t *testing.T) {
	spec := deviceSpec{VRF: "LEGACY-VRF", VRFs: []string{"NEW-VRF-1", "NEW-VRF-2"}}
	got := spec.vrfs()
	want := []string{"LEGACY-VRF", "NEW-VRF-1", "NEW-VRF-2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

// TestDeviceSpecVRFsDropsBlankEntriesAndDedupes guards against a stray ""
// in a vrfs: list (blank list item, trailing comma typo) turning into a
// malformed "show route vrf  summary" command, and against the legacy vrf:
// field duplicating an entry already present in vrfs:.
func TestDeviceSpecVRFsDropsBlankEntriesAndDedupes(t *testing.T) {
	spec := deviceSpec{VRF: "CUSTOMER-A", VRFs: []string{"", "CUSTOMER-A", "  ", "CUSTOMER-B"}}
	got := spec.vrfs()
	want := "CUSTOMER-A,CUSTOMER-B"
	if strings.Join(got, ",") != want {
		t.Fatalf("expected %q, got %v", want, got)
	}
}

// TestLoadDeviceSpecsReportsAllValidationErrorsNotJustTheFirst guards
// against a devices file with two unrelated problems (a missing hostname
// on one device, a missing gateway prefix for another's auto_detect_vrf)
// only ever surfacing the first one found by index order, which would
// otherwise mask the second until the operator fixes the first and reruns.
func TestLoadDeviceSpecsReportsAllValidationErrorsNotJustTheFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - vrf: CUSTOMER-A-INTERNET
  - hostname: pe-router-2
    auto_detect_vrf: true
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, err := loadDeviceSpecs(path)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "missing hostname") {
		t.Fatalf("expected the missing-hostname error to be reported, got: %v", err)
	}
	if !strings.Contains(err.Error(), "customer_gateway_prefix") {
		t.Fatalf("expected the missing-gateway-prefix error to also be reported (not masked by the first error), got: %v", err)
	}
}
