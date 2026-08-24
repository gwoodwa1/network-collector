package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Cross-platform onboarding-order and hostname-dedup guarantees are proven
// at internal/monitorsetup (HostnameRegistry) and each platform package's
// own onboarding tests, not here: xrmonitor.OnboardDevicesFromSpecs's
// connect parameter type is deliberately unexported, so an external package
// like this one can only ever pass the real xrmonitor.ConnectDevice/
// junosmonitor.ConnectDevice — there is no seam here to inject a fake
// connect and observe call order without a real SSH/NETCONF connection.
// These tests instead cover what is fully testable at this layer:
// loadMixedFleetDocument's YAML parsing and validation.

func TestLoadMixedFleetDocumentBothSectionsPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.yaml")
	content := `interval: 30s

cisco_iosxr:
  devices:
    - hostname: xr-router-1
      vrfs: [CUSTOMER-A]

juniper_junos:
  netconf_snapshot: true
  devices:
    - hostname: pe-router-1
      tables: [CUSTOMER-A.inet.0]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	doc, interval, err := loadMixedFleetDocument(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if interval != 30*time.Second {
		t.Fatalf("expected 30s interval, got %v", interval)
	}
	if doc.CiscoIOSXR == nil || len(doc.CiscoIOSXR.Devices) != 1 || doc.CiscoIOSXR.Devices[0].Hostname != "xr-router-1" {
		t.Fatalf("unexpected cisco_iosxr section: %+v", doc.CiscoIOSXR)
	}
	if doc.JuniperJunos == nil || len(doc.JuniperJunos.Devices) != 1 || doc.JuniperJunos.Devices[0].Hostname != "pe-router-1" {
		t.Fatalf("unexpected juniper_junos section: %+v", doc.JuniperJunos)
	}
	if doc.JuniperJunos.NetconfSnapshot == nil || !*doc.JuniperJunos.NetconfSnapshot {
		t.Fatalf("expected juniper_junos.netconf_snapshot true, got %v", doc.JuniperJunos.NetconfSnapshot)
	}
}

func TestLoadMixedFleetDocumentOneSectionAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junos-only.yaml")
	content := `juniper_junos:
  devices:
    - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	doc, _, err := loadMixedFleetDocument(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.CiscoIOSXR != nil {
		t.Fatalf("expected nil cisco_iosxr section, got %+v", doc.CiscoIOSXR)
	}
	if doc.JuniperJunos == nil || len(doc.JuniperJunos.Devices) != 1 {
		t.Fatalf("unexpected juniper_junos section: %+v", doc.JuniperJunos)
	}
}

func TestLoadMixedFleetDocumentRequiresAtLeastOneSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, []byte("interval: 30s\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, err := loadMixedFleetDocument(path); err == nil {
		t.Fatal("expected an error when neither cisco_iosxr nor juniper_junos is set")
	}
}

// TestLoadMixedFleetDocumentValidatesEachSectionWithItsOwnRules proves a
// per-device validation failure (missing hostname) inside a nested section
// is caught by that platform's own ValidateDevicesDocument, not silently
// ignored because it's nested rather than top-level.
func TestLoadMixedFleetDocumentValidatesEachSectionWithItsOwnRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-hostname.yaml")
	content := `cisco_iosxr:
  devices:
    - vrfs: [CUSTOMER-A]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, err := loadMixedFleetDocument(path); err == nil {
		t.Fatal("expected an error for a cisco_iosxr device missing hostname")
	}
}

// TestLoadMixedFleetDocumentValidatesJunosCommandTemplate proves the
// juniper_junos section's own command-template-placeholder rule is applied
// too, not just the cisco_iosxr section's.
func TestLoadMixedFleetDocumentValidatesJunosCommandTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-command.yaml")
	content := `juniper_junos:
  commands:
    route_command: "show route summary table"
  devices:
    - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, err := loadMixedFleetDocument(path); err == nil {
		t.Fatal("expected an error for a route_command override missing its placeholder")
	}
}

func TestLoadMixedFleetDocumentInvalidInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-interval.yaml")
	content := `interval: not-a-duration

juniper_junos:
  devices:
    - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, err := loadMixedFleetDocument(path); err == nil {
		t.Fatal("expected an error for an invalid top-level interval")
	}
}

func TestLoadMixedFleetDocumentMissingFile(t *testing.T) {
	if _, _, err := loadMixedFleetDocument(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a missing devices file")
	}
}
