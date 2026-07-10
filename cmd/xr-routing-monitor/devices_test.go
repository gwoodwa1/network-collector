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

	specs, interval, gatewayPrefix, _, _, _, err := loadDeviceSpecs(path)
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

	if _, _, _, _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for a device spec missing hostname")
	}
}

func TestLoadDeviceSpecsMissingFile(t *testing.T) {
	if _, _, _, _, _, _, err := loadDeviceSpecs(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a missing devices file")
	}
}

func TestLoadDeviceSpecsInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(path, []byte("devices: [this is not valid: yaml:"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, _, _, _, err := loadDeviceSpecs(path); err == nil {
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
	_, interval, _, _, _, _, err := loadDeviceSpecs(path)
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
	if _, _, _, _, _, _, err := loadDeviceSpecs(path); err == nil {
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
	if _, _, _, _, _, _, err := loadDeviceSpecs(path); err == nil {
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
	specs, _, gatewayPrefix, _, _, _, err := loadDeviceSpecs(path)
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
	if _, _, _, _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected an error for auto_detect_vrf without a top-level customer_gateway_prefix")
	}
}

func TestLoadDeviceSpecsCommandAndExcludePrefixOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `exclude_interface_prefixes: [loopback, tunnel-ip]

commands:
  bgp_command: show bgp summary
  route_parser: xr_custom_route_parser

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, commands, excludePrefixes, _, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if commands.BGPCommand != "show bgp summary" || commands.RouteParser != "xr_custom_route_parser" {
		t.Fatalf("unexpected commands: %+v", commands)
	}
	if strings.Join(excludePrefixes, ",") != "loopback,tunnel-ip" {
		t.Fatalf("unexpected exclude prefixes: %v", excludePrefixes)
	}
}

// TestLoadDeviceSpecsHubTopInterfaces proves hub_top_interfaces round-trips
// when set, comes back nil (not zero) when unset so the caller can tell
// "unset" apart from an explicit "0" (see resolveHubTopInterfaces), and is
// rejected when negative.
func TestLoadDeviceSpecsHubTopInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `hub_top_interfaces: 4

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, _, _, hubTopInterfaces, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hubTopInterfaces == nil || *hubTopInterfaces != 4 {
		t.Fatalf("expected hub_top_interfaces 4, got %v", hubTopInterfaces)
	}
}

func TestLoadDeviceSpecsHubTopInterfacesDefaultsWhenUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, _, _, hubTopInterfaces, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hubTopInterfaces != nil {
		t.Fatalf("expected unset hub_top_interfaces to come back as nil, got %d", *hubTopInterfaces)
	}
	if resolveHubTopInterfaces(hubTopInterfaces) != defaultHubTopInterfaces {
		t.Fatalf("expected resolveHubTopInterfaces(nil) to fall back to the default")
	}
}

// TestLoadDeviceSpecsHubTopInterfacesZeroDisablesSampling proves an
// explicit "hub_top_interfaces: 0" is preserved as a real, non-default 0
// (disabling hub-VRF interface sampling) rather than being treated the
// same as the field being left out of the file entirely.
func TestLoadDeviceSpecsHubTopInterfacesZeroDisablesSampling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `hub_top_interfaces: 0

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, _, _, hubTopInterfaces, err := loadDeviceSpecs(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hubTopInterfaces == nil || *hubTopInterfaces != 0 {
		t.Fatalf("expected an explicit 0 to round-trip as a non-nil pointer to 0, got %v", hubTopInterfaces)
	}
	if got := resolveHubTopInterfaces(hubTopInterfaces); got != 0 {
		t.Fatalf("expected resolveHubTopInterfaces to keep an explicit 0 rather than defaulting it, got %d", got)
	}
}

func TestLoadDeviceSpecsRejectsNegativeHubTopInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `hub_top_interfaces: -1

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, _, _, _, _, err := loadDeviceSpecs(path); err == nil {
		t.Fatal("expected a negative hub_top_interfaces to be rejected")
	}
}

func TestLoadDeviceSpecsCommandOverridesRequireOnePlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	content := `commands:
  route_command: show route vrf summary
  interface_command: show interface %s %s

devices:
  - hostname: pe-router-1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	_, _, _, _, _, _, err := loadDeviceSpecs(path)
	if err == nil {
		t.Fatal("expected invalid command placeholders to be rejected")
	}
	if !strings.Contains(err.Error(), "commands.route_command") {
		t.Fatalf("expected route_command validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "commands.interface_command") {
		t.Fatalf("expected interface_command validation error, got: %v", err)
	}
}

// TestValidateCommandTemplateRejectsEscapedPlaceholder guards against a
// regression where substring-counting "%s" occurrences (rather than
// checking fmt's actual verb semantics) let an escaped literal "%%s" pass
// validation. "%%s" is not a %s verb — fmt treats "%%" as a literal percent
// sign, leaving "s" as ordinary text — so fmt.Sprintf(value, vrf) would
// never substitute the VRF name and would instead append
// "%!(EXTRA string=...)" to the command actually sent to a live router.
func TestValidateCommandTemplateRejectsEscapedPlaceholder(t *testing.T) {
	if err := validateCommandTemplate("devices.yaml", "route_command", "show route vrf %%s summary"); err == nil {
		t.Fatal("expected an escaped percent-percent-s (not a real placeholder) to be rejected")
	}
}

func TestValidateCommandTemplateAcceptsExactlyOnePlaceholder(t *testing.T) {
	if err := validateCommandTemplate("devices.yaml", "route_command", "show route vrf %s summary"); err != nil {
		t.Fatalf("unexpected error for a valid single placeholder: %v", err)
	}
}

func TestValidateCommandTemplateRejectsMissingPlaceholder(t *testing.T) {
	if err := validateCommandTemplate("devices.yaml", "route_command", "show route vrf summary"); err == nil {
		t.Fatal("expected a template with no placeholder to be rejected")
	}
}

func TestValidateCommandTemplateRejectsExtraPlaceholder(t *testing.T) {
	if err := validateCommandTemplate("devices.yaml", "interface_command", "show interface %s %s"); err == nil {
		t.Fatal("expected a template with two placeholders to be rejected")
	}
}

func TestValidateCommandTemplateRejectsOtherFormatVerbs(t *testing.T) {
	if err := validateCommandTemplate("devices.yaml", "route_command", "show route vrf %q summary"); err == nil {
		t.Fatal("expected a template using a non-string placeholder to be rejected")
	}
}

func TestValidateCommandTemplateAllowsBlank(t *testing.T) {
	if err := validateCommandTemplate("devices.yaml", "route_command", ""); err != nil {
		t.Fatalf("expected a blank (unset) override to be allowed, got: %v", err)
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
	_, _, _, _, _, _, err := loadDeviceSpecs(path)
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
