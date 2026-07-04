package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeviceSelectorBooleanExpressions(t *testing.T) {
	selector, err := parseDeviceSelector(`site=london and (role=core or role=edge) and not maintenance=true`)
	if err != nil {
		t.Fatal(err)
	}
	matching := DeviceConfig{Labels: map[string]string{"site": "London", "role": "core"}}
	excluded := DeviceConfig{Labels: map[string]string{"site": "london", "role": "core", "maintenance": "true"}}
	if !selector(matching) {
		t.Fatal("expected device to match selector")
	}
	if selector(excluded) {
		t.Fatal("maintenance device unexpectedly matched selector")
	}
}

func TestDeviceSelectorBuiltinsAndExclude(t *testing.T) {
	include, err := parseDeviceSelector(`type=iosxr or hostname="edge-1"`)
	if err != nil {
		t.Fatal(err)
	}
	exclude, err := parseDeviceSelector(`site=lab`)
	if err != nil {
		t.Fatal(err)
	}
	devices := []DeviceConfig{
		{Hostname: "core-1", Type: "iosxr", Labels: map[string]string{"site": "prod"}},
		{Hostname: "edge-1", Type: "junos", Labels: map[string]string{"site": "prod"}},
		{Hostname: "lab-1", Type: "iosxr", Labels: map[string]string{"site": "lab"}},
	}
	got := filterDevices(devices, include, exclude, nil)
	if len(got) != 2 || got[0].Hostname != "core-1" || got[1].Hostname != "edge-1" {
		t.Fatalf("unexpected filtered devices: %+v", got)
	}
}

func TestInventoryLabelsMergeWithDeviceOverride(t *testing.T) {
	resolved := applyInventoryHost(
		DeviceConfig{Labels: map[string]string{"role": "override", "change": "CHG1"}},
		InventoryHostConfig{Name: "router-1", IP: "192.0.2.1", Labels: map[string]string{"site": "london", "role": "core"}},
	)
	if resolved.Labels["site"] != "london" || resolved.Labels["role"] != "override" || resolved.Labels["change"] != "CHG1" {
		t.Fatalf("unexpected merged labels: %+v", resolved.Labels)
	}
}

func TestLoadFailedDevices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	content, err := json.Marshal(runSummary{Devices: []deviceOutcome{
		{Hostname: "good", Failed: false},
		{Hostname: "bad", IP: "192.0.2.2", Failed: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	failed, err := loadFailedDevices(path)
	if err != nil {
		t.Fatal(err)
	}
	if !failed["bad"] || !failed["192.0.2.2"] || failed["good"] {
		t.Fatalf("unexpected failed-device set: %+v", failed)
	}
}

func TestInvalidDeviceSelector(t *testing.T) {
	for _, input := range []string{`site`, `site=`, `(site=london`, `site=london trailing`} {
		if _, err := parseDeviceSelector(input); err == nil {
			t.Errorf("parseDeviceSelector(%q) unexpectedly succeeded", input)
		}
	}
}
