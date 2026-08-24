package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/junosmonitor"
	"github.com/gwoodwa1/network-collector/internal/safeyaml"
	"github.com/gwoodwa1/network-collector/internal/xrmonitor"
)

// mixedFleetDocument is the combined --devices YAML schema: one shared
// top-level interval plus a cisco_iosxr and/or juniper_junos section, each
// using its platform's own DevicesDocument schema exactly as
// xr-routing-monitor/junos-routing-monitor's own --devices files already
// do — nested under its own key rather than flattened into one struct,
// deliberately: both platforms' DevicesDocument already use a top-level
// commands: key with different, incompatible sub-shapes, so flattening
// would collide. At least one of the two sections must be present.
type mixedFleetDocument struct {
	// Interval sets the default polling interval for every device in this
	// run, across both platforms — the -interval CLI flag takes precedence
	// when passed explicitly, same as xr-routing-monitor/
	// junos-routing-monitor's own top-level interval field. Each nested
	// section's own DevicesDocument.Interval field is intentionally unused
	// here (there is no per-platform interval override in this schema) —
	// only this top-level field is read.
	Interval     string                        `yaml:"interval"`
	CiscoIOSXR   *xrmonitor.DevicesDocument    `yaml:"cisco_iosxr"`
	JuniperJunos *junosmonitor.DevicesDocument `yaml:"juniper_junos"`
}

// loadMixedFleetDocument reads and validates a combined --devices YAML
// file. Each present section is validated with its own platform's
// ValidateDevicesDocument (the exact same hostname/command-template checks
// xr-routing-monitor/junos-routing-monitor apply to a standalone --devices
// file), so a mixed-fleet file is held to the same standard as either
// platform's own file — just split across two sections instead of one.
func loadMixedFleetDocument(path string) (*mixedFleetDocument, time.Duration, error) {
	b, err := safeyaml.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var doc mixedFleetDocument
	if err := safeyaml.Unmarshal(b, &doc); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.CiscoIOSXR == nil && doc.JuniperJunos == nil {
		return nil, 0, fmt.Errorf("%s: must set at least one of cisco_iosxr or juniper_junos", path)
	}
	if doc.CiscoIOSXR != nil {
		if _, err := xrmonitor.ValidateDevicesDocument(path, *doc.CiscoIOSXR); err != nil {
			return nil, 0, err
		}
	}
	if doc.JuniperJunos != nil {
		if _, err := junosmonitor.ValidateDevicesDocument(path, *doc.JuniperJunos); err != nil {
			return nil, 0, err
		}
	}
	var interval time.Duration
	if raw := strings.TrimSpace(doc.Interval); raw != "" {
		interval, err = time.ParseDuration(raw)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: invalid interval %q: %w", path, raw, err)
		}
		if interval <= 0 {
			return nil, 0, fmt.Errorf("%s: interval %q must be positive", path, raw)
		}
	}
	return &doc, interval, nil
}
