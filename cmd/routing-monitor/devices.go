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
	// run, across both platforms, when a section doesn't set its own —
	// the -interval CLI flag takes precedence over both when passed
	// explicitly, same as xr-routing-monitor/junos-routing-monitor's own
	// top-level interval field. Each nested section's own
	// DevicesDocument.Interval, if set, overrides this shared value for
	// just that platform (see mixedFleetIntervals).
	Interval     string                        `yaml:"interval"`
	CiscoIOSXR   *xrmonitor.DevicesDocument    `yaml:"cisco_iosxr"`
	JuniperJunos *junosmonitor.DevicesDocument `yaml:"juniper_junos"`
}

// mixedFleetIntervals holds the polling intervals loadMixedFleetDocument
// parsed out of a combined --devices file: the shared top-level interval,
// and each platform section's own override (zero when that section didn't
// set one). CiscoIOSXR/JuniperJunos come straight from
// xrmonitor/junosmonitor.ValidateDevicesDocument, which already parse and
// validate each DevicesDocument's own Interval field — nothing new to
// validate here.
type mixedFleetIntervals struct {
	TopLevel     time.Duration
	CiscoIOSXR   time.Duration
	JuniperJunos time.Duration
}

// loadMixedFleetDocument reads and validates a combined --devices YAML
// file. Each present section is validated with its own platform's
// ValidateDevicesDocument (the exact same hostname/command-template checks
// xr-routing-monitor/junos-routing-monitor apply to a standalone --devices
// file), so a mixed-fleet file is held to the same standard as either
// platform's own file — just split across two sections instead of one.
func loadMixedFleetDocument(path string) (*mixedFleetDocument, mixedFleetIntervals, error) {
	b, err := safeyaml.ReadFile(path)
	if err != nil {
		return nil, mixedFleetIntervals{}, err
	}
	var doc mixedFleetDocument
	if err := safeyaml.Unmarshal(b, &doc); err != nil {
		return nil, mixedFleetIntervals{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.CiscoIOSXR == nil && doc.JuniperJunos == nil {
		return nil, mixedFleetIntervals{}, fmt.Errorf("%s: must set at least one of cisco_iosxr or juniper_junos", path)
	}
	var intervals mixedFleetIntervals
	if doc.CiscoIOSXR != nil {
		xrInterval, err := xrmonitor.ValidateDevicesDocument(path, *doc.CiscoIOSXR)
		if err != nil {
			return nil, mixedFleetIntervals{}, err
		}
		intervals.CiscoIOSXR = xrInterval
	}
	if doc.JuniperJunos != nil {
		junosInterval, err := junosmonitor.ValidateDevicesDocument(path, *doc.JuniperJunos)
		if err != nil {
			return nil, mixedFleetIntervals{}, err
		}
		intervals.JuniperJunos = junosInterval
	}
	if raw := strings.TrimSpace(doc.Interval); raw != "" {
		topLevel, err := time.ParseDuration(raw)
		if err != nil {
			return nil, mixedFleetIntervals{}, fmt.Errorf("%s: invalid interval %q: %w", path, raw, err)
		}
		if topLevel <= 0 {
			return nil, mixedFleetIntervals{}, fmt.Errorf("%s: interval %q must be positive", path, raw)
		}
		intervals.TopLevel = topLevel
	}
	return &doc, intervals, nil
}
