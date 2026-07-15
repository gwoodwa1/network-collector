package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// deviceSpec is one entry from an optional --devices YAML file. It only
// covers the static per-device fields gathered during interactive
// onboarding (hostname/table(s)/interfaces/neighbors) — credentials are
// deliberately never part of this file, since a one-time passcode must
// always be typed interactively per device.
type deviceSpec struct {
	Hostname string `yaml:"hostname"`
	// Table is a single-table legacy alias for Tables, kept for files
	// written with only one routing table in mind; both may be set, and
	// their values are merged.
	Table      string   `yaml:"table"`
	Tables     []string `yaml:"tables"`
	Interfaces []string `yaml:"interfaces"`
	Neighbors  []string `yaml:"neighbors"`
}

// tables returns spec's Table and Tables fields merged into one
// deduplicated, sorted list — blank entries (a stray "" in a tables: list)
// are dropped rather than turning into a malformed "show route summary
// table " command.
func (spec deviceSpec) tables() []string {
	all := append([]string{spec.Table}, spec.Tables...)
	return dedupeSorted(all)
}

// commandOverrides lets a --devices file replace the default show-commands
// and parser modules this tool polls (see defaultSpec in poll.go), so an
// operator whose fleet needs a different command can edit a config file
// instead of patching Go source and rebuilding the static binary
// mid-engagement. Every field is optional; only non-empty ones override
// defaultSpec (see resolveCollectionSpec).
type commandOverrides struct {
	BGPCommand          string `yaml:"bgp_command"`
	BGPParser           string `yaml:"bgp_parser"`
	RouteCommand        string `yaml:"route_command"`
	RouteParser         string `yaml:"route_parser"`
	DefaultRouteCommand string `yaml:"default_route_command"`
	DefaultRouteParser  string `yaml:"default_route_parser"`
	InterfaceCommand    string `yaml:"interface_command"`
	InterfaceParser     string `yaml:"interface_parser"`
}

type devicesDocument struct {
	// Interval sets the default polling interval for this run, e.g. "30s".
	// The -interval CLI flag takes precedence when passed explicitly; this
	// exists so the interval can be checked into the same file as the
	// device list instead of retyped on the command line every time.
	Interval string           `yaml:"interval"`
	Commands commandOverrides `yaml:"commands"`
	Devices  []deviceSpec     `yaml:"devices"`
}

func countStringPlaceholders(format string) (count int, ok bool) {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		if i+1 >= len(format) {
			return 0, false
		}
		switch format[i+1] {
		case '%':
			i++
		case 's':
			count++
			i++
		default:
			return 0, false
		}
	}
	return count, true
}

func validateCommandTemplate(path, field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if count, ok := countStringPlaceholders(value); !ok || count != 1 {
		return fmt.Errorf("%s: commands.%s must contain exactly one %%s placeholder", path, field)
	}
	return nil
}

// loadDeviceSpecs reads an optional --devices YAML file, e.g.:
//
//	interval: 30s
//
//	devices:
//	  - hostname: pe-router-1
//	    tables: [CUSTOMER-A.inet.0]
//	    interfaces: [ae0, ae1]
//	    neighbors: [198.51.100.101]
//	  - hostname: pe-router-2
//	    tables: [inet.0]
//	    interfaces: [ae10]
//
// The returned duration is zero when the file has no top-level interval
// set, signaling the caller should fall back to its own default.
func loadDeviceSpecs(path string) (specs []deviceSpec, interval time.Duration, commands commandOverrides, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, commandOverrides{}, err
	}
	var doc devicesDocument
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, 0, commandOverrides{}, fmt.Errorf("parse %s: %w", path, err)
	}
	// Collected across every device rather than returning on the first hit,
	// so a file with more than one problem reports both in one pass instead
	// of masking the second until the first is fixed and the file is
	// reloaded.
	var errs []error
	for i, spec := range doc.Devices {
		if strings.TrimSpace(spec.Hostname) == "" {
			errs = append(errs, fmt.Errorf("%s: device at index %d is missing hostname", path, i))
		}
	}
	if err := validateCommandTemplate(path, "route_command", doc.Commands.RouteCommand); err != nil {
		errs = append(errs, err)
	}
	if err := validateCommandTemplate(path, "default_route_command", doc.Commands.DefaultRouteCommand); err != nil {
		errs = append(errs, err)
	}
	if err := validateCommandTemplate(path, "interface_command", doc.Commands.InterfaceCommand); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, 0, commandOverrides{}, err
	}
	if raw := strings.TrimSpace(doc.Interval); raw != "" {
		interval, err = time.ParseDuration(raw)
		if err != nil {
			return nil, 0, commandOverrides{}, fmt.Errorf("%s: invalid interval %q: %w", path, raw, err)
		}
		if interval <= 0 {
			return nil, 0, commandOverrides{}, fmt.Errorf("%s: interval %q must be positive", path, raw)
		}
	}
	return doc.Devices, interval, doc.Commands, nil
}

// onboardDevicesFromSpecs connects to each device from a --devices file in
// order, prompting for credentials only (all other fields come from the
// spec). A connection failure is reported (no retry, per connectDevice) and
// does not stop the remaining devices in the file from being tried. A
// hostname already claimed in registry (e.g. duplicated within the file, or
// present more than once for any other reason) is skipped without
// attempting to connect again.
func onboardDevicesFromSpecs(reader *bufio.Reader, specs []deviceSpec, deviceType string, cache *credentialCache, registry *hostnameRegistry, connect connectFunc) []*deviceSession {
	var sessions []*deviceSession
	for _, spec := range specs {
		if exists, existing := registry.has(spec.Hostname); exists {
			fmt.Fprintf(os.Stderr, "already connected to %s (as %q), skipping duplicate\n\n", spec.Hostname, existing)
			continue
		}
		fmt.Fprintf(os.Stderr, "Connecting to %s (tables=%v interfaces=%v neighbors=%v)\n", spec.Hostname, spec.tables(), spec.Interfaces, spec.Neighbors)
		client, err := connect(reader, spec.Hostname, deviceType, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", spec.Hostname, err)
			continue
		}
		registry.claim(spec.Hostname)

		fmt.Fprintf(os.Stderr, "connected to %s\n\n", spec.Hostname)
		sessions = append(sessions, &deviceSession{
			hostname:   spec.Hostname,
			tables:     spec.tables(),
			interfaces: dedupeSorted(spec.Interfaces),
			neighbors:  dedupeSorted(spec.Neighbors),
			client:     client,
		})
	}
	return sessions
}
