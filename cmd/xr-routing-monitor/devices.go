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
// onboarding (hostname/VRF(s)/interfaces/neighbors) — credentials are
// deliberately never part of this file, since RSA SecurID passcodes are
// single-use and must always be typed interactively per device.
type deviceSpec struct {
	Hostname string `yaml:"hostname"`
	// VRF is a single-VRF legacy alias for VRFs, kept for files written
	// before multi-VRF support existed; both may be set, and their values
	// are merged.
	VRF  string   `yaml:"vrf"`
	VRFs []string `yaml:"vrfs"`
	// AutoDetectVRF runs the same customer-VRF/interface discovery as the
	// interactive "Auto-detect customer VRF(s)..." onboarding prompt (see
	// autoDetectCustomerVRFs), using the document's top-level
	// customer_gateway_prefix. Discovered VRFs/interfaces are merged with
	// VRF/VRFs/Interfaces rather than replacing them.
	AutoDetectVRF bool     `yaml:"auto_detect_vrf"`
	Interfaces    []string `yaml:"interfaces"`
	Neighbors     []string `yaml:"neighbors"`
}

// vrfs returns spec's VRF and VRFs fields merged into one deduplicated,
// sorted list — blank entries (a stray "" in a vrfs: list) are dropped
// rather than turning into a malformed "show route vrf  summary" command.
func (spec deviceSpec) vrfs() []string {
	all := append([]string{spec.VRF}, spec.VRFs...)
	return dedupeSorted(all)
}

// commandOverrides lets a --devices file replace the default show-commands
// and parser modules this tool polls (see defaultSpec in poll.go), so an
// operator whose fleet needs a different command — a code variant without
// "show bgp vpnv4 unicast summary", or a "... detail" variant — can edit a
// config file instead of patching Go source and rebuilding the static
// binary mid-engagement. Every field is optional; only non-empty ones
// override defaultSpec (see resolveCollectionSpec).
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
	Interval string `yaml:"interval"`
	// CustomerGatewayPrefix is the default-route gateway prefix (e.g.
	// "10.99.99.") that identifies a customer-facing VRF on this fleet,
	// used by any device with auto_detect_vrf: true. Fleet-wide rather than
	// per-device since it describes the network, not an individual router.
	CustomerGatewayPrefix string `yaml:"customer_gateway_prefix"`
	// ExcludeInterfacePrefixes overrides the default set of (lowercase)
	// interface-name prefixes excluded from auto-detected polling targets
	// (default: "loopback" — see defaultExcludeInterfacePrefixes in
	// discover.go). Fleet-wide, like CustomerGatewayPrefix, since it
	// describes what counts as a "core-facing" interface on this network.
	ExcludeInterfacePrefixes []string `yaml:"exclude_interface_prefixes"`
	// HubTopInterfaces caps how many of a hub VRF's interfaces (ranked by
	// current utilization — see rankInterfacesByUtilization in discover.go)
	// get sampled, device-wide, for any device with auto_detect_vrf: true.
	// A *int (rather than int) so an explicit "hub_top_interfaces: 0"
	// (disable hub-VRF sampling entirely) is distinguishable from the field
	// being left out of the file altogether (nil falls back to
	// defaultHubTopInterfaces) — see resolveHubTopInterfaces. Fleet-wide,
	// like CustomerGatewayPrefix, since a hub VRF's interface count varies
	// by device, not by any per-device setting.
	HubTopInterfaces *int             `yaml:"hub_top_interfaces"`
	Commands         commandOverrides `yaml:"commands"`
	Devices          []deviceSpec     `yaml:"devices"`
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
//	customer_gateway_prefix: 10.99.99.
//
//	devices:
//	  - hostname: pe-router-1
//	    vrfs: [CUSTOMER-A-INTERNET]
//	    interfaces: [BE45, BE46]
//	    neighbors: [198.51.100.101]
//	  - hostname: pe-router-2
//	    auto_detect_vrf: true
//	    interfaces: [BE45, BE46]
//
// The returned duration is zero when the file has no top-level interval
// set, signaling the caller should fall back to its own default. Likewise,
// the returned excludeInterfacePrefixes is nil when the file didn't set
// exclude_interface_prefixes, signaling the caller should fall back to
// defaultExcludeInterfacePrefixes.
func loadDeviceSpecs(path string) (specs []deviceSpec, interval time.Duration, gatewayPrefix string, commands commandOverrides, excludeInterfacePrefixes []string, hubTopInterfaces *int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, "", commandOverrides{}, nil, nil, err
	}
	var doc devicesDocument
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, 0, "", commandOverrides{}, nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Collected across every device rather than returning on the first hit,
	// so a file with more than one problem (e.g. device 0 missing a
	// hostname and device 5 missing customer_gateway_prefix) reports both
	// in one pass instead of masking the second until the first is fixed
	// and the file is reloaded.
	var errs []error
	for i, spec := range doc.Devices {
		if strings.TrimSpace(spec.Hostname) == "" {
			errs = append(errs, fmt.Errorf("%s: device at index %d is missing hostname", path, i))
			continue
		}
		if spec.AutoDetectVRF && strings.TrimSpace(doc.CustomerGatewayPrefix) == "" {
			errs = append(errs, fmt.Errorf("%s: device %q has auto_detect_vrf: true but the file has no top-level customer_gateway_prefix", path, spec.Hostname))
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
	if doc.HubTopInterfaces != nil && *doc.HubTopInterfaces < 0 {
		errs = append(errs, fmt.Errorf("%s: hub_top_interfaces must not be negative", path))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, 0, "", commandOverrides{}, nil, nil, err
	}
	if raw := strings.TrimSpace(doc.Interval); raw != "" {
		interval, err = time.ParseDuration(raw)
		if err != nil {
			return nil, 0, "", commandOverrides{}, nil, nil, fmt.Errorf("%s: invalid interval %q: %w", path, raw, err)
		}
		if interval <= 0 {
			return nil, 0, "", commandOverrides{}, nil, nil, fmt.Errorf("%s: interval %q must be positive", path, raw)
		}
	}
	return doc.Devices, interval, doc.CustomerGatewayPrefix, doc.Commands, doc.ExcludeInterfacePrefixes, doc.HubTopInterfaces, nil
}

// onboardDevicesFromSpecs connects to each device from a --devices file in
// order, prompting for credentials only (all other fields come from the
// spec). A connection failure is reported (no retry, per connectDevice) and
// does not stop the remaining devices in the file from being tried. A
// hostname already claimed in registry (e.g. duplicated within the file, or
// present more than once for any other reason) is skipped without
// attempting to connect again. gatewayPrefix is the document's top-level
// customer_gateway_prefix, used for any spec with AutoDetectVRF set —
// loadDeviceSpecs already guarantees it's non-empty in that case.
func onboardDevicesFromSpecs(reader *bufio.Reader, specs []deviceSpec, deviceType string, cache *credentialCache, registry *hostnameRegistry, connect connectFunc, parsers map[string]parserModule, gatewayPrefix string, excludeInterfacePrefixes []string, collectSpec collectionSpec, hubTopInterfaces int) []*deviceSession {
	var sessions []*deviceSession
	for _, spec := range specs {
		if exists, existing := registry.has(spec.Hostname); exists {
			fmt.Fprintf(os.Stderr, "already connected to %s (as %q), skipping duplicate\n\n", spec.Hostname, existing)
			continue
		}
		fmt.Fprintf(os.Stderr, "Connecting to %s (vrfs=%v auto_detect_vrf=%v interfaces=%v neighbors=%v)\n", spec.Hostname, spec.vrfs(), spec.AutoDetectVRF, spec.Interfaces, spec.Neighbors)
		client, err := connect(reader, spec.Hostname, deviceType, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", spec.Hostname, err)
			continue
		}
		registry.claim(spec.Hostname)

		vrfs := spec.vrfs()
		coreInterfaces := dedupeSorted(spec.Interfaces)
		var customerInterfaces, hubInterfaces []string
		if spec.AutoDetectVRF {
			vrfs, customerInterfaces, hubInterfaces = applyAutoDetectResult(client, gatewayPrefix, parsers, excludeInterfacePrefixes, collectSpec, hubTopInterfaces, spec.Hostname, vrfs, os.Stderr)
		}
		fmt.Fprintf(os.Stderr, "connected to %s\n\n", spec.Hostname)
		sessions = append(sessions, &deviceSession{
			hostname:           spec.Hostname,
			vrfs:               vrfs,
			coreInterfaces:     coreInterfaces,
			customerInterfaces: customerInterfaces,
			hubInterfaces:      hubInterfaces,
			neighbors:          spec.Neighbors,
			client:             client,
		})
	}
	return sessions
}
