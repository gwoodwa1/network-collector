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
	CustomerGatewayPrefix string       `yaml:"customer_gateway_prefix"`
	Devices               []deviceSpec `yaml:"devices"`
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
// set, signaling the caller should fall back to its own default.
func loadDeviceSpecs(path string) ([]deviceSpec, time.Duration, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, "", err
	}
	var doc devicesDocument
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, 0, "", fmt.Errorf("parse %s: %w", path, err)
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
	if err := errors.Join(errs...); err != nil {
		return nil, 0, "", err
	}
	var interval time.Duration
	if raw := strings.TrimSpace(doc.Interval); raw != "" {
		interval, err = time.ParseDuration(raw)
		if err != nil {
			return nil, 0, "", fmt.Errorf("%s: invalid interval %q: %w", path, raw, err)
		}
		if interval <= 0 {
			return nil, 0, "", fmt.Errorf("%s: interval %q must be positive", path, raw)
		}
	}
	return doc.Devices, interval, doc.CustomerGatewayPrefix, nil
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
func onboardDevicesFromSpecs(reader *bufio.Reader, specs []deviceSpec, deviceType string, cache *credentialCache, registry *hostnameRegistry, connect connectFunc, parsers map[string]parserModule, gatewayPrefix string) []*deviceSession {
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
		interfaces := dedupeSorted(spec.Interfaces)
		if spec.AutoDetectVRF {
			vrfs, interfaces = applyAutoDetectResult(client, gatewayPrefix, parsers, spec.Hostname, vrfs, interfaces, os.Stderr)
		}
		fmt.Fprintf(os.Stderr, "connected to %s\n\n", spec.Hostname)
		sessions = append(sessions, &deviceSession{
			hostname:   spec.Hostname,
			vrfs:       vrfs,
			interfaces: interfaces,
			neighbors:  spec.Neighbors,
			client:     client,
		})
	}
	return sessions
}
