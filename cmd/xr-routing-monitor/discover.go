package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// validVRFName allow-lists VRF names before they're embedded into any
// Sprintf-built CLI command (discoverConnectedInterfaces here, and later
// collectTick/captureSnapshot's "show route vrf %s summary" / "show bgp vrf
// %s" once a discovered VRF lands in deviceSession.vrfs). VRF names come
// from parsing device output, not a fixed enum, so this is defense in
// depth against a spoofed/malformed response — not something real IOS-XR
// VRF names (numbered, named, or Cisco's system VRFs like **nVSatellite)
// would ever fail.
var validVRFName = regexp.MustCompile(`^[A-Za-z0-9_*-]+$`)

// dedupeSorted trims, drops empty entries from, deduplicates, and sorts
// values. Used everywhere a VRF or interface list gets merged from more
// than one source (manually specified, legacy singular field, and/or
// auto-detected), so the same VRF/interface never ends up polled twice.
func dedupeSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// discoverCustomerVRFs runs "show route vrf all" filtered to VRF-name and
// default-route-gateway lines, and returns the VRF names whose default
// route (0.0.0.0/0) is sourced from a gateway starting with gatewayPrefix
// — this fleet's signature for "this VRF is customer-facing", as opposed
// to the many other VRFs (system VRFs like **eint/**iid, and numbered VRFs
// with no default route at all) that share the same box. gatewayPrefix
// must be non-empty: strings.HasPrefix(x, "") is always true in Go, so an
// empty prefix would otherwise silently match every VRF with any default
// route at all instead of erroring.
func discoverCustomerVRFs(client sessionExecutor, gatewayPrefix string, parsers map[string]parserModule) ([]string, error) {
	if strings.TrimSpace(gatewayPrefix) == "" {
		return nil, fmt.Errorf("gateway prefix must not be empty")
	}
	const cmd = `show route vrf all | inc "Gateway of last resort|VRF:"`
	output, err := client.Execute(cmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd, err)
	}
	parsed, err := parseOutputWithModule(output, "xr_route_vrf_all_gateways", parsers)
	if err != nil {
		return nil, fmt.Errorf("parse vrf gateways: %w", err)
	}
	var decoded struct {
		VRFs []map[string]string `json:"vrfs"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		return nil, fmt.Errorf("decode vrf gateways: %w", err)
	}
	var matched []string
	var errs []error
	for _, record := range decoded.VRFs {
		vrf := record["VRF"]
		if strings.HasPrefix(record["GATEWAY"], gatewayPrefix) {
			if !validVRFName.MatchString(vrf) {
				errs = append(errs, fmt.Errorf("matched gateway %s for invalid VRF name %q; skipping unsafe command target", record["GATEWAY"], vrf))
				continue
			}
			matched = append(matched, vrf)
		}
	}
	return dedupeSorted(matched), errors.Join(errs...)
}

// discoverConnectedInterfaces runs "show route vrf <vrf>" filtered to
// directly-connected routes, and returns the distinct interface names
// carrying them, deduped (each connected subnet produces both a C and an L
// route naming the same interface) and sorted. vrf is validated against
// validVRFName here too (not just in discoverCustomerVRFs), since this is
// the function that actually embeds it into a command string — callers
// should never reach this with anything else, but a single call site
// forgetting to pre-validate shouldn't be able to build an unsafe command.
func discoverConnectedInterfaces(client sessionExecutor, vrf string, parsers map[string]parserModule) ([]string, error) {
	if !validVRFName.MatchString(vrf) {
		return nil, fmt.Errorf("refusing to query invalid VRF name %q", vrf)
	}
	cmd := fmt.Sprintf(`show route vrf %s | inc "is directly connected"`, vrf)
	output, err := client.Execute(cmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd, err)
	}
	parsed, err := parseOutputWithModule(output, "xr_route_vrf_connected_interfaces", parsers)
	if err != nil {
		return nil, fmt.Errorf("parse connected interfaces: %w", err)
	}
	var decoded struct {
		Interfaces []map[string]string `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		return nil, fmt.Errorf("decode connected interfaces: %w", err)
	}
	var names []string
	for _, record := range decoded.Interfaces {
		name := strings.TrimSpace(record["INTERFACE"])
		if isAutoDiscoveredPollInterface(name) {
			names = append(names, name)
		}
	}
	return dedupeSorted(names), nil
}

func isAutoDiscoveredPollInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	return !strings.HasPrefix(lower, "loopback") && !strings.HasPrefix(lower, "bvi")
}

// autoDetectCustomerVRFs runs the full discovery flow for one device: finds
// the VRF(s) whose default route is sourced from gatewayPrefix, then for
// each one, the physical/sub-interfaces carrying its connected routes
// (deduped across all matched VRFs, since two customer VRFs on the same box
// commonly share an uplink). If VRF discovery itself fails, both return
// values are empty and the error is fatal to auto-detection for this
// device. If VRF discovery succeeds but interface discovery fails for one
// or more of the matched VRFs, the successfully matched VRFs and whatever
// interfaces were found are still returned alongside the combined error —
// callers can choose to proceed with that partial result rather than
// discard a working VRF match over one failed follow-up command.
func autoDetectCustomerVRFs(client sessionExecutor, gatewayPrefix string, parsers map[string]parserModule) (vrfs []string, interfaces []string, err error) {
	vrfs, err = discoverCustomerVRFs(client, gatewayPrefix, parsers)
	if err != nil && len(vrfs) == 0 {
		return nil, nil, err
	}

	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	var allInterfaces []string
	for _, vrf := range vrfs {
		vrfInterfaces, ifaceErr := discoverConnectedInterfaces(client, vrf, parsers)
		if ifaceErr != nil {
			errs = append(errs, fmt.Errorf("vrf %s: %w", vrf, ifaceErr))
			continue
		}
		allInterfaces = append(allInterfaces, vrfInterfaces...)
	}
	return vrfs, dedupeSorted(allInterfaces), errors.Join(errs...)
}

// applyAutoDetectResult runs auto-detection for one device and merges the
// result into vrfs/interfaces (deduplicated against whatever was already
// manually specified), printing the same confirmation/warning line
// regardless of which onboarding path — interactive (main.go's
// onboardDevices) or devices.yaml-driven (devices.go's
// onboardDevicesFromSpecs) — is calling it, so the two don't drift.
func applyAutoDetectResult(client sessionExecutor, gatewayPrefix string, parsers map[string]parserModule, host string, vrfs, interfaces []string, out io.Writer) ([]string, []string) {
	discoveredVRFs, discoveredInterfaces, err := autoDetectCustomerVRFs(client, gatewayPrefix, parsers)
	if err != nil {
		fmt.Fprintf(out, "auto-detection issue on %s: %v\n", host, err)
	}
	vrfs = dedupeSorted(append(vrfs, discoveredVRFs...))
	interfaces = dedupeSorted(append(interfaces, discoveredInterfaces...))
	fmt.Fprintf(out, "auto-detected %d VRF(s) %s with %d interface(s) %s on %s\n", len(discoveredVRFs), formatListSummary(discoveredVRFs, 4), len(discoveredInterfaces), formatListSummary(discoveredInterfaces, 6), host)
	return vrfs, interfaces
}

func formatListSummary(values []string, limit int) string {
	values = dedupeSorted(values)
	if len(values) == 0 {
		return "[]"
	}
	if limit <= 0 || len(values) <= limit {
		return fmt.Sprintf("%v", values)
	}
	shown := append([]string{}, values[:limit]...)
	return fmt.Sprintf("%v +%d more", shown, len(values)-limit)
}
