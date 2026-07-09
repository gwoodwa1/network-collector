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
// VRF names (numbered, named, Cisco's system VRFs like **nVSatellite, or
// this fleet's "V<circuit-id>:<SERVICE>" style like "V10:CDN") would ever
// fail. ":" is allow-listed specifically for that naming style; it has no
// special meaning to the exec-channel command string it's embedded into.
var validVRFName = regexp.MustCompile(`^[A-Za-z0-9_*:-]+$`)

// customerVRFName matches this fleet's naming conventions for a
// single-customer VRF: a purely numeric circuit/account ID (e.g.
// "1115679"), or a "V<circuit-id>:<SERVICE>" tag (e.g. "V10:CDN",
// "V100:SDN") — both styles are anchored on a numeric circuit/account ID.
// Descriptively-named VRFs with no such numeric anchor (e.g.
// "RI-INTERNET-ENTERPRISE") are shared internet-breakout/hub VRFs that
// independently peer with the same route-reflector range used to identify
// internet-facing VRFs — they legitimately carry dozens of unrelated
// customers' interfaces and BGP sessions, and must never be treated as
// "the" customer's own VRF just because they also match the gateway-prefix
// heuristic. See discoverCustomerVRFs, which filters matches down to this
// convention; a VRF style not covered here still surfaces to the operator
// as a hub-VRF note (with its interface count) rather than vanishing
// silently, so a gap in this pattern is visible, not silent data loss.
var customerVRFName = regexp.MustCompile(`^(?:[0-9]+|V[0-9]+:\S+)$`)

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
// route (0.0.0.0/0) is advertised by a router starting with gatewayPrefix
// — this fleet's signature for "this VRF has internet access imported into
// it", as opposed to the many other VRFs (system VRFs like **eint/**iid,
// and numbered VRFs with no default route at all) that share the same box.
// The matched advertising-router address is deliberately not carried any
// further than this: it identifies which VRF is internet-facing and
// nothing more — see discoverConnectedInterfaces, which once a VRF is
// identified here just polls every directly-connected interface *in that
// VRF*, without trying to match it back against the advertising router.
// gatewayPrefix must be non-empty: strings.HasPrefix(x, "") is always true
// in Go, so an empty prefix would otherwise silently match every VRF with
// any default route at all instead of erroring.
//
// The gateway-prefix signal alone isn't enough to identify a single
// customer's own VRF: a shared internet-breakout/hub VRF (e.g.
// "RI-INTERNET-ENTERPRISE") independently peers with the same
// route-reflector range and matches too, but legitimately carries dozens of
// unrelated customers' interfaces (confirmed against a real device: ~33
// distinct connected subnets across many unrelated physical ports, versus a
// genuine customer VRF's handful). So matches are further filtered to
// customerVRFName (purely numeric) — this fleet's convention for a
// single-customer circuit VRF. Non-numeric matches (hub VRFs) are excluded
// from the returned customer list but reported back separately via
// hubVRFs — not flagged as an error, since they're not malformed, just out
// of scope for "the customer's own VRF" — so a caller can still let the
// operator know one was seen (see autoDetectCustomerVRFs, which annotates
// each with its interface count).
func discoverCustomerVRFs(client sessionExecutor, gatewayPrefix string, parsers map[string]parserModule) (customerVRFs, hubVRFs []string, err error) {
	if strings.TrimSpace(gatewayPrefix) == "" {
		return nil, nil, fmt.Errorf("gateway prefix must not be empty")
	}
	const cmd = `show route vrf all | inc "Gateway of last resort|VRF:"`
	output, err := client.Execute(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cmd, err)
	}
	parsed, err := parseOutputWithModule(output, "xr_route_vrf_all_gateways", parsers)
	if err != nil {
		return nil, nil, fmt.Errorf("parse vrf gateways: %w", err)
	}
	var decoded struct {
		VRFs []map[string]string `json:"vrfs"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		return nil, nil, fmt.Errorf("decode vrf gateways: %w", err)
	}
	var matched, hubs []string
	var errs []error
	for _, record := range decoded.VRFs {
		vrf := record["VRF"]
		gateway := record["GATEWAY"]
		if strings.HasPrefix(gateway, gatewayPrefix) {
			if !validVRFName.MatchString(vrf) {
				errs = append(errs, fmt.Errorf("matched gateway %s for invalid VRF name %q; skipping unsafe command target", gateway, vrf))
				continue
			}
			if !customerVRFName.MatchString(vrf) {
				hubs = append(hubs, vrf)
				continue
			}
			matched = append(matched, vrf)
		}
	}
	return dedupeSorted(matched), dedupeSorted(hubs), errors.Join(errs...)
}

// discoverConnectedInterfaces runs "show vrf <vrf> ipv4 detail" and returns
// the interfaces actually assigned to that VRF (from its own "Interfaces:"
// config section), deduped and sorted. vrf is validated against
// validVRFName here too (not just in discoverCustomerVRFs), since this is
// the function that actually embeds it into a command string — callers
// should never reach this with anything else, but a single call site
// forgetting to pre-validate shouldn't be able to build an unsafe command.
//
// This deliberately does not use "show route vrf <vrf> | inc is directly
// connected": a VRF can import a route-target that's also exported by
// other, unrelated VRFs (e.g. a shared "internet access" RT), and an
// imported connected route still displays as "C ... is directly connected"
// in the importing VRF's table — indistinguishable from the VRF's own
// genuine interfaces (confirmed against a real device where a shared VRF's
// routing table showed 45 connected interfaces belonging to many different
// customers, while "show vrf <vrf> ipv4 detail" correctly listed only the
// handful actually assigned to it). An interface assigned here but
// currently down/inactive may still be returned — that's an accepted
// tradeoff for staying on one simple command; it just shows as
// unavailable/0bps on the status line rather than being excluded.
func discoverConnectedInterfaces(client sessionExecutor, vrf string, parsers map[string]parserModule, excludePrefixes []string) ([]string, error) {
	if !validVRFName.MatchString(vrf) {
		return nil, fmt.Errorf("refusing to query invalid VRF name %q", vrf)
	}
	cmd := fmt.Sprintf(`show vrf %s ipv4 detail`, vrf)
	output, err := client.Execute(cmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd, err)
	}
	parsed, err := parseOutputWithModule(output, "xr_vrf_detail_interfaces", parsers)
	if err != nil {
		return nil, fmt.Errorf("parse vrf interfaces: %w", err)
	}
	var decoded struct {
		Interfaces []map[string]string `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		return nil, fmt.Errorf("decode vrf interfaces: %w", err)
	}
	var names []string
	for _, record := range decoded.Interfaces {
		name := strings.TrimSpace(record["INTERFACE"])
		if isAutoDiscoveredPollInterface(name, excludePrefixes) {
			names = append(names, name)
		}
	}
	return dedupeSorted(names), nil
}

// defaultExcludeInterfacePrefixes lists the (lowercase) interface-name
// prefixes excluded from auto-discovered polling targets by default: these
// are never core-facing links, just per-VRF virtual interfaces that happen
// to carry a connected route too. Overridable via a --devices file's
// top-level exclude_interface_prefixes (see resolveExcludeInterfacePrefixes)
// for fleets where some other virtual interface type (e.g. tunnel-ip) also
// needs excluding, without a code change and rebuild.
var defaultExcludeInterfacePrefixes = []string{"loopback", "bvi"}

// resolveExcludeInterfacePrefixes falls back to
// defaultExcludeInterfacePrefixes when a --devices file didn't set
// exclude_interface_prefixes (nil, as opposed to an explicit empty list,
// which disables exclusion entirely).
func resolveExcludeInterfacePrefixes(configured []string) []string {
	if configured == nil {
		return defaultExcludeInterfacePrefixes
	}
	return configured
}

func isAutoDiscoveredPollInterface(name string, excludePrefixes []string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	for _, prefix := range excludePrefixes {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix != "" && strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

// autoDetectCustomerVRFs runs the full discovery flow for one device: finds
// the customer VRF(s) whose default route is sourced from gatewayPrefix,
// then for each one, the physical/sub-interfaces carrying its connected
// routes (deduped across all matched VRFs, since two customer VRFs on the
// same box commonly share an uplink). If VRF discovery itself fails, both
// vrfs and interfaces are empty and the error is fatal to auto-detection for
// this device. If VRF discovery succeeds but interface discovery fails for
// one or more of the matched VRFs, the successfully matched VRFs and
// whatever interfaces were found are still returned alongside the combined
// error — callers can choose to proceed with that partial result rather
// than discard a working VRF match over one failed follow-up command.
//
// Any hub VRF discoverCustomerVRFs also saw (matched the gateway heuristic
// but is non-numeric, so excluded from vrfs/interfaces) is reported back via
// hubVRFNotes as "<name> (<N> interfaces)" — a purely informational,
// best-effort count so the operator can see it was recognized and
// deliberately skipped rather than silently vanishing. Counting a hub VRF's
// interfaces is never fatal: if that lookup fails, the note just says
// "interface count unavailable" instead of dropping the VRF from the list.
func autoDetectCustomerVRFs(client sessionExecutor, gatewayPrefix string, parsers map[string]parserModule, excludePrefixes []string) (vrfs []string, interfaces []string, hubVRFNotes []string, err error) {
	vrfs, hubVRFs, err := discoverCustomerVRFs(client, gatewayPrefix, parsers)
	if err != nil && len(vrfs) == 0 {
		return nil, nil, nil, err
	}

	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	var allInterfaces []string
	for _, vrf := range vrfs {
		vrfInterfaces, ifaceErr := discoverConnectedInterfaces(client, vrf, parsers, excludePrefixes)
		if ifaceErr != nil {
			errs = append(errs, fmt.Errorf("vrf %s: %w", vrf, ifaceErr))
			continue
		}
		allInterfaces = append(allInterfaces, vrfInterfaces...)
	}

	for _, vrf := range hubVRFs {
		hubInterfaces, ifaceErr := discoverConnectedInterfaces(client, vrf, parsers, excludePrefixes)
		if ifaceErr != nil {
			hubVRFNotes = append(hubVRFNotes, fmt.Sprintf("%s (interface count unavailable)", vrf))
			continue
		}
		hubVRFNotes = append(hubVRFNotes, fmt.Sprintf("%s (%d interfaces)", vrf, len(hubInterfaces)))
	}

	return vrfs, dedupeSorted(allInterfaces), hubVRFNotes, errors.Join(errs...)
}

// applyAutoDetectResult runs auto-detection for one device and merges the
// discovered VRFs into vrfs (deduplicated against whatever was already
// manually specified), printing the same confirmation/warning line
// regardless of which onboarding path — interactive (main.go's
// onboardDevices) or devices.yaml-driven (devices.go's
// onboardDevicesFromSpecs) — is calling it, so the two don't drift.
// Discovered interfaces are returned separately (not merged with any
// manually-specified ones) so the caller can keep them labeled as
// customer-facing — see deviceSession's coreInterfaces/customerInterfaces
// split in main.go.
func applyAutoDetectResult(client sessionExecutor, gatewayPrefix string, parsers map[string]parserModule, excludePrefixes []string, host string, vrfs []string, out io.Writer) (mergedVRFs, customerInterfaces []string) {
	discoveredVRFs, discoveredInterfaces, hubVRFNotes, err := autoDetectCustomerVRFs(client, gatewayPrefix, parsers, excludePrefixes)
	if err != nil {
		fmt.Fprintf(out, "auto-detection issue on %s: %v\n", host, err)
	}
	vrfs = dedupeSorted(append(vrfs, discoveredVRFs...))
	customerInterfaces = dedupeSorted(discoveredInterfaces)
	fmt.Fprintf(out, "auto-detected on %s:\n", host)
	fmt.Fprintf(out, "  VRFs (%d): %s\n", len(discoveredVRFs), formatListSummary(discoveredVRFs, 4))
	fmt.Fprintf(out, "  customer interfaces (%d): %s\n", len(discoveredInterfaces), formatListSummary(discoveredInterfaces, 3))
	if len(hubVRFNotes) > 0 {
		fmt.Fprintf(out, "  skipped hub VRFs: %s\n", formatListSummary(hubVRFNotes, 3))
	}
	return vrfs, customerInterfaces
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
