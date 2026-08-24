package xrmonitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// validVRFName allow-lists VRF names before they're embedded into any
// Sprintf-built CLI command (discoverConnectedInterfaces here, and later
// collectTick/captureSnapshot's "show route vrf %s summary" / "show bgp vrf
// %s" once a discovered VRF lands in DeviceSession.vrfs). VRF names come
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
// operator know one was seen (see AutoDetectCustomerVRFs, which annotates
// each with its interface count).
func discoverCustomerVRFs(client sessionExecutor, gatewayPrefix string, parsers map[string]ParserModule) (customerVRFs, hubVRFs []string, err error) {
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
func discoverConnectedInterfaces(client sessionExecutor, vrf string, parsers map[string]ParserModule, excludePrefixes []string) ([]string, error) {
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
// to carry a connected route too. BVI is deliberately not in this list —
// unlike Loopback, a BVI is a customer-facing bridge-group interface that
// can carry real traffic worth polling. Overridable via a --devices file's
// top-level exclude_interface_prefixes (see ResolveExcludeInterfacePrefixes)
// for fleets where some other virtual interface type (e.g. tunnel-ip)
// needs excluding, without a code change and rebuild.
var defaultExcludeInterfacePrefixes = []string{"loopback"}

// ResolveExcludeInterfacePrefixes falls back to
// defaultExcludeInterfacePrefixes when a --devices file didn't set
// exclude_interface_prefixes (nil, as opposed to an explicit empty list,
// which disables exclusion entirely).
func ResolveExcludeInterfacePrefixes(configured []string) []string {
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

// defaultHubTopInterfaces is how many of a hub VRF's interfaces get sampled
// when a --devices file doesn't set hub_top_interfaces: enough to catch the
// traffic that matters (a customer's own designated interface doesn't
// always carry it) without polling every one of a hub VRF's potentially
// dozens of unrelated interfaces every tick.
const defaultHubTopInterfaces = 2

// ResolveHubTopInterfaces falls back to defaultHubTopInterfaces when a
// --devices file left hub_top_interfaces unset (configured == nil).
// configured == 0 is a deliberate, valid value — an operator explicitly
// disabling hub-VRF interface sampling entirely — so it must be
// distinguishable from "unset", which a plain int can't do on its own
// (YAML's zero value for an omitted int field is indistinguishable from an
// explicit 0). LoadDeviceSpecs only sets a non-nil pointer when the
// --devices file actually set hub_top_interfaces (mirroring the
// nil-vs-explicit-empty convention ResolveExcludeInterfacePrefixes already
// uses for exclude_interface_prefixes). Negative values are rejected during
// --devices file validation before this is ever called, so callers should
// only ever pass nil or a non-negative pointer.
func ResolveHubTopInterfaces(configured *int) int {
	if configured == nil {
		return defaultHubTopInterfaces
	}
	return *configured
}

// interfaceUtilization pairs an interface name with its scored current
// rate, as ranked by rankInterfacesByUtilization.
type interfaceUtilization struct {
	name  string
	score float64
}

// rankInterfacesByUtilization queries each interface's current traffic rate
// (the same command/parser used for per-tick polling, spec.InterfaceCommand
// / spec.InterfaceParser — see collectTick in poll.go) and returns the
// names sorted by combined input+output bps, busiest first. Used during hub
// VRF discovery to pick which of a hub VRF's (potentially dozens of)
// interfaces are worth polling on every subsequent tick, rather than all of
// them.
//
// A query or parse failure for one interface scores it 0 (lowest priority)
// rather than aborting discovery for the rest — an interface that's down or
// briefly unreadable during onboarding shouldn't block ranking the ones
// that did respond. Ties (including all-zero scores) are broken
// alphabetically so the selection is deterministic across runs.
func rankInterfacesByUtilization(client sessionExecutor, interfaces []string, parsers map[string]ParserModule, spec CollectionSpec) []string {
	scored := make([]interfaceUtilization, 0, len(interfaces))
	for _, name := range interfaces {
		scored = append(scored, interfaceUtilization{name: name, score: queryInterfaceUtilization(client, name, parsers, spec)})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].name < scored[j].name
	})
	names := make([]string, len(scored))
	for i, s := range scored {
		names[i] = s.name
	}
	return names
}

// queryInterfaceUtilization runs spec.InterfaceCommand for one interface
// and returns its input+output rate in bits/sec, or 0 if the command fails,
// the output doesn't parse, or the rate fields are missing/malformed.
// Decoding is shared with the status line renderer via firstInterfaceStat
// (status.go) so both interpret the parser's output shape identically.
func queryInterfaceUtilization(client sessionExecutor, name string, parsers map[string]ParserModule, spec CollectionSpec) float64 {
	output, err := client.Execute(fmt.Sprintf(spec.InterfaceCommand, name))
	if err != nil {
		return 0
	}
	parsed, err := parseOutputWithModule(output, spec.InterfaceParser, parsers)
	if err != nil {
		return 0
	}
	stat, ok := firstInterfaceStat(json.RawMessage(parsed))
	if !ok {
		return 0
	}
	inRate, _ := strconv.ParseFloat(stat["INPUT_RATE_BPS"], 64)
	outRate, _ := strconv.ParseFloat(stat["OUTPUT_RATE_BPS"], 64)
	return inRate + outRate
}

// AutoDetectCustomerVRFs runs the full discovery flow for one device: finds
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
// Every hub VRF discoverCustomerVRFs also saw (matched the gateway
// heuristic but is non-numeric, so excluded from vrfs/interfaces) has its
// own interfaces ranked by current utilization (rankInterfacesByUtilization)
// independently, and the top hubTopInterfaces (see ResolveHubTopInterfaces)
// *of that hub VRF* — not device-wide across every hub VRF matched — are
// added to the returned hubInterfaces. This is deliberate: each hub VRF is
// its own shared entity, and capping device-wide would let one especially
// busy hub VRF crowd out any visibility into a second, unrelated hub VRF on
// the same device. A customer's own designated interface doesn't always
// carry the traffic that matters during a change window, and the busiest
// hub-VRF interfaces are a proxy for where it actually is. The full hub VRF
// is deliberately never added to vrfs/interfaces: it's shared by dozens of
// unrelated customers, so only a small, ranked sample of its interfaces is
// worth polling on every tick, and its route table is never queried at all.
// hubVRFNotes reports what was found/selected per hub VRF as "<name> (<N>
// interfaces, sampling top <M>: ...)" so the operator can see what's being
// watched rather than it vanishing silently. Ranking/counting a hub VRF's
// interfaces is never fatal: if that lookup fails, the note just says
// "interface count unavailable" instead of dropping the VRF from the list.
func AutoDetectCustomerVRFs(client sessionExecutor, gatewayPrefix string, parsers map[string]ParserModule, excludePrefixes []string, spec CollectionSpec, hubTopInterfaces int) (vrfs []string, interfaces []string, hubInterfaces []string, hubVRFNotes []string, err error) {
	vrfs, hubVRFs, err := discoverCustomerVRFs(client, gatewayPrefix, parsers)
	if err != nil && len(vrfs) == 0 {
		return nil, nil, nil, nil, err
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

	topN := hubTopInterfaces
	var allHubInterfaces []string
	for _, vrf := range hubVRFs {
		vrfInterfaces, ifaceErr := discoverConnectedInterfaces(client, vrf, parsers, excludePrefixes)
		if ifaceErr != nil {
			hubVRFNotes = append(hubVRFNotes, fmt.Sprintf("%s (interface count unavailable)", vrf))
			continue
		}
		ranked := rankInterfacesByUtilization(client, vrfInterfaces, parsers, spec)
		top := ranked
		if len(top) > topN {
			top = top[:topN]
		}
		allHubInterfaces = append(allHubInterfaces, top...)
		hubVRFNotes = append(hubVRFNotes, fmt.Sprintf("%s (%d interfaces, sampling top %d: %v)", vrf, len(vrfInterfaces), len(top), top))
	}

	return vrfs, dedupeSorted(allInterfaces), dedupeSorted(allHubInterfaces), hubVRFNotes, errors.Join(errs...)
}

// ApplyAutoDetectResult runs auto-detection for one device and merges the
// discovered VRFs into vrfs (deduplicated against whatever was already
// manually specified), printing the same confirmation/warning line
// regardless of which onboarding path — interactive (main.go's
// OnboardDevices) or devices.yaml-driven (devices.go's
// OnboardDevicesFromSpecs) — is calling it, so the two don't drift.
// Discovered interfaces are returned separately (not merged with any
// manually-specified ones) so the caller can keep them labeled as
// customer-facing or hub-facing — see DeviceSession's
// coreInterfaces/customerInterfaces/hubInterfaces split in main.go.
func ApplyAutoDetectResult(client sessionExecutor, gatewayPrefix string, parsers map[string]ParserModule, excludePrefixes []string, spec CollectionSpec, hubTopInterfaces int, host string, vrfs []string, out io.Writer) (mergedVRFs, customerInterfaces, hubInterfaces []string) {
	discoveredVRFs, discoveredInterfaces, discoveredHubInterfaces, hubVRFNotes, err := AutoDetectCustomerVRFs(client, gatewayPrefix, parsers, excludePrefixes, spec, hubTopInterfaces)
	if err != nil {
		fmt.Fprintf(out, "auto-detection issue on %s: %v\n", host, err)
	}
	vrfs = dedupeSorted(append(vrfs, discoveredVRFs...))
	customerInterfaces = dedupeSorted(discoveredInterfaces)
	hubInterfaces = dedupeSorted(discoveredHubInterfaces)
	fmt.Fprintf(out, "auto-detected on %s:\n", host)
	fmt.Fprintf(out, "  VRFs (%d): %s\n", len(discoveredVRFs), formatListSummary(discoveredVRFs, 4))
	fmt.Fprintf(out, "  customer interfaces (%d): %s\n", len(discoveredInterfaces), formatListSummary(discoveredInterfaces, 3))
	if len(hubVRFNotes) > 0 {
		fmt.Fprintf(out, "  hub VRFs: %s\n", formatListSummary(hubVRFNotes, 3))
	}
	return vrfs, customerInterfaces, hubInterfaces
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
