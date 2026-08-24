package xrmonitor

import (
	"fmt"
	"strings"
	"testing"
)

// discoverFakeExecutor returns a scripted response per exact command, or a
// scripted error if the command is listed in errs — lets tests simulate one
// specific command (e.g. one VRF's connected-interfaces lookup) failing
// without affecting any other command.
type discoverFakeExecutor struct {
	responses map[string]string
	errs      map[string]error
}

func (f *discoverFakeExecutor) Execute(cmd string) (string, error) {
	if err, ok := f.errs[cmd]; ok {
		return "", err
	}
	return f.responses[cmd], nil
}

func (f *discoverFakeExecutor) Close() error { return nil }

func TestDedupeSortedTrimsFiltersDedupesAndSorts(t *testing.T) {
	got := dedupeSorted([]string{"CUSTOMER-B", "", "CUSTOMER-A", "  CUSTOMER-A  ", "CUSTOMER-B", "   "})
	want := "CUSTOMER-A,CUSTOMER-B"
	if strings.Join(got, ",") != want {
		t.Fatalf("expected %q, got %v", want, got)
	}
}

func TestDiscoverCustomerVRFsFiltersByGatewayPrefix(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	vrfs, hubVRFs, err := discoverCustomerVRFs(exec, "192.0.2.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CUSTOMER-A-INTERNET also matches the gateway prefix but is filtered
	// out of the customer list: it's non-numeric, this fleet's signal for a
	// shared/hub VRF rather than a single customer's own VRF (see
	// customerVRFName) — it's reported back separately via hubVRFs instead.
	want := []string{"4000001"}
	if strings.Join(vrfs, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, vrfs)
	}
	if strings.Join(hubVRFs, ",") != "CUSTOMER-A-INTERNET" {
		t.Fatalf("expected CUSTOMER-A-INTERNET reported as a hub VRF, got %v", hubVRFs)
	}
}

// TestDiscoverCustomerVRFsExcludesNonNumericHubVRF is the direct regression
// guard for the real production bug this filter addresses: a shared
// internet-breakout VRF (e.g. "RI-INTERNET-ENTERPRISE") independently peers
// with the same route-reflector range as genuine customer VRFs, so it
// matches the gateway-prefix heuristic too — but it's not a single
// customer's circuit and must never be treated as one.
func TestDiscoverCustomerVRFsExcludesNonNumericHubVRF(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: 1115679
Gateway of last resort is 192.0.2.58 to network 0.0.0.0
VRF: RI-INTERNET-ENTERPRISE
Gateway of last resort is 192.0.2.58 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
	}}

	vrfs, hubVRFs, err := discoverCustomerVRFs(exec, "192.0.2.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(vrfs, ",") != "1115679" {
		t.Fatalf("expected only the numeric customer VRF 1115679, got %v (hub VRF leaked in)", vrfs)
	}
	if strings.Join(hubVRFs, ",") != "RI-INTERNET-ENTERPRISE" {
		t.Fatalf("expected RI-INTERNET-ENTERPRISE reported as a hub VRF, got %v", hubVRFs)
	}
}

// TestDiscoverCustomerVRFsAcceptsVColonServiceNamingStyle proves the
// "V<circuit-id>:<SERVICE>" naming style used on some other routers in the
// fleet (e.g. "V10:CDN", "V100:SDN") is recognized as a customer VRF too,
// not just the plain-numeric style — both are anchored on a numeric
// circuit/account ID (see customerVRFName).
func TestDiscoverCustomerVRFsAcceptsVColonServiceNamingStyle(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: V10:CDN
Gateway of last resort is 192.0.2.58 to network 0.0.0.0
VRF: RI-INTERNET-ENTERPRISE
Gateway of last resort is 192.0.2.58 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
	}}

	vrfs, hubVRFs, err := discoverCustomerVRFs(exec, "192.0.2.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(vrfs, ",") != "V10:CDN" {
		t.Fatalf("expected V10:CDN recognized as a customer VRF, got %v", vrfs)
	}
	if strings.Join(hubVRFs, ",") != "RI-INTERNET-ENTERPRISE" {
		t.Fatalf("expected RI-INTERNET-ENTERPRISE still reported as a hub VRF, got %v", hubVRFs)
	}
}

func TestDiscoverCustomerVRFsNarrowerPrefixMatchesOneGateway(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	vrfs, hubVRFs, err := discoverCustomerVRFs(exec, "192.0.2.57", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CUSTOMER-A-INTERNET is the only gateway match for this narrower
	// prefix, but it's non-numeric, so it's reported as a hub VRF rather
	// than a customer match.
	if len(vrfs) != 0 {
		t.Fatalf("expected no customer VRF matches, got %v", vrfs)
	}
	if len(hubVRFs) != 1 || hubVRFs[0] != "CUSTOMER-A-INTERNET" {
		t.Fatalf("expected only CUSTOMER-A-INTERNET reported as a hub VRF, got %v", hubVRFs)
	}
}

func TestDiscoverCustomerVRFsNoMatchingGateway(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	vrfs, hubVRFs, err := discoverCustomerVRFs(exec, "203.0.113.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vrfs) != 0 {
		t.Fatalf("expected no matching VRFs, got %v", vrfs)
	}
	if len(hubVRFs) != 0 {
		t.Fatalf("expected no hub VRF matches either, got %v", hubVRFs)
	}
}

// TestDiscoverCustomerVRFsRejectsEmptyGatewayPrefix guards against
// strings.HasPrefix(x, "") being always true in Go — without this check, a
// blank gateway prefix (e.g. an operator hitting Enter at the interactive
// prompt with nothing typed) would silently match every VRF with any
// default route at all, not just customer-facing ones.
func TestDiscoverCustomerVRFsRejectsEmptyGatewayPrefix(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	if _, _, err := discoverCustomerVRFs(exec, "", parsers); err == nil {
		t.Fatal("expected an error for an empty gateway prefix instead of silently matching every VRF")
	}
	if _, _, err := discoverCustomerVRFs(exec, "   ", parsers); err == nil {
		t.Fatal("expected an error for a whitespace-only gateway prefix")
	}
}

// TestDiscoverCustomerVRFsRejectsMalformedVRFName is defense-in-depth
// against a VRF name from device output flowing unvalidated into a later
// Sprintf-built CLI command (discoverConnectedInterfaces, and every
// subsequent poll tick / snapshot once it lands in DeviceSession.vrfs).
func TestDiscoverCustomerVRFsReportsMalformedMatchingVRFName(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: CUSTOMER-A|whoami
Gateway of last resort is 192.0.2.57 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
	}}

	vrfs, hubVRFs, err := discoverCustomerVRFs(exec, "192.0.2.", parsers)
	if err == nil {
		t.Fatal("expected an error for the malformed matching VRF name")
	}
	if len(vrfs) != 0 {
		t.Fatalf("expected the malformed VRF name to be filtered out, got %v", vrfs)
	}
	if len(hubVRFs) != 0 {
		t.Fatalf("expected the malformed VRF name to not be reported as a hub VRF either, got %v", hubVRFs)
	}
	if !strings.Contains(err.Error(), "CUSTOMER-A|whoami") {
		t.Fatalf("expected error to name the skipped VRF, got: %v", err)
	}
}

func TestAutoDetectCustomerVRFsKeepsValidMatchesWhenAnotherMatchedVRFIsMalformed(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: CUSTOMER-A|whoami
Gateway of last resort is 192.0.2.59 to network 0.0.0.0
VRF: 5000002
Gateway of last resort is 192.0.2.57 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
		`show vrf 5000002 ipv4 detail`:                           "",
	}}

	vrfs, interfaces, _, _, err := AutoDetectCustomerVRFs(exec, "192.0.2.", parsers, defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)
	if err == nil {
		t.Fatal("expected a non-nil warning error for the malformed matching VRF")
	}
	if strings.Join(vrfs, ",") != "5000002" {
		t.Fatalf("expected valid VRF 5000002 to be kept, got %v", vrfs)
	}
	if len(interfaces) != 0 {
		t.Fatalf("expected no discovered interfaces, got %v", interfaces)
	}
}

func TestDiscoverConnectedInterfacesRejectsMalformedVRFName(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{}

	if _, err := discoverConnectedInterfaces(exec, "CUSTOMER-A|whoami", parsers, defaultExcludeInterfacePrefixes); err == nil {
		t.Fatal("expected an error for a VRF name containing shell/CLI metacharacters")
	}
}

func TestDiscoverCustomerVRFsPropagatesExecuteFailure(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{errs: map[string]error{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: fmt.Errorf("channel closed"),
	}}

	if _, _, err := discoverCustomerVRFs(exec, "192.0.2.", parsers); err == nil {
		t.Fatal("expected an error when the discovery command fails")
	}
}

// TestDiscoverConnectedInterfacesReturnsVRFAssignedInterfaces proves
// interface discovery uses "show vrf <vrf> ipv4 detail" (config-based VRF
// membership), not the routing table — see discoverConnectedInterfaces'
// doc comment for why the routing-table approach was abandoned.
func TestDiscoverConnectedInterfacesReturnsVRFAssignedInterfaces(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show vrf 4000001 ipv4 detail`: sampleVRFDetailInterfacesOutput,
	}}

	interfaces, err := discoverConnectedInterfaces(exec, "4000001", parsers, defaultExcludeInterfacePrefixes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"TenGigE0/0/0/22.11240078",
		"TenGigE0/7/0/18.38010079",
		"TenGigE0/7/0/18.38540079",
		"TenGigE0/7/0/18.39890079",
		"TenGigE0/7/0/18.39930079",
		"TenGigE0/7/0/19.39890079",
	}
	if strings.Join(interfaces, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, interfaces)
	}
}

// TestDiscoverConnectedInterfacesIgnoresRoutingTableLeaking is the direct
// regression guard for the real production bug this fix addresses: a
// shared VRF's routing table can list interfaces belonging to other,
// unrelated VRFs (via an imported route-target still displaying as
// "C ... is directly connected"). The decoy routing-table response here
// contains interfaces that must NEVER appear in the result — if
// discoverConnectedInterfaces ever goes back to consulting the routing
// table, this test starts failing.
func TestDiscoverConnectedInterfacesIgnoresRoutingTableLeaking(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	decoyRoutingTable := `RP/0/RSP0/CPU0:pe-router-1#show route vrf 4000001 | inc "is directly connected"
C    192.0.2.60/31 is directly connected, 1y51w, TenGigE0/7/0/18.37930079
L    192.0.2.60/32 is directly connected, 1y51w, TenGigE0/7/0/18.37930079
C    192.0.2.61/31 is directly connected, 1y21w, TenGigE0/7/0/21.37510079
L    192.0.2.61/32 is directly connected, 1y21w, TenGigE0/7/0/21.37510079
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show vrf 4000001 ipv4 detail`:                         sampleVRFDetailInterfacesOutput,
		`show route vrf 4000001 | inc "is directly connected"`: decoyRoutingTable,
	}}

	interfaces, err := discoverConnectedInterfaces(exec, "4000001", parsers, defaultExcludeInterfacePrefixes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"TenGigE0/0/0/22.11240078",
		"TenGigE0/7/0/18.38010079",
		"TenGigE0/7/0/18.38540079",
		"TenGigE0/7/0/18.39890079",
		"TenGigE0/7/0/18.39930079",
		"TenGigE0/7/0/19.39890079",
	}
	if strings.Join(interfaces, ",") != strings.Join(want, ",") {
		t.Fatalf("expected only the VRF-assigned interfaces %v, got %v (routing-table decoy leaked in)", want, interfaces)
	}
}

// TestDiscoverConnectedInterfacesSkipsLoopbackKeepsBVI proves Loopback is
// still excluded by default (never customer traffic), while BVI is not — a
// BVI is a customer-facing bridge-group interface that can carry real
// traffic worth polling, unlike a loopback.
func TestDiscoverConnectedInterfacesSkipsLoopbackKeepsBVI(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show vrf 4000001 ipv4 detail
VRF 4000001; RD 65001:4000001; VPN ID not set
VRF mode: Regular
Interfaces:
  BVI101
  Loopback30000
  TenGigE200/0/0/10.10
Address family IPV4 Unicast
  No import route policy
  No export route policy
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show vrf 4000001 ipv4 detail`: output,
	}}

	interfaces, err := discoverConnectedInterfaces(exec, "4000001", parsers, defaultExcludeInterfacePrefixes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(interfaces, ",") != "BVI101,TenGigE200/0/0/10.10" {
		t.Fatalf("expected Loopback30000 excluded but BVI101 kept, got %v", interfaces)
	}
}

// TestIsAutoDiscoveredPollInterfaceHonorsCustomExcludePrefixes guards the
// --devices file "exclude_interface_prefixes:" override (added because the
// default loopback-only denylist is hardcoded and can't cover every fleet's
// other non-core virtual interface types, e.g. tunnel-ip): a custom list
// must be used verbatim instead of silently falling back to the default.
func TestIsAutoDiscoveredPollInterfaceHonorsCustomExcludePrefixes(t *testing.T) {
	custom := []string{"tunnel-ip"}
	if isAutoDiscoveredPollInterface("tunnel-ip100", custom) {
		t.Fatal("expected tunnel-ip100 to be excluded by the custom prefix list")
	}
	// loopback is only excluded by the default list; a custom list replaces
	// it entirely rather than merging with the default.
	if !isAutoDiscoveredPollInterface("Loopback0", custom) {
		t.Fatal("expected Loopback0 to be included since the custom list doesn't exclude loopback")
	}
}

func TestResolveExcludeInterfacePrefixesFallsBackToDefaultOnlyWhenNil(t *testing.T) {
	if got := ResolveExcludeInterfacePrefixes(nil); strings.Join(got, ",") != strings.Join(defaultExcludeInterfacePrefixes, ",") {
		t.Fatalf("expected default prefixes for nil, got %v", got)
	}
	if got := ResolveExcludeInterfacePrefixes([]string{}); len(got) != 0 {
		t.Fatalf("expected an explicit empty list to disable exclusion entirely, got %v", got)
	}
	custom := []string{"tunnel-ip"}
	if got := ResolveExcludeInterfacePrefixes(custom); strings.Join(got, ",") != "tunnel-ip" {
		t.Fatalf("expected custom prefixes to pass through unchanged, got %v", got)
	}
}

func TestFormatListSummaryCapsLongLists(t *testing.T) {
	got := formatListSummary([]string{"c", "a", "b", "d"}, 2)
	want := "[a b] +2 more"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestAutoDetectCustomerVRFsCombinesVRFsAndInterfaces(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
		`show vrf 4000001 ipv4 detail`:                           sampleVRFDetailInterfacesOutput,
		`show vrf CUSTOMER-A-INTERNET ipv4 detail`:               "",
	}}

	vrfs, interfaces, hubInterfaces, hubVRFNotes, err := AutoDetectCustomerVRFs(exec, "192.0.2.", parsers, defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CUSTOMER-A-INTERNET also matches the gateway prefix but is non-numeric
	// (a hub VRF), so it's excluded from vrfs/interfaces and reported
	// separately via hubVRFNotes instead.
	wantVRFs := []string{"4000001"}
	if strings.Join(vrfs, ",") != strings.Join(wantVRFs, ",") {
		t.Fatalf("expected VRFs %v, got %v", wantVRFs, vrfs)
	}
	wantInterfaces := []string{
		"TenGigE0/0/0/22.11240078",
		"TenGigE0/7/0/18.38010079",
		"TenGigE0/7/0/18.38540079",
		"TenGigE0/7/0/18.39890079",
		"TenGigE0/7/0/18.39930079",
		"TenGigE0/7/0/19.39890079",
	}
	if strings.Join(interfaces, ",") != strings.Join(wantInterfaces, ",") {
		t.Fatalf("expected interfaces %v, got %v", wantInterfaces, interfaces)
	}
	if len(hubInterfaces) != 0 {
		t.Fatalf("expected no hub interfaces sampled (CUSTOMER-A-INTERNET has none), got %v", hubInterfaces)
	}
	wantHubNotes := []string{"CUSTOMER-A-INTERNET (0 interfaces, sampling top 0: [])"}
	if strings.Join(hubVRFNotes, ",") != strings.Join(wantHubNotes, ",") {
		t.Fatalf("expected hub VRF notes %v, got %v", wantHubNotes, hubVRFNotes)
	}
}

// TestAutoDetectCustomerVRFsKeepsPartialResultsOnInterfaceFailure proves that
// one customer VRF's connected-interfaces command failing doesn't discard
// the VRF match itself or another VRF's successfully discovered interfaces
// — the operator still gets a working (if incomplete) auto-detect result
// rather than nothing.
func TestAutoDetectCustomerVRFsKeepsPartialResultsOnInterfaceFailure(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: 4000001
Gateway of last resort is 192.0.2.56 to network 0.0.0.0
VRF: 5000002
Gateway of last resort is 192.0.2.57 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{
		responses: map[string]string{
			`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
			`show vrf 4000001 ipv4 detail`:                           sampleVRFDetailInterfacesOutput,
		},
		errs: map[string]error{
			`show vrf 5000002 ipv4 detail`: fmt.Errorf("channel closed"),
		},
	}

	vrfs, interfaces, _, _, err := AutoDetectCustomerVRFs(exec, "192.0.2.", parsers, defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)
	if err == nil {
		t.Fatal("expected a non-nil error summarizing the failed VRF's interface lookup")
	}
	wantVRFs := []string{"4000001", "5000002"}
	if strings.Join(vrfs, ",") != strings.Join(wantVRFs, ",") {
		t.Fatalf("expected both VRFs still returned despite the interface lookup failure, got %v", vrfs)
	}
	wantInterfaces := []string{
		"TenGigE0/0/0/22.11240078",
		"TenGigE0/7/0/18.38010079",
		"TenGigE0/7/0/18.38540079",
		"TenGigE0/7/0/18.39890079",
		"TenGigE0/7/0/18.39930079",
		"TenGigE0/7/0/19.39890079",
	}
	if strings.Join(interfaces, ",") != strings.Join(wantInterfaces, ",") {
		t.Fatalf("expected the successfully discovered VRF's interfaces to still be present, got %v", interfaces)
	}
}

func TestAutoDetectCustomerVRFsPropagatesVRFDiscoveryFailure(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{errs: map[string]error{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: fmt.Errorf("channel closed"),
	}}

	vrfs, interfaces, hubInterfaces, hubVRFNotes, err := AutoDetectCustomerVRFs(exec, "192.0.2.", parsers, defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)
	if err == nil {
		t.Fatal("expected an error when VRF discovery itself fails")
	}
	if vrfs != nil || interfaces != nil || hubInterfaces != nil || hubVRFNotes != nil {
		t.Fatalf("expected no results when VRF discovery fails, got vrfs=%v interfaces=%v hubInterfaces=%v hubVRFNotes=%v", vrfs, interfaces, hubInterfaces, hubVRFNotes)
	}
}
