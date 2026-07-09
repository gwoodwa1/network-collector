package main

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
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	vrfs, err := discoverCustomerVRFs(exec, "10.99.99.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"4000001", "CUSTOMER-A-INTERNET"}
	if strings.Join(vrfs, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, vrfs)
	}
}

func TestDiscoverCustomerVRFsNarrowerPrefixMatchesOneGateway(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	vrfs, err := discoverCustomerVRFs(exec, "10.99.99.51", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vrfs) != 1 || vrfs[0] != "CUSTOMER-A-INTERNET" {
		t.Fatalf("expected only CUSTOMER-A-INTERNET, got %v", vrfs)
	}
}

func TestDiscoverCustomerVRFsNoMatchingGateway(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	vrfs, err := discoverCustomerVRFs(exec, "10.0.0.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vrfs) != 0 {
		t.Fatalf("expected no matching VRFs, got %v", vrfs)
	}
}

// TestDiscoverCustomerVRFsRejectsEmptyGatewayPrefix guards against
// strings.HasPrefix(x, "") being always true in Go — without this check, a
// blank gateway prefix (e.g. an operator hitting Enter at the interactive
// prompt with nothing typed) would silently match every VRF with any
// default route at all, not just customer-facing ones.
func TestDiscoverCustomerVRFsRejectsEmptyGatewayPrefix(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
	}}

	if _, err := discoverCustomerVRFs(exec, "", parsers); err == nil {
		t.Fatal("expected an error for an empty gateway prefix instead of silently matching every VRF")
	}
	if _, err := discoverCustomerVRFs(exec, "   ", parsers); err == nil {
		t.Fatal("expected an error for a whitespace-only gateway prefix")
	}
}

// TestDiscoverCustomerVRFsRejectsMalformedVRFName is defense-in-depth
// against a VRF name from device output flowing unvalidated into a later
// Sprintf-built CLI command (discoverConnectedInterfaces, and every
// subsequent poll tick / snapshot once it lands in deviceSession.vrfs).
func TestDiscoverCustomerVRFsReportsMalformedMatchingVRFName(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: CUSTOMER-A|whoami
Gateway of last resort is 10.99.99.51 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
	}}

	vrfs, err := discoverCustomerVRFs(exec, "10.99.99.", parsers)
	if err == nil {
		t.Fatal("expected an error for the malformed matching VRF name")
	}
	if len(vrfs) != 0 {
		t.Fatalf("expected the malformed VRF name to be filtered out, got %v", vrfs)
	}
	if !strings.Contains(err.Error(), "CUSTOMER-A|whoami") {
		t.Fatalf("expected error to name the skipped VRF, got: %v", err)
	}
}

func TestAutoDetectCustomerVRFsKeepsValidMatchesWhenAnotherMatchedVRFIsMalformed(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: CUSTOMER-A|whoami
Gateway of last resort is 10.99.99.50 to network 0.0.0.0
VRF: CUSTOMER-B
Gateway of last resort is 10.99.99.51 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`:  output,
		`show route vrf CUSTOMER-B | inc "is directly connected"`: "",
	}}

	vrfs, interfaces, err := autoDetectCustomerVRFs(exec, "10.99.99.", parsers)
	if err == nil {
		t.Fatal("expected a non-nil warning error for the malformed matching VRF")
	}
	if strings.Join(vrfs, ",") != "CUSTOMER-B" {
		t.Fatalf("expected valid VRF CUSTOMER-B to be kept, got %v", vrfs)
	}
	if len(interfaces) != 0 {
		t.Fatalf("expected no discovered interfaces, got %v", interfaces)
	}
}

func TestDiscoverConnectedInterfacesRejectsMalformedVRFName(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{}

	if _, err := discoverConnectedInterfaces(exec, "CUSTOMER-A|whoami", parsers); err == nil {
		t.Fatal("expected an error for a VRF name containing shell/CLI metacharacters")
	}
}

func TestDiscoverCustomerVRFsPropagatesExecuteFailure(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{errs: map[string]error{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: fmt.Errorf("channel closed"),
	}}

	if _, err := discoverCustomerVRFs(exec, "10.99.99.", parsers); err == nil {
		t.Fatal("expected an error when the discovery command fails")
	}
}

func TestDiscoverConnectedInterfacesDedupsCAndLLines(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf 4000001 | inc "is directly connected"`: sampleRouteVRFConnectedInterfacesOutput,
	}}

	interfaces, err := discoverConnectedInterfaces(exec, "4000001", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"GigabitEthernet0/0/0/1.100", "TenGigE0/0/0/2.200"}
	if strings.Join(interfaces, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, interfaces)
	}
}

func TestDiscoverConnectedInterfacesSkipsLoopbackAndBVI(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf 4000001 | inc "is directly connected"
C    10.0.0.0/24 is directly connected, 1y51w, BVI101
C    10.0.1.0/32 is directly connected, 1y51w, Loopback30000
C    10.0.2.0/31 is directly connected, 3w3d, TenGigE200/0/0/10.10
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf 4000001 | inc "is directly connected"`: output,
	}}

	interfaces, err := discoverConnectedInterfaces(exec, "4000001", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(interfaces, ",") != "TenGigE200/0/0/10.10" {
		t.Fatalf("expected only the physical/sub-interface poll target, got %v", interfaces)
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
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`:           sampleRouteVRFAllGatewaysOutput,
		`show route vrf 4000001 | inc "is directly connected"`:             sampleRouteVRFConnectedInterfacesOutput,
		`show route vrf CUSTOMER-A-INTERNET | inc "is directly connected"`: "",
	}}

	vrfs, interfaces, err := autoDetectCustomerVRFs(exec, "10.99.99.", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantVRFs := []string{"4000001", "CUSTOMER-A-INTERNET"}
	if strings.Join(vrfs, ",") != strings.Join(wantVRFs, ",") {
		t.Fatalf("expected VRFs %v, got %v", wantVRFs, vrfs)
	}
	wantInterfaces := []string{"GigabitEthernet0/0/0/1.100", "TenGigE0/0/0/2.200"}
	if strings.Join(interfaces, ",") != strings.Join(wantInterfaces, ",") {
		t.Fatalf("expected interfaces %v, got %v", wantInterfaces, interfaces)
	}
}

// TestAutoDetectCustomerVRFsKeepsPartialResultsOnInterfaceFailure proves that
// one VRF's connected-interfaces command failing doesn't discard the VRF
// match itself or another VRF's successfully discovered interfaces — the
// operator still gets a working (if incomplete) auto-detect result rather
// than nothing.
func TestAutoDetectCustomerVRFsKeepsPartialResultsOnInterfaceFailure(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{
		responses: map[string]string{
			`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
			`show route vrf 4000001 | inc "is directly connected"`:   sampleRouteVRFConnectedInterfacesOutput,
		},
		errs: map[string]error{
			`show route vrf CUSTOMER-A-INTERNET | inc "is directly connected"`: fmt.Errorf("channel closed"),
		},
	}

	vrfs, interfaces, err := autoDetectCustomerVRFs(exec, "10.99.99.", parsers)
	if err == nil {
		t.Fatal("expected a non-nil error summarizing the failed VRF's interface lookup")
	}
	wantVRFs := []string{"4000001", "CUSTOMER-A-INTERNET"}
	if strings.Join(vrfs, ",") != strings.Join(wantVRFs, ",") {
		t.Fatalf("expected both VRFs still returned despite the interface lookup failure, got %v", vrfs)
	}
	wantInterfaces := []string{"GigabitEthernet0/0/0/1.100", "TenGigE0/0/0/2.200"}
	if strings.Join(interfaces, ",") != strings.Join(wantInterfaces, ",") {
		t.Fatalf("expected the successfully discovered VRF's interfaces to still be present, got %v", interfaces)
	}
}

func TestAutoDetectCustomerVRFsPropagatesVRFDiscoveryFailure(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{errs: map[string]error{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: fmt.Errorf("channel closed"),
	}}

	vrfs, interfaces, err := autoDetectCustomerVRFs(exec, "10.99.99.", parsers)
	if err == nil {
		t.Fatal("expected an error when VRF discovery itself fails")
	}
	if vrfs != nil || interfaces != nil {
		t.Fatalf("expected no results when VRF discovery fails, got vrfs=%v interfaces=%v", vrfs, interfaces)
	}
}
