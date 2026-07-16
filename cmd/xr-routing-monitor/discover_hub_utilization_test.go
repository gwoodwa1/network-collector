package main

import (
	"fmt"
	"strings"
	"testing"
)

func interfaceRateOutput(inputBps, outputBps string) string {
	return fmt.Sprintf(`RP/0/RSP0/CPU0:pe-router-1#show int TenGigE0/0/0/1 | inc "rate|Description:"
  Description: sample
  5 minute input rate %s bits/sec, 100 packets/sec
  5 minute output rate %s bits/sec, 100 packets/sec
RP/0/RSP0/CPU0:pe-router-1#
`, inputBps, outputBps)
}

// TestRankInterfacesByUtilizationOrdersByCombinedRate proves interfaces are
// ranked busiest-first by their summed input+output bps, not by name.
func TestRankInterfacesByUtilizationOrdersByCombinedRate(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show int Gi0/0/0/1 | inc "rate|Description:"`: interfaceRateOutput("1000", "0"),
		`show int Gi0/0/0/2 | inc "rate|Description:"`: interfaceRateOutput("5000000", "1000000"),
		`show int Gi0/0/0/3 | inc "rate|Description:"`: interfaceRateOutput("0", "0"),
	}}

	got := rankInterfacesByUtilization(exec, []string{"Gi0/0/0/1", "Gi0/0/0/2", "Gi0/0/0/3"}, parsers, defaultSpec)
	want := []string{"Gi0/0/0/2", "Gi0/0/0/1", "Gi0/0/0/3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected ranking %v, got %v", want, got)
	}
}

// TestRankInterfacesByUtilizationTreatsFailureAsZero proves an interface
// whose rate query fails (or doesn't parse) scores 0 and sorts last, rather
// than aborting the ranking for the rest.
func TestRankInterfacesByUtilizationTreatsFailureAsZero(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{
		responses: map[string]string{
			`show int Gi0/0/0/1 | inc "rate|Description:"`: interfaceRateOutput("100", "0"),
		},
		errs: map[string]error{
			`show int Gi0/0/0/2 | inc "rate|Description:"`: fmt.Errorf("channel closed"),
		},
	}

	got := rankInterfacesByUtilization(exec, []string{"Gi0/0/0/2", "Gi0/0/0/1"}, parsers, defaultSpec)
	want := []string{"Gi0/0/0/1", "Gi0/0/0/2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected the failed query to score 0 and sort last, got %v", got)
	}
}

// TestRankInterfacesByUtilizationBreaksTiesAlphabetically proves equal
// scores (including two interfaces that both fail/score 0) don't produce a
// nondeterministic order.
func TestRankInterfacesByUtilizationBreaksTiesAlphabetically(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	exec := &discoverFakeExecutor{}

	got := rankInterfacesByUtilization(exec, []string{"Gi0/0/0/9", "Gi0/0/0/2", "Gi0/0/0/5"}, parsers, defaultSpec)
	want := []string{"Gi0/0/0/2", "Gi0/0/0/5", "Gi0/0/0/9"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected alphabetical tiebreak %v, got %v", want, got)
	}
}

func TestResolveHubTopInterfacesFallsBackToDefault(t *testing.T) {
	if got := resolveHubTopInterfaces(nil); got != defaultHubTopInterfaces {
		t.Fatalf("expected default %d for nil (unset), got %d", defaultHubTopInterfaces, got)
	}
	zero := 0
	if got := resolveHubTopInterfaces(&zero); got != 0 {
		t.Fatalf("expected an explicit 0 to be kept (disables hub sampling), got %d", got)
	}
	five := 5
	if got := resolveHubTopInterfaces(&five); got != 5 {
		t.Fatalf("expected configured value 5 to be kept, got %d", got)
	}
}

// TestAutoDetectCustomerVRFsSamplesTopHubInterfacesByUtilization proves a
// hub VRF with more interfaces than hubTopInterfaces only contributes its
// busiest hubTopInterfaces to hubInterfaces, while a customer VRF's
// interfaces are all still returned unfiltered (this fleet's call to scope
// utilization-based sampling to hub VRFs only).
func TestAutoDetectCustomerVRFsSamplesTopHubInterfacesByUtilization(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
VRF: 4000001
Gateway of last resort is 192.0.2.56 to network 0.0.0.0
VRF: RI-INTERNET-ENTERPRISE
Gateway of last resort is 192.0.2.57 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	hubDetail := `RP/0/RSP0/CPU0:pe-router-1#show vrf RI-INTERNET-ENTERPRISE ipv4 detail
VRF RI-INTERNET-ENTERPRISE; RD 100:1; VPN ID not set
Interfaces:
  TenGigE0/0/0/1
  TenGigE0/0/0/2
  TenGigE0/0/0/3
RP/0/RSP0/CPU0:pe-router-1#
`
	exec := &discoverFakeExecutor{responses: map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: output,
		`show vrf 4000001 ipv4 detail`:                           sampleVRFDetailInterfacesOutput,
		`show vrf RI-INTERNET-ENTERPRISE ipv4 detail`:            hubDetail,
		`show int TenGigE0/0/0/1 | inc "rate|Description:"`:      interfaceRateOutput("100", "0"),
		`show int TenGigE0/0/0/2 | inc "rate|Description:"`:      interfaceRateOutput("9000000", "1000000"),
		`show int TenGigE0/0/0/3 | inc "rate|Description:"`:      interfaceRateOutput("500", "0"),
	}}

	vrfs, interfaces, hubInterfaces, hubVRFNotes, err := autoDetectCustomerVRFs(exec, "192.0.2.", parsers, defaultExcludeInterfacePrefixes, defaultSpec, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(vrfs, ",") != "4000001" {
		t.Fatalf("expected only the customer VRF 4000001, got %v", vrfs)
	}
	wantCustomerInterfaces := []string{
		"TenGigE0/0/0/22.11240078",
		"TenGigE0/7/0/18.38010079",
		"TenGigE0/7/0/18.38540079",
		"TenGigE0/7/0/18.39890079",
		"TenGigE0/7/0/18.39930079",
		"TenGigE0/7/0/19.39890079",
	}
	if strings.Join(interfaces, ",") != strings.Join(wantCustomerInterfaces, ",") {
		t.Fatalf("expected all of the customer VRF's interfaces unfiltered, got %v", interfaces)
	}
	wantHubInterfaces := []string{"TenGigE0/0/0/2", "TenGigE0/0/0/3"}
	if strings.Join(hubInterfaces, ",") != strings.Join(wantHubInterfaces, ",") {
		t.Fatalf("expected only the top 2 hub interfaces by utilization %v, got %v", wantHubInterfaces, hubInterfaces)
	}
	if len(hubVRFNotes) != 1 || !strings.Contains(hubVRFNotes[0], "RI-INTERNET-ENTERPRISE") || !strings.Contains(hubVRFNotes[0], "3 interfaces") {
		t.Fatalf("expected a hub VRF note naming the VRF and its interface count, got %v", hubVRFNotes)
	}
}
