package main

import (
	"bufio"
	"fmt"
	"strings"
	"testing"
)

// fakeSessionExecutor is a no-op sessionExecutor for onboarding tests that
// don't care about command execution, only connection outcome.
type fakeSessionExecutor struct{}

func (fakeSessionExecutor) Execute(cmd string) (string, error) { return "", nil }
func (fakeSessionExecutor) Close() error                       { return nil }

// These tests exercise the real onboardDevices/onboardDevicesFromSpecs code
// paths end-to-end (via an injected connectFunc, so no real SSH connection
// is needed) to directly prove the claim-after-success/no-claim-on-failure
// sequencing that TestHostnameRegistryFailedAttemptRemainsClaimable only
// verified for the registry type in isolation, not for these call sites.

func TestOnboardDevicesDoesNotClaimHostnameOnFailedConnect(t *testing.T) {
	registry := newHostnameRegistry()
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		attempts++
		return nil, fmt.Errorf("simulated connect failure")
	}

	// hostname, auto-detect?, vrf, interfaces, neighbors, then blank hostname to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\n\n\n\n\n\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if attempts != 1 {
		t.Fatalf("expected exactly 1 connect attempt, got %d", attempts)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no sessions after a failed connect, got %d", len(sessions))
	}
	if exists, _ := registry.has("pe-router-1"); exists {
		t.Fatal("expected hostname to remain unclaimed after a failed connect")
	}
}

func TestOnboardDevicesClaimsHostnameOnSuccessfulConnect(t *testing.T) {
	registry := newHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	reader := bufio.NewReader(strings.NewReader("pe-router-1\n\n\n\n\n\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after a successful connect, got %d", len(sessions))
	}
	if exists, existing := registry.has("pe-router-1"); !exists || existing != "pe-router-1" {
		t.Fatalf("expected hostname to be claimed after a successful connect, got exists=%v existing=%q", exists, existing)
	}
}

func TestOnboardDevicesSkipsAlreadyClaimedHostnameWithoutConnecting(t *testing.T) {
	registry := newHostnameRegistry()
	registry.claim("pe-router-1")
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		attempts++
		return fakeSessionExecutor{}, nil
	}

	reader := bufio.NewReader(strings.NewReader("pe-router-1\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if attempts != 0 {
		t.Fatalf("expected connect to never be called for an already-claimed hostname, got %d attempts", attempts)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no new sessions for an already-claimed hostname, got %d", len(sessions))
	}
}

// discoveryResponses is the shared fixture (from discover_test.go /
// parser_test.go) for a connect that succeeds and, once auto-detect runs,
// finds one customer VRF (4000001, with its connected interfaces) plus one
// non-numeric hub VRF (CUSTOMER-A-INTERNET) that matches the same gateway
// heuristic but is excluded from vrfs/interfaces — see customerVRFName.
func discoveryResponses() map[string]string {
	return map[string]string{
		`show route vrf all | inc "Gateway of last resort|VRF:"`: sampleRouteVRFAllGatewaysOutput,
		`show vrf 4000001 ipv4 detail`:                           sampleVRFDetailInterfacesOutput,
		`show vrf CUSTOMER-A-INTERNET ipv4 detail`:               "",
	}
}

// TestOnboardDevicesAutoDetectKeepsManualAndDiscoveredInterfacesSeparate
// proves the interactive "Auto-detect customer VRF(s)..." prompt (chosen
// instead of the manual VRF-name prompt) populates deviceSession.vrfs from
// discovery, and that manually-typed interfaces (BE40 here) land in
// coreInterfaces while auto-discovered ones land in customerInterfaces —
// kept apart (not merged into one list) so the status line can label them
// "Core Int" vs "Cust Int" by provenance.
func TestOnboardDevicesAutoDetectKeepsManualAndDiscoveredInterfacesSeparate(t *testing.T) {
	registry := newHostnameRegistry()
	exec := &discoverFakeExecutor{responses: discoveryResponses()}
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return exec, nil
	}
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}

	// hostname, auto-detect=yes, gateway prefix, core interfaces, neighbors, then blank hostname to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\ny\n10.99.99.\nBE40\n\n\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, parsers, "", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	wantVRFs := "4000001"
	if strings.Join(sessions[0].vrfs, ",") != wantVRFs {
		t.Fatalf("expected vrfs %q, got %v", wantVRFs, sessions[0].vrfs)
	}
	if strings.Join(sessions[0].coreInterfaces, ",") != "BE40" {
		t.Fatalf("expected core interfaces %q, got %v", "BE40", sessions[0].coreInterfaces)
	}
	wantCustomerInterfaces := "TenGigE0/0/0/22.11240078,TenGigE0/7/0/18.38010079,TenGigE0/7/0/18.38540079,TenGigE0/7/0/18.39890079,TenGigE0/7/0/18.39930079,TenGigE0/7/0/19.39890079"
	if strings.Join(sessions[0].customerInterfaces, ",") != wantCustomerInterfaces {
		t.Fatalf("expected customer interfaces %q, got %v", wantCustomerInterfaces, sessions[0].customerInterfaces)
	}
}

// TestOnboardDevicesAutoDetectUsesDefaultGatewayPrefixWithoutPrompting
// proves that when a --devices file already supplied
// customer_gateway_prefix, the operator isn't asked for it again when
// opting into auto-detect during the interactive follow-up onboarding.
func TestOnboardDevicesAutoDetectUsesDefaultGatewayPrefixWithoutPrompting(t *testing.T) {
	registry := newHostnameRegistry()
	exec := &discoverFakeExecutor{responses: discoveryResponses()}
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return exec, nil
	}
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}

	// hostname, auto-detect=yes, [no gateway prompt: default supplied], interfaces, neighbors, blank to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\ny\n\n\n\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, parsers, "10.99.99.", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	wantVRFs := "4000001"
	if strings.Join(sessions[0].vrfs, ",") != wantVRFs {
		t.Fatalf("expected vrfs %q, got %v", wantVRFs, sessions[0].vrfs)
	}
}

// TestOnboardDevicesDecliningAutoDetectKeepsManualVRFPrompt proves the
// default answer ("N") to the new prompt falls through to the original
// manual VRF-name behavior unchanged.
func TestOnboardDevicesDecliningAutoDetectKeepsManualVRFPrompt(t *testing.T) {
	registry := newHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	// hostname, auto-detect=no (blank/default), vrf, interfaces, neighbors, blank to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\n\nCUSTOMER-A\n\n\n\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if strings.Join(sessions[0].vrfs, ",") != "CUSTOMER-A" {
		t.Fatalf("expected manually-entered vrf CUSTOMER-A, got %v", sessions[0].vrfs)
	}
}

func TestOnboardDevicesBlankAutoDetectGatewayPrefixFallsBackToManualVRFPrompt(t *testing.T) {
	registry := newHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	// hostname, auto-detect=yes, blank gateway prefix, manual VRF, interfaces, neighbors, blank to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\ny\n\nCUSTOMER-A\n\n\n\n"))
	sessions := onboardDevices(reader, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if strings.Join(sessions[0].vrfs, ",") != "CUSTOMER-A" {
		t.Fatalf("expected fallback manual VRF CUSTOMER-A, got %v", sessions[0].vrfs)
	}
}

// TestOnboardDevicesFromSpecsAutoDetectKeepsManualAndDiscoveredInterfacesSeparate
// is the --devices-file-driven equivalent of
// TestOnboardDevicesAutoDetectKeepsManualAndDiscoveredInterfacesSeparate: a
// spec with auto_detect_vrf: true merges discovered VRFs with whatever the
// spec already listed, using the document's customer_gateway_prefix
// (loadDeviceSpecs already guarantees one is set whenever auto_detect_vrf
// is used), but keeps interfaces split into coreInterfaces (from the spec)
// vs customerInterfaces (discovered).
func TestOnboardDevicesFromSpecsAutoDetectKeepsManualAndDiscoveredInterfacesSeparate(t *testing.T) {
	registry := newHostnameRegistry()
	exec := &discoverFakeExecutor{responses: discoveryResponses()}
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return exec, nil
	}
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}

	specs := []deviceSpec{{Hostname: "pe-router-1", AutoDetectVRF: true, Interfaces: []string{"BE40"}}}
	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "cisco_iosxr", &credentialCache{}, registry, connect, parsers, "10.99.99.", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	wantVRFs := "4000001"
	if strings.Join(sessions[0].vrfs, ",") != wantVRFs {
		t.Fatalf("expected vrfs %q, got %v", wantVRFs, sessions[0].vrfs)
	}
	if strings.Join(sessions[0].coreInterfaces, ",") != "BE40" {
		t.Fatalf("expected core interfaces %q, got %v", "BE40", sessions[0].coreInterfaces)
	}
	wantCustomerInterfaces := "TenGigE0/0/0/22.11240078,TenGigE0/7/0/18.38010079,TenGigE0/7/0/18.38540079,TenGigE0/7/0/18.39890079,TenGigE0/7/0/18.39930079,TenGigE0/7/0/19.39890079"
	if strings.Join(sessions[0].customerInterfaces, ",") != wantCustomerInterfaces {
		t.Fatalf("expected customer interfaces %q, got %v", wantCustomerInterfaces, sessions[0].customerInterfaces)
	}
}

func TestOnboardDevicesFromSpecsDoesNotClaimHostnameOnFailedConnect(t *testing.T) {
	registry := newHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return nil, fmt.Errorf("simulated connect failure")
	}

	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), []deviceSpec{{Hostname: "pe-router-1"}}, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if len(sessions) != 0 {
		t.Fatalf("expected no sessions after a failed connect, got %d", len(sessions))
	}
	if exists, _ := registry.has("pe-router-1"); exists {
		t.Fatal("expected hostname to remain unclaimed after a failed connect")
	}
}

func TestOnboardDevicesFromSpecsSkipsDuplicateWithinFileWithoutSecondConnect(t *testing.T) {
	registry := newHostnameRegistry()
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		attempts++
		return fakeSessionExecutor{}, nil
	}

	specs := []deviceSpec{{Hostname: "pe-router-1"}, {Hostname: "PE-Router-1"}}
	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if attempts != 1 {
		t.Fatalf("expected exactly 1 connect attempt for a case-insensitive duplicate, got %d", attempts)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected exactly 1 session, got %d", len(sessions))
	}
}

func TestOnboardDevicesFromSpecsClaimsHostnameOnSuccessfulConnect(t *testing.T) {
	registry := newHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), []deviceSpec{{Hostname: "pe-router-1"}}, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after a successful connect, got %d", len(sessions))
	}
	if exists, existing := registry.has("pe-router-1"); !exists || existing != "pe-router-1" {
		t.Fatalf("expected hostname to be claimed after a successful connect, got exists=%v existing=%q", exists, existing)
	}
}

// TestOnboardDevicesFromSpecsSkipsHostnameAlreadyClaimedElsewhere covers a
// different case than the within-file duplicate test above: a hostname
// claimed by a prior pass entirely (e.g. onboardDevices ran first and
// already connected it) rather than a duplicate within this same specs
// list.
func TestOnboardDevicesFromSpecsSkipsHostnameAlreadyClaimedElsewhere(t *testing.T) {
	registry := newHostnameRegistry()
	registry.claim("pe-router-1")
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
		attempts++
		return fakeSessionExecutor{}, nil
	}

	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), []deviceSpec{{Hostname: "pe-router-1"}}, "cisco_iosxr", &credentialCache{}, registry, connect, map[string]parserModule{}, "", defaultExcludeInterfacePrefixes)

	if attempts != 0 {
		t.Fatalf("expected connect to never be called for an already-claimed hostname, got %d attempts", attempts)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no new sessions for an already-claimed hostname, got %d", len(sessions))
	}
}
