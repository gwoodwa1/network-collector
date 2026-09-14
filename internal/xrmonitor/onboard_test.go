package xrmonitor

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
)

// fakeSessionExecutor is a no-op sessionExecutor for onboarding tests that
// don't care about command execution, only connection outcome.
type fakeSessionExecutor struct{}

func (fakeSessionExecutor) Execute(cmd string) (string, error) { return "", nil }
func (fakeSessionExecutor) Close() error                       { return nil }

// These tests exercise the real OnboardDevices/OnboardDevicesFromSpecs code
// paths end-to-end (via an injected connectFunc, so no real SSH connection
// is needed) to directly prove the claim-after-success/no-claim-on-failure
// sequencing that TestHostnameRegistryFailedAttemptRemainsClaimable only
// verified for the registry type in isolation, not for these call sites.

func TestOnboardDevicesDoesNotClaimHostnameOnFailedConnect(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		attempts++
		return nil, fmt.Errorf("simulated connect failure")
	}

	// hostname, auto-detect?, vrf, interfaces, neighbors, then blank hostname to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\n\n\n\n\n\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if attempts != 1 {
		t.Fatalf("expected exactly 1 connect attempt, got %d", attempts)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no sessions after a failed connect, got %d", len(sessions))
	}
	if exists, _ := registry.Has("pe-router-1"); exists {
		t.Fatal("expected hostname to remain unclaimed after a failed connect")
	}
}

func TestOnboardDevicesClaimsHostnameOnSuccessfulConnect(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	reader := bufio.NewReader(strings.NewReader("pe-router-1\n\n\n\n\n\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after a successful connect, got %d", len(sessions))
	}
	if exists, existing := registry.Has("pe-router-1"); !exists || existing != "pe-router-1" {
		t.Fatalf("expected hostname to be claimed after a successful connect, got exists=%v existing=%q", exists, existing)
	}
}

func TestOnboardDevicesSkipsAlreadyClaimedHostnameWithoutConnecting(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	registry.Claim("pe-router-1")
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		attempts++
		return fakeSessionExecutor{}, nil
	}

	reader := bufio.NewReader(strings.NewReader("pe-router-1\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

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
// instead of the manual VRF-name prompt) populates DeviceSession.vrfs from
// discovery, and that manually-typed interfaces (BE40 here) land in
// coreInterfaces while auto-discovered ones land in customerInterfaces —
// kept apart (not merged into one list) so the status line can label them
// "Core Int" vs "Cust Int" by provenance.
func TestOnboardDevicesAutoDetectKeepsManualAndDiscoveredInterfacesSeparate(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	exec := &discoverFakeExecutor{responses: discoveryResponses()}
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return exec, nil
	}
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}

	// hostname, auto-detect=yes, gateway prefix, core interfaces, neighbors, then blank hostname to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\ny\n192.0.2.\nBE40\n\n\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, parsers, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

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
	registry := monitorsetup.NewHostnameRegistry()
	exec := &discoverFakeExecutor{responses: discoveryResponses()}
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return exec, nil
	}
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}

	// hostname, auto-detect=yes, [no gateway prompt: default supplied], interfaces, neighbors, blank to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\ny\n\n\n\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, parsers, "192.0.2.", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

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
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	// hostname, auto-detect=no (blank/default), vrf, interfaces, neighbors, blank to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\n\nCUSTOMER-A\n\n\n\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if strings.Join(sessions[0].vrfs, ",") != "CUSTOMER-A" {
		t.Fatalf("expected manually-entered vrf CUSTOMER-A, got %v", sessions[0].vrfs)
	}
}

func TestOnboardDevicesBlankAutoDetectGatewayPrefixFallsBackToManualVRFPrompt(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	// hostname, auto-detect=yes, blank gateway prefix, manual VRF, interfaces, neighbors, blank to end.
	reader := bufio.NewReader(strings.NewReader("pe-router-1\ny\n\nCUSTOMER-A\n\n\n\n"))
	sessions := OnboardDevices(reader, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

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
// (LoadDeviceSpecs already guarantees one is set whenever auto_detect_vrf
// is used), but keeps interfaces split into coreInterfaces (from the spec)
// vs customerInterfaces (discovered).
func TestOnboardDevicesFromSpecsAutoDetectKeepsManualAndDiscoveredInterfacesSeparate(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	exec := &discoverFakeExecutor{responses: discoveryResponses()}
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return exec, nil
	}
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}

	specs := []DeviceSpec{{Hostname: "pe-router-1", AutoDetectVRF: true, Interfaces: []string{"BE40"}}}
	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, parsers, "192.0.2.", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

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
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return nil, fmt.Errorf("simulated connect failure")
	}

	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), []DeviceSpec{{Hostname: "pe-router-1"}}, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if len(sessions) != 0 {
		t.Fatalf("expected no sessions after a failed connect, got %d", len(sessions))
	}
	if exists, _ := registry.Has("pe-router-1"); exists {
		t.Fatal("expected hostname to remain unclaimed after a failed connect")
	}
}

func TestOnboardDevicesFromSpecsSkipsDuplicateWithinFileWithoutSecondConnect(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		attempts++
		return fakeSessionExecutor{}, nil
	}

	specs := []DeviceSpec{{Hostname: "pe-router-1"}, {Hostname: "PE-Router-1"}}
	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if attempts != 1 {
		t.Fatalf("expected exactly 1 connect attempt for a case-insensitive duplicate, got %d", attempts)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected exactly 1 session, got %d", len(sessions))
	}
}

func TestOnboardDevicesFromSpecsClaimsHostnameOnSuccessfulConnect(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}

	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), []DeviceSpec{{Hostname: "pe-router-1"}}, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after a successful connect, got %d", len(sessions))
	}
	if exists, existing := registry.Has("pe-router-1"); !exists || existing != "pe-router-1" {
		t.Fatalf("expected hostname to be claimed after a successful connect, got exists=%v existing=%q", exists, existing)
	}
}

// TestOnboardDevicesFromSpecsSkipsHostnameAlreadyClaimedElsewhere covers a
// different case than the within-file duplicate test above: a hostname
// claimed by a prior pass entirely (e.g. OnboardDevices ran first and
// already connected it) rather than a duplicate within this same specs
// list.
func TestOnboardDevicesFromSpecsSkipsHostnameAlreadyClaimedElsewhere(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	registry.Claim("pe-router-1")
	attempts := 0
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		attempts++
		return fakeSessionExecutor{}, nil
	}

	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), []DeviceSpec{{Hostname: "pe-router-1"}}, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)

	if attempts != 0 {
		t.Fatalf("expected connect to never be called for an already-claimed hostname, got %d attempts", attempts)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no new sessions for an already-claimed hostname, got %d", len(sessions))
	}
}

// TestConnectWithRetrySucceedsWithoutPromptingOnFirstAttempt proves the
// retry question (see promptRetryConnection) is never asked when the first
// connection attempt succeeds: dial is called exactly once, and a sentinel
// line placed right after the credentials is left completely unread,
// proving the code never tried to read a retry answer off reader.
func TestConnectWithRetrySucceedsWithoutPromptingOnFirstAttempt(t *testing.T) {
	var dialCalls int
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls++
		return fakeSessionExecutor{}, nil
	}
	reader := bufio.NewReader(strings.NewReader("mretz1\npasscode1\nSENTINEL\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client")
	}
	if dialCalls != 1 {
		t.Fatalf("expected exactly 1 dial attempt, got %d", dialCalls)
	}
	if leftover, _ := reader.ReadString('\n'); leftover != "SENTINEL\n" {
		t.Fatalf("expected the retry prompt to never read from reader on a successful first attempt; leftover input was %q", leftover)
	}
}

// TestConnectWithRetryRetriesOnceWhenOperatorConfirms is the regression
// test for the fat-finger scenario this feature exists for: a failed first
// attempt (e.g. the passcode typed into the username prompt) followed by
// the operator confirming "y" must re-prompt for fresh credentials and
// succeed, without the caller having to restart onboarding for the device.
func TestConnectWithRetryRetriesOnceWhenOperatorConfirms(t *testing.T) {
	var dialCalls []string
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls = append(dialCalls, username+"/"+password)
		if len(dialCalls) == 1 {
			return nil, fmt.Errorf("simulated failure")
		}
		return fakeSessionExecutor{}, nil
	}
	// First attempt: wrong username/password. "y" to retry. Second attempt:
	// correct username/password.
	reader := bufio.NewReader(strings.NewReader("wronguser\nwrongpass\ny\ncorrectuser\ncorrectpass\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client from the retried attempt")
	}
	wantCalls := []string{"wronguser/wrongpass", "correctuser/correctpass"}
	if len(dialCalls) != len(wantCalls) || dialCalls[0] != wantCalls[0] || dialCalls[1] != wantCalls[1] {
		t.Fatalf("expected dial calls %v, got %v", wantCalls, dialCalls)
	}
}

// TestConnectWithRetryDoesNotRetryWhenOperatorDeclines proves declining the
// retry prompt still ends onboarding for that device after exactly one
// attempt — the feature adds recourse, it doesn't turn the connect into a
// loop the operator has to opt out of.
func TestConnectWithRetryDoesNotRetryWhenOperatorDeclines(t *testing.T) {
	var dialCalls int
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls++
		return nil, fmt.Errorf("simulated failure")
	}
	reader := bufio.NewReader(strings.NewReader("user1\npass1\nn\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial)
	if err == nil {
		t.Fatal("expected an error when the operator declines the retry")
	}
	if client != nil {
		t.Fatal("expected a nil client when the operator declines the retry")
	}
	if dialCalls != 1 {
		t.Fatalf("expected exactly 1 dial attempt, got %d", dialCalls)
	}
}

// TestConnectWithRetryAllowsMultipleConsecutiveRetries proves the retry
// question isn't capped at a single retry: confirming it again after a
// second failure retries again, so an operator can keep recovering from
// repeated mistakes as long as they keep confirming "y".
func TestConnectWithRetryAllowsMultipleConsecutiveRetries(t *testing.T) {
	var dialCalls []string
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls = append(dialCalls, username+"/"+password)
		if len(dialCalls) < 3 {
			return nil, fmt.Errorf("simulated failure")
		}
		return fakeSessionExecutor{}, nil
	}
	// Fail, retry; fail again, retry again; succeed on the third attempt.
	reader := bufio.NewReader(strings.NewReader("user1\nwrong1\ny\nuser1\nwrong2\ny\nuser1\ncorrect\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client after two retries")
	}
	wantCalls := []string{"user1/wrong1", "user1/wrong2", "user1/correct"}
	if len(dialCalls) != len(wantCalls) {
		t.Fatalf("expected 3 dial attempts, got %d: %v", len(dialCalls), dialCalls)
	}
	for i, want := range wantCalls {
		if dialCalls[i] != want {
			t.Fatalf("dial call %d: expected %q, got %q", i, want, dialCalls[i])
		}
	}
}

// TestConnectWithRetryStopsWhenAConfirmedRetryAlsoFailsAndIsDeclined covers
// the case where the retry itself fails: confirming once, having that
// attempt fail too, then declining the next prompt must stop after exactly
// 2 dial attempts, not swallow the second failure or loop past a decline.
func TestConnectWithRetryStopsWhenAConfirmedRetryAlsoFailsAndIsDeclined(t *testing.T) {
	var dialCalls int
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls++
		return nil, fmt.Errorf("simulated failure")
	}
	// Fail, retry ("y"); the retry also fails, decline the next prompt ("n").
	reader := bufio.NewReader(strings.NewReader("user1\nwrong1\ny\nuser1\nwrong2\nn\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial)
	if err == nil {
		t.Fatal("expected an error once the retried attempt also fails and is declined")
	}
	if client != nil {
		t.Fatal("expected a nil client")
	}
	if dialCalls != 2 {
		t.Fatalf("expected exactly 2 dial attempts (original + one retry), got %d", dialCalls)
	}
}

// TestConnectWithRetryDefaultsToNoOnBlankAnswer proves leaving the retry
// prompt blank (just pressing Enter) declines the retry — required so
// holding/mashing Enter under pressure during a change window can never
// trigger an unintended retry loop against a genuinely rejected passcode.
func TestConnectWithRetryDefaultsToNoOnBlankAnswer(t *testing.T) {
	var dialCalls int
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls++
		return nil, fmt.Errorf("simulated failure")
	}
	reader := bufio.NewReader(strings.NewReader("user1\npass1\n\n"))
	cache := monitorsetup.NewCredentialCache(0)

	if _, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial); err == nil {
		t.Fatal("expected an error when the retry prompt is left blank")
	}
	if dialCalls != 1 {
		t.Fatalf("expected exactly 1 dial attempt when the retry prompt defaults to no, got %d", dialCalls)
	}
}

// TestConnectWithRetryDefaultsUsernameFromPreviousAttempt proves a retried
// attempt still offers the username just entered as the default (via
// CredentialCache.lastUsername, preserved across RecordFailure — see commit
// 6a65a63), so recovering from a mistyped password doesn't also require
// retyping a correctly-typed username.
func TestConnectWithRetryDefaultsUsernameFromPreviousAttempt(t *testing.T) {
	var dialUsers []string
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialUsers = append(dialUsers, username)
		if len(dialUsers) == 1 {
			return nil, fmt.Errorf("simulated failure")
		}
		return fakeSessionExecutor{}, nil
	}
	// First attempt: username "mretz1", wrong password. "y" to retry, then
	// a blank username line (should default to "mretz1") and fresh password.
	reader := bufio.NewReader(strings.NewReader("mretz1\nwrongpass\ny\n\ncorrectpass\n"))
	cache := monitorsetup.NewCredentialCache(0)

	if _, err := connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dialUsers) != 2 || dialUsers[0] != "mretz1" || dialUsers[1] != "mretz1" {
		t.Fatalf("expected the retry to default to the previously entered username %q, got %v", "mretz1", dialUsers)
	}
}
