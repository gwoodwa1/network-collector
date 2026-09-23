package xrmonitor

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
	scrapliutil "github.com/scrapli/scrapligo/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// realisticHostKeyVerificationError builds an error shaped exactly like what
// connectWithRetry's real dial path produces in production (see
// pkg/drivers/hostkey.ClassifyConnectError's doc comment): scrapligo's
// "system" transport surfaces a host-key failure as a fixed
// "host key verification failed" message wrapping util.ErrConnectionError,
// itself wrapped by pkg/drivers/ssh.Client.connectWithProfile.
func realisticHostKeyVerificationError() error {
	inner := fmt.Errorf("%w: encountered error output during in channel ssh authentication, error: 'host key verification failed'", scrapliutil.ErrConnectionError)
	return fmt.Errorf("failed to open driver: %w", inner)
}

// stubKnownHostsFileResolver points hostkey.KnownHostsFilesResolver at file
// for the duration of the calling test, restoring the original on cleanup.
func stubKnownHostsFileResolver(t *testing.T, file string) {
	t.Helper()
	original := hostkey.KnownHostsFilesResolver
	hostkey.KnownHostsFilesResolver = func() ([]string, error) { return []string{file}, nil }
	t.Cleanup(func() { hostkey.KnownHostsFilesResolver = original })
}

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

// captureStderr temporarily redirects the real os.Stderr to a pipe for the
// duration of fn, returning everything written to it. OnboardDevicesFromSpecs
// (like the rest of onboarding) writes straight to os.Stderr rather than an
// injectable io.Writer, so this is the only way to assert on that output.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	real := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = real }()

	fn()

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return buf.String()
}

// TestOnboardDevicesFromSpecsPrintsALiveUpdatingChecklist proves the full
// device checklist (from the --devices file, before any connection is
// attempted) is printed up front, and reprinted with each device's real
// outcome as onboarding proceeds — so an operator watching a long run
// always sees progress against the whole fleet, not just whichever device
// is connecting right now.
func TestOnboardDevicesFromSpecsPrintsALiveUpdatingChecklist(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		if host == "router-bad" {
			return nil, fmt.Errorf("simulated connect failure")
		}
		return fakeSessionExecutor{}, nil
	}
	specs := []DeviceSpec{{Hostname: "router-good"}, {Hostname: "router-bad"}}

	output := captureStderr(t, func() {
		OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "cisco_iosxr", monitorsetup.NewCredentialCache(0), registry, connect, map[string]ParserModule{}, "", defaultExcludeInterfacePrefixes, defaultSpec, defaultHubTopInterfaces)
	})

	if !strings.Contains(output, "2 total, 0 connected, 0 failed, 0 skipped, 2 pending") {
		t.Fatalf("expected an initial all-pending checklist printed up front, got:\n%s", output)
	}
	if !strings.Contains(output, "2 total, 1 connected, 1 failed, 0 skipped, 0 pending") {
		t.Fatalf("expected a final checklist reprint summarizing both outcomes, got:\n%s", output)
	}
	if !strings.Contains(output, "[x] router-good") {
		t.Fatalf("expected router-good marked connected in a later checklist reprint, got:\n%s", output)
	}
	if !strings.Contains(output, "[!] router-bad") || !strings.Contains(output, "failed: simulated connect failure") {
		t.Fatalf("expected router-bad marked failed with its error in a later checklist reprint, got:\n%s", output)
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

// TestOnboardingRecoversFromFatFingeredUsernameAcrossDevices is a regression
// test for a real incident: mid-run, an operator fat-fingered a fresh RSA
// passcode into the username prompt for one device (entrcn-bpe-1a in the
// real transcript), declined the retry, and the very next device then
// offered that garbage value ("91896774") as its username default — one
// mistake cascading forward instead of staying confined to the device it
// happened on. This walks through the exact three-device shape of that
// incident (good device, fat-fingered device, next device) using the real
// connectWithRetry + CredentialCache, the same objects
// OnboardDevicesFromSpecs shares across every device in a --devices run.
func TestOnboardingRecoversFromFatFingeredUsernameAcrossDevices(t *testing.T) {
	cache := monitorsetup.NewCredentialCache(0) // isolate from the separate passcode-reuse-window feature

	// Device 1: entered correctly, connects successfully.
	dial1 := func(host, username, password, deviceType string) (sessionExecutor, error) {
		if username != "mretz1" || password != "goodpasscode1" {
			t.Fatalf("device 1: unexpected credentials %q/%q", username, password)
		}
		return fakeSessionExecutor{}, nil
	}
	reader1 := bufio.NewReader(strings.NewReader("mretz1\ngoodpasscode1\n"))
	if _, err := connectWithRetry(reader1, "entell-bpe-1a", "cisco_iosxr", cache, dial1); err != nil {
		t.Fatalf("device 1: unexpected error: %v", err)
	}

	// Device 2: the operator fat-fingers a fresh RSA passcode into the
	// username prompt (instead of pressing Enter to keep "mretz1"), the
	// connection fails, and they decline the retry ("n").
	dial2 := func(host, username, password, deviceType string) (sessionExecutor, error) {
		return nil, fmt.Errorf("errAuthError: password prompt seen multiple times, assuming authentication failed")
	}
	reader2 := bufio.NewReader(strings.NewReader("91896774\n\nn\n"))
	if _, err := connectWithRetry(reader2, "entrcn-bpe-1a", "cisco_iosxr", cache, dial2); err == nil {
		t.Fatal("device 2: expected an error (operator declined the retry)")
	}

	// Device 3: must default to "mretz1" (the last username that actually
	// authenticated), never "91896774" (the fat-fingered value from device
	// 2, which never connected).
	var device3User string
	dial3 := func(host, username, password, deviceType string) (sessionExecutor, error) {
		device3User = username
		return fakeSessionExecutor{}, nil
	}
	// Blank line accepts the offered default.
	reader3 := bufio.NewReader(strings.NewReader("\ngoodpasscode3\n"))
	if _, err := connectWithRetry(reader3, "entsov-bpe-1a", "cisco_iosxr", cache, dial3); err != nil {
		t.Fatalf("device 3: unexpected error: %v", err)
	}
	if device3User != "mretz1" {
		t.Fatalf("device 3: expected the default username to stay %q, got poisoned value %q", "mretz1", device3User)
	}
}

func generateHostKeyTestKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return signer, sshPub
}

// startFakeSSHServer spins up a minimal local SSH server presenting
// hostKey, purely so hostkey.FetchPresentedKey (called for real by
// connectWithRetry, not injected) has something real to dial during the
// key-refresh flow below. It never completes authentication.
func startFakeSSHServer(t *testing.T) (addr string) {
	t.Helper()
	signer, pub := generateHostKeyTestKey(t)
	_ = pub

	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password auth not supported by this test server")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _, _, _ = ssh.NewServerConn(c, config)
			}(conn)
		}
	}()
	return listener.Addr().String()
}

// TestConnectWithRetryDeclinesHostKeyMismatchWithoutTouchingCredentialCache
// proves a host-key mismatch never reaches promptRetryConnection/
// cache.RecordFailure — it's routed to its own confirmation flow (see
// PromptHostKeyMismatch), and declining it (not typing REPLACE, so no real
// network dial ever happens) ends the attempt cleanly, leaving a
// pre-existing valid cached credential untouched and never printing the
// unrelated "Retry credentials?" prompt.
func TestConnectWithRetryDeclinesHostKeyMismatchWithoutTouchingCredentialCache(t *testing.T) {
	_, staleKey := generateHostKeyTestKey(t)
	dir := t.TempDir()
	knownHostsFile := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHostsFile, []byte(knownhosts.Line([]string{"host1"}, staleKey)+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts fixture: %v", err)
	}
	stubKnownHostsFileResolver(t, knownHostsFile)

	dialCalls := 0
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls++
		return nil, realisticHostKeyVerificationError()
	}

	cache := monitorsetup.NewCredentialCache(45 * time.Second)
	cache.RecordSuccess("mretz1", "goodpass") // pre-existing valid cache entry

	// Accept the reuse offer ("y") — declining it invalidates the cache on
	// its own (existing, unrelated behavior), which would make this test
	// unable to isolate whether the *mismatch* decline path is the thing
	// leaving the cache untouched. Then decline the mismatch's REPLACE
	// prompt (blank line).
	reader := bufio.NewReader(strings.NewReader("y\n\n"))
	var connErr error
	output := captureStderr(t, func() {
		_, connErr = connectWithRetry(reader, "host1", "cisco_iosxr", cache, dial)
	})
	if connErr == nil {
		t.Fatal("expected an error when the operator declines to refresh the mismatched host key")
	}
	if dialCalls != 1 {
		t.Fatalf("expected exactly 1 dial attempt (no retry after declining), got %d", dialCalls)
	}
	if strings.Contains(output, "Retry credentials") {
		t.Fatalf("expected the unrelated credential-retry prompt to never be shown for a host-key mismatch, got:\n%s", output)
	}

	// cache.valid() is unexported, so prove the passcode-reuse cache
	// survived behaviorally instead: a second device sharing this cache
	// must still be offered reuse (only possible while capturedAt is still
	// set and within Window — RecordFailure would have zeroed it).
	succeedDial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		return fakeSessionExecutor{}, nil
	}
	reader2 := bufio.NewReader(strings.NewReader("y\n"))
	output2 := captureStderr(t, func() {
		_, _ = connectWithRetry(reader2, "host2", "cisco_iosxr", cache, succeedDial)
	})
	if !strings.Contains(output2, "Reuse cached passcode") {
		t.Fatalf("expected the cache to still offer reuse for the next device, got:\n%s", output2)
	}
}

// TestConnectWithRetryRefreshesHostKeyAndRetriesWithSameCredentials is the
// full end-to-end happy path through the real (non-injected) wiring in
// connectWithRetry: a mismatch is detected, the operator confirms REPLACE
// and y, hostkey.FetchPresentedKey dials a real (fake) SSH server to fetch
// its current key, known_hosts is rewritten, and the connection is retried
// with the exact same credentials that were typed once — no second
// credential prompt.
func TestConnectWithRetryRefreshesHostKeyAndRetriesWithSameCredentials(t *testing.T) {
	addr := startFakeSSHServer(t)
	_, staleKey := generateHostKeyTestKey(t)

	dir := t.TempDir()
	knownHostsFile := filepath.Join(dir, "known_hosts")
	content := knownhosts.Line([]string{addr}, staleKey) + "\n"
	if err := os.WriteFile(knownHostsFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write known_hosts fixture: %v", err)
	}
	stubKnownHostsFileResolver(t, knownHostsFile)

	var dialUsers []string
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialUsers = append(dialUsers, username+"/"+password)
		if len(dialUsers) == 1 {
			return nil, realisticHostKeyVerificationError()
		}
		return fakeSessionExecutor{}, nil
	}

	cache := monitorsetup.NewCredentialCache(0)
	reader := bufio.NewReader(strings.NewReader("mretz1\ngoodpass\nREPLACE\ny\n"))
	client, err := connectWithRetry(reader, addr, "cisco_iosxr", cache, dial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client after the key refresh succeeds")
	}
	if len(dialUsers) != 2 || dialUsers[0] != "mretz1/goodpass" || dialUsers[1] != "mretz1/goodpass" {
		t.Fatalf("expected both dial attempts to use the same credentials with no re-prompt, got %v", dialUsers)
	}

	got, err := os.ReadFile(knownHostsFile)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if strings.Contains(string(got), knownhosts.Line([]string{addr}, staleKey)) {
		t.Fatal("expected the stale entry to be replaced")
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
