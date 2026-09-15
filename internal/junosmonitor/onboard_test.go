package junosmonitor

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
)

// fakeConnect simulates ConnectDevice's contract for onboarding tests
// without a real SSH/NETCONF connection: it records which netconfSnapshot
// value each host was called with, and returns a NETCONF client only when
// netconfFailsFor doesn't name the host — mirroring ConnectDevice's real
// behavior of a failed NETCONF dial never failing the SSH connection or the
// device's onboarding overall (see ConnectDevice's doc comment).
type fakeConnect struct {
	netconfFailsFor map[string]bool
	calls           map[string]bool // host -> netconfSnapshot value it was called with
}

func (f *fakeConnect) connect(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *monitorsetup.CredentialCache) (sessionExecutor, sessionExecutor, error) {
	if f.calls == nil {
		f.calls = map[string]bool{}
	}
	f.calls[host] = netconfSnapshot
	client := &genericFakeExecutor{}
	if !netconfSnapshot || f.netconfFailsFor[host] {
		return client, nil, nil
	}
	return client, &genericFakeExecutor{}, nil
}

// TestOnboardDevicesFromSpecsThreadsPerDeviceNetconfSnapshotOverride proves
// each device's resolvedNetconfSnapshot (fleet default vs. per-device
// override) is what actually reaches connect, and that the resulting
// DeviceSession.netconfClient reflects it.
func TestOnboardDevicesFromSpecsThreadsPerDeviceNetconfSnapshotOverride(t *testing.T) {
	specs := []DeviceSpec{
		{Hostname: "pe-router-1"},                                  // inherits fleet default (true)
		{Hostname: "pe-router-2", NetconfSnapshot: boolPtr(false)}, // opts out
	}
	fake := &fakeConnect{}
	registry := monitorsetup.NewHostnameRegistry()
	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "juniper_junos", true, monitorsetup.NewCredentialCache(0), registry, fake.connect)

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if !fake.calls["pe-router-1"] {
		t.Fatalf("expected pe-router-1 to inherit the fleet default (true), got calls=%v", fake.calls)
	}
	if fake.calls["pe-router-2"] {
		t.Fatalf("expected pe-router-2's explicit override (false) to win, got calls=%v", fake.calls)
	}
	byHost := map[string]*DeviceSession{}
	for _, s := range sessions {
		byHost[s.hostname] = s
	}
	if byHost["pe-router-1"].netconfClient == nil {
		t.Fatal("expected pe-router-1 to have a NETCONF client (fleet default true, dial succeeds)")
	}
	if byHost["pe-router-2"].netconfClient != nil {
		t.Fatal("expected pe-router-2 to have no NETCONF client (opted out)")
	}
}

// TestOnboardDevicesFromSpecsNetconfDialFailureStillProducesSession proves
// a NETCONF dial failure degrades gracefully: the device still gets a
// working session (SSH client set), just with netconfClient left nil,
// rather than the whole device being skipped the way an SSH failure would
// skip it.
func TestOnboardDevicesFromSpecsNetconfDialFailureStillProducesSession(t *testing.T) {
	specs := []DeviceSpec{{Hostname: "pe-router-1"}}
	fake := &fakeConnect{netconfFailsFor: map[string]bool{"pe-router-1": true}}
	registry := monitorsetup.NewHostnameRegistry()
	sessions := OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "juniper_junos", true, monitorsetup.NewCredentialCache(0), registry, fake.connect)

	if len(sessions) != 1 {
		t.Fatalf("expected the device to still onboard despite the NETCONF dial failure, got %d sessions", len(sessions))
	}
	if sessions[0].client == nil {
		t.Fatal("expected the SSH client to still be set")
	}
	if sessions[0].netconfClient != nil {
		t.Fatal("expected netconfClient to be nil after a simulated NETCONF dial failure")
	}
}

// noopDialNetconf stands in for ConnectJunosNetconfDevice in
// connectWithRetry tests that pass netconfSnapshot=false, where it must
// never actually be called.
func noopDialNetconf(t *testing.T) func(host, username, password string) (sessionExecutor, error) {
	return func(host, username, password string) (sessionExecutor, error) {
		t.Fatal("dialNetconf should never be called when netconfSnapshot is false")
		return nil, nil
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
		return &genericFakeExecutor{}, nil
	}
	reader := bufio.NewReader(strings.NewReader("mretz1\npasscode1\nSENTINEL\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, netconfClient, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client")
	}
	if netconfClient != nil {
		t.Fatal("expected no NETCONF client when netconfSnapshot is false")
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
		return &genericFakeExecutor{}, nil
	}
	// First attempt: wrong username/password. "y" to retry. Second attempt:
	// correct username/password.
	reader := bufio.NewReader(strings.NewReader("wronguser\nwrongpass\ny\ncorrectuser\ncorrectpass\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, _, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t))
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

	client, _, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t))
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
		return &genericFakeExecutor{}, nil
	}
	// Fail, retry; fail again, retry again; succeed on the third attempt.
	reader := bufio.NewReader(strings.NewReader("user1\nwrong1\ny\nuser1\nwrong2\ny\nuser1\ncorrect\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, _, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t))
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

	client, _, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t))
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

	if _, _, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t)); err == nil {
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
		return &genericFakeExecutor{}, nil
	}
	// First attempt: username "mretz1", wrong password. "y" to retry, then
	// a blank username line (should default to "mretz1") and fresh password.
	reader := bufio.NewReader(strings.NewReader("mretz1\nwrongpass\ny\n\ncorrectpass\n"))
	cache := monitorsetup.NewCredentialCache(0)

	if _, _, err := connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dialUsers) != 2 || dialUsers[0] != "mretz1" || dialUsers[1] != "mretz1" {
		t.Fatalf("expected the retry to default to the previously entered username %q, got %v", "mretz1", dialUsers)
	}
}

// TestConnectWithRetryDialsNetconfAfterSuccessfulRetry proves a
// netconfSnapshot dial still happens normally following a retried-and-then-
// successful SSH connection, using the credentials from the successful
// attempt (not the failed first one).
func TestConnectWithRetryDialsNetconfAfterSuccessfulRetry(t *testing.T) {
	var dialAttempt int
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialAttempt++
		if dialAttempt == 1 {
			return nil, fmt.Errorf("simulated failure")
		}
		return &genericFakeExecutor{}, nil
	}
	var netconfUser, netconfPassword string
	dialNetconf := func(host, username, password string) (sessionExecutor, error) {
		netconfUser = username
		netconfPassword = password
		return &genericFakeExecutor{}, nil
	}
	reader := bufio.NewReader(strings.NewReader("wronguser\nwrongpass\ny\ncorrectuser\ncorrectpass\n"))
	cache := monitorsetup.NewCredentialCache(0)

	client, netconfClient, err := connectWithRetry(reader, "host1", "juniper_junos", true, cache, dial, dialNetconf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil || netconfClient == nil {
		t.Fatal("expected both an SSH client and a NETCONF client")
	}
	if netconfUser != "correctuser" || netconfPassword != "correctpass" {
		t.Fatalf("expected the NETCONF dial to use the successful attempt's credentials (correctuser/correctpass), got %q/%q", netconfUser, netconfPassword)
	}
}
