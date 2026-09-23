package junosmonitor

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
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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

// TestOnboardDevicesFromSpecsPrintsALiveUpdatingChecklist mirrors
// xrmonitor's equivalent test: the full device checklist (from the
// --devices file, before any connection is attempted) is printed up front,
// and reprinted with each device's real outcome as onboarding proceeds.
func TestOnboardDevicesFromSpecsPrintsALiveUpdatingChecklist(t *testing.T) {
	registry := monitorsetup.NewHostnameRegistry()
	connect := func(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *monitorsetup.CredentialCache) (sessionExecutor, sessionExecutor, error) {
		if host == "router-bad" {
			return nil, nil, fmt.Errorf("simulated connect failure")
		}
		return &genericFakeExecutor{}, nil, nil
	}
	specs := []DeviceSpec{{Hostname: "router-good"}, {Hostname: "router-bad"}}

	output := captureStderr(t, func() {
		OnboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "juniper_junos", false, monitorsetup.NewCredentialCache(0), registry, connect)
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

// TestConnectWithRetryDeclinesHostKeyMismatchWithoutTouchingCredentialCache
// mirrors xrmonitor's equivalent test: a host-key mismatch must never reach
// promptRetryConnection/cache.RecordFailure as if it were a bad
// credential — it gets its own confirmation flow (PromptHostKeyMismatch),
// and declining it (not typing REPLACE, so no real network dial happens)
// ends the attempt after exactly one dial call, never prints the unrelated
// "Retry credentials?" prompt, and leaves a pre-existing valid cached
// credential untouched.
func TestConnectWithRetryDeclinesHostKeyMismatchWithoutTouchingCredentialCache(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	staleKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	dialCalls := 0
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialCalls++
		keyErr := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: staleKey, Filename: "/home/op/.ssh/known_hosts", Line: 3}}}
		return nil, fmt.Errorf("failed to open driver: %w", fmt.Errorf("ssh: handshake failed: %w", keyErr))
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
		_, _, connErr = connectWithRetry(reader, "host1", "juniper_junos", false, cache, dial, noopDialNetconf(t))
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
		return &genericFakeExecutor{}, nil
	}
	reader2 := bufio.NewReader(strings.NewReader("y\n"))
	output2 := captureStderr(t, func() {
		_, _, _ = connectWithRetry(reader2, "host2", "juniper_junos", false, cache, succeedDial, noopDialNetconf(t))
	})
	if !strings.Contains(output2, "Reuse cached passcode") {
		t.Fatalf("expected the cache to still offer reuse for the next device, got:\n%s", output2)
	}
}

// TestConnectWithRetryRefreshesHostKeyAndRetriesWithSameCredentials mirrors
// xrmonitor's equivalent test — the full end-to-end happy path through the
// real (non-injected) wiring in connectWithRetry: a mismatch is detected,
// the operator confirms REPLACE and y, hostkey.FetchPresentedKey dials a
// real (fake) SSH server to fetch its current key, known_hosts is
// rewritten, and the connection is retried with the exact same credentials
// that were typed once — no second credential prompt.
func TestConnectWithRetryRefreshesHostKeyAndRetriesWithSameCredentials(t *testing.T) {
	addr := startFakeSSHServer(t)
	stalePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	staleKey, err := ssh.NewPublicKey(stalePub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	dir := t.TempDir()
	knownHostsFile := filepath.Join(dir, "known_hosts")
	content := knownhosts.Line([]string{addr}, staleKey) + "\n"
	if err := os.WriteFile(knownHostsFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write known_hosts fixture: %v", err)
	}

	var dialUsers []string
	dial := func(host, username, password, deviceType string) (sessionExecutor, error) {
		dialUsers = append(dialUsers, username+"/"+password)
		if len(dialUsers) == 1 {
			keyErr := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: staleKey, Filename: knownHostsFile, Line: 1}}}
			return nil, fmt.Errorf("failed to open driver: %w", fmt.Errorf("ssh: handshake failed: %w", keyErr))
		}
		return &genericFakeExecutor{}, nil
	}

	cache := monitorsetup.NewCredentialCache(0)
	reader := bufio.NewReader(strings.NewReader("mretz1\ngoodpass\nREPLACE\ny\n"))
	client, _, err := connectWithRetry(reader, addr, "juniper_junos", false, cache, dial, noopDialNetconf(t))
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

// startFakeSSHServer spins up a minimal local SSH server presenting a
// generated host key, purely so hostkey.FetchPresentedKey (called for real
// by connectWithRetry, not injected) has something real to dial during the
// key-refresh flow above. It never completes authentication.
func startFakeSSHServer(t *testing.T) (addr string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}

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
