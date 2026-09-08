package junosmonitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
)

// fakeIdenticalDevice mimics a Junos node answering the per-tick commands
// with fixed output — two of these stand in for two identically-configured
// nodes listed in one --devices YAML file.
type fakeIdenticalDevice struct {
	calls []string
}

func (f *fakeIdenticalDevice) Execute(cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case strings.Contains(cmd, "0/0 exact"):
		return sampleDefaultRouteNextHopOutput, nil
	case strings.Contains(cmd, "show route summary"):
		return sampleRouteSummaryTableOutput, nil
	case strings.Contains(cmd, "show bgp summary"):
		return sampleBGPSummaryOutput, nil
	default:
		return "", nil
	}
}

func (f *fakeIdenticalDevice) Close() error { return nil }

// genericFakeExecutor is a sessionExecutor that answers any command with
// placeholder text, for tests that only care about PollDevice's control
// flow (capture/diff sequencing) rather than realistic Junos output.
type genericFakeExecutor struct{}

func (f *genericFakeExecutor) Execute(cmd string) (string, error) {
	return "output for: " + cmd, nil
}

func (f *genericFakeExecutor) Close() error { return nil }

// controllableFakeExecutor is a sessionExecutor whose Execute behavior is
// scripted per command prefix, letting tests simulate a dropped session
// (BGP command failing) and a TACACS command-authorization denial (BGP
// command succeeding but returning a rejection banner instead of real
// output).
type controllableFakeExecutor struct {
	mu           sync.Mutex
	closed       bool
	failBGP      bool
	authzFailBGP bool
	callCount    int32
}

func (f *controllableFakeExecutor) Execute(cmd string) (string, error) {
	atomic.AddInt32(&f.callCount, 1)
	if f.failBGP && strings.HasPrefix(cmd, "show bgp") {
		return "", fmt.Errorf("channel closed")
	}
	if f.authzFailBGP && strings.HasPrefix(cmd, "show bgp") {
		return "Command authorization failed", nil
	}
	return "output for: " + cmd, nil
}

func (f *controllableFakeExecutor) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// TestPollDeviceAutomaticallyPrintsSnapshotDiffOnCtrlC proves PollDevice
// diffs the before/after snapshots itself right after capturing "after" on
// context cancellation (Ctrl+C), instead of requiring a second, separate
// -diff-before/-diff-after invocation to see what changed.
func TestPollDeviceAutomaticallyPrintsSnapshotDiffOnCtrlC(t *testing.T) {
	dir := t.TempDir()
	exec := &genericFakeExecutor{}
	session := &DeviceSession{hostname: "node-1", tables: []string{"CUSTOMER-A.inet.0"}, client: exec}

	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		PollDevice(ctx, session, 10*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), &syncWriter{w: &buf}, "", defaultSpec, false, nil)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollDevice did not return after context cancellation")
	}

	got := buf.String()
	if !strings.Contains(got, "snapshot diff for node-1") {
		t.Fatalf("expected an automatic snapshot diff to be printed, got: %q", got)
	}
}

// TestPollDeviceAutomaticallyPrintsRunningConfigDiffOnCtrlC proves the same
// automatic behavior extends to the running-config diff when
// --capture-running-config is enabled.
func TestPollDeviceAutomaticallyPrintsRunningConfigDiffOnCtrlC(t *testing.T) {
	dir := t.TempDir()
	exec := &genericFakeExecutor{}
	session := &DeviceSession{hostname: "node-1", tables: []string{"CUSTOMER-A.inet.0"}, client: exec}

	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		PollDevice(ctx, session, 10*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), &syncWriter{w: &buf}, "", defaultSpec, true, nil)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollDevice did not return after context cancellation")
	}

	got := buf.String()
	if !strings.Contains(got, "running-config diff:") {
		t.Fatalf("expected an automatic running-config diff to be printed, got: %q", got)
	}
}

// syncBuffer is a mutex-guarded bytes.Buffer so PollDevice's concurrent
// writers (session.log style output plus the diff report) can't race with
// the test goroutine reading buf.String() after cancel.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestCollectTickTwoIdenticalDevicesBothReportNextHop runs the full
// per-tick pipeline (collectTick then tickHeaderLine) for two
// identically-configured devices in sequence, sharing the same loaded
// parsers — regression test for a field report of the second device's
// status line missing the nexthop clause. The shared compiled TextFSM
// templates must not leak state between devices' parses.
func TestCollectTickTwoIdenticalDevicesBothReportNextHop(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}
	tables := []string{"RI-CUSTOMER-G-300001.inet.0"}

	for i, host := range []string{"node-1", "node-2"} {
		session := &DeviceSession{hostname: host, tables: tables, client: &fakeIdenticalDevice{}}
		result, alive, _ := collectTick(session, parsers, defaultSpec)
		if !alive {
			t.Fatalf("device %d: session reported dead", i+1)
		}
		if len(result.Errors) > 0 {
			t.Fatalf("device %d: unexpected tick errors: %v", i+1, result.Errors)
		}
		header := tickHeaderLine(result, true)
		if !strings.Contains(header, "nexthop 192.0.2.9") {
			t.Errorf("device %d (%s): header line missing nexthop clause: %q", i+1, host, header)
		}
	}
}

// TestCollectTickAuthorizationFailureRequestsReauth covers a TACACS
// command-authorization denial (err == nil, since the transport is fine —
// only AAA rejected the command). collectTick must report the session as
// still alive but needing reauth, not as dead.
func TestCollectTickAuthorizationFailureRequestsReauth(t *testing.T) {
	exec := &controllableFakeExecutor{authzFailBGP: true}
	session := &DeviceSession{hostname: "node-1", client: exec}

	result, alive, needsReauth := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if !alive {
		t.Fatal("expected the session to be reported alive: the transport is fine, only AAA rejected the command")
	}
	if !needsReauth {
		t.Fatal("expected needsReauth when a command's output matches the authorization-failure pattern")
	}
	if len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "authorization failed") {
		t.Fatalf("expected an authorization-failure error, got %v", result.Errors)
	}
}

// TestPollDeviceReconnectsAfterAuthorizationFailure proves PollDevice, given
// a ReauthCoordinator, closes the stale session and resumes polling against
// a freshly reconnected one after a TACACS authorization failure — the
// user-requested "restart the SSH session" behavior.
func TestPollDeviceReconnectsAfterAuthorizationFailure(t *testing.T) {
	dir := t.TempDir()
	stale := &controllableFakeExecutor{authzFailBGP: true}
	fresh := &controllableFakeExecutor{}
	session := &DeviceSession{hostname: "node-1", client: stale}

	var connectCalls int32
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		atomic.AddInt32(&connectCalls, 1)
		return fresh, nil
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "juniper_junos")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		PollDevice(ctx, session, 30*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false, reauth)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollDevice did not return after context cancellation")
	}

	if atomic.LoadInt32(&connectCalls) == 0 {
		t.Fatal("expected reauth.Reconnect to be called after the authorization failure")
	}
	stale.mu.Lock()
	staleClosed := stale.closed
	stale.mu.Unlock()
	if !staleClosed {
		t.Fatal("expected the stale session to be closed once reconnected")
	}
	if atomic.LoadInt32(&fresh.callCount) == 0 {
		t.Fatal("expected polling to resume against the reconnected session")
	}
}

// TestPollDeviceStopsWhenReconnectFails proves a failed reconnect attempt
// stops polling for that device only, rather than looping — ConnectDevice's
// own no-retry stance must hold for the reauth path too.
func TestPollDeviceStopsWhenReconnectFails(t *testing.T) {
	dir := t.TempDir()
	stale := &controllableFakeExecutor{authzFailBGP: true}
	session := &DeviceSession{hostname: "node-1", client: stale}

	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return nil, fmt.Errorf("passcode rejected")
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "juniper_junos")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		PollDevice(ctx, session, 20*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false, reauth)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected PollDevice to return after a failed reconnect")
	}

	if atomic.LoadInt32(&stale.callCount) != 1 {
		t.Fatalf("expected polling to stop after the first (failed-reconnect) tick, got %d calls", stale.callCount)
	}
}

// TestReauthCoordinatorSerializesConcurrentReconnects proves two device
// goroutines reconnecting at the same time never run the connect closure
// concurrently, so their terminal prompts can never interleave — the same
// shared-mutex design cmd/routing-monitor relies on to serialize both
// platforms' coordinators together.
func TestReauthCoordinatorSerializesConcurrentReconnects(t *testing.T) {
	var active, maxActive int32
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		n := atomic.AddInt32(&active, 1)
		for {
			cur := atomic.LoadInt32(&maxActive)
			if n <= cur {
				break
			}
			if atomic.CompareAndSwapInt32(&maxActive, cur, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return &controllableFakeExecutor{}, nil
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "juniper_junos")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = reauth.Reconnect(context.Background(), "device-a") }()
	go func() { defer wg.Done(); _, _ = reauth.Reconnect(context.Background(), "device-b") }()
	wg.Wait()

	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("expected reconnects to be serialized (max concurrent = 1), got %d", got)
	}
}

// TestPollDeviceReturnsPromptlyOnCancelDuringReauthPrompt is the regression
// test for the Ctrl+C hang: connect blocks forever (standing in for a
// credential prompt no one is answering), simulating a run being shut down
// while a device's reauth prompt is stuck waiting for human input. Without
// ReauthCoordinator.Reconnect selecting on ctx, PollDevice's goroutine — and
// therefore main's wg.Wait() and report generation — would never return.
func TestPollDeviceReturnsPromptlyOnCancelDuringReauthPrompt(t *testing.T) {
	dir := t.TempDir()
	stale := &controllableFakeExecutor{authzFailBGP: true}
	session := &DeviceSession{hostname: "node-1", client: stale}

	blockForever := make(chan struct{}) // never closed: stands in for an unanswered prompt
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		<-blockForever
		return nil, fmt.Errorf("unreachable")
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "juniper_junos")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		PollDevice(ctx, session, 20*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false, reauth)
		close(done)
	}()

	// Let the first tick hit the authorization failure and start blocking
	// inside Reconnect's connect call before cancelling.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollDevice did not return promptly after ctx cancellation while a reauth prompt was pending — Ctrl+C would hang here")
	}
}

// TestReauthCoordinatorReconnectCancelledWhileQueued proves a reconnect
// still waiting for its turn behind another device's in-progress prompt
// (not yet inside connect at all) also returns promptly on cancellation,
// and never ends up invoking connect afterward.
func TestReauthCoordinatorReconnectCancelledWhileQueued(t *testing.T) {
	sem := make(chan struct{}, 1)
	release := make(chan struct{})
	holderStarted := make(chan struct{})
	holderConnect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		close(holderStarted)
		<-release
		return &controllableFakeExecutor{}, nil
	}
	holder := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), holderConnect, "juniper_junos")
	go func() { _, _ = holder.Reconnect(context.Background(), "holder-device") }()
	<-holderStarted // holder now owns sem and is blocked inside its own connect

	var queuedConnectCalled int32
	queuedConnect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		atomic.StoreInt32(&queuedConnectCalled, 1)
		return &controllableFakeExecutor{}, nil
	}
	queued := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), queuedConnect, "juniper_junos")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := queued.Reconnect(ctx, "queued-device")
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond) // let queued.Reconnect actually start waiting on sem
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected the queued Reconnect to return an error once cancelled while waiting for its turn")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued Reconnect did not return promptly after its ctx was cancelled while waiting for the semaphore")
	}
	if atomic.LoadInt32(&queuedConnectCalled) != 0 {
		t.Fatal("expected the cancelled, still-queued reconnect to never invoke connect")
	}

	close(release)
}

// TestReauthCoordinatorHoldsSemUntilAbandonedConnectFinishes is the
// regression test for sem releasing too early: the first Reconnect call is
// cancelled while its own connect is still running, and a second, freshly
// (non-cancelled) reconnect must still be blocked from starting until the
// first, abandoned connect actually finishes — otherwise both would run
// concurrently against the same shared reader/cache.
func TestReauthCoordinatorHoldsSemUntilAbandonedConnectFinishes(t *testing.T) {
	sem := make(chan struct{}, 1)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstConnect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		close(firstStarted)
		<-releaseFirst
		return &controllableFakeExecutor{}, nil
	}
	first := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), firstConnect, "juniper_junos")

	ctx1, cancel1 := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	go func() {
		_, _ = first.Reconnect(ctx1, "device-a")
		close(firstDone)
	}()
	<-firstStarted // first now holds sem and is blocked inside its own connect

	cancel1() // abandon the first Reconnect call while its connect is still running
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first Reconnect did not return after cancellation")
	}

	// A second, fresh (non-cancelled) reconnect must NOT be able to proceed
	// yet: the abandoned first connect is still running and must still hold
	// sem, or this second attempt could run its own connect concurrently
	// with the first — racing on the shared reader/cache.
	var secondStarted int32
	secondConnect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		atomic.StoreInt32(&secondStarted, 1)
		return &controllableFakeExecutor{}, nil
	}
	second := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), secondConnect, "juniper_junos")
	secondDone := make(chan struct{})
	go func() {
		_, _ = second.Reconnect(context.Background(), "device-b")
		close(secondDone)
	}()

	time.Sleep(30 * time.Millisecond)
	if atomic.LoadInt32(&secondStarted) != 0 {
		t.Fatal("expected the second reconnect to wait for sem while the abandoned first connect is still running")
	}

	close(releaseFirst) // let the abandoned first connect finish, releasing sem

	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("second Reconnect did not proceed after the abandoned first connect released sem")
	}
	if atomic.LoadInt32(&secondStarted) == 0 {
		t.Fatal("expected the second reconnect to eventually run once sem was released")
	}
}

// TestReauthCoordinatorClosesClientFromAbandonedButSuccessfulConnect is the
// regression test for a leaked SSH session: when Reconnect is cancelled
// while its connect call is in flight, and that call later succeeds anyway,
// nobody is left to receive the new client from Reconnect's return value —
// it must be closed instead of leaking the connection.
func TestReauthCoordinatorClosesClientFromAbandonedButSuccessfulConnect(t *testing.T) {
	sem := make(chan struct{}, 1)
	abandonedClient := &controllableFakeExecutor{}
	proceed := make(chan struct{})
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		<-proceed
		return abandonedClient, nil
	}
	reauth := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "juniper_junos")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if _, err := reauth.Reconnect(ctx, "device-a"); err == nil {
			t.Error("expected an error from the cancelled Reconnect call")
		}
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // let Reconnect start waiting on its connect goroutine
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Reconnect did not return promptly after cancellation")
	}

	close(proceed) // let the abandoned connect complete successfully

	deadline := time.Now().Add(2 * time.Second)
	for {
		abandonedClient.mu.Lock()
		closed := abandonedClient.closed
		abandonedClient.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected the abandoned-but-successful client to eventually be closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestReauthCoordinatorNeverConnectsWithAlreadyCancelledContext proves the
// select race between acquiring sem and observing an already-cancelled ctx
// (both ready at once) can never let connect actually run — the recheck
// after acquiring sem must catch it every time, not just when the
// pseudo-random select happens to favor ctx.Done() on the first select.
func TestReauthCoordinatorNeverConnectsWithAlreadyCancelledContext(t *testing.T) {
	sem := make(chan struct{}, 1)
	var connectCalled int32
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		atomic.StoreInt32(&connectCalled, 1)
		return &controllableFakeExecutor{}, nil
	}
	reauth := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "juniper_junos")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Reconnect is ever called

	for i := 0; i < 50; i++ {
		if _, err := reauth.Reconnect(ctx, "device-a"); err == nil {
			t.Fatal("expected an error from Reconnect with an already-cancelled context")
		}
	}
	if atomic.LoadInt32(&connectCalled) != 0 {
		t.Fatal("expected connect to never be invoked once ctx was already cancelled")
	}
}

// TestAuthzFailurePatternOverrideMatchesMixedCaseOutput is the regression
// test for a documented override like "authorization failed" silently
// missing real device output such as "Command Authorization Failed" —
// ResolveCollectionSpec must compile an operator-provided
// authz_failure_pattern case-insensitively, the same as the built-in
// default, not literally as typed.
func TestAuthzFailurePatternOverrideMatchesMixedCaseOutput(t *testing.T) {
	spec := ResolveCollectionSpec(CommandOverrides{AuthzFailurePattern: "authorization failed"})
	if !authorizationFailed(spec, "Command Authorization Failed") {
		t.Fatal("expected a lowercase authz_failure_pattern override to still match mixed-case device output")
	}
}
