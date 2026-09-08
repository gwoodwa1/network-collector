package xrmonitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
)

// TestResolveCollectionSpecOverridesOnlyNonEmptyFields guards the
// --devices file "commands:" override mechanism (added so an operator can
// point this tool at a different show-command or parser without patching
// Go source and rebuilding): every unset override field must fall back to
// defaultSpec, and setting one field must never blank out the others.
func TestResolveCollectionSpecOverridesOnlyNonEmptyFields(t *testing.T) {
	spec := ResolveCollectionSpec(CommandOverrides{BGPCommand: "show bgp summary"})
	if spec.BGPCommand != "show bgp summary" {
		t.Fatalf("expected overridden BGP command, got %q", spec.BGPCommand)
	}
	if spec.BGPParser != defaultSpec.BGPParser || spec.RouteCommand != defaultSpec.RouteCommand ||
		spec.RouteParser != defaultSpec.RouteParser || spec.InterfaceCommand != defaultSpec.InterfaceCommand ||
		spec.InterfaceParser != defaultSpec.InterfaceParser {
		t.Fatalf("expected every other field to fall back to defaultSpec, got %+v", spec)
	}
}

func TestResolveCollectionSpecNoOverridesMatchesDefault(t *testing.T) {
	if got := ResolveCollectionSpec(CommandOverrides{}); got != defaultSpec {
		t.Fatalf("expected defaultSpec unchanged, got %+v", got)
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

// fakeExecutor is a sessionExecutor whose Execute behavior is scripted per
// command prefix, letting tests simulate healthy ticks, a dropped session
// (BGP command failing), and Close() being called on shutdown.
type fakeExecutor struct {
	mu           sync.Mutex
	calls        []string
	closed       bool
	failBGP      bool
	authzFailBGP bool
	callCount    int32
}

func (f *fakeExecutor) Execute(cmd string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	f.mu.Unlock()
	atomic.AddInt32(&f.callCount, 1)
	if f.failBGP && strings.HasPrefix(cmd, "show bgp") {
		return "", fmt.Errorf("channel closed")
	}
	if f.authzFailBGP && strings.HasPrefix(cmd, "show bgp") {
		return "Command authorization failed", nil
	}
	return "output for: " + cmd, nil
}

func (f *fakeExecutor) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestCollectTickHappyPathAllFieldsPopulated(t *testing.T) {
	exec := &fakeExecutor{}
	session := &DeviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A"}, coreInterfaces: []string{"Bundle-Ether10"}, client: exec}

	result, alive, _ := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if !alive {
		t.Fatal("expected session to remain alive")
	}
	if result.Hostname != "xr1" {
		t.Fatalf("unexpected hostname: %s", result.Hostname)
	}
	if result.BGP == nil {
		t.Fatal("expected bgp result to be populated")
	}
	if _, ok := result.Routes["CUSTOMER-A"]; !ok {
		t.Fatal("expected route result for VRF CUSTOMER-A to be populated")
	}
	if _, ok := result.Interfaces["Bundle-Ether10"]; !ok {
		t.Fatal("expected Bundle-Ether10 interface result to be populated")
	}
	// No parsers are registered yet, so every field should fall back to raw
	// output rather than erroring the whole tick.
	var bgpRaw map[string]string
	if err := json.Unmarshal(result.BGP, &bgpRaw); err != nil {
		t.Fatalf("expected raw fallback JSON for bgp: %v", err)
	}
	if !strings.Contains(bgpRaw["raw"], "show bgp vpnv4 unicast summary") {
		t.Fatalf("unexpected raw bgp output: %q", bgpRaw["raw"])
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected parser-not-found errors to be recorded even though the tick succeeded")
	}
}

// TestCollectTickMultipleVRFsEachGetOwnRouteCommand covers a device
// monitoring more than one VRF at once (e.g. a manually specified core VRF
// plus one or more auto-detected customer VRFs, see DeviceSession.vrfs) —
// each must get its own "show route vrf <name> summary" command and its own
// entry in the result, keyed by VRF name.
func TestCollectTickMultipleVRFsEachGetOwnRouteCommand(t *testing.T) {
	exec := &fakeExecutor{}
	session := &DeviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A", "4000001"}, client: exec}

	result, alive, _ := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if !alive {
		t.Fatal("expected session to remain alive")
	}
	if len(result.Routes) != 2 {
		t.Fatalf("expected 2 route results, got %d: %+v", len(result.Routes), result.Routes)
	}
	for _, vrf := range []string{"CUSTOMER-A", "4000001"} {
		if _, ok := result.Routes[vrf]; !ok {
			t.Fatalf("expected a route result for VRF %s, got: %+v", vrf, result.Routes)
		}
	}
	wantCalls := []string{
		"show bgp vpnv4 unicast summary",
		"show route vrf CUSTOMER-A summary",
		"show route vrf CUSTOMER-A 0.0.0.0/0 detail",
		"show route vrf 4000001 summary",
		"show route vrf 4000001 0.0.0.0/0 detail",
	}
	if len(exec.calls) != len(wantCalls) {
		t.Fatalf("expected calls %v, got %v", wantCalls, exec.calls)
	}
	for i, want := range wantCalls {
		if exec.calls[i] != want {
			t.Fatalf("call %d: expected %q, got %q", i, want, exec.calls[i])
		}
	}
}

func TestCollectTickOnlyExecutesIdentifiedVRFAndInterfaces(t *testing.T) {
	exec := &fakeExecutor{}
	session := &DeviceSession{
		hostname:           "xr1",
		vrfs:               []string{"4000001"},
		coreInterfaces:     []string{"BE45"},
		customerInterfaces: []string{"GigabitEthernet0/0/0/1.100"},
		client:             exec,
	}

	result, alive, _ := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if !alive {
		t.Fatal("expected session to remain alive")
	}
	if len(result.Routes) != 1 {
		t.Fatalf("expected exactly one VRF route result, got %+v", result.Routes)
	}
	if _, ok := result.Routes["4000001"]; !ok {
		t.Fatalf("expected route result only for identified VRF 4000001, got %+v", result.Routes)
	}
	if len(result.Interfaces) != 2 {
		t.Fatalf("expected exactly the identified core and customer interfaces, got %+v", result.Interfaces)
	}
	for _, iface := range []string{"BE45", "GigabitEthernet0/0/0/1.100"} {
		if _, ok := result.Interfaces[iface]; !ok {
			t.Fatalf("expected interface result for %s, got %+v", iface, result.Interfaces)
		}
	}

	wantCalls := []string{
		"show bgp vpnv4 unicast summary",
		"show route vrf 4000001 summary",
		"show route vrf 4000001 0.0.0.0/0 detail",
		`show int BE45 | inc "rate|Description:"`,
		`show int GigabitEthernet0/0/0/1.100 | inc "rate|Description:"`,
	}
	if strings.Join(exec.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("expected only identified tick commands:\n%v\ngot:\n%v", wantCalls, exec.calls)
	}
	for _, forbidden := range []string{"CUSTOMER-A-INTERNET", "TenGigE0/0/0/2.200"} {
		if strings.Contains(strings.Join(exec.calls, "\n"), forbidden) {
			t.Fatalf("tick executed command for non-identified target %q: %v", forbidden, exec.calls)
		}
	}
}

func TestCollectTickSkipsOptionalFieldsWhenNotConfigured(t *testing.T) {
	exec := &fakeExecutor{}
	session := &DeviceSession{hostname: "xr1", client: exec}

	result, alive, _ := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if !alive {
		t.Fatal("expected session to remain alive")
	}
	if result.Routes != nil {
		t.Fatal("expected route to be skipped when no VRF was configured")
	}
	if result.Interfaces != nil {
		t.Fatal("expected interfaces to be skipped when none were configured")
	}
}

func TestCollectTickBGPExecuteFailureMarksSessionDead(t *testing.T) {
	exec := &fakeExecutor{failBGP: true}
	session := &DeviceSession{hostname: "xr1", client: exec}

	result, alive, _ := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if alive {
		t.Fatal("expected session to be reported dead when the BGP command fails to execute")
	}
	if len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "execute failed") {
		t.Fatalf("expected an execute-failed error, got %v", result.Errors)
	}
}

// TestCollectTickAuthorizationFailureRequestsReauth covers the confirmed
// real-world case: the device answers a command with a TACACS
// command-authorization denial (err == nil, since the transport is fine —
// only AAA rejected the command). collectTick must report the session as
// still alive but needing reauth, not as dead.
func TestCollectTickAuthorizationFailureRequestsReauth(t *testing.T) {
	exec := &fakeExecutor{authzFailBGP: true}
	session := &DeviceSession{hostname: "xr1", client: exec}

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
	stale := &fakeExecutor{authzFailBGP: true}
	fresh := &fakeExecutor{}
	session := &DeviceSession{hostname: "xr1", client: stale}

	var connectCalls int32
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		atomic.AddInt32(&connectCalls, 1)
		return fresh, nil
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "cisco_iosxr")

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
// (e.g. a rejected passcode) stops polling for that device only, rather than
// looping — ConnectDevice's own no-retry stance (avoiding RSA/ISE lockout)
// must hold for the reauth path too.
func TestPollDeviceStopsWhenReconnectFails(t *testing.T) {
	dir := t.TempDir()
	stale := &fakeExecutor{authzFailBGP: true}
	session := &DeviceSession{hostname: "xr1", client: stale}

	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		return nil, fmt.Errorf("passcode rejected")
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "cisco_iosxr")

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
// goroutines reconnecting at the same time never run ConnectDevice's
// prompt-and-connect sequence concurrently — required so their terminal
// prompts (username/passcode) never interleave, per the shared-mutex design
// used by cmd/routing-monitor to serialize both platforms' coordinators too.
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
		return &fakeExecutor{}, nil
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "cisco_iosxr")

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
	stale := &fakeExecutor{authzFailBGP: true}
	session := &DeviceSession{hostname: "xr1", client: stale}

	blockForever := make(chan struct{}) // never closed: stands in for an unanswered prompt
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		<-blockForever
		return nil, fmt.Errorf("unreachable")
	}
	reauth := NewReauthCoordinator(make(chan struct{}, 1), bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "cisco_iosxr")

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
		return &fakeExecutor{}, nil
	}
	holder := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), holderConnect, "cisco_iosxr")
	go func() { _, _ = holder.Reconnect(context.Background(), "holder-device") }()
	<-holderStarted // holder now owns sem and is blocked inside its own connect

	var queuedConnectCalled int32
	queuedConnect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		atomic.StoreInt32(&queuedConnectCalled, 1)
		return &fakeExecutor{}, nil
	}
	queued := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), queuedConnect, "cisco_iosxr")

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
		return &fakeExecutor{}, nil
	}
	first := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), firstConnect, "cisco_iosxr")

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
		return &fakeExecutor{}, nil
	}
	second := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), secondConnect, "cisco_iosxr")
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
	abandonedClient := &fakeExecutor{}
	proceed := make(chan struct{})
	connect := func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
		<-proceed
		return abandonedClient, nil
	}
	reauth := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "cisco_iosxr")

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
		return &fakeExecutor{}, nil
	}
	reauth := NewReauthCoordinator(sem, bufio.NewReader(strings.NewReader("")), monitorsetup.NewCredentialCache(0), connect, "cisco_iosxr")

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

func TestPollDeviceWritesJSONLAndStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &DeviceSession{hostname: "xr1", client: exec}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		PollDevice(ctx, session, 30*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollDevice did not return after context cancellation")
	}

	exec.mu.Lock()
	closed := exec.closed
	exec.mu.Unlock()
	if !closed {
		t.Fatal("expected session to be closed when polling stops")
	}

	data, err := os.ReadFile(filepath.Join(dir, "xr1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 ticks (immediate + 1 interval) to be written, got %d: %s", len(lines), data)
	}
	for _, line := range lines {
		var decoded tickResult
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("failed to decode JSONL line %q: %v", line, err)
		}
		if decoded.Hostname != "xr1" {
			t.Fatalf("unexpected hostname in line: %q", line)
		}
	}
}

func TestPollDeviceStopsOnDroppedSessionWithoutBlockingOthers(t *testing.T) {
	dir := t.TempDir()
	dying := &fakeExecutor{failBGP: true}
	healthy := &fakeExecutor{}
	dyingSession := &DeviceSession{hostname: "dying", client: dying}
	healthySession := &DeviceSession{hostname: "healthy", client: healthy}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		PollDevice(ctx, dyingSession, 20*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false, nil)
	}()
	go func() {
		defer wg.Done()
		PollDevice(ctx, healthySession, 20*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false, nil)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected both PollDevice goroutines to return")
	}

	if atomic.LoadInt32(&dying.callCount) != 1 {
		t.Fatalf("expected the dying session to stop after its first failed tick, got %d calls", dying.callCount)
	}
	if atomic.LoadInt32(&healthy.callCount) <= dying.callCount {
		t.Fatalf("expected the healthy session to keep polling after the other session died: healthy=%d dying=%d", healthy.callCount, dying.callCount)
	}

	dyingData, err := os.ReadFile(filepath.Join(dir, "dying.jsonl"))
	if err != nil {
		t.Fatalf("failed to read dying device output: %v", err)
	}
	if len(strings.Split(strings.TrimSpace(string(dyingData)), "\n")) != 1 {
		t.Fatalf("expected exactly one tick recorded for the dying device, got: %s", dyingData)
	}
}

func TestSanitizeFilename(t *testing.T) {
	if got := sanitizeFilename("192.0.2.13"); got != "192.0.2.13" {
		t.Fatalf("unexpected sanitized name: %q", got)
	}
	if got := sanitizeFilename("xr-router 1/edge"); got != "xr-router_1_edge" {
		t.Fatalf("unexpected sanitized name: %q", got)
	}
}
