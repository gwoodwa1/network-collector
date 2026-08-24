package xrmonitor

import (
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

// fakeExecutor is a sessionExecutor whose Execute behavior is scripted per
// command prefix, letting tests simulate healthy ticks, a dropped session
// (BGP command failing), and Close() being called on shutdown.
type fakeExecutor struct {
	mu        sync.Mutex
	calls     []string
	closed    bool
	failBGP   bool
	callCount int32
}

func (f *fakeExecutor) Execute(cmd string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	f.mu.Unlock()
	atomic.AddInt32(&f.callCount, 1)
	if f.failBGP && strings.HasPrefix(cmd, "show bgp") {
		return "", fmt.Errorf("channel closed")
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

	result, alive := collectTick(session, map[string]ParserModule{}, defaultSpec)
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

	result, alive := collectTick(session, map[string]ParserModule{}, defaultSpec)
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

	result, alive := collectTick(session, map[string]ParserModule{}, defaultSpec)
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

	result, alive := collectTick(session, map[string]ParserModule{}, defaultSpec)
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

	result, alive := collectTick(session, map[string]ParserModule{}, defaultSpec)
	if alive {
		t.Fatal("expected session to be reported dead when the BGP command fails to execute")
	}
	if len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "execute failed") {
		t.Fatalf("expected an execute-failed error, got %v", result.Errors)
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
		PollDevice(ctx, session, 30*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false)
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
		PollDevice(ctx, dyingSession, 20*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false)
	}()
	go func() {
		defer wg.Done()
		PollDevice(ctx, healthySession, 20*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec, false)
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
