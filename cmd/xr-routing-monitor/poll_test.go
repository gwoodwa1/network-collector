package main

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
	session := &deviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A"}, interfaces: []string{"Bundle-Ether10"}, client: exec}

	result, alive := collectTick(session, map[string]parserModule{})
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
// plus one or more auto-detected customer VRFs, see deviceSession.vrfs) —
// each must get its own "show route vrf <name> summary" command and its own
// entry in the result, keyed by VRF name.
func TestCollectTickMultipleVRFsEachGetOwnRouteCommand(t *testing.T) {
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A", "4000001"}, client: exec}

	result, alive := collectTick(session, map[string]parserModule{})
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
		"show route vrf 4000001 summary",
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

func TestCollectTickSkipsOptionalFieldsWhenNotConfigured(t *testing.T) {
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "xr1", client: exec}

	result, alive := collectTick(session, map[string]parserModule{})
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
	session := &deviceSession{hostname: "xr1", client: exec}

	result, alive := collectTick(session, map[string]parserModule{})
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
	session := &deviceSession{hostname: "xr1", client: exec}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		pollDevice(ctx, session, 30*time.Millisecond, dir, map[string]parserModule{}, newTickStatusPrinter(io.Discard), io.Discard, "")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pollDevice did not return after context cancellation")
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
	dyingSession := &deviceSession{hostname: "dying", client: dying}
	healthySession := &deviceSession{hostname: "healthy", client: healthy}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pollDevice(ctx, dyingSession, 20*time.Millisecond, dir, map[string]parserModule{}, newTickStatusPrinter(io.Discard), io.Discard, "")
	}()
	go func() {
		defer wg.Done()
		pollDevice(ctx, healthySession, 20*time.Millisecond, dir, map[string]parserModule{}, newTickStatusPrinter(io.Discard), io.Discard, "")
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected both pollDevice goroutines to return")
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
	if got := sanitizeFilename("10.0.0.1"); got != "10.0.0.1" {
		t.Fatalf("unexpected sanitized name: %q", got)
	}
	if got := sanitizeFilename("xr-router 1/edge"); got != "xr-router_1_edge" {
		t.Fatalf("unexpected sanitized name: %q", got)
	}
}
