package junosmonitor

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
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
		PollDevice(ctx, session, 10*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), &syncWriter{w: &buf}, "", defaultSpec, false)
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
		PollDevice(ctx, session, 10*time.Millisecond, dir, map[string]ParserModule{}, NewTickStatusPrinter(io.Discard), &syncWriter{w: &buf}, "", defaultSpec, true)
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
		result, alive := collectTick(session, parsers, defaultSpec)
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
