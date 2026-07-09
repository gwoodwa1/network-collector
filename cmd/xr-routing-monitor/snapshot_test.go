package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptedExecutor returns a specific canned response per exact command,
// falling back to an empty string for anything unscripted. Used to feed
// real sample device output into captureSnapshot so the actual production
// parsing path (not just parseOutputWithModule in isolation) is exercised.
type scriptedExecutor struct {
	responses map[string]string
}

func (s *scriptedExecutor) Execute(cmd string) (string, error) {
	return s.responses[cmd], nil
}

func (s *scriptedExecutor) Close() error { return nil }

func TestSnapshotFilenameBase(t *testing.T) {
	capturedAt := time.Date(2026, 7, 9, 14, 30, 22, 0, time.UTC)

	got := snapshotFilenameBase("CRQXXX", "pe-router-1", "before", capturedAt)
	want := "CRQXXX-pe-router-1-20260709-143022-before"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}

	gotNoRunLabel := snapshotFilenameBase("", "pe-router-1", "after", capturedAt)
	wantNoRunLabel := "pe-router-1-20260709-143022-after"
	if gotNoRunLabel != wantNoRunLabel {
		t.Fatalf("expected %q, got %q", wantNoRunLabel, gotNoRunLabel)
	}
}

// TestCaptureSnapshotUsesRunLabelInFilename locks in that a non-empty
// runLabel (main.go derives this from the --devices YAML file's basename,
// e.g. "CRQXXX" for a dedicated per-change devices file) actually reaches
// the written filename, not just snapshotFilenameBase in isolation.
func TestCaptureSnapshotUsesRunLabelInFilename(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "pe-router-1", vrfs: []string{"CUSTOMER-A-INTERNET"}, client: exec}

	if err := captureSnapshot(session, "before", dir, "CRQXXX", map[string]parserModule{}, io.Discard); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "CRQXXX-pe-router-1-*-before.txt"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one CRQXXX-prefixed snapshot file, found: %v", matches)
	}
}

func TestCaptureSnapshotSkippedWhenNothingConfigured(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "xr1", client: exec}

	if err := captureSnapshot(session, "before", dir, "", map[string]parserModule{}, io.Discard); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("expected no commands to be executed, got %v", exec.calls)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "xr1-*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no snapshot file to be written, found: %v", matches)
	}
}

func TestCaptureSnapshotWritesVRFAndNeighborSections(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &deviceSession{
		hostname:  "xr1",
		vrfs:      []string{"CUSTOMER-A-INTERNET"},
		neighbors: []string{"198.51.100.1"},
		client:    exec,
	}

	if err := captureSnapshot(session, "before", dir, "", map[string]parserModule{}, io.Discard); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantCalls := []string{
		"show bgp vrf CUSTOMER-A-INTERNET",
		"show bgp vpnv4 unicast neighbors 198.51.100.1 routes",
		"show bgp vpnv4 unicast neighbors 198.51.100.1 advertised-routes",
	}
	if len(exec.calls) != len(wantCalls) {
		t.Fatalf("expected calls %v, got %v", wantCalls, exec.calls)
	}
	for i, want := range wantCalls {
		if exec.calls[i] != want {
			t.Fatalf("call %d: expected %q, got %q", i, want, exec.calls[i])
		}
	}

	matches, err := filepath.Glob(filepath.Join(dir, "xr1-*-before.txt"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one xr1-*-before.txt snapshot file, found: %v", matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("failed to read snapshot file: %v", err)
	}
	content := string(data)
	for _, want := range wantCalls {
		if !strings.Contains(content, want) {
			t.Fatalf("expected snapshot content to contain %q, got:\n%s", want, content)
		}
	}
}

// TestCaptureSnapshotMultipleVRFsEachGetOwnSection covers a device
// monitoring more than one VRF (see deviceSession.vrfs) — each must get its
// own "show bgp vrf <name>" command and its own entry in VRFTables, keyed
// by VRF name, rather than only the last one surviving.
func TestCaptureSnapshotMultipleVRFsEachGetOwnSection(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A-INTERNET", "4000001"}, client: exec}

	if err := captureSnapshot(session, "before", dir, "", map[string]parserModule{}, io.Discard); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantCalls := []string{
		"show bgp vrf CUSTOMER-A-INTERNET",
		"show bgp vrf 4000001",
	}
	if len(exec.calls) != len(wantCalls) {
		t.Fatalf("expected calls %v, got %v", wantCalls, exec.calls)
	}
	for i, want := range wantCalls {
		if exec.calls[i] != want {
			t.Fatalf("call %d: expected %q, got %q", i, want, exec.calls[i])
		}
	}

	matches, err := filepath.Glob(filepath.Join(dir, "xr1-*-before.json"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one xr1-*-before.json snapshot file, found: %v", matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("failed to read snapshot file: %v", err)
	}
	var decoded snapshotResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to decode structured snapshot: %v", err)
	}
	for _, vrf := range []string{"CUSTOMER-A-INTERNET", "4000001"} {
		if _, ok := decoded.VRFTables[vrf]; !ok {
			t.Fatalf("expected a vrf_tables entry for %s, got: %+v", vrf, decoded.VRFTables)
		}
	}
}

// TestCaptureSnapshotWritesConfirmationToProvidedWriter locks in that the
// success confirmation goes wherever the caller points it (main.go points
// this at both os.Stderr and session.log, so the confirmation survives even
// if the operator isn't watching the terminal live) rather than being
// hardcoded to os.Stderr only.
func TestCaptureSnapshotWritesConfirmationToProvidedWriter(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A-INTERNET"}, client: exec}

	var buf bytes.Buffer
	if err := captureSnapshot(session, "before", dir, "", map[string]parserModule{}, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "before-change snapshot captured for xr1") {
		t.Fatalf("expected confirmation to be written to the provided writer, got: %q", buf.String())
	}
}

// TestCaptureSnapshotParsesRealNeighborRoutesOutput exercises the actual
// captureSnapshot code path (not just parseOutputWithModule in isolation)
// against real sample output for the neighbor-routes command, using the
// binary's real embedded parsers rather than an empty map. This closes the
// gap where snapshot.go's neighbor-routes call to xr_bgp_route_table had no
// fixture proving that command's real output actually matches what the
// parser expects — a mismatch there would have silently fallen back to
// {"raw": ...} instead of structured JSON, which parseOrRaw would hide.
func TestCaptureSnapshotParsesRealNeighborRoutesOutput(t *testing.T) {
	dir := t.TempDir()
	neighbor := "198.51.100.101"
	exec := &scriptedExecutor{responses: map[string]string{
		"show bgp vpnv4 unicast neighbors " + neighbor + " routes":            sampleBGPNeighborRoutesOutput,
		"show bgp vpnv4 unicast neighbors " + neighbor + " advertised-routes": sampleBGPAdvertisedRoutesOutput,
	}}
	session := &deviceSession{hostname: "xr1", neighbors: []string{neighbor}, client: exec}

	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	if err := captureSnapshot(session, "before", dir, "", parsers, io.Discard); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "xr1-*-before.json"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one xr1-*-before.json snapshot file, found: %v", matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("failed to read structured snapshot: %v", err)
	}
	var decoded snapshotResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to decode structured snapshot: %v", err)
	}
	if len(decoded.Errors) != 0 {
		t.Fatalf("expected no parse errors, got: %v", decoded.Errors)
	}
	neighborResult, ok := decoded.Neighbors[neighbor]
	if !ok {
		t.Fatalf("expected a snapshot entry for neighbor %s, got: %+v", neighbor, decoded.Neighbors)
	}

	var routes struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(neighborResult.Routes, &routes); err != nil {
		t.Fatalf("neighbor routes did not decode as structured route records (likely fell back to raw text): %v\ncontent: %s", err, neighborResult.Routes)
	}
	if len(routes.Routes) != 5 {
		t.Fatalf("expected 5 structured route records from the real neighbor-routes sample, got %d: %s", len(routes.Routes), neighborResult.Routes)
	}
	if _, hasRaw := routes.Routes[0]["raw"]; hasRaw {
		t.Fatalf("neighbor routes fell back to raw output instead of parsing: %+v", routes.Routes[0])
	}
}

func TestPollDeviceCapturesBeforeAndAfterSnapshots(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	session := &deviceSession{hostname: "xr1", vrfs: []string{"CUSTOMER-A"}, client: exec}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollDevice(ctx, session, 10*time.Millisecond, dir, map[string]parserModule{}, newTickStatusPrinter(io.Discard), io.Discard, "", defaultSpec)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pollDevice did not return after context cancellation")
	}

	for _, label := range []string{"before", "after"} {
		matches, err := filepath.Glob(filepath.Join(dir, "xr1-*-"+label+".txt"))
		if err != nil {
			t.Fatalf("glob failed: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("expected exactly one %s snapshot to exist, found: %v", label, matches)
		}
	}
}
