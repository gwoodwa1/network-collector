package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func routeRecordsRaw(t *testing.T, records ...map[string]string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"routes": records})
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	return raw
}

// TestDiffRouteRecordsIdentifiesAddedRemovedAndChanged proves the diff is
// keyed by prefix (NETWORK), not position: a prefix present on both sides
// at different slice positions is not reported at all unless its next hop
// actually changed.
func TestDiffRouteRecordsIdentifiesAddedRemovedAndChanged(t *testing.T) {
	before := []map[string]string{
		{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"},
		{"NETWORK": "192.0.2.39/24", "NEXTHOP": "192.0.2.1"},
		{"NETWORK": "192.0.2.37/24", "NEXTHOP": "192.0.2.1"},
	}
	after := []map[string]string{
		// same three prefixes, reordered, one with a new next hop, plus one
		// new prefix and one withdrawn.
		{"NETWORK": "192.0.2.37/24", "NEXTHOP": "192.0.2.1"},
		{"NETWORK": "192.0.2.39/24", "NEXTHOP": "192.0.2.2"},
		{"NETWORK": "192.0.2.40/24", "NEXTHOP": "192.0.2.1"},
	}

	added, removed, changed := diffRouteRecords(before, after)
	if strings.Join(added, ",") != "192.0.2.40/24" {
		t.Fatalf("expected only 192.0.2.40/24 added, got %v", added)
	}
	if strings.Join(removed, ",") != "192.0.2.12/24" {
		t.Fatalf("expected only 192.0.2.12/24 removed, got %v", removed)
	}
	if len(changed) != 1 || !strings.Contains(changed[0], "192.0.2.39/24") || !strings.Contains(changed[0], "192.0.2.1 -> 192.0.2.2") {
		t.Fatalf("expected 192.0.2.39/24's next hop change reported, got %v", changed)
	}
}

func TestDiffRouteRecordsNoChanges(t *testing.T) {
	records := []map[string]string{{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}}
	added, removed, changed := diffRouteRecords(records, records)
	if len(added) != 0 || len(removed) != 0 || len(changed) != 0 {
		t.Fatalf("expected no diff for identical route lists, got added=%v removed=%v changed=%v", added, removed, changed)
	}
}

// TestDecodeRouteRecordsDistinguishesEmptyFromRawFallback proves a
// genuinely empty route table ({"routes": []}) is told apart from a
// parser-failure fallback ({"raw": "..."}) — the latter must not be treated
// as "zero routes" or the diff would wrongly report every route on the
// other side as added/removed.
func TestDecodeRouteRecordsDistinguishesEmptyFromRawFallback(t *testing.T) {
	empty, ok := decodeRouteRecords(routeRecordsRaw(t))
	if !ok || len(empty) != 0 {
		t.Fatalf("expected an empty-but-parsed route table, got records=%v ok=%v", empty, ok)
	}

	rawFallback, err := json.Marshal(map[string]string{"raw": "unparsed output"})
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	records, ok := decodeRouteRecords(rawFallback)
	if ok {
		t.Fatalf("expected raw-fallback output to be reported as not structurally parseable, got records=%v ok=%v", records, ok)
	}
}

// TestDecodeRouteRecordsTreatsNilAsUnavailableNotEmpty proves a nil/empty
// json.RawMessage — what a neighborSnapshot field is left at when
// captureSnapshot's Execute() call for it failed (see snapshot.go: the
// neighbor loop still records a result even when one of its two Execute
// calls errors, leaving that field at its zero value) — is reported as
// unavailable, not as "successfully captured, zero routes". Getting this
// backwards would make diffSnapshots report every route on the other side
// as spuriously added or removed.
func TestDecodeRouteRecordsTreatsNilAsUnavailableNotEmpty(t *testing.T) {
	records, ok := decodeRouteRecords(nil)
	if ok {
		t.Fatalf("expected nil raw (capture-time Execute failure) to be reported as unavailable, got records=%v ok=%v", records, ok)
	}
}

// TestDecodeRouteRecordsTreatsJSONNullAsUnavailable covers the realistic
// on-disk shape of the same capture failure: a nil json.RawMessage
// marshals to the literal JSON text "null" (RawMessage.MarshalJSON's
// documented behavior for nil), so a snapshot loaded back from a captured
// .json file (see loadSnapshotFile/runSnapshotDiff) has this field as the
// 4-byte string "null", not a zero-length byte slice. Only checking
// len(raw)==0 would miss this — the field must be recognized as
// unavailable after a real file round-trip too, not just when a
// snapshotResult is constructed directly in memory (as the Go nil case
// above does).
func TestDecodeRouteRecordsTreatsJSONNullAsUnavailable(t *testing.T) {
	records, ok := decodeRouteRecords(json.RawMessage("null"))
	if ok {
		t.Fatalf("expected JSON null (a round-tripped capture failure) to be reported as unavailable, got records=%v ok=%v", records, ok)
	}
}

// TestDiffSnapshotsSkipsNeighborSectionOnCaptureFailureInsteadOfFalseDiff
// reproduces the exact shape a neighbor's Routes field has after
// snapshot.go's captureSnapshot neighbor loop suffers an Execute failure on
// one side only: the neighbor key is still present in the Neighbors map
// (captureSnapshot always assigns it), but the specific field that failed
// to execute is left as a nil json.RawMessage rather than a parsed
// {"routes": [...]} result. Before the fix, this was indistinguishable
// from "genuinely zero routes", so the diff would report every route
// visible on the other side as newly added — a fabricated result presented
// as trustworthy data during a live change window.
func TestDiffSnapshotsSkipsNeighborSectionOnCaptureFailureInsteadOfFalseDiff(t *testing.T) {
	before := snapshotResult{
		Hostname: "pe-router-1",
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {Routes: nil}, // simulates a failed "show bgp ... routes" Execute()
		},
	}
	after := snapshotResult{
		Hostname: "pe-router-1",
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {Routes: routeRecordsRaw(t,
				map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"},
				map[string]string{"NETWORK": "192.0.2.39/24", "NEXTHOP": "192.0.2.1"},
			)},
		},
	}

	sections := diffSnapshots(before, after)
	var routesSection *snapshotDiffSection
	for i := range sections {
		if sections[i].Label == "neighbor 198.51.100.1 routes" {
			routesSection = &sections[i]
		}
	}
	if routesSection == nil {
		t.Fatalf("expected a neighbor routes section, got %+v", sections)
	}
	if !routesSection.Skipped {
		t.Fatalf("expected the section to be marked Skipped due to the capture failure, got %+v — a non-skipped section here would mean the 2 real routes got reported as falsely added", routesSection)
	}
	if len(routesSection.Added) != 0 || len(routesSection.Removed) != 0 || len(routesSection.Changed) != 0 {
		t.Fatalf("expected no diff data for a skipped section, got %+v", routesSection)
	}
}

// TestDiffSnapshotsCoversVRFsAndNeighbors proves a full snapshot diff
// produces one section per VRF table and per neighbor routes/
// advertised-routes pair, and correctly finds the change in each.
func TestDiffSnapshotsCoversVRFsAndNeighbors(t *testing.T) {
	before := snapshotResult{
		Hostname: "pe-router-1",
		VRFTables: map[string]json.RawMessage{
			"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
		},
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {
				Routes:           routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.41/24", "NEXTHOP": "192.0.2.1"}),
				AdvertisedRoutes: routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.42/24", "NEXTHOP": "192.0.2.1"}),
			},
		},
	}
	after := snapshotResult{
		Hostname: "pe-router-1",
		VRFTables: map[string]json.RawMessage{
			"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.9"}),
		},
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {
				Routes:           routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.41/24", "NEXTHOP": "192.0.2.1"}),
				AdvertisedRoutes: routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.42/24", "NEXTHOP": "192.0.2.1"}, map[string]string{"NETWORK": "192.0.2.43/24", "NEXTHOP": "192.0.2.1"}),
			},
		},
	}

	sections := diffSnapshots(before, after)
	byLabel := map[string]snapshotDiffSection{}
	for _, s := range sections {
		byLabel[s.Label] = s
	}

	vrfSection, ok := byLabel["vrf 1115679"]
	if !ok || len(vrfSection.Changed) != 1 {
		t.Fatalf("expected vrf 1115679 to show one changed next hop, got %+v", vrfSection)
	}
	routesSection, ok := byLabel["neighbor 198.51.100.1 routes"]
	if !ok || !routesSection.empty() {
		t.Fatalf("expected neighbor routes to show no changes, got %+v", routesSection)
	}
	advertisedSection, ok := byLabel["neighbor 198.51.100.1 advertised-routes"]
	if !ok || strings.Join(advertisedSection.Added, ",") != "192.0.2.43/24" {
		t.Fatalf("expected neighbor advertised-routes to show 192.0.2.43/24 added, got %+v", advertisedSection)
	}
}

// TestDiffSnapshotsSkipsSectionsWithRawFallback proves a section that
// failed to parse on either side is reported as skipped rather than
// producing a misleading full-add or full-remove diff.
func TestDiffSnapshotsSkipsSectionsWithRawFallback(t *testing.T) {
	rawFallback, err := json.Marshal(map[string]string{"raw": "unparsed output"})
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	before := snapshotResult{
		Hostname:  "pe-router-1",
		VRFTables: map[string]json.RawMessage{"1115679": rawFallback},
	}
	after := snapshotResult{
		Hostname:  "pe-router-1",
		VRFTables: map[string]json.RawMessage{"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"})},
	}

	sections := diffSnapshots(before, after)
	if len(sections) != 1 || !sections[0].Skipped {
		t.Fatalf("expected one skipped section, got %+v", sections)
	}
}

// TestRunSnapshotDiffEndToEnd proves runSnapshotDiff loads two real
// captureSnapshot-shaped JSON files from disk and prints a readable report.
func TestRunSnapshotDiffEndToEnd(t *testing.T) {
	dir := t.TempDir()
	before := snapshotResult{
		Hostname:  "pe-router-1",
		Timestamp: "2026-07-10T08:00:00Z",
		VRFTables: map[string]json.RawMessage{
			"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
		},
	}
	after := snapshotResult{
		Hostname:  "pe-router-1",
		Timestamp: "2026-07-10T09:00:00Z",
		VRFTables: map[string]json.RawMessage{
			"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}, map[string]string{"NETWORK": "192.0.2.11/24", "NEXTHOP": "192.0.2.1"}),
		},
	}
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")
	writeSnapshotFixture(t, beforePath, before)
	writeSnapshotFixture(t, afterPath, after)

	var buf bytes.Buffer
	if err := runSnapshotDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "192.0.2.11/24") || !strings.Contains(got, "+ added") {
		t.Fatalf("expected the added prefix to be reported, got %q", got)
	}
	if !strings.Contains(got, "1 of 1 section(s) changed") {
		t.Fatalf("expected a summary line, got %q", got)
	}
}

// TestRunSnapshotDiffCaptureFailureDoesNotProduceFalseAddedDiff is the
// full end-to-end regression test for the neighbor-capture-failure bug:
// it writes real .json files to disk (going through an actual
// json.Marshal/Unmarshal round trip, unlike constructing a snapshotResult
// directly in memory) so a nil neighborSnapshot.Routes field is exercised
// exactly as it appears in a real captured snapshot — as the literal JSON
// text "null", not a zero-length byte slice. Before the fix, this
// round-tripped exactly the same as a genuinely empty route table, so the
// diff reported the "after" side's 2 real routes as newly added.
func TestRunSnapshotDiffCaptureFailureDoesNotProduceFalseAddedDiff(t *testing.T) {
	dir := t.TempDir()
	before := snapshotResult{
		Hostname: "pe-router-1",
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {}, // Routes/AdvertisedRoutes left nil, as if both Execute() calls failed
		},
	}
	after := snapshotResult{
		Hostname: "pe-router-1",
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {Routes: routeRecordsRaw(t,
				map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"},
				map[string]string{"NETWORK": "192.0.2.39/24", "NEXTHOP": "192.0.2.1"},
			)},
		},
	}
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")
	writeSnapshotFixture(t, beforePath, before)
	writeSnapshotFixture(t, afterPath, after)

	var buf bytes.Buffer
	if err := runSnapshotDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if strings.Contains(got, "+ added") {
		t.Fatalf("expected no fabricated \"added\" diff for a capture failure, got %q", got)
	}
	if !strings.Contains(got, "skipped") {
		t.Fatalf("expected the neighbor routes section to be reported as skipped, got %q", got)
	}
}

func TestRunSnapshotDiffMissingFile(t *testing.T) {
	if err := runSnapshotDiff(filepath.Join(t.TempDir(), "missing.json"), filepath.Join(t.TempDir(), "also-missing.json"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for a missing snapshot file")
	}
}

// TestPrintAutoDiffAfterChangeSkipsWhenCaptureFailed proves a failed
// before/after capture (snapshotCapturesOK=false) skips the diff attempt
// entirely rather than trying to read a file that was never written and
// logging a confusing second error on top of the original capture failure.
func TestPrintAutoDiffAfterChangeSkipsWhenCaptureFailed(t *testing.T) {
	dir := t.TempDir()
	session := &deviceSession{hostname: "pe-router-1", vrfs: []string{"1115679"}}
	beforeCapturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	afterCapturedAt := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	// Deliberately don't write the "before" snapshot file, simulating a
	// failed before-capture. If snapshotCapturesOK weren't honored, this
	// would try runSnapshotDiff against a nonexistent file.
	after := snapshotResult{Hostname: "pe-router-1", VRFTables: map[string]json.RawMessage{
		"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
	}}
	afterPath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "after", afterCapturedAt)+".json")
	writeSnapshotFixture(t, afterPath, after)

	var buf bytes.Buffer
	printAutoDiffAfterChange(session, dir, "", beforeCapturedAt, afterCapturedAt, false, false, true, &buf)

	if got := buf.String(); got != "" {
		t.Fatalf("expected no output when the capture failed (diff should be skipped, not attempted), got %q", got)
	}
}

// countingWriter records how many separate Write calls it received, so
// tests can assert a multi-line report was delivered as one atomic write.
type countingWriter struct {
	calls int
	buf   bytes.Buffer
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.calls++
	return w.buf.Write(p)
}

// TestPrintAutoDiffAfterChangeWritesAtomically proves the combined
// snapshot + running-config diff report is delivered to the writer in
// exactly one Write call, not many small ones — the shared syncWriter's
// mutex only serializes one Write call at a time, so concurrent devices'
// auto-diffs (all triggered by the same Ctrl+C) would otherwise be able to
// interleave line-by-line into unreadable output.
func TestPrintAutoDiffAfterChangeWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	session := &deviceSession{hostname: "pe-router-1", vrfs: []string{"1115679"}}
	beforeCapturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	afterCapturedAt := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	before := snapshotResult{Hostname: "pe-router-1", VRFTables: map[string]json.RawMessage{
		"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
	}}
	after := snapshotResult{Hostname: "pe-router-1", VRFTables: map[string]json.RawMessage{
		"1115679": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.9"}),
	}}
	beforePath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "before", beforeCapturedAt)+".json")
	afterPath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "after", afterCapturedAt)+".json")
	writeSnapshotFixture(t, beforePath, before)
	writeSnapshotFixture(t, afterPath, after)

	beforeCfgPath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "before", beforeCapturedAt)+"-running-config.txt")
	afterCfgPath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "after", afterCapturedAt)+"-running-config.txt")
	if err := os.WriteFile(beforeCfgPath, []byte("interface X\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if err := os.WriteFile(afterCfgPath, []byte("interface Y\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	wc := &countingWriter{}
	printAutoDiffAfterChange(session, dir, "", beforeCapturedAt, afterCapturedAt, true, true, true, wc)

	if wc.calls != 1 {
		t.Fatalf("expected the whole combined report in exactly one Write call, got %d calls: %q", wc.calls, wc.buf.String())
	}
	got := wc.buf.String()
	if !strings.Contains(got, "snapshot diff for") || !strings.Contains(got, "running-config diff:") {
		t.Fatalf("expected both diff reports in the single write, got %q", got)
	}
}

func writeSnapshotFixture(t *testing.T, path string, result snapshotResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
}
