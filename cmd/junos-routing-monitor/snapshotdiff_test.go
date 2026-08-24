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
// marshals to the literal JSON text "null", so a snapshot loaded back from
// a captured .json file has this field as the 4-byte string "null", not a
// zero-length byte slice.
func TestDecodeRouteRecordsTreatsJSONNullAsUnavailable(t *testing.T) {
	records, ok := decodeRouteRecords(json.RawMessage("null"))
	if ok {
		t.Fatalf("expected JSON null (a round-tripped capture failure) to be reported as unavailable, got records=%v ok=%v", records, ok)
	}
}

func TestDiffSnapshotsSkipsNeighborSectionOnCaptureFailureInsteadOfFalseDiff(t *testing.T) {
	before := snapshotResult{
		Hostname: "pe-router-1",
		Neighbors: map[string]neighborSnapshot{
			"198.51.100.1": {Routes: nil}, // simulates a failed "show route receive-protocol bgp" Execute()
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

// TestDiffSnapshotsCoversTablesAndNeighbors proves a full snapshot diff
// produces one section per routing table and per neighbor routes/
// advertised-routes pair, and correctly finds the change in each.
func TestDiffSnapshotsCoversTablesAndNeighbors(t *testing.T) {
	before := snapshotResult{
		Hostname: "pe-router-1",
		Tables: map[string]json.RawMessage{
			"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
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
		Tables: map[string]json.RawMessage{
			"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.9"}),
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

	tableSection, ok := byLabel["table CUSTOMER-A.inet.0"]
	if !ok || len(tableSection.Changed) != 1 {
		t.Fatalf("expected table CUSTOMER-A.inet.0 to show one changed next hop, got %+v", tableSection)
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
		Hostname: "pe-router-1",
		Tables:   map[string]json.RawMessage{"CUSTOMER-A.inet.0": rawFallback},
	}
	after := snapshotResult{
		Hostname: "pe-router-1",
		Tables:   map[string]json.RawMessage{"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"})},
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
		Tables: map[string]json.RawMessage{
			"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
		},
	}
	after := snapshotResult{
		Hostname:  "pe-router-1",
		Timestamp: "2026-07-10T09:00:00Z",
		Tables: map[string]json.RawMessage{
			"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}, map[string]string{"NETWORK": "192.0.2.11/24", "NEXTHOP": "192.0.2.1"}),
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
// end-to-end regression test for the neighbor-capture-failure bug: it
// writes real .json files to disk (going through an actual
// json.Marshal/Unmarshal round trip) so a nil neighborSnapshot.Routes field
// is exercised exactly as it appears in a real captured snapshot.
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
	session := &deviceSession{hostname: "pe-router-1", tables: []string{"CUSTOMER-A.inet.0"}}
	beforeCapturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	afterCapturedAt := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	// Deliberately don't write the "before" snapshot file, simulating a
	// failed before-capture. If snapshotCapturesOK weren't honored, this
	// would try runSnapshotDiff against a nonexistent file.
	after := snapshotResult{Hostname: "pe-router-1", Tables: map[string]json.RawMessage{
		"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
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
// tests can assert the diff report was delivered as one atomic write.
type countingWriter struct {
	calls int
	buf   bytes.Buffer
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.calls++
	return w.buf.Write(p)
}

// TestPrintAutoDiffAfterChangeWritesAtomically proves the diff report is
// delivered to the writer in exactly one Write call, not many small ones —
// the shared syncWriter's mutex only serializes one Write call at a time,
// so concurrent devices' auto-diffs (all triggered by the same Ctrl+C)
// could otherwise interleave line-by-line into unreadable output.
func TestPrintAutoDiffAfterChangeWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	session := &deviceSession{hostname: "pe-router-1", tables: []string{"CUSTOMER-A.inet.0"}}
	beforeCapturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	afterCapturedAt := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	before := snapshotResult{Hostname: "pe-router-1", Tables: map[string]json.RawMessage{
		"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.1"}),
	}}
	after := snapshotResult{Hostname: "pe-router-1", Tables: map[string]json.RawMessage{
		"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.12/24", "NEXTHOP": "192.0.2.9"}),
	}}
	beforePath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "before", beforeCapturedAt)+".json")
	afterPath := filepath.Join(dir, snapshotFilenameBase("", "pe-router-1", "after", afterCapturedAt)+".json")
	writeSnapshotFixture(t, beforePath, before)
	writeSnapshotFixture(t, afterPath, after)

	wc := &countingWriter{}
	printAutoDiffAfterChange(session, dir, "", beforeCapturedAt, afterCapturedAt, false, true, true, wc)

	if wc.calls != 1 {
		t.Fatalf("expected the whole report in exactly one Write call, got %d calls: %q", wc.calls, wc.buf.String())
	}
	got := wc.buf.String()
	if !strings.Contains(got, "snapshot diff for") {
		t.Fatalf("expected the diff report in the single write, got %q", got)
	}
}

// TestDiffRecordsByKeyMultiFieldFormatsEachChangedField proves that,
// unlike diffRouteRecords's single-field ("key (old -> new)") format,
// watching more than one changeFields prefixes each differing field with
// its name so the reader can tell which one moved.
func TestDiffRecordsByKeyMultiFieldFormatsEachChangedField(t *testing.T) {
	before := []map[string]string{{"PEER_ADDRESS": "192.0.2.1", "PEER_STATE": "Established", "ACTIVE_PREFIX_COUNT": "4"}}
	after := []map[string]string{{"PEER_ADDRESS": "192.0.2.1", "PEER_STATE": "Idle", "ACTIVE_PREFIX_COUNT": "0"}}

	_, _, changed := diffRecordsByKey(before, after, "PEER_ADDRESS", "PEER_STATE", "ACTIVE_PREFIX_COUNT")
	if len(changed) != 1 {
		t.Fatalf("expected one changed record, got %v", changed)
	}
	if !strings.Contains(changed[0], "PEER_STATE Established -> Idle") || !strings.Contains(changed[0], "ACTIVE_PREFIX_COUNT 4 -> 0") {
		t.Fatalf("expected both changed fields named in the report, got %q", changed[0])
	}
}

// TestDiffRecordsByKeyNoChangeFieldsIsPresenceOnly proves that omitting
// changeFields entirely (used for alarms/core-dumps) never reports a
// "changed" entry — only added/removed, since presence is the only signal
// for those sections.
func TestDiffRecordsByKeyNoChangeFieldsIsPresenceOnly(t *testing.T) {
	before := []map[string]string{{"KEY": "Minor|Fan removed"}}
	after := []map[string]string{{"KEY": "Minor|Fan removed"}, {"KEY": "Major|PSU failed"}}

	added, removed, changed := diffRecordsByKey(before, after, "KEY")
	if len(changed) != 0 {
		t.Fatalf("expected no changed entries with zero changeFields, got %v", changed)
	}
	if strings.Join(added, ",") != "Major|PSU failed" || len(removed) != 0 {
		t.Fatalf("expected only the new alarm added, got added=%v removed=%v", added, removed)
	}
}

// TestDiffSnapshotsIncludesNetconfBGPNeighborDetailSection proves a
// NETCONF-sourced section (present only when NetconfDetail is set) is
// picked up by diffSnapshots and reports a PEER_STATE flap the same way a
// route table reports a next-hop change.
func TestDiffSnapshotsIncludesNetconfBGPNeighborDetailSection(t *testing.T) {
	bgpRaw := func(state string) json.RawMessage {
		raw, err := json.Marshal(map[string]any{"bgp_neighbors": []map[string]string{{"PEER_ADDRESS": "192.0.2.1", "PEER_STATE": state}}})
		if err != nil {
			t.Fatalf("failed to marshal fixture: %v", err)
		}
		return raw
	}
	before := snapshotResult{Hostname: "pe-router-1", NetconfDetail: &netconfSnapshotDetail{BGPNeighborDetail: bgpRaw("Established")}}
	after := snapshotResult{Hostname: "pe-router-1", NetconfDetail: &netconfSnapshotDetail{BGPNeighborDetail: bgpRaw("Idle")}}

	sections := diffSnapshots(before, after)
	var found bool
	for _, section := range sections {
		if section.Label != "netconf bgp neighbor detail" {
			continue
		}
		found = true
		if len(section.Changed) != 1 || !strings.Contains(section.Changed[0], "Established -> Idle") {
			t.Fatalf("expected the peer state flap reported, got %+v", section)
		}
	}
	if !found {
		t.Fatalf("expected a %q section, got %+v", "netconf bgp neighbor detail", sections)
	}
}

// TestDiffSnapshotsOmitsNetconfSectionsWhenNeitherSideUsedNetconf proves a
// device that never opted into NETCONF snapshot capture doesn't get 11
// spurious "skipped" NETCONF sections cluttering its diff report.
func TestDiffSnapshotsOmitsNetconfSectionsWhenNeitherSideUsedNetconf(t *testing.T) {
	before := snapshotResult{Hostname: "pe-router-1", Tables: map[string]json.RawMessage{
		"CUSTOMER-A.inet.0": routeRecordsRaw(t, map[string]string{"NETWORK": "192.0.2.0/24", "NEXTHOP": "192.0.2.1"}),
	}}
	after := before

	sections := diffSnapshots(before, after)
	for _, section := range sections {
		if strings.HasPrefix(section.Label, "netconf ") {
			t.Fatalf("expected no netconf sections when NetconfDetail is nil on both sides, got %q", section.Label)
		}
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
