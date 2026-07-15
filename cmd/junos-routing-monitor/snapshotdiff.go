package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// snapshotDiffSection is one labeled route table's before/after comparison
// — a routing table, or one neighbor's received/advertised routes — keyed
// by prefix (NETWORK) rather than compared positionally: BGP route tables
// can reorder between two captures with no real change, so a prefix
// present in both, even at a different index, is not a diff. Only a
// genuinely new/withdrawn prefix, or one whose next hop changed, is
// reported.
type snapshotDiffSection struct {
	Label   string
	Skipped bool
	Added   []string
	Removed []string
	Changed []string
}

func (s snapshotDiffSection) empty() bool {
	return len(s.Added) == 0 && len(s.Removed) == 0 && len(s.Changed) == 0
}

// loadSnapshotFile reads and decodes one of captureSnapshot's structured
// <base>.json outputs (see snapshot.go).
func loadSnapshotFile(path string) (snapshotResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return snapshotResult{}, err
	}
	var result snapshotResult
	if err := json.Unmarshal(b, &result); err != nil {
		return snapshotResult{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return result, nil
}

// decodeRouteRecords unpacks one table's or neighbor route list's raw JSON
// (as produced by parseOrRaw with the junos_route_table/
// junos_bgp_neighbor_routes parsers: {"routes": [...]}"). A snapshot whose
// parse failed at capture time falls back to {"raw": "..."} instead, which
// decodes to no records here — the section is then reported as unavailable
// for structured diffing rather than silently comparing nothing as if
// everything matched.
//
// Empty/nil/JSON-null raw is also reported as unavailable, not as "a
// legitimately empty route table": captureSnapshot (snapshot.go) always
// calls parseOrRaw on a successful command execution, and parseOrRaw always
// marshals *something* non-empty — either {"routes": [...]} or the
// {"raw": ...} fallback — so the only way this field is empty or null is
// that the command itself failed to execute (see captureSnapshot's
// neighbor loop, which still records a neighborSnapshot entry even when
// one of its two Execute calls failed, leaving that one field's
// json.RawMessage at its nil zero value). A nil json.RawMessage marshals
// to the literal JSON text "null" (RawMessage.MarshalJSON's documented
// nil behavior) — not an empty value — so a snapshot loaded back from a
// captured .json file has this field as the 4-byte string "null", not a
// zero-length byte slice; both must be checked, or a round-tripped nil
// field parses as "successfully decoded, zero routes" instead of
// unavailable. Treating that as "zero routes" would make diffSnapshots
// report every route in the other snapshot as spuriously added or removed.
func decodeRouteRecords(raw json.RawMessage) ([]map[string]string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, false
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, false
	}
	if decoded.Routes == nil {
		// A raw-fallback record ({"raw": "..."}) still unmarshals into this
		// struct successfully (Routes just stays nil), so it must be told
		// apart from "zero routes" so the diff doesn't claim every route in
		// the other snapshot was added/removed based on a parser failure.
		var rawFallback struct {
			Raw *string `json:"raw"`
		}
		if err := json.Unmarshal(raw, &rawFallback); err == nil && rawFallback.Raw != nil {
			return nil, false
		}
	}
	return decoded.Routes, true
}

// diffRouteRecords compares two route lists by prefix (NETWORK), not
// position — see snapshotDiffSection. A prefix present on both sides with a
// different NEXTHOP is reported as changed; AS-path/MED/local-preference
// churn is not, since next hop is what actually matters operationally
// during a change window.
func diffRouteRecords(before, after []map[string]string) (added, removed, changed []string) {
	beforeByPrefix := make(map[string]map[string]string, len(before))
	for _, r := range before {
		if prefix := r["NETWORK"]; prefix != "" {
			beforeByPrefix[prefix] = r
		}
	}
	afterByPrefix := make(map[string]map[string]string, len(after))
	for _, r := range after {
		if prefix := r["NETWORK"]; prefix != "" {
			afterByPrefix[prefix] = r
		}
	}

	for prefix, a := range afterByPrefix {
		b, ok := beforeByPrefix[prefix]
		if !ok {
			added = append(added, prefix)
			continue
		}
		if b["NEXTHOP"] != a["NEXTHOP"] {
			changed = append(changed, fmt.Sprintf("%s (%s -> %s)", prefix, b["NEXTHOP"], a["NEXTHOP"]))
		}
	}
	for prefix := range beforeByPrefix {
		if _, ok := afterByPrefix[prefix]; !ok {
			removed = append(removed, prefix)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

// diffSnapshots compares every table and neighbor route/advertised-route
// section present in either snapshot, returning one snapshotDiffSection per
// section in a stable (sorted-by-label) order. A section that's missing
// entirely from one side, or whose data didn't decode into structured
// records on either side (parse failure or capture-time Execute failure —
// see decodeRouteRecords), gets Skipped: true and a nil
// Added/Removed/Changed instead of a possibly-misleading empty diff —
// printSnapshotDiff reports that distinctly from "compared, found no
// changes".
func diffSnapshots(before, after snapshotResult) []snapshotDiffSection {
	type sectionSource struct {
		label      string
		beforeRaw  json.RawMessage
		afterRaw   json.RawMessage
		haveBefore bool
		haveAfter  bool
	}
	var sources []sectionSource

	tableNames := map[string]bool{}
	for table := range before.Tables {
		tableNames[table] = true
	}
	for table := range after.Tables {
		tableNames[table] = true
	}
	for table := range tableNames {
		b, bok := before.Tables[table]
		a, aok := after.Tables[table]
		sources = append(sources, sectionSource{label: "table " + table, beforeRaw: b, afterRaw: a, haveBefore: bok, haveAfter: aok})
	}

	neighborNames := map[string]bool{}
	for n := range before.Neighbors {
		neighborNames[n] = true
	}
	for n := range after.Neighbors {
		neighborNames[n] = true
	}
	for n := range neighborNames {
		bNeighbor, bok := before.Neighbors[n]
		aNeighbor, aok := after.Neighbors[n]
		sources = append(sources,
			sectionSource{label: "neighbor " + n + " routes", beforeRaw: bNeighbor.Routes, afterRaw: aNeighbor.Routes, haveBefore: bok, haveAfter: aok},
			sectionSource{label: "neighbor " + n + " advertised-routes", beforeRaw: bNeighbor.AdvertisedRoutes, afterRaw: aNeighbor.AdvertisedRoutes, haveBefore: bok, haveAfter: aok},
		)
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].label < sources[j].label })

	sections := make([]snapshotDiffSection, 0, len(sources))
	for _, src := range sources {
		beforeRecords, beforeOK := decodeRouteRecords(src.beforeRaw)
		afterRecords, afterOK := decodeRouteRecords(src.afterRaw)
		if !src.haveBefore || !src.haveAfter || !beforeOK || !afterOK {
			sections = append(sections, snapshotDiffSection{Label: src.label, Skipped: true})
			continue
		}
		added, removed, changed := diffRouteRecords(beforeRecords, afterRecords)
		sections = append(sections, snapshotDiffSection{Label: src.label, Added: added, Removed: removed, Changed: changed})
	}
	return sections
}

// printSnapshotDiff writes a human-readable before/after route diff to out
// — a "+N added"/"-N removed"/"~N changed" summary line per section (only
// for sections with a change), plus every affected prefix, so an operator
// can see exactly what moved during the change window without eyeballing
// two raw route table dumps.
func printSnapshotDiff(out io.Writer, before, after snapshotResult) {
	fmt.Fprintf(out, "snapshot diff for %s: %s -> %s\n", before.Hostname, before.Timestamp, after.Timestamp)
	if before.Hostname != after.Hostname {
		fmt.Fprintf(out, "warning: hostnames differ between snapshots (%q vs %q); comparing anyway\n", before.Hostname, after.Hostname)
	}

	sections := diffSnapshots(before, after)
	changedCount := 0
	skippedCount := 0
	for _, section := range sections {
		fmt.Fprintf(out, "\n%s:\n", section.Label)
		if section.Skipped {
			skippedCount++
			fmt.Fprintln(out, "  skipped: missing or not structurally parseable on one or both sides")
			continue
		}
		if section.empty() {
			fmt.Fprintln(out, "  no changes")
			continue
		}
		changedCount++
		if len(section.Added) > 0 {
			fmt.Fprintf(out, "  + added (%d): %v\n", len(section.Added), section.Added)
		}
		if len(section.Removed) > 0 {
			fmt.Fprintf(out, "  - removed (%d): %v\n", len(section.Removed), section.Removed)
		}
		if len(section.Changed) > 0 {
			fmt.Fprintf(out, "  ~ changed (%d): %v\n", len(section.Changed), section.Changed)
		}
	}
	summary := fmt.Sprintf("\n%d of %d section(s) changed", changedCount, len(sections))
	if skippedCount > 0 {
		summary += fmt.Sprintf(" (%d skipped)", skippedCount)
	}
	fmt.Fprintln(out, summary)
}

// runSnapshotDiff loads two captured snapshot JSON files (see
// captureSnapshot) and prints their route-level diff to out. Used by
// main's -diff-before/-diff-after flags, entirely offline — it never opens
// an SSH session or prompts for credentials.
func runSnapshotDiff(beforePath, afterPath string, out io.Writer) error {
	before, err := loadSnapshotFile(beforePath)
	if err != nil {
		return fmt.Errorf("load before snapshot: %w", err)
	}
	after, err := loadSnapshotFile(afterPath)
	if err != nil {
		return fmt.Errorf("load after snapshot: %w", err)
	}
	printSnapshotDiff(out, before, after)
	return nil
}

// printAutoDiffAfterChange runs the same route-level diff as the standalone
// -diff-before/-diff-after flags, automatically right after the
// after-change capture on Ctrl+C — so an operator sees what changed
// immediately, without a second invocation to point the diff flags at the
// files by hand. The diff is read back from the files captureSnapshot just
// wrote (rather than threading the in-memory capture results through
// pollDevice), reusing exactly the same offline diff path the manual flag
// uses, keyed by the same capturedAt timestamps and filename convention
// (snapshotFilenameBase) used to write them.
//
// Mirrors captureSnapshot's own "nothing to do" gate: no route-level diff
// is attempted for a device with no tables and no neighbors configured,
// since captureSnapshot itself wrote no files to diff in that case.
// snapshotCapturesOK reports whether the before *and* after captures this
// diff would read back both actually succeeded (poll.go tracks this from
// captureSnapshot's own return value) — skipping a diff attempt here when
// either side failed avoids a second, confusing "file not found" error on
// top of the already-logged capture failure.
//
// Every device polls on its own goroutine, and Ctrl+C fires all of their
// auto-diffs at nearly the same instant against the shared snapshotOut
// writer — so the whole report is built in a local buffer and written to
// out in one Write call, rather than the many small Fprintf/Fprintln calls
// printSnapshotDiff would otherwise make directly against out. out's
// underlying syncWriter only serializes one Write call at a time, not a
// whole sequence of them, so multiple small writes from concurrent devices
// could otherwise interleave into unreadable output.
func printAutoDiffAfterChange(session *deviceSession, outputDir, runLabel string, beforeCapturedAt, afterCapturedAt time.Time, snapshotCapturesOK bool, out io.Writer) {
	if len(session.tables) == 0 && len(session.neighbors) == 0 {
		return
	}
	if !snapshotCapturesOK {
		slog.Warn("skipping automatic snapshot diff: before or after capture failed, see prior error", "hostname", session.hostname)
		return
	}

	var buf bytes.Buffer
	beforePath := filepath.Join(outputDir, snapshotFilenameBase(runLabel, session.hostname, "before", beforeCapturedAt)+".json")
	afterPath := filepath.Join(outputDir, snapshotFilenameBase(runLabel, session.hostname, "after", afterCapturedAt)+".json")
	fmt.Fprintln(&buf)
	if err := runSnapshotDiff(beforePath, afterPath, &buf); err != nil {
		slog.Error("failed to print automatic snapshot diff", "hostname", session.hostname, "error", err)
		return
	}
	out.Write(buf.Bytes())
}
