package junosmonitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// snapshotDiffSection is one labeled section's before/after comparison — a
// routing table, a neighbor's received/advertised routes, or (when NETCONF
// snapshot capture is enabled) one of the NETCONF-sourced sections — keyed
// by a stable field rather than compared positionally: a section's records
// can reorder between two captures with no real change, so a key present in
// both, even at a different index, is not a diff. Only a genuinely new/
// withdrawn key, or one whose watched field(s) changed, is reported.
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

// decodeKeyedRecords unpacks one section's raw JSON (as produced by
// parseOrRaw/decodeNetconfOrRaw: {"<root>": [...]}). A snapshot whose parse
// failed at capture time falls back to {"raw": "..."} instead, which is
// detected explicitly below and reported as unavailable for structured
// diffing rather than silently comparing nothing as if everything matched.
//
// Empty/nil/JSON-null raw is also reported as unavailable, not as "a
// legitimately empty section": captureSnapshot (snapshot.go) always calls
// parseOrRaw/decodeNetconfOrRaw on a successful command/RPC execution, and
// both always marshal *something* non-empty — either {"<root>": [...]} or
// the {"raw": ...} fallback — so the only way this field is empty or null
// is that the command/RPC itself failed to execute (see captureSnapshot's
// neighbor loop, which still records a neighborSnapshot entry even when one
// of its two Execute calls failed, leaving that one field's json.RawMessage
// at its nil zero value). A nil json.RawMessage marshals to the literal
// JSON text "null" (RawMessage.MarshalJSON's documented nil behavior) — not
// an empty value — so a snapshot loaded back from a captured .json file has
// this field as the 4-byte string "null", not a zero-length byte slice;
// both must be checked, or a round-tripped nil field parses as
// "successfully decoded, zero records" instead of unavailable. Treating
// that as "zero records" would make diffSnapshots report every record in
// the other snapshot as spuriously added or removed.
func decodeKeyedRecords(raw json.RawMessage, root string) ([]map[string]string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, false
	}
	if _, isRawFallback := top["raw"]; isRawFallback {
		return nil, false
	}
	recordsRaw, ok := top[root]
	if !ok {
		return nil, false
	}
	var records []map[string]string
	if err := json.Unmarshal(recordsRaw, &records); err != nil {
		return nil, false
	}
	return records, true
}

// decodeRouteRecords is decodeKeyedRecords scoped to the "routes" root that
// junos_route_table/junos_bgp_neighbor_routes/get-route-information all
// produce.
func decodeRouteRecords(raw json.RawMessage) ([]map[string]string, bool) {
	return decodeKeyedRecords(raw, "routes")
}

// diffRecordsByKey compares two record lists by keyField, not position — a
// section's records can reorder between two captures with no real change.
// A key present on both sides whose value differs in any of changeFields is
// reported as changed, formatted as "key (old -> new)" when watching
// exactly one field (matching the original route-diff format, e.g.
// "192.0.2.12/24 (192.0.2.1 -> 192.0.2.9)"), or "key (FIELD old -> new,
// ...)" per differing field when watching more than one, so the reader
// knows which field moved. No changeFields at all means presence-only
// diffing (used for alarms/core-dumps, where any appearance is itself the
// signal, not a field-level change).
func diffRecordsByKey(before, after []map[string]string, keyField string, changeFields ...string) (added, removed, changed []string) {
	beforeByKey := make(map[string]map[string]string, len(before))
	for _, r := range before {
		if key := r[keyField]; key != "" {
			beforeByKey[key] = r
		}
	}
	afterByKey := make(map[string]map[string]string, len(after))
	for _, r := range after {
		if key := r[keyField]; key != "" {
			afterByKey[key] = r
		}
	}

	for key, a := range afterByKey {
		b, ok := beforeByKey[key]
		if !ok {
			added = append(added, key)
			continue
		}
		var diffs []string
		for _, field := range changeFields {
			if b[field] == a[field] {
				continue
			}
			if len(changeFields) == 1 {
				diffs = append(diffs, fmt.Sprintf("%s -> %s", b[field], a[field]))
			} else {
				diffs = append(diffs, fmt.Sprintf("%s %s -> %s", field, b[field], a[field]))
			}
		}
		if len(diffs) > 0 {
			changed = append(changed, fmt.Sprintf("%s (%s)", key, strings.Join(diffs, ", ")))
		}
	}
	for key := range beforeByKey {
		if _, ok := afterByKey[key]; !ok {
			removed = append(removed, key)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

// diffRouteRecords compares two route lists by prefix (NETWORK); AS-path/
// MED/local-preference churn is not watched, since next hop is what
// actually matters operationally during a change window.
func diffRouteRecords(before, after []map[string]string) (added, removed, changed []string) {
	return diffRecordsByKey(before, after, "NETWORK", "NEXTHOP")
}

// netconfSingleSectionSpec describes one of netconfSnapshotDetail's
// device-wide (not table-keyed) sections for diffSnapshots below: its
// report label, the JSON root decodeKeyedRecords should look for, which
// field uniquely identifies a record, and which fields are worth flagging
// as changed. A table-driven list here, rather than elevenths of
// near-identical hand-written diff blocks, is what keeps diffSnapshots
// itself small as this list grows.
type netconfSingleSectionSpec struct {
	label        string
	root         string
	keyField     string
	changeFields []string
	extract      func(*netconfSnapshotDetail) json.RawMessage
}

var netconfSingleSections = []netconfSingleSectionSpec{
	{"netconf bgp neighbor detail", "bgp_neighbors", "PEER_ADDRESS", []string{"PEER_STATE"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.BGPNeighborDetail }},
	{"netconf isis adjacencies", "isis_adjacencies", "INTERFACE_NAME", []string{"STATE"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.ISISAdjacencies }},
	{"netconf ldp database", "ldp_bindings", "KEY", []string{"LABEL"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.LDPDatabase }},
	{"netconf mpls lsp information", "mpls_lsp_sessions", "SESSION_TYPE", []string{"UP_COUNT", "DOWN_COUNT"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.MPLSLSPInformation }},
	{"netconf interface information", "interfaces", "INTERFACE_NAME", []string{"ADMIN_STATUS", "OPER_STATUS"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.InterfaceInformation }},
	{"netconf software information", "software", "HOST_NAME", []string{"JUNOS_VERSION", "PRODUCT_MODEL"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.SoftwareInformation }},
	{"netconf route engine information", "route_engines", "SLOT", []string{"MASTERSHIP_STATE"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.RouteEngineInformation }},
	{"netconf fpc information", "fpc_information", "SLOT", []string{"STATE", "TEMPERATURE"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.FPCInformation }},
	{"netconf pic information", "pic_information", "KEY", []string{"PIC_STATE"}, func(d *netconfSnapshotDetail) json.RawMessage { return d.PICInformation }},
	{"netconf alarm information", "alarms", "KEY", nil, func(d *netconfSnapshotDetail) json.RawMessage { return d.AlarmInformation }},
	{"netconf core dumps", "core_dumps", "KEY", nil, func(d *netconfSnapshotDetail) json.RawMessage { return d.CoreDumps }},
}

// diffSnapshots compares every table, neighbor route/advertised-route, and
// (when present) NETCONF-sourced section in either snapshot, returning one
// snapshotDiffSection per section in a stable (sorted-by-label) order. A
// section that's missing entirely from one side, or whose data didn't
// decode into structured records on either side (parse failure or
// capture-time Execute failure — see decodeKeyedRecords), gets Skipped:
// true and a nil Added/Removed/Changed instead of a possibly-misleading
// empty diff — printSnapshotDiff reports that distinctly from "compared,
// found no changes".
func diffSnapshots(before, after snapshotResult) []snapshotDiffSection {
	type sectionSource struct {
		label        string
		beforeRaw    json.RawMessage
		afterRaw     json.RawMessage
		haveBefore   bool
		haveAfter    bool
		root         string
		keyField     string
		changeFields []string
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
		sources = append(sources, sectionSource{label: "table " + table, beforeRaw: b, afterRaw: a, haveBefore: bok, haveAfter: aok, root: "routes", keyField: "NETWORK", changeFields: []string{"NEXTHOP"}})
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
			sectionSource{label: "neighbor " + n + " routes", beforeRaw: bNeighbor.Routes, afterRaw: aNeighbor.Routes, haveBefore: bok, haveAfter: aok, root: "routes", keyField: "NETWORK", changeFields: []string{"NEXTHOP"}},
			sectionSource{label: "neighbor " + n + " advertised-routes", beforeRaw: bNeighbor.AdvertisedRoutes, afterRaw: aNeighbor.AdvertisedRoutes, haveBefore: bok, haveAfter: aok, root: "routes", keyField: "NETWORK", changeFields: []string{"NEXTHOP"}},
		)
	}

	// NETCONF route-information/route-summary are table-keyed the same way
	// Tables is, just sourced from NetconfDetail instead — only present at
	// all for a device that opted into NETCONF snapshot capture.
	netconfTableNames := map[string]bool{}
	if before.NetconfDetail != nil {
		for table := range before.NetconfDetail.RouteInformation {
			netconfTableNames[table] = true
		}
	}
	if after.NetconfDetail != nil {
		for table := range after.NetconfDetail.RouteInformation {
			netconfTableNames[table] = true
		}
	}
	for table := range netconfTableNames {
		var b, a json.RawMessage
		var bok, aok bool
		if before.NetconfDetail != nil {
			b, bok = before.NetconfDetail.RouteInformation[table]
		}
		if after.NetconfDetail != nil {
			a, aok = after.NetconfDetail.RouteInformation[table]
		}
		sources = append(sources, sectionSource{label: "netconf route information " + table, beforeRaw: b, afterRaw: a, haveBefore: bok, haveAfter: aok, root: "routes", keyField: "NETWORK", changeFields: []string{"NEXTHOP"}})
	}
	netconfSummaryTableNames := map[string]bool{}
	if before.NetconfDetail != nil {
		for table := range before.NetconfDetail.RouteSummary {
			netconfSummaryTableNames[table] = true
		}
	}
	if after.NetconfDetail != nil {
		for table := range after.NetconfDetail.RouteSummary {
			netconfSummaryTableNames[table] = true
		}
	}
	for table := range netconfSummaryTableNames {
		var b, a json.RawMessage
		var bok, aok bool
		if before.NetconfDetail != nil {
			b, bok = before.NetconfDetail.RouteSummary[table]
		}
		if after.NetconfDetail != nil {
			a, aok = after.NetconfDetail.RouteSummary[table]
		}
		sources = append(sources, sectionSource{label: "netconf route summary " + table, beforeRaw: b, afterRaw: a, haveBefore: bok, haveAfter: aok, root: "routes", keyField: "TABLE", changeFields: []string{"TOTAL_ROUTES", "ACTIVE_ROUTES"}})
	}

	// The remaining NETCONF sections are device-wide, present at most once
	// per snapshot (not per table/neighbor) — only added when at least one
	// side actually has a NetconfDetail to read from.
	if before.NetconfDetail != nil || after.NetconfDetail != nil {
		for _, spec := range netconfSingleSections {
			var b, a json.RawMessage
			if before.NetconfDetail != nil {
				b = spec.extract(before.NetconfDetail)
			}
			if after.NetconfDetail != nil {
				a = spec.extract(after.NetconfDetail)
			}
			sources = append(sources, sectionSource{
				label: spec.label, beforeRaw: b, afterRaw: a,
				haveBefore: before.NetconfDetail != nil, haveAfter: after.NetconfDetail != nil,
				root: spec.root, keyField: spec.keyField, changeFields: spec.changeFields,
			})
		}
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].label < sources[j].label })

	sections := make([]snapshotDiffSection, 0, len(sources))
	for _, src := range sources {
		beforeRecords, beforeOK := decodeKeyedRecords(src.beforeRaw, src.root)
		afterRecords, afterOK := decodeKeyedRecords(src.afterRaw, src.root)
		if !src.haveBefore || !src.haveAfter || !beforeOK || !afterOK {
			sections = append(sections, snapshotDiffSection{Label: src.label, Skipped: true})
			continue
		}
		added, removed, changed := diffRecordsByKey(beforeRecords, afterRecords, src.keyField, src.changeFields...)
		sections = append(sections, snapshotDiffSection{Label: src.label, Added: added, Removed: removed, Changed: changed})
	}
	return sections
}

// printSnapshotDiff writes a human-readable before/after diff to out — a
// "+N added"/"-N removed"/"~N changed" summary line per section (only for
// sections with a change), plus every affected key, so an operator can see
// exactly what moved during the change window without eyeballing raw
// before/after dumps.
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

// RunSnapshotDiff loads two captured snapshot JSON files (see
// captureSnapshot) and prints their diff to out. Used by main's
// -diff-before/-diff-after flags, entirely offline — it never opens an SSH
// or NETCONF session or prompts for credentials.
func RunSnapshotDiff(beforePath, afterPath string, out io.Writer) error {
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

// printAutoDiffAfterChange runs the same diff as the standalone
// -diff-before/-diff-after flags, plus (when --capture-running-config is
// enabled) a config diff, automatically right after the after-change
// capture on Ctrl+C — so an operator sees what changed immediately, without
// a second invocation to point a diff flag at the files by hand. Both
// diffs are read back from the files captureSnapshot/CaptureRunningConfig
// just wrote (rather than threading the in-memory capture results through
// PollDevice), keyed by the same capturedAt timestamps and filename
// convention (snapshotFilenameBase) used to write them. There is no
// standalone -diff-before-config/-diff-after-config flag pair (unlike
// route snapshots) — the automatic diff on Ctrl+C is the only workflow
// running-config capture needs.
//
// Mirrors captureSnapshot's own "nothing to do" gate: no snapshot diff is
// attempted for a device with no tables, no neighbors, and no NETCONF
// connection, since captureSnapshot itself wrote no files to diff in that
// case. snapshotCapturesOK/configCapturesOK report whether the before *and*
// after captures each diff would read back both actually succeeded (poll.go
// tracks this from captureSnapshot's/CaptureRunningConfig's own return
// values) — skipping a diff attempt when either side failed avoids a
// second, confusing "file not found" error on top of the already-logged
// capture failure.
//
// Every device polls on its own goroutine, and Ctrl+C fires all of their
// auto-diffs at nearly the same instant against the shared snapshotOut
// writer — so the whole report is built in a local buffer and written to
// out in one Write call, rather than the many small Fprintf/Fprintln calls
// printSnapshotDiff/RunConfigDiff would otherwise make directly against
// out. out's underlying syncWriter only serializes one Write call at a
// time, not a whole sequence of them, so multiple small writes from
// concurrent devices could otherwise interleave into unreadable output.
func printAutoDiffAfterChange(session *DeviceSession, outputDir, runLabel string, beforeCapturedAt, afterCapturedAt time.Time, captureRunningConfigEnabled, snapshotCapturesOK, configCapturesOK bool, out io.Writer) {
	var buf bytes.Buffer
	wroteAny := false
	if len(session.tables) > 0 || len(session.neighbors) > 0 || session.netconfClient != nil {
		if !snapshotCapturesOK {
			slog.Warn("skipping automatic snapshot diff: before or after capture failed, see prior error", "hostname", session.hostname)
		} else {
			beforePath := filepath.Join(outputDir, snapshotFilenameBase(runLabel, session.hostname, "before", beforeCapturedAt)+".json")
			afterPath := filepath.Join(outputDir, snapshotFilenameBase(runLabel, session.hostname, "after", afterCapturedAt)+".json")
			fmt.Fprintln(&buf)
			if err := RunSnapshotDiff(beforePath, afterPath, &buf); err != nil {
				slog.Error("failed to print automatic snapshot diff", "hostname", session.hostname, "error", err)
			}
			wroteAny = true
		}
	}
	if captureRunningConfigEnabled {
		if !configCapturesOK {
			slog.Warn("skipping automatic running-config diff: before or after capture failed, see prior error", "hostname", session.hostname)
		} else {
			beforePath := filepath.Join(outputDir, snapshotFilenameBase(runLabel, session.hostname, "before", beforeCapturedAt)+"-running-config.txt")
			afterPath := filepath.Join(outputDir, snapshotFilenameBase(runLabel, session.hostname, "after", afterCapturedAt)+"-running-config.txt")
			fmt.Fprintln(&buf)
			if err := RunConfigDiff(beforePath, afterPath, &buf); err != nil {
				slog.Error("failed to print automatic running-config diff", "hostname", session.hostname, "error", err)
			}
			wroteAny = true
		}
	}
	if wroteAny {
		out.Write(buf.Bytes())
	}
}
