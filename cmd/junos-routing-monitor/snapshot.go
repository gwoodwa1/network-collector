package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

// snapshotResult is the structured counterpart to the raw .txt snapshot:
// same commands, parsed via junos_route_table/junos_bgp_neighbor_routes so
// before/after prefix sets and next hops can be diffed programmatically
// instead of by eye. Fields fall back to raw text (via parseOrRaw, the same
// helper used for periodic ticks) if a parser isn't available.
type snapshotResult struct {
	Timestamp string                      `json:"timestamp"`
	Hostname  string                      `json:"hostname"`
	Label     string                      `json:"label"`
	Tables    map[string]json.RawMessage  `json:"tables,omitempty"`
	Neighbors map[string]neighborSnapshot `json:"neighbors,omitempty"`
	Errors    []string                    `json:"errors,omitempty"`
}

type neighborSnapshot struct {
	Routes           json.RawMessage `json:"routes,omitempty"`
	AdvertisedRoutes json.RawMessage `json:"advertised_routes,omitempty"`
}

// captureSnapshot records the full route table for every monitored table
// and, per configured neighbor, the routes learned from and advertised to
// that neighbor. It writes two files: a raw <base>.txt (verbatim command
// output, for a quick eyeball diff) and a structured <base>.json (parsed via
// junos_route_table/junos_bgp_neighbor_routes, for a programmatic
// before/after diff of prefixes and next hops), where <base> is
// "[<runLabel>-]<hostname>-<capture-timestamp>-<label>" (see
// snapshotFilenameBase) — the timestamp keeps repeat runs against the same
// devices file from overwriting a previous change window's snapshots, and
// runLabel (typically the devices YAML file's basename, one dedicated file
// per change) keeps concurrent change windows' snapshots apart in a shared
// output directory. label is typically "before" or "after". A device with
// no tables and no neighbors configured produces no files. On success, a
// confirmation line is written to out (mirrored to session.log by the
// caller, not just the terminal, so the confirmation survives even if
// nobody is watching the terminal live).
func captureSnapshot(session *deviceSession, label, outputDir, runLabel string, capturedAt time.Time, parsers map[string]parserModule, out io.Writer) error {
	if len(session.tables) == 0 && len(session.neighbors) == 0 {
		return nil
	}

	result := snapshotResult{
		Timestamp: capturedAt.Format(time.RFC3339),
		Hostname:  session.hostname,
		Label:     label,
	}
	var rawSections []string

	if len(session.tables) > 0 {
		result.Tables = map[string]json.RawMessage{}
	}
	for _, table := range session.tables {
		cmd := fmt.Sprintf("show route table %s", table)
		output, err := session.client.Execute(cmd)
		rawSections = append(rawSections, formatSnapshotSection(cmd, output, err))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("table %s: execute failed: %v", table, err))
		} else {
			result.Tables[table] = parseOrRaw(output, "junos_route_table", parsers, &result.Errors, "table "+table)
		}
	}

	if len(session.neighbors) > 0 {
		result.Neighbors = map[string]neighborSnapshot{}
	}
	for _, neighbor := range session.neighbors {
		var neighborResult neighborSnapshot

		routesCmd := fmt.Sprintf("show route receive-protocol bgp %s", neighbor)
		routesOutput, err := session.client.Execute(routesCmd)
		rawSections = append(rawSections, formatSnapshotSection(routesCmd, routesOutput, err))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("neighbor %s routes: execute failed: %v", neighbor, err))
		} else {
			neighborResult.Routes = parseOrRaw(routesOutput, "junos_bgp_neighbor_routes", parsers, &result.Errors, "neighbor "+neighbor+" routes")
		}

		advertisedCmd := fmt.Sprintf("show route advertising-protocol bgp %s", neighbor)
		advertisedOutput, err := session.client.Execute(advertisedCmd)
		rawSections = append(rawSections, formatSnapshotSection(advertisedCmd, advertisedOutput, err))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("neighbor %s advertised-routes: execute failed: %v", neighbor, err))
		} else {
			neighborResult.AdvertisedRoutes = parseOrRaw(advertisedOutput, "junos_bgp_neighbor_routes", parsers, &result.Errors, "neighbor "+neighbor+" advertised-routes")
		}

		result.Neighbors[neighbor] = neighborResult
	}

	base := snapshotFilenameBase(runLabel, session.hostname, label, capturedAt)

	textPath := filepath.Join(outputDir, base+".txt")
	header := fmt.Sprintf("# snapshot %s for %s captured %s\n\n", label, session.hostname, result.Timestamp)
	textContent := header + strings.Join(rawSections, "\n")
	if err := secureartifact.WriteFile(textPath, []byte(textContent)); err != nil {
		return fmt.Errorf("write raw snapshot: %w", err)
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode structured snapshot: %w", err)
	}
	jsonPath := filepath.Join(outputDir, base+".json")
	if err := secureartifact.WriteFile(jsonPath, encoded); err != nil {
		return fmt.Errorf("write structured snapshot: %w", err)
	}

	fmt.Fprintf(out, "%s-change snapshot captured for %s (%s, %s)\n", label, session.hostname, filepath.Base(textPath), filepath.Base(jsonPath))
	return nil
}

// snapshotFilenameBase builds the shared "<base>" (no extension) for a
// snapshot's .txt/.json pair: "[<runLabel>-]<hostname>-<timestamp>-<label>",
// e.g. "CRQXXX-pe-router-1-20260709-143022-before". runLabel is omitted
// entirely (along with its separator) when empty, e.g. for devices onboarded
// interactively without a --devices file.
func snapshotFilenameBase(runLabel, hostname, label string, capturedAt time.Time) string {
	var parts []string
	if trimmed := strings.TrimSpace(runLabel); trimmed != "" {
		parts = append(parts, sanitizeFilename(trimmed))
	}
	parts = append(parts, sanitizeFilename(hostname), capturedAt.Format("20060102-150405"), label)
	return strings.Join(parts, "-")
}

func formatSnapshotSection(cmd, output string, err error) string {
	if err != nil {
		return fmt.Sprintf("## %s\n(execute failed: %v)\n", cmd, err)
	}
	return fmt.Sprintf("## %s\n%s\n", cmd, output)
}
