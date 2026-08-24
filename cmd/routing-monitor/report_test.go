package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorreport"
)

// TestSharedReportCoversBothPlatformsFromOneOutputDirectory proves the
// central claim this tool's design rests on: internal/monitorreport's HTML
// report generation is platform-agnostic — it globs *.jsonl in the output
// directory and only reads fields both xrmonitor.tickResult and
// junosmonitor.tickResult already produce identically (hostname,
// interfaces, default_route_next_hops) — so writing both platforms' tick
// data into the same directory and calling
// GenerateProfessionalInterfaceReport once produces one report covering
// both, with no platform-aware code in cmd/routing-monitor or
// internal/monitorreport at all. The fixtures below are hand-constructed
// JSON matching each platform's real tickResult shape (not test doubles),
// one file per hostname, exactly as xrmonitor.PollDevice/
// junosmonitor.PollDevice would have written them.
func TestSharedReportCoversBothPlatformsFromOneOutputDirectory(t *testing.T) {
	dir := t.TempDir()

	xrTicks := `{"timestamp":"2026-08-01T00:00:00Z","hostname":"xr-router-1","interfaces":{"BE45":{"stats":[{"DESCRIPTION":"to-customer","INPUT_RATE_BPS":"1000","OUTPUT_RATE_BPS":"2000"}]}}}
{"timestamp":"2026-08-01T00:01:00Z","hostname":"xr-router-1","interfaces":{"BE45":{"stats":[{"DESCRIPTION":"to-customer","INPUT_RATE_BPS":"1100","OUTPUT_RATE_BPS":"2100"}]}}}
`
	junosTicks := `{"timestamp":"2026-08-01T00:00:00Z","hostname":"pe-router-1","interfaces":{"ae0":{"stats":[{"DESCRIPTION":"to-customer","INPUT_RATE_BPS":"3000","OUTPUT_RATE_BPS":"4000"}]}}}
{"timestamp":"2026-08-01T00:01:00Z","hostname":"pe-router-1","interfaces":{"ae0":{"stats":[{"DESCRIPTION":"to-customer","INPUT_RATE_BPS":"3100","OUTPUT_RATE_BPS":"4100"}]}}}
`
	if err := os.WriteFile(filepath.Join(dir, "xr-router-1.jsonl"), []byte(xrTicks), 0o644); err != nil {
		t.Fatalf("failed to write xr fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pe-router-1.jsonl"), []byte(junosTicks), 0o644); err != nil {
		t.Fatalf("failed to write junos fixture: %v", err)
	}

	since := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	path, err := monitorreport.GenerateProfessionalInterfaceReport(dir, since, monitorreport.ProfessionalReportConfig{
		Output: "interface-traffic.html", Title: "Mixed Fleet Test", CompletedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Fatal("expected a non-empty report path")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read generated report: %v", err)
	}
	html := string(content)
	if !strings.Contains(html, "xr-router-1") {
		t.Error("expected the IOS-XR device's hostname in the shared report")
	}
	if !strings.Contains(html, "pe-router-1") {
		t.Error("expected the Junos device's hostname in the shared report")
	}
}
