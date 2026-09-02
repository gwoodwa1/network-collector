package monitorreport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateInterfaceReportFromJSONL(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		`{"timestamp":"2026-07-15T10:00:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1000","OUTPUT_RATE_BPS":"2000"}]}}}`,
		`{"timestamp":"2026-07-15T10:01:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1500","OUTPUT_RATE_BPS":"2500"}]},"ae1":{"raw":"parser failed"}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	since := mustParseTime(t, "2026-07-15T09:00:00Z")
	path, err := GenerateInterfaceReport(dir, since)
	if err != nil {
		t.Fatalf("GenerateInterfaceReport returned error: %v", err)
	}
	if filepath.Base(path) != "interface-traffic.html" {
		t.Fatalf("unexpected report path: %s", path)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	// minuteTicks is the x-axis time-scale generator — asserting its
	// presence pins the report to shipping with the minute gridlines
	// (the JS itself is untested; see interfaceReportTemplate's comment).
	for _, want := range []string{`"hostname":"pe1"`, `"interface":"ae0"`, `"input_bps":1000`, `"output_bps":2500`, "minuteTicks"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected report to contain %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"interface":"ae1"`) {
		t.Fatalf("raw fallback interface should not be graphed, got:\n%s", got)
	}
}

func TestGenerateInterfaceReportEscapesHostileOutputAndRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	hostile := `</script><script>alert(1)</script>`
	secret := "token=NC_INTERFACE_SECRET_CANARY"
	line, err := json.Marshal(map[string]interface{}{
		"timestamp": "2026-07-15T10:00:00Z",
		"hostname":  hostile,
		"interfaces": map[string]interface{}{
			secret: map[string]interface{}{
				"stats": []map[string]string{{"INPUT_RATE_BPS": "1", "OUTPUT_RATE_BPS": "2"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hostile.jsonl"), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := GenerateInterfaceReport(dir, mustParseTime(t, "2026-07-15T09:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(content)
	if strings.Contains(html, hostile) {
		t.Fatal("hostile device output escaped its script-data context")
	}
	if strings.Contains(html, "NC_INTERFACE_SECRET_CANARY") {
		t.Fatal("known secret form reached the interface report")
	}
	if !strings.Contains(html, "[REDACTED]") {
		t.Fatal("interface report did not retain a redaction marker")
	}
}

func TestGenerateInterfaceReportReturnsEmptyWhenNoSamples(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(`{"timestamp":"2026-07-15T10:00:00Z","hostname":"pe1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	path, err := GenerateInterfaceReport(dir, mustParseTime(t, "2026-07-15T09:00:00Z"))
	if err != nil {
		t.Fatalf("GenerateInterfaceReport returned error: %v", err)
	}
	if path != "" {
		t.Fatalf("expected no report path when there are no samples, got %q", path)
	}
}

// TestGenerateInterfaceReportFiltersPointsBeforeSince proves the report is
// scoped to the run that just happened, not the full accumulated history of
// a --devices file's .jsonl (which both cmd/xr-routing-monitor and
// cmd/junos-routing-monitor deliberately never truncate on re-runs — see
// their READMEs). Without this filter, re-running the same --devices file
// would plot every prior run's samples on the same time axis as the run
// that just finished, diluting the data anyone re-running the tool actually
// wants to see.
func TestGenerateInterfaceReportFiltersPointsBeforeSince(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		// A stale sample from a previous run against the same --devices file.
		`{"timestamp":"2026-07-10T10:00:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"999999","OUTPUT_RATE_BPS":"999999"}]}}}`,
		// The sample from the run that just finished.
		`{"timestamp":"2026-07-15T10:00:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1000","OUTPUT_RATE_BPS":"2000"}]}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	since := mustParseTime(t, "2026-07-15T09:00:00Z")
	path, err := GenerateInterfaceReport(dir, since)
	if err != nil {
		t.Fatalf("GenerateInterfaceReport returned error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	if strings.Contains(got, "999999") {
		t.Fatalf("expected the stale pre-since sample to be excluded, got:\n%s", got)
	}
	if !strings.Contains(got, `"input_bps":1000`) {
		t.Fatalf("expected the current run's sample to be included, got:\n%s", got)
	}
}

// TestCollectInterfaceSeriesSkipsMalformedLineInsteadOfAborting proves one
// corrupted line (e.g. from a process killed mid-write) doesn't discard
// every other valid tick in the same file, let alone every other device's
// file in the same run.
func TestCollectInterfaceSeriesSkipsMalformedLineInsteadOfAborting(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		`{"timestamp":"2026-07-15T10:00:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1000","OUTPUT_RATE_BPS":"2000"}]}}}`,
		`{not valid json`,
		`{"timestamp":"2026-07-15T10:01:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1500","OUTPUT_RATE_BPS":"2500"}]}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	path, err := GenerateInterfaceReport(dir, mustParseTime(t, "2026-07-15T09:00:00Z"))
	if err != nil {
		t.Fatalf("expected a malformed line to be skipped, not returned as an error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `"input_bps":1000`) || !strings.Contains(got, `"input_bps":1500`) {
		t.Fatalf("expected both valid ticks surrounding the malformed line to be included, got:\n%s", got)
	}
}

// TestGenerateInterfaceReportMarksNextHopChangeEvents proves a change in a
// table's default-route next hop between ticks becomes exactly one chart
// event: stable ticks produce nothing, an unparseable (raw-fallback) tick
// is treated as unknown rather than fabricating a change-and-revert pair,
// and the event carries the old and new values.
func TestGenerateInterfaceReportMarksNextHopChangeEvents(t *testing.T) {
	dir := t.TempDir()
	iface := `"interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1000","OUTPUT_RATE_BPS":"2000"}]}}`
	content := strings.Join([]string{
		// Baseline: next hop .38 (repeated per route reflector, as Junos does).
		`{"timestamp":"2026-07-15T10:00:00Z","hostname":"pe1",` + iface + `,"default_route_next_hops":{"RI-CUSTOMER-G-300001.inet.0":{"next_hops":[{"NEXTHOP":"192.0.2.9"},{"NEXTHOP":"192.0.2.9"}]}}}`,
		// Unchanged: no event.
		`{"timestamp":"2026-07-15T10:01:00Z","hostname":"pe1",` + iface + `,"default_route_next_hops":{"RI-CUSTOMER-G-300001.inet.0":{"next_hops":[{"NEXTHOP":"192.0.2.9"}]}}}`,
		// Parse hiccup: unknown, must not produce an event or reset the baseline.
		`{"timestamp":"2026-07-15T10:02:00Z","hostname":"pe1",` + iface + `,"default_route_next_hops":{"RI-CUSTOMER-G-300001.inet.0":{"raw":"unexpected output"}}}`,
		// The migration: .38 -> .39, exactly one event expected.
		`{"timestamp":"2026-07-15T10:03:00Z","hostname":"pe1",` + iface + `,"default_route_next_hops":{"RI-CUSTOMER-G-300001.inet.0":{"next_hops":[{"NEXTHOP":"192.0.2.10"}]}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	path, err := GenerateInterfaceReport(dir, mustParseTime(t, "2026-07-15T09:00:00Z"))
	if err != nil {
		t.Fatalf("GenerateInterfaceReport returned error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	for _, fragment := range []string{`"from":"192.0.2.9"`, `"to":"192.0.2.10"`, `"timestamp":"2026-07-15T10:03:00Z"`} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("expected report events to contain %q, got:\n%s", fragment, got)
		}
	}
	if n := strings.Count(got, `"from":`); n != 1 {
		t.Fatalf("expected exactly 1 next-hop change event, found %d", n)
	}
}

func TestGenerateProfessionalInterfaceReport(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		`{"timestamp":"2026-07-15T10:00:00Z","hostname":"pe1","interfaces":{"HundredGigE0/0/0/0":{"stats":[{"INPUT_RATE_BPS":"1000000","OUTPUT_RATE_BPS":"2000000"}]}},"default_route_next_hops":{"default":{"next_hops":[{"NEXTHOP":"192.0.2.1"}]}}}`,
		`{"timestamp":"2026-07-15T10:01:00Z","hostname":"pe1","interfaces":{"HundredGigE0/0/0/0":{"stats":[{"INPUT_RATE_BPS":"1200000","OUTPUT_RATE_BPS":"2200000"}]}},"default_route_next_hops":{"default":{"next_hops":[{"NEXTHOP":"192.0.2.2"}]}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	path, err := GenerateProfessionalInterfaceReport(
		dir,
		mustParseTime(t, "2026-07-15T09:00:00Z"),
		ProfessionalReportConfig{
			Output:          "professional.html",
			Title:           "Core path change",
			ChangeReference: "CHG-42",
			CompletedAt:     mustParseTime(t, "2026-07-15T10:02:00Z"),
		},
	)
	if err != nil {
		t.Fatalf("GenerateProfessionalInterfaceReport returned error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		"Core path change", "CHG-42", `"hostname":"pe1"`,
		`"interface":"HundredGigE0/0/0/0"`, `"from":"192.0.2.1"`,
		`"to":"192.0.2.2"`, `id="charts"`,
		"Generated by Network Collector Reporter",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected professional report to contain %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "http://") || strings.Contains(got, "https://") {
		t.Fatal("professional monitor report must remain self-contained")
	}
}

func TestGenerateProfessionalInterfaceReportPreservesExplicitSinceForWindow(t *testing.T) {
	dir := t.TempDir()
	content := `{"timestamp":"2026-07-15T10:05:00Z","hostname":"pe1","interfaces":{"ae0":{"stats":[{"INPUT_RATE_BPS":"1000","OUTPUT_RATE_BPS":"2000"}]}}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pe1.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	path, err := GenerateProfessionalInterfaceReport(
		dir,
		mustParseTime(t, "2026-07-15T10:00:00Z"),
		ProfessionalReportConfig{
			Output:      "professional.html",
			CompletedAt: mustParseTime(t, "2026-07-15T10:20:00Z"),
		},
	)
	if err != nil {
		t.Fatalf("GenerateProfessionalInterfaceReport returned error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `<div class="value">20m0s</div>`) {
		t.Fatalf("expected the report window to use the explicit since time, got:\n%s", got)
	}
	if strings.Contains(got, `<div class="value">15m0s</div>`) {
		t.Fatalf("report window was clamped to the first sample instead of explicit since, got:\n%s", got)
	}
}

func TestGenerateProfessionalInterfaceReportEscapesCombinedLegendLabels(t *testing.T) {
	dir := t.TempDir()
	hostileHost := `<img src=x onerror=alert(1)>`
	hostileInterface := `<b>ae0</b>`
	line, err := json.Marshal(map[string]interface{}{
		"timestamp": "2026-07-15T10:05:00Z",
		"hostname":  hostileHost,
		"interfaces": map[string]interface{}{
			hostileInterface: map[string]interface{}{
				"stats": []map[string]string{{"INPUT_RATE_BPS": "1000", "OUTPUT_RATE_BPS": "2000"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hostile.jsonl"), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := GenerateProfessionalInterfaceReport(
		dir,
		mustParseTime(t, "2026-07-15T10:00:00Z"),
		ProfessionalReportConfig{Output: "professional.html", CompletedAt: mustParseTime(t, "2026-07-15T10:10:00Z")},
	)
	if err != nil {
		t.Fatalf("GenerateProfessionalInterfaceReport returned error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `esc(item.hostname)+" / "+esc(item.interface)`) {
		t.Fatalf("combined legend does not escape hostname/interface labels, got:\n%s", got)
	}
	if strings.Contains(got, `+item.hostname+" / "+item.interface`) {
		t.Fatalf("combined legend still injects raw hostname/interface labels, got:\n%s", got)
	}
	if strings.Contains(got, hostileHost) || strings.Contains(got, hostileInterface) {
		t.Fatalf("hostile labels appeared as raw markup in professional report, got:\n%s", got)
	}
}

func TestFirstInterfaceStat(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "1000"}}})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	stat, ok := FirstInterfaceStat(raw)
	if !ok || stat["INPUT_RATE_BPS"] != "1000" {
		t.Fatalf("expected a decoded stat record, got %+v ok=%v", stat, ok)
	}

	if _, ok := FirstInterfaceStat(json.RawMessage(`{"raw":"parser failed"}`)); ok {
		t.Fatal("expected a raw-fallback record (no stats field) to report ok=false")
	}
	if _, ok := FirstInterfaceStat(nil); ok {
		t.Fatal("expected nil input to report ok=false")
	}
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse fixture time %q: %v", value, err)
	}
	return parsed
}
