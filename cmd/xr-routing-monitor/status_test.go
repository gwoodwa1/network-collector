package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestSyncWriterSerializesConcurrentWrites proves syncWriter prevents the
// interleaving/splicing that a bare io.MultiWriter would allow when many
// devices' polling goroutines write status lines concurrently. Run with
// -race: without the mutex, concurrent writes to the underlying
// bytes.Buffer would be flagged as a data race, in addition to the content
// check below catching any spliced lines.
func TestSyncWriterSerializesConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	w := &syncWriter{w: &buf}

	var wg sync.WaitGroup
	const goroutines = 50
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			fmt.Fprintf(w, "line-%d\n", n)
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != goroutines {
		t.Fatalf("expected %d intact lines, got %d: %q", goroutines, len(lines), buf.String())
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "line-") {
			t.Fatalf("found a spliced/corrupted line: %q", line)
		}
	}
}

func TestPrintTickStatusLineSessionDropped(t *testing.T) {
	var buf bytes.Buffer
	printTickStatusLine(&buf, tickResult{Hostname: "pe-router-1"}, false)
	if !strings.Contains(buf.String(), "SESSION DROPPED") || !strings.Contains(buf.String(), "pe-router-1") {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestPrintTickStatusLineHealthyTick(t *testing.T) {
	bgp, _ := json.Marshal(map[string]any{"neighbors": []map[string]string{
		{"NEIGHBOR": "198.51.100.10", "STATE_OR_PFXRCD": "59809"},
		{"NEIGHBOR": "198.51.100.11", "STATE_OR_PFXRCD": "Idle"},
	}})
	route, _ := json.Marshal(map[string]any{"routes": []map[string]string{
		{"SOURCE": "static", "ROUTES": "15"},
		{"SOURCE": "Total", "ROUTES": "383"},
	}})
	iface, _ := json.Marshal(map[string]any{"stats": []map[string]string{
		{"INPUT_RATE_BPS": "6200210000", "OUTPUT_RATE_BPS": "4067093000"},
	}})

	var buf bytes.Buffer
	printTickStatusLine(&buf, tickResult{
		Hostname:   "pe-router-1",
		BGP:        bgp,
		Routes:     map[string]json.RawMessage{"CUSTOMER-A-INTERNET": route},
		Interfaces: map[string]json.RawMessage{"BE45": iface},
	}, true)

	line := buf.String()
	for _, want := range []string{"pe-router-1", "BGP 1/2 up", "CUSTOMER-A-INTERNET routes 383", "BE45 in   6.2Gbps/out   4.1Gbps"} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected line to contain %q, got: %q", want, line)
		}
	}
}

// TestTickStatusPrinterBlankLineBetweenRounds proves a blank line is
// inserted the moment a hostname reports again before every other
// still-active hostname has reported once, and that a device dropping out
// (dev-b stops after round 1) doesn't wedge future rounds.
func TestTickStatusPrinterBlankLineBetweenRounds(t *testing.T) {
	var buf bytes.Buffer
	p := newTickStatusPrinter(&buf)

	p.printTick(tickResult{Hostname: "dev-a"}, true)
	p.printTick(tickResult{Hostname: "dev-b"}, true)
	p.printTick(tickResult{Hostname: "dev-a"}, true) // dev-b has dropped out; round 2 has only dev-a
	p.printTick(tickResult{Hostname: "dev-a"}, true) // round 3

	lines := strings.Split(buf.String(), "\n")
	var blankLineIndexes []int
	for i, line := range lines {
		if line == "" {
			blankLineIndexes = append(blankLineIndexes, i)
		}
	}
	// One trailing blank from the final newline, plus one between each round.
	if len(blankLineIndexes) != 3 {
		t.Fatalf("expected 3 blank lines (2 round separators + trailing newline), got %d: %q", len(blankLineIndexes), buf.String())
	}
}

func TestSummarizeBGPHandlesMissingOrUnparsable(t *testing.T) {
	if got := summarizeBGP(nil); got != "" {
		t.Fatalf("expected empty string for nil input, got %q", got)
	}
	if got := summarizeBGP(json.RawMessage(`{"raw":"not structured"}`)); got != "BGP unavailable" {
		t.Fatalf("expected fallback message, got %q", got)
	}
}

func TestSummarizeRoutesFindsTotal(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"routes": []map[string]string{
		{"SOURCE": "static", "ROUTES": "15"},
		{"SOURCE": "Total", "ROUTES": "383"},
	}})
	got := summarizeRoutes(map[string]json.RawMessage{"CUSTOMER-A-INTERNET": raw})
	if got != "CUSTOMER-A-INTERNET routes 383" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestSummarizeRoutesMissingTotal(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"routes": []map[string]string{
		{"SOURCE": "static", "ROUTES": "15"},
	}})
	got := summarizeRoutes(map[string]json.RawMessage{"CUSTOMER-A-INTERNET": raw})
	if got != "CUSTOMER-A-INTERNET routes unavailable" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

// TestSummarizeRoutesMultipleSortedByName covers a device monitoring more
// than one VRF (manually specified, auto-detected, or both — see
// deviceSession.vrfs), proving each gets its own labeled segment sorted by
// VRF name, the same convention summarizeInterfaces already uses.
func TestSummarizeRoutesMultipleSortedByName(t *testing.T) {
	a, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"SOURCE": "Total", "ROUTES": "40"}}})
	b, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"SOURCE": "Total", "ROUTES": "12"}}})
	got := summarizeRoutes(map[string]json.RawMessage{"4000001": a, "CUSTOMER-A-INTERNET": b})
	want := "4000001 routes 40 | CUSTOMER-A-INTERNET routes 12"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestSummarizeInterfacesMultipleSortedByName(t *testing.T) {
	be45, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "1500000000", "OUTPUT_RATE_BPS": "500000"}}})
	be46, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "900", "OUTPUT_RATE_BPS": "0"}}})
	got := summarizeInterfaces(map[string]json.RawMessage{"BE46": be46, "BE45": be45})
	want := "BE45 in   1.5Gbps/out 500.0Kbps | BE46 in    900bps/out      0bps"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestSummarizeInterfacesCapsLongLists(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "0", "OUTPUT_RATE_BPS": "0"}}})
	got := summarizeInterfaces(map[string]json.RawMessage{
		"BE40":           raw,
		"BE45":           raw,
		"TenGigE0/0/0/1": raw,
		"TenGigE0/0/0/2": raw,
		"TenGigE0/0/0/3": raw,
	})
	for _, want := range []string{"BE40 in", "BE45 in", "TenGigE0/0/0/1 in", "TenGigE0/0/0/2 in", "+1 interfaces"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected summary to contain %q, got %q", want, got)
		}
	}
	if strings.Contains(got, "TenGigE0/0/0/3 in") {
		t.Fatalf("expected fifth interface to be summarized, got %q", got)
	}
}

func TestFormatBitsPerSecondUnits(t *testing.T) {
	cases := map[string]string{
		"500":          "500bps",
		"1500":         "1.5Kbps",
		"1500000":      "1.5Mbps",
		"1500000000":   "1.5Gbps",
		"not-a-number": "?",
	}
	for input, want := range cases {
		if got := formatBitsPerSecond(input); got != want {
			t.Fatalf("formatBitsPerSecond(%q) = %q, want %q", input, got, want)
		}
	}
}
