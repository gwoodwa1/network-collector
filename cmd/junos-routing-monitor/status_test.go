package main

import (
	"encoding/json"
	"testing"
)

func TestSummarizeBGPCountsEstablOnly(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"neighbors": []map[string]string{
		{"NEIGHBOR": "10.0.0.1", "STATE": "Establ"},
		{"NEIGHBOR": "10.0.0.2", "STATE": "Establ"},
		{"NEIGHBOR": "10.0.0.3", "STATE": "Active"},
	}})
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	if got := summarizeBGP(raw); got != "BGP 2/3 up" {
		t.Fatalf("expected %q, got %q", "BGP 2/3 up", got)
	}
}

func TestSummarizeBGPEmptyOrUnparseable(t *testing.T) {
	if got := summarizeBGP(nil); got != "" {
		t.Fatalf("expected empty string for nil input, got %q", got)
	}
	if got := summarizeBGP(json.RawMessage("not json")); got != "BGP unavailable" {
		t.Fatalf("expected %q for unparseable input, got %q", "BGP unavailable", got)
	}
}

func TestSummarizeRouteTotal(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"routes": []map[string]string{
		{"TABLE": "CUSTOMER-A.inet.0", "TOTAL_ROUTES": "383"},
	}})
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	if got := summarizeRouteTotal(raw); got != "routes 383" {
		t.Fatalf("expected %q, got %q", "routes 383", got)
	}
}

func TestSummarizeRouteTotalUnavailable(t *testing.T) {
	if got := summarizeRouteTotal(nil); got != "routes unavailable" {
		t.Fatalf("expected %q for nil input, got %q", "routes unavailable", got)
	}
	rawNoTotal, err := json.Marshal(map[string]any{"routes": []map[string]string{{"TABLE": "inet.0"}}})
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	if got := summarizeRouteTotal(rawNoTotal); got != "routes unavailable" {
		t.Fatalf("expected %q when TOTAL_ROUTES is missing, got %q", "routes unavailable", got)
	}
}

func TestSummarizeRoutesSortsByTableName(t *testing.T) {
	tableB, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"TOTAL_ROUTES": "5"}}})
	tableA, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"TOTAL_ROUTES": "10"}}})
	got := summarizeRoutes(map[string]json.RawMessage{
		"CUSTOMER-B.inet.0": tableB,
		"CUSTOMER-A.inet.0": tableA,
	}, nil)
	want := "CUSTOMER-A.inet.0 routes 10 | CUSTOMER-B.inet.0 routes 5"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// TestSummarizeRoutesAppendsDedupedNextHop proves the default-route next
// hop clause is appended per table, and that repeated NEXTHOP values (as
// Junos emits once per route reflector — see summarizeDefaultRouteNextHops)
// collapse to the distinct set rather than being reported as multiple
// separate next hops.
func TestSummarizeRoutesAppendsDedupedNextHop(t *testing.T) {
	table, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"TOTAL_ROUTES": "23"}}})
	nextHops, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{
		{"NEXTHOP": "172.16.252.38"},
		{"NEXTHOP": "172.16.252.38"},
		{"NEXTHOP": "172.16.252.38"},
	}})
	got := summarizeRoutes(
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": table},
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": nextHops},
	)
	want := "RI-CUSTOMER-G-300001.inet.0 routes 23, nexthop 172.16.252.38"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestSummarizeDefaultRouteNextHopsMultipleDistinctValues(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{
		{"NEXTHOP": "172.16.252.39"},
		{"NEXTHOP": "172.16.252.38"},
		{"NEXTHOP": "172.16.252.38"},
	}})
	if got := summarizeDefaultRouteNextHops(raw); got != "172.16.252.38,172.16.252.39" {
		t.Fatalf("expected sorted distinct next hops, got %q", got)
	}
}

func TestSummarizeDefaultRouteNextHopsEmpty(t *testing.T) {
	if got := summarizeDefaultRouteNextHops(nil); got != "" {
		t.Fatalf("expected empty string for nil input (optional data, not \"unavailable\"), got %q", got)
	}
}

func TestFormatBitsPerSecond(t *testing.T) {
	cases := map[string]string{
		"0":            "0bps",
		"999":          "999bps",
		"1500":         "1.5Kbps",
		"12500000":     "12.5Mbps",
		"6200000000":   "6.2Gbps",
		"not-a-number": "?",
	}
	for input, want := range cases {
		if got := formatBitsPerSecond(input); got != want {
			t.Fatalf("formatBitsPerSecond(%q): expected %q, got %q", input, want, got)
		}
	}
}

func TestInterfaceTableLinesHidesZeroRateInterfaces(t *testing.T) {
	idle, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "0", "OUTPUT_RATE_BPS": "0"}}})
	busy, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "1000000", "OUTPUT_RATE_BPS": "2000000"}}})
	result := tickResult{Interfaces: map[string]json.RawMessage{
		"ae0": busy,
		"ae1": idle,
	}}
	lines := interfaceTableLines(result)
	foundBusy := false
	foundZeroNote := false
	for _, l := range lines {
		if l == "| ae0       | 1.0Mbps |  2.0Mbps |" {
			foundBusy = true
		}
		if l == "+1 zero-rate interfaces not shown" {
			foundZeroNote = true
		}
	}
	if !foundBusy {
		t.Fatalf("expected ae0's non-zero rate row, got %v", lines)
	}
	if !foundZeroNote {
		t.Fatalf("expected a zero-rate summary line, got %v", lines)
	}
}
