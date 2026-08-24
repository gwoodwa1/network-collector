package junosmonitor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintTickStatusLineNeutralisesHostileDeviceOutput(t *testing.T) {
	stats, _ := json.Marshal(map[string]any{"stats": []map[string]string{{
		"INPUT_RATE_BPS": "1", "OUTPUT_RATE_BPS": "2",
	}}})
	var buf bytes.Buffer
	printTickStatusLine(&buf, tickResult{
		Hostname: "\x1b]2;hostile-title\x07 password=JUNOS_SECRET_CANARY",
		Interfaces: map[string]json.RawMessage{
			"token=JUNOS_INTERFACE_CANARY": stats,
		},
	}, true)
	got := buf.String()
	for _, secret := range []string{"JUNOS_SECRET_CANARY", "JUNOS_INTERFACE_CANARY"} {
		if strings.Contains(got, secret) {
			t.Fatalf("terminal status retained secret %q: %q", secret, got)
		}
	}
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\a') {
		t.Fatalf("terminal status retained a control sequence: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("terminal status omitted its redaction marker: %q", got)
	}
}

func TestSummarizeBGPCountsEstablOnly(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"neighbors": []map[string]string{
		{"NEIGHBOR": "192.0.2.13", "STATE": "Establ"},
		{"NEIGHBOR": "192.0.2.44", "STATE": "Establ"},
		{"NEIGHBOR": "192.0.2.45", "STATE": "Active"},
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
		{"NEXTHOP": "192.0.2.9"},
		{"NEXTHOP": "192.0.2.9"},
		{"NEXTHOP": "192.0.2.9"},
	}})
	got := summarizeRoutes(
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": table},
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": nextHops},
	)
	want := "RI-CUSTOMER-G-300001.inet.0 routes 23, nexthop 192.0.2.9"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// TestSummarizeRoutesDistinguishesNoneAndUnknownNextHop pins the status
// line's three visible next-hop states — a value, "none" (command ran and
// parsed but found nothing, e.g. the node genuinely has no default route),
// and "?" (execute failed, or output unparseable) — so a collection
// problem on one device can never again be silently indistinguishable from
// "not collected" (the original field report: two identically-configured
// devices, next hop shown only for the first, with no clue why).
func TestSummarizeRoutesDistinguishesNoneAndUnknownNextHop(t *testing.T) {
	table, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"TOTAL_ROUTES": "23"}}})
	emptyParse, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{}})
	rawFallback, _ := json.Marshal(map[string]string{"raw": "unexpected output"})

	// Parsed cleanly, zero records -> "none".
	got := summarizeRoutes(
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": table},
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": emptyParse},
	)
	if want := "RI-CUSTOMER-G-300001.inet.0 routes 23, nexthop none"; got != want {
		t.Fatalf("empty parse: expected %q, got %q", want, got)
	}

	// Raw fallback (parser failed) -> "?".
	got = summarizeRoutes(
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": table},
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": rawFallback},
	)
	if want := "RI-CUSTOMER-G-300001.inet.0 routes 23, nexthop ?"; got != want {
		t.Fatalf("raw fallback: expected %q, got %q", want, got)
	}

	// Key missing from a non-nil map (execute failed) -> "?".
	got = summarizeRoutes(
		map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": table},
		map[string]json.RawMessage{},
	)
	if want := "RI-CUSTOMER-G-300001.inet.0 routes 23, nexthop ?"; got != want {
		t.Fatalf("missing key: expected %q, got %q", want, got)
	}

	// nil map (collection not attempted) -> no clause at all.
	got = summarizeRoutes(map[string]json.RawMessage{"RI-CUSTOMER-G-300001.inet.0": table}, nil)
	if want := "RI-CUSTOMER-G-300001.inet.0 routes 23"; got != want {
		t.Fatalf("nil map: expected %q, got %q", want, got)
	}
}

func TestSummarizeDefaultRouteNextHopsMultipleDistinctValues(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{
		{"NEXTHOP": "192.0.2.10"},
		{"NEXTHOP": "192.0.2.9"},
		{"NEXTHOP": "192.0.2.9"},
	}})
	if got := summarizeDefaultRouteNextHops(raw); got != "192.0.2.10,192.0.2.9" {
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
