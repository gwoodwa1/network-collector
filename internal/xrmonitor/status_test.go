package xrmonitor

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
	printTickStatusLine(&buf, tickResult{Hostname: "pe-router-1"}, false, nil, nil)
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
	coreIface, _ := json.Marshal(map[string]any{"stats": []map[string]string{
		{"INPUT_RATE_BPS": "6200210000", "OUTPUT_RATE_BPS": "4067093000"},
	}})
	custIface, _ := json.Marshal(map[string]any{"stats": []map[string]string{
		{"INPUT_RATE_BPS": "0", "OUTPUT_RATE_BPS": "272000"},
	}})

	var buf bytes.Buffer
	printTickStatusLine(&buf, tickResult{
		Hostname: "pe-router-1",
		BGP:      bgp,
		Routes:   map[string]json.RawMessage{"CUSTOMER-A-INTERNET": route},
		Interfaces: map[string]json.RawMessage{
			"BE45":                   coreIface,
			"GigabitEthernet0/0/0/1": custIface,
		},
	}, true, []string{"BE45"}, nil)

	line := buf.String()
	for _, want := range []string{
		"pe-router-1",
		"BGP 1/2 up",
		"CUSTOMER-A-INTERNET routes 383",
		"| VRF                 | Interface              | Inbound |  Outbound |",
		"| core                | BE45                   | 6.2Gbps |   4.1Gbps |",
		"| CUSTOMER-A-INTERNET | GigabitEthernet0/0/0/1 |    0bps | 272.0Kbps |",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected line to contain %q, got: %q", want, line)
		}
	}
}

func TestPrintTickStatusLineNeutralisesHostileDeviceOutput(t *testing.T) {
	stats, _ := json.Marshal(map[string]any{"stats": []map[string]string{{
		"INPUT_RATE_BPS": "1", "OUTPUT_RATE_BPS": "2",
	}}})
	var buf bytes.Buffer
	printTickStatusLine(&buf, tickResult{
		Hostname: "\x1b]2;hostile-title\x07 password=XR_SECRET_CANARY",
		Interfaces: map[string]json.RawMessage{
			"token=XR_INTERFACE_CANARY": stats,
		},
	}, true, []string{"token=XR_INTERFACE_CANARY"}, nil)
	got := buf.String()
	for _, secret := range []string{"XR_SECRET_CANARY", "XR_INTERFACE_CANARY"} {
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

// TestTickStatusPrinterBlankLineBetweenRounds proves a blank line is
// inserted the moment a hostname reports again before every other
// still-active hostname has reported once, and that a device dropping out
// (dev-b stops after round 1) doesn't wedge future rounds.
func TestTickStatusPrinterBlankLineBetweenRounds(t *testing.T) {
	var buf bytes.Buffer
	p := NewTickStatusPrinter(&buf)

	p.printTick(tickResult{Hostname: "dev-a"}, true, nil, nil)
	p.printTick(tickResult{Hostname: "dev-b"}, true, nil, nil)
	p.printTick(tickResult{Hostname: "dev-a"}, true, nil, nil) // dev-b has dropped out; round 2 has only dev-a
	p.printTick(tickResult{Hostname: "dev-a"}, true, nil, nil) // round 3

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
	got := summarizeRoutes(map[string]json.RawMessage{"CUSTOMER-A-INTERNET": raw}, nil)
	if got != "CUSTOMER-A-INTERNET routes 383" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestSummarizeRoutesMissingTotal(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"routes": []map[string]string{
		{"SOURCE": "static", "ROUTES": "15"},
	}})
	got := summarizeRoutes(map[string]json.RawMessage{"CUSTOMER-A-INTERNET": raw}, nil)
	if got != "CUSTOMER-A-INTERNET routes unavailable" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

// TestSummarizeRoutesMultipleSortedByName covers a device monitoring more
// than one VRF (manually specified, auto-detected, or both — see
// DeviceSession.vrfs), proving each gets its own labeled segment sorted by
// VRF name, the same convention summarizeInterfaces already uses.
func TestSummarizeRoutesMultipleSortedByName(t *testing.T) {
	a, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"SOURCE": "Total", "ROUTES": "40"}}})
	b, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"SOURCE": "Total", "ROUTES": "12"}}})
	got := summarizeRoutes(map[string]json.RawMessage{"4000001": a, "CUSTOMER-A-INTERNET": b}, nil)
	want := "4000001 routes 40 | CUSTOMER-A-INTERNET routes 12"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// TestSummarizeRoutesAppendsDedupedNextHop proves the default-route next
// hop clause is appended per VRF, and that repeated NEXTHOP values dedupe
// to the distinct set rather than being reported as multiple separate next
// hops.
func TestSummarizeRoutesAppendsDedupedNextHop(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"SOURCE": "Total", "ROUTES": "383"}}})
	nextHops, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{
		{"NEXTHOP": "192.0.2.23"},
	}})
	got := summarizeRoutes(
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": raw},
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": nextHops},
	)
	want := "CUSTOMER-A-INTERNET routes 383, nexthop 192.0.2.23"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// TestSummarizeRoutesDistinguishesNoneAndUnknownNextHop pins the status
// line's three visible next-hop states — a value, "none" (command ran and
// parsed but found nothing), and "?" (execute failed, or output
// unparseable) — so a collection problem on one device is visible on the
// status line rather than silently indistinguishable from "not collected".
func TestSummarizeRoutesDistinguishesNoneAndUnknownNextHop(t *testing.T) {
	routes, _ := json.Marshal(map[string]any{"routes": []map[string]string{{"SOURCE": "Total", "ROUTES": "383"}}})
	emptyParse, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{}})
	rawFallback, _ := json.Marshal(map[string]string{"raw": "unexpected output"})

	got := summarizeRoutes(
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": routes},
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": emptyParse},
	)
	if want := "CUSTOMER-A-INTERNET routes 383, nexthop none"; got != want {
		t.Fatalf("empty parse: expected %q, got %q", want, got)
	}

	got = summarizeRoutes(
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": routes},
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": rawFallback},
	)
	if want := "CUSTOMER-A-INTERNET routes 383, nexthop ?"; got != want {
		t.Fatalf("raw fallback: expected %q, got %q", want, got)
	}

	got = summarizeRoutes(
		map[string]json.RawMessage{"CUSTOMER-A-INTERNET": routes},
		map[string]json.RawMessage{},
	)
	if want := "CUSTOMER-A-INTERNET routes 383, nexthop ?"; got != want {
		t.Fatalf("missing key: expected %q, got %q", want, got)
	}

	got = summarizeRoutes(map[string]json.RawMessage{"CUSTOMER-A-INTERNET": routes}, nil)
	if want := "CUSTOMER-A-INTERNET routes 383"; got != want {
		t.Fatalf("nil map: expected %q, got %q", want, got)
	}
}

func TestSummarizeDefaultRouteNextHopsMultipleDistinctValues(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"next_hops": []map[string]string{
		{"NEXTHOP": "192.0.2.9"},
		{"NEXTHOP": "192.0.2.23"},
		{"NEXTHOP": "192.0.2.23"},
	}})
	if got := summarizeDefaultRouteNextHops(raw); got != "192.0.2.23,192.0.2.9" {
		t.Fatalf("expected sorted distinct next hops, got %q", got)
	}
}

func TestSummarizeDefaultRouteNextHopsEmpty(t *testing.T) {
	if got := summarizeDefaultRouteNextHops(nil); got != "" {
		t.Fatalf("expected empty string for nil input (optional data, not \"unavailable\"), got %q", got)
	}
}

// TestInterfaceTableLinesMultipleSortedByName proves the table keeps
// interfaces sorted by name and uses the coreInterfaces argument for the
// VRF/role column: BE46 sorts after BE45 but is the one not in
// coreInterfaces here, so it must still come out as the customer VRF.
func TestInterfaceTableLinesMultipleSortedByName(t *testing.T) {
	be45, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "1500000000", "OUTPUT_RATE_BPS": "500000"}}})
	be46, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "900", "OUTPUT_RATE_BPS": "0"}}})
	got := interfaceTableLines(tickResult{
		Routes: map[string]json.RawMessage{"4000001": nil},
		Interfaces: map[string]json.RawMessage{
			"BE46": be46,
			"BE45": be45,
		},
	}, []string{"BE45"}, nil)
	want := []string{
		"| VRF     | Interface | Inbound |  Outbound |",
		"| core    | BE45      | 1.5Gbps | 500.0Kbps |",
		"| 4000001 | BE46      |  900bps |      0bps |",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestInterfaceTableLinesShowsAllNonZeroAndSummarizesZeroRate(t *testing.T) {
	zero, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "0", "OUTPUT_RATE_BPS": "0"}}})
	nonZeroIn, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "1000", "OUTPUT_RATE_BPS": "0"}}})
	nonZeroOut, _ := json.Marshal(map[string]any{"stats": []map[string]string{{"INPUT_RATE_BPS": "0", "OUTPUT_RATE_BPS": "2000"}}})
	got := interfaceTableLines(tickResult{
		Routes: map[string]json.RawMessage{"4000001": nil},
		Interfaces: map[string]json.RawMessage{
			"BE40":           nonZeroIn,
			"BE45":           nonZeroOut,
			"TenGigE0/0/0/1": nonZeroIn,
			"TenGigE0/0/0/2": nonZeroOut,
			"TenGigE0/0/0/3": nonZeroIn,
			"TenGigE0/0/0/4": zero,
			"TenGigE0/0/0/5": zero,
		},
	}, []string{"BE40", "BE45"}, nil)
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"| VRF",
		"| core    | BE40",
		"| core    | BE45",
		"| 4000001 | TenGigE0/0/0/1",
		"| 4000001 | TenGigE0/0/0/2",
		"| 4000001 | TenGigE0/0/0/3",
		"+2 zero-rate interfaces not shown",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected lines to contain %q, got %q", want, joined)
		}
	}
	for _, hidden := range []string{"TenGigE0/0/0/4", "TenGigE0/0/0/5"} {
		if strings.Contains(joined, hidden) {
			t.Fatalf("expected zero-rate interface %s to be summarized, got %q", hidden, joined)
		}
	}
	if len(got) != 7 {
		t.Fatalf("expected header + 5 active interfaces + 1 zero-rate summary line, got %d lines: %q", len(got), got)
	}
}

// TestInterfaceTableLinesLabelsHubSampledInterfaces proves an interface
// that discovery sampled from a hub VRF (DeviceSession.hubInterfaces) is
// labeled "hub" on the status line rather than falling into the
// single-VRF/"customer" fallback used for auto-detected customer VRF
// interfaces.
func TestInterfaceTableLinesLabelsHubSampledInterfaces(t *testing.T) {
	iface, _ := json.Marshal(map[string]any{"stats": []map[string]string{
		{"INPUT_RATE_BPS": "1000", "OUTPUT_RATE_BPS": "0"},
	}})
	got := interfaceTableLines(tickResult{
		Routes: map[string]json.RawMessage{"4000001": nil},
		Interfaces: map[string]json.RawMessage{
			"TenGigE0/0/0/2": iface,
		},
	}, nil, []string{"TenGigE0/0/0/2"})
	want := []string{
		"| VRF | Interface      | Inbound | Outbound |",
		"| hub | TenGigE0/0/0/2 |  1000bps |     0bps |",
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "| hub ") {
		t.Fatalf("expected the hub-sampled interface to be labeled \"hub\", got %q (want something like %v)", joined, want)
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
