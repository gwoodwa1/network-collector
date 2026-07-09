package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxStatusInterfaces = 4

// syncWriter serializes concurrent Write calls with a mutex. Every device
// polls independently on its own goroutine and they all share one status
// output stream (stdout + session.log); neither fmt.Fprintf nor
// io.MultiWriter provide any locking on their own, so without this,
// concurrent devices' status lines could interleave mid-line.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// tickStatusPrinter groups printTickStatusLine output into blank-line
// separated rounds. Each device polls on its own goroutine/ticker, so
// there's no single "round" signal to key off; instead, since every
// device's ticker starts around the same time and shares the same
// interval, a round is inferred as "every still-active device has
// reported once": a blank line goes out the moment a hostname reports
// again before that has happened. This keeps working correctly even as
// devices drop out over a long-running change window.
type tickStatusPrinter struct {
	mu   sync.Mutex
	w    io.Writer
	seen map[string]bool
}

func newTickStatusPrinter(w io.Writer) *tickStatusPrinter {
	return &tickStatusPrinter{w: w, seen: map[string]bool{}}
}

func (p *tickStatusPrinter) printTick(result tickResult, sessionAlive bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[result.Hostname] {
		fmt.Fprintln(p.w)
		p.seen = map[string]bool{}
	}
	p.seen[result.Hostname] = true
	printTickStatusLine(p.w, result, sessionAlive)
}

// printTickStatusLine writes one scrolling status line per tick to out
// (typically stdout, mirrored to session.log), e.g.:
//
//	22:07:26 | pe-router-1    | BGP 6/6 up  | routes 383 | BE45 in 6.2Gbps/out 4.1Gbps
//
// Fields are separated with " | " and padded to fixed widths so that, since
// devices are polled on independent goroutines/tickers, same-shaped fields
// (BGP, routes, a given interface's rate) land in the same column across
// consecutive lines even though the lines themselves interleave across
// devices and are only ever appended, never overwritten or rewritten in
// place. It degrades field-by-field if a section failed to parse rather
// than skipping the whole line.
func printTickStatusLine(out io.Writer, result tickResult, sessionAlive bool) {
	timestamp := time.Now().Format("15:04:05")
	if !sessionAlive {
		fmt.Fprintf(out, "%s | %-14s | SESSION DROPPED — polling stopped for this device\n", timestamp, result.Hostname)
		return
	}

	fields := []string{fmt.Sprintf("%-14s", result.Hostname)}
	if bgp := summarizeBGP(result.BGP); bgp != "" {
		fields = append(fields, fmt.Sprintf("%-11s", bgp))
	}
	if routes := summarizeRoutes(result.Routes); routes != "" {
		fields = append(fields, routes)
	}
	if interfaces := summarizeInterfaces(result.Interfaces); interfaces != "" {
		fields = append(fields, interfaces)
	}

	fmt.Fprintf(out, "%s | %s\n", timestamp, strings.Join(fields, " | "))
}

func summarizeBGP(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var decoded struct {
		Neighbors []map[string]string `json:"neighbors"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.Neighbors) == 0 {
		return "BGP unavailable"
	}
	up := 0
	for _, neighbor := range decoded.Neighbors {
		if isDigits(neighbor["STATE_OR_PFXRCD"]) {
			up++
		}
	}
	return fmt.Sprintf("BGP %d/%d up", up, len(decoded.Neighbors))
}

// summarizeRoutes formats one "<vrf> routes <N>" segment per monitored VRF,
// sorted by VRF name and joined like summarizeInterfaces, since a device can
// now monitor more than one VRF (manually specified, auto-detected, or
// both).
func summarizeRoutes(routes map[string]json.RawMessage) string {
	if len(routes) == 0 {
		return ""
	}
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+" "+summarizeRouteTotal(routes[name]))
	}
	return strings.Join(parts, " | ")
}

func summarizeRouteTotal(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "routes unavailable"
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "routes unavailable"
	}
	for _, record := range decoded.Routes {
		if record["SOURCE"] == "Total" {
			return "routes " + record["ROUTES"]
		}
	}
	return "routes unavailable"
}

func summarizeInterfaces(interfaces map[string]json.RawMessage) string {
	if len(interfaces) == 0 {
		return ""
	}
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	shownNames := names
	if len(shownNames) > maxStatusInterfaces {
		shownNames = shownNames[:maxStatusInterfaces]
	}

	parts := make([]string, 0, len(shownNames)+1)
	for _, name := range shownNames {
		var decoded struct {
			Stats []map[string]string `json:"stats"`
		}
		if err := json.Unmarshal(interfaces[name], &decoded); err != nil || len(decoded.Stats) == 0 {
			parts = append(parts, name+" unavailable")
			continue
		}
		stat := decoded.Stats[0]
		in := formatBitsPerSecond(stat["INPUT_RATE_BPS"])
		out := formatBitsPerSecond(stat["OUTPUT_RATE_BPS"])
		// Right-aligned to a fixed width so the units/decimal points of
		// successive ticks for the same interface line up in the terminal.
		parts = append(parts, fmt.Sprintf("%s in %9s/out %9s", name, in, out))
	}
	if hidden := len(names) - len(shownNames); hidden > 0 {
		parts = append(parts, fmt.Sprintf("+%d interfaces", hidden))
	}
	return strings.Join(parts, " | ")
}

func formatBitsPerSecond(raw string) string {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "?"
	}
	switch {
	case value >= 1e9:
		return fmt.Sprintf("%.1fGbps", value/1e9)
	case value >= 1e6:
		return fmt.Sprintf("%.1fMbps", value/1e6)
	case value >= 1e3:
		return fmt.Sprintf("%.1fKbps", value/1e3)
	default:
		return fmt.Sprintf("%.0fbps", value)
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
