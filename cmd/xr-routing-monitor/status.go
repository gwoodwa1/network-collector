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

func (p *tickStatusPrinter) printTick(result tickResult, sessionAlive bool, coreInterfaces []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[result.Hostname] {
		fmt.Fprintln(p.w)
		p.seen = map[string]bool{}
	}
	p.seen[result.Hostname] = true
	printTickStatusLine(p.w, result, sessionAlive, coreInterfaces)
}

// tickHeaderLine formats the fixed-width, single-line part of a tick's
// status — timestamp, hostname, BGP, routes — with no per-interface detail.
// This is what a device with many interfaces would otherwise blow well past
// a terminal's column limit on, so interfaces are printed as their own
// lines instead (see interfaceTableLines/printTickStatusLine); it's also what
// tickStatusPrinter stores for the round-boundary recap, keeping that
// compact regardless of how many interfaces a device has.
func tickHeaderLine(result tickResult, sessionAlive bool) string {
	timestamp := time.Now().Format("15:04:05")
	if !sessionAlive {
		return fmt.Sprintf("%s | %-14s | SESSION DROPPED — polling stopped for this device", timestamp, result.Hostname)
	}

	fields := []string{fmt.Sprintf("%-14s", result.Hostname)}
	if bgp := summarizeBGP(result.BGP); bgp != "" {
		fields = append(fields, fmt.Sprintf("%-11s", bgp))
	}
	if routes := summarizeRoutes(result.Routes); routes != "" {
		fields = append(fields, routes)
	}
	return fmt.Sprintf("%s | %s", timestamp, strings.Join(fields, " | "))
}

// printTickStatusLine writes one tick's status as tickHeaderLine followed
// by a compact interface table (see interfaceTableLines) — never packed
// onto the header line, since a device with many interfaces would otherwise
// produce a line far longer than a typical terminal's column limit. Lines
// are only ever appended, never overwritten or rewritten in place, so
// scrollback (and a session.log redirect) stays a faithful, replayable
// record either way.
func printTickStatusLine(out io.Writer, result tickResult, sessionAlive bool, coreInterfaces []string) {
	fmt.Fprintln(out, tickHeaderLine(result, sessionAlive))
	if !sessionAlive {
		return
	}
	for _, line := range interfaceTableLines(result, coreInterfaces) {
		fmt.Fprintln(out, "  "+line)
	}
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

type interfaceStatusRow struct {
	vrf      string
	iface    string
	inbound  string
	outbound string
}

// interfaceTableLines formats polled interfaces as an ASCII table:
//
//	| VRF | Interface | Inbound | Outbound |
//
// Core interfaces are manually supplied uplinks rather than VRF-specific
// targets, so their VRF column is "core". Auto-discovered customer
// interfaces show the single monitored VRF when there is exactly one; with
// multiple monitored VRFs, the current tick result has no interface-to-VRF
// mapping, so the column uses "customer" rather than inventing precision.
// Only interfaces with non-zero inbound or outbound rates are expanded into
// rows; idle 0/0 interfaces are counted in a summary line instead.
func interfaceTableLines(result tickResult, coreInterfaces []string) []string {
	if len(result.Interfaces) == 0 {
		return nil
	}
	core := make(map[string]bool, len(coreInterfaces))
	for _, name := range coreInterfaces {
		core[name] = true
	}

	names := make([]string, 0, len(result.Interfaces))
	for name := range result.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	routeNames := sortedRouteNames(result.Routes)
	rows := make([]interfaceStatusRow, 0, len(names))
	hiddenZeroRate := 0
	for _, name := range names {
		row := interfaceStatusRow{vrf: interfaceVRFLabel(name, core, routeNames), iface: name, inbound: "?", outbound: "?"}
		var decoded struct {
			Stats []map[string]string `json:"stats"`
		}
		if err := json.Unmarshal(result.Interfaces[name], &decoded); err != nil || len(decoded.Stats) == 0 {
			rows = append(rows, row)
			continue
		}
		stat := decoded.Stats[0]
		if isZeroRate(stat["INPUT_RATE_BPS"]) && isZeroRate(stat["OUTPUT_RATE_BPS"]) {
			hiddenZeroRate++
			continue
		}
		row.inbound = formatBitsPerSecond(stat["INPUT_RATE_BPS"])
		row.outbound = formatBitsPerSecond(stat["OUTPUT_RATE_BPS"])
		rows = append(rows, row)
	}
	lines := formatInterfaceTable(rows)
	if hiddenZeroRate > 0 {
		lines = append(lines, fmt.Sprintf("+%d zero-rate interfaces not shown", hiddenZeroRate))
	}
	return lines
}

func isZeroRate(raw string) bool {
	value, err := strconv.ParseFloat(raw, 64)
	return err == nil && value == 0
}

func sortedRouteNames(routes map[string]json.RawMessage) []string {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func interfaceVRFLabel(name string, core map[string]bool, routeNames []string) string {
	if core[name] {
		return "core"
	}
	if len(routeNames) == 1 {
		return routeNames[0]
	}
	return "customer"
}

func formatInterfaceTable(rows []interfaceStatusRow) []string {
	if len(rows) == 0 {
		return nil
	}
	vrfWidth := len("VRF")
	ifaceWidth := len("Interface")
	inWidth := len("Inbound")
	outWidth := len("Outbound")
	for _, row := range rows {
		vrfWidth = max(vrfWidth, len(row.vrf))
		ifaceWidth = max(ifaceWidth, len(row.iface))
		inWidth = max(inWidth, len(row.inbound))
		outWidth = max(outWidth, len(row.outbound))
	}

	rowFormat := fmt.Sprintf("| %%-%ds | %%-%ds | %%%ds | %%%ds |", vrfWidth, ifaceWidth, inWidth, outWidth)
	lines := make([]string, 0, len(rows)+1)
	lines = append(lines, fmt.Sprintf(rowFormat, "VRF", "Interface", "Inbound", "Outbound"))
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf(rowFormat, row.vrf, row.iface, row.inbound, row.outbound))
	}
	return lines
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
