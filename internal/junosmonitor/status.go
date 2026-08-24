package junosmonitor

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorreport"
	"github.com/gwoodwa1/network-collector/internal/safeoutput"
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

// TickStatusPrinter groups printTickStatusLine output into blank-line
// separated rounds. Each device polls on its own goroutine/ticker, so
// there's no single "round" signal to key off; instead, since every
// device's ticker starts around the same time and shares the same
// interval, a round is inferred as "every still-active device has
// reported once": a blank line goes out the moment a hostname reports
// again before that has happened. This keeps working correctly even as
// devices drop out over a long-running change window.
type TickStatusPrinter struct {
	mu   sync.Mutex
	w    io.Writer
	seen map[string]bool
}

func NewTickStatusPrinter(w io.Writer) *TickStatusPrinter {
	return &TickStatusPrinter{w: w, seen: map[string]bool{}}
}

func (p *TickStatusPrinter) printTick(result tickResult, sessionAlive bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[result.Hostname] {
		fmt.Fprintln(p.w)
		p.seen = map[string]bool{}
	}
	p.seen[result.Hostname] = true
	printTickStatusLine(p.w, result, sessionAlive)
}

// tickHeaderLine formats the fixed-width, single-line part of a tick's
// status — timestamp, hostname, BGP, routes — with no per-interface detail.
// This is what a device with many interfaces would otherwise blow well past
// a terminal's column limit on, so interfaces are printed as their own
// lines instead (see interfaceTableLines/printTickStatusLine).
func tickHeaderLine(result tickResult, sessionAlive bool) string {
	timestamp := time.Now().Format("15:04:05")
	if !sessionAlive {
		return fmt.Sprintf("%s | %-14s | SESSION DROPPED — polling stopped for this device", timestamp, result.Hostname)
	}

	fields := []string{fmt.Sprintf("%-14s", result.Hostname)}
	if bgp := summarizeBGP(result.BGP); bgp != "" {
		fields = append(fields, fmt.Sprintf("%-11s", bgp))
	}
	if routes := summarizeRoutes(result.Tables, result.DefaultRouteNextHops); routes != "" {
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
func printTickStatusLine(out io.Writer, result tickResult, sessionAlive bool) {
	fmt.Fprintln(out, safeoutput.Sanitize(tickHeaderLine(result, sessionAlive)))
	if !sessionAlive {
		return
	}
	for _, line := range interfaceTableLines(result) {
		fmt.Fprintln(out, safeoutput.Sanitize("  "+line))
	}
}

// summarizeBGP reports "BGP N/M up" from a junos_bgp_summary result. Unlike
// IOS-XR's "show bgp vpnv4 unicast summary" (which shows a digit prefix
// count in the state column for an established session and the state name
// otherwise), Junos's "show bgp summary" always shows a state word in that
// column — "Establ" for an established session, "Active"/"Connect"/"Idle"/
// etc. otherwise — so up/down here is a literal STATE comparison instead of
// a digits-vs-word heuristic.
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
		if strings.EqualFold(neighbor["STATE"], "Establ") {
			up++
		}
	}
	return fmt.Sprintf("BGP %d/%d up", up, len(decoded.Neighbors))
}

// summarizeRoutes formats one "<table> routes <N>, nexthop <...>" segment
// per monitored routing table, sorted by table name and joined, since a
// device can monitor more than one table. The nexthop clause is omitted
// only when next-hop collection wasn't attempted at all (nextHops is nil);
// otherwise it always appears — see defaultRouteNextHopClause for the
// "none" vs "?" distinction that keeps a collection problem visible
// instead of silently dropping the clause.
func summarizeRoutes(tables, nextHops map[string]json.RawMessage) string {
	if len(tables) == 0 {
		return ""
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+" "+summarizeRouteTotal(tables[name])+defaultRouteNextHopClause(nextHops, name))
	}
	return strings.Join(parts, " | ")
}

// defaultRouteNextHopClause formats the ", nexthop ..." suffix for one
// monitored table's status-line segment. A nil nextHops map means next-hop
// collection wasn't attempted at all — no clause. Otherwise the clause is
// always present, so a broken or empty collection is visible on the status
// line rather than silently omitted (an omission is indistinguishable from
// "not collected", which made a real fleet issue — the second of two
// identically-configured devices showing no next hop — undiagnosable from
// the terminal):
//
//   - "nexthop <ip>[,<ip>...]": parsed, distinct next hop value(s) found.
//   - "nexthop none": the command ran and parsed cleanly, but produced no
//     protocol next hop — e.g. this node's table genuinely has no default
//     route, or its default route carries no "Protocol next hop:" line.
//   - "nexthop ?": the command failed to execute (its error is in the
//     tick's errors field in the .jsonl), or its output didn't parse (raw
//     fallback).
func defaultRouteNextHopClause(nextHops map[string]json.RawMessage, name string) string {
	if nextHops == nil {
		return ""
	}
	raw, ok := nextHops[name]
	if !ok {
		// collectTick only leaves a monitored table's key unset when the
		// default-route command itself failed to execute.
		return ", nexthop ?"
	}
	if nextHop := summarizeDefaultRouteNextHops(raw); nextHop != "" {
		return ", nexthop " + nextHop
	}
	// No values: tell a clean-but-empty parse ({"next_hops": []}) apart
	// from parseOrRaw's raw fallback ({"raw": "..."}), which means the
	// parser failed rather than the device having nothing to report.
	var rawFallback struct {
		Raw *string `json:"raw"`
	}
	if err := json.Unmarshal(raw, &rawFallback); err == nil && rawFallback.Raw != nil {
		return ", nexthop ?"
	}
	return ", nexthop none"
}

func summarizeRouteTotal(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "routes unavailable"
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.Routes) == 0 {
		return "routes unavailable"
	}
	total := decoded.Routes[0]["TOTAL_ROUTES"]
	if total == "" {
		return "routes unavailable"
	}
	return "routes " + total
}

// summarizeDefaultRouteNextHops decodes a junos_default_route_nexthop
// result ({"next_hops": [...]}) and returns the distinct NEXTHOP values,
// sorted and comma-joined via the same dedupeSorted (poll.go) every other
// table/interface list in this binary uses. Junos's "show route ... 0/0
// exact extensive" repeats "Protocol next hop: <ip>" once per route
// reflector that advertised the path (a fleet with 3 RRs commonly emits the
// same value 3 times) plus a second, more detailed line per path — deduping
// here is what turns that RR-count-inflated raw line count into "the
// default route's next hop(s) actually changed" signal. Returns "" (not
// "unavailable") for empty/unparseable input, matching the "optional
// per-table data" contract summarizeRoutes relies on.
func summarizeDefaultRouteNextHops(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var decoded struct {
		NextHops []map[string]string `json:"next_hops"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.NextHops) == 0 {
		return ""
	}
	nextHops := make([]string, 0, len(decoded.NextHops))
	for _, record := range decoded.NextHops {
		nextHops = append(nextHops, record["NEXTHOP"])
	}
	return strings.Join(dedupeSorted(nextHops), ",")
}

type interfaceStatusRow struct {
	iface    string
	inbound  string
	outbound string
}

// interfaceTableLines formats polled interfaces as an ASCII table:
//
//	| Interface | Inbound | Outbound |
//
// Unlike xr-routing-monitor, there is no per-interface routing-table label
// here: this tool's MVP has no auto-detection linking an interface back to
// the table it serves (see cmd/xr-routing-monitor's VRF auto-detect for
// that feature; it is not yet ported — every interface is simply whatever
// the operator typed at onboarding). Only interfaces with non-zero inbound
// or outbound rates are expanded into rows; idle 0/0 interfaces are counted
// in a summary line instead.
func interfaceTableLines(result tickResult) []string {
	if len(result.Interfaces) == 0 {
		return nil
	}

	names := make([]string, 0, len(result.Interfaces))
	for name := range result.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]interfaceStatusRow, 0, len(names))
	hiddenZeroRate := 0
	for _, name := range names {
		row := interfaceStatusRow{iface: name, inbound: "?", outbound: "?"}
		stat, ok := firstInterfaceStat(result.Interfaces[name])
		if !ok {
			rows = append(rows, row)
			continue
		}
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

// firstInterfaceStat decodes one interface's {"stats": [...]} result (as
// produced by parseOrRaw with the junos_interface_stats parser, see
// poll.go/collectTick) and returns its first record, or ok=false if the
// JSON doesn't decode or has no records. Delegates to
// monitorreport.FirstInterfaceStat so this tool, cmd/xr-routing-monitor,
// and internal/monitorreport's own report generator all interpret the same
// parser output shape from one definition instead of three independent
// copies that could silently drift apart.
func firstInterfaceStat(raw json.RawMessage) (map[string]string, bool) {
	return monitorreport.FirstInterfaceStat(raw)
}

func isZeroRate(raw string) bool {
	value, err := strconv.ParseFloat(raw, 64)
	return err == nil && value == 0
}

func formatInterfaceTable(rows []interfaceStatusRow) []string {
	if len(rows) == 0 {
		return nil
	}
	ifaceWidth := len("Interface")
	inWidth := len("Inbound")
	outWidth := len("Outbound")
	for _, row := range rows {
		ifaceWidth = max(ifaceWidth, len(row.iface))
		inWidth = max(inWidth, len(row.inbound))
		outWidth = max(outWidth, len(row.outbound))
	}

	rowFormat := fmt.Sprintf("| %%-%ds | %%%ds | %%%ds |", ifaceWidth, inWidth, outWidth)
	lines := make([]string, 0, len(rows)+1)
	lines = append(lines, fmt.Sprintf(rowFormat, "Interface", "Inbound", "Outbound"))
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf(rowFormat, row.iface, row.inbound, row.outbound))
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
