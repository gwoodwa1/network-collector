package main

import (
	"encoding/json"
	"testing"
)

// sampleBGPSummaryOutput mirrors the shape of real "show bgp summary"
// output (peer IPs kept in RFC 1918 space; all AS numbers replaced with
// private-range/documentation-safe values and all routing-instance names
// replaced with generic CUSTOMER-A/B/C-style names — see cmd/xr-routing-monitor's
// own parser_test.go for the same sanitization convention), covering the
// awkward cases that are easy to get wrong: the "Table" section's summary
// lines wrap the table name and its counts onto two separate lines when
// the table name is long (must not be mistaken for a peer line); Last
// Up/Dwn appears as weeks+days concatenated with no space then a separate
// H:MM:SS token ("12w6d 2:57:25", "8w6d 6:05:16"), as bare days
// ("1d 6:06:03", "5d 3:21:53", "6d 13:32:27" — no leading zero-padding),
// and — not exercised by earlier synthetic fixtures — a 4-byte ASN in the
// private 4200000000-4294967294 block; down peers show "Idle"/"Connect"
// with no per-table breakdown line following.
const sampleBGPSummaryOutput = `Groups: 251 Peers: 268 Down peers: 24
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
bgp.rtarget.0
                      17          4          0          0          0          0
inet.0
                     103          6          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.1               1111          0          0       0       0 12w6d 2:57:25 Idle
10.0.10.50            65400     280604     202341       0       0 12w6d 2:45:31 Establ
  RI-CUSTOMER-A-100001.inet.0: 1/1/1/0
10.0.17.85            64582    1151509    1151468       0       1 8w6d 6:05:16 Establ
  RI-CUSTOMER-B-100002.inet.0: 34/34/34/0
10.10.10.11           65001          0          0       0       1 11w4d 16:07:05 Connect
10.28.0.2             65514       3730       3725       0       6  1d 6:06:03 Establ
  RI-CUSTOMER-C-100003.inet.0: 5/9/8/0
10.116.0.6            65020      14829      15245       0       7  5d 3:21:53 Establ
  RI-CUSTOMER-D-100004.inet.0: 11/11/11/0
10.130.144.8     4200000001      86606      141889       0       1 3w5d 3:40:29 Establ
  RI-CUSTOMER-D-100004.inet.0: 1/3/1/0
10.173.255.247        65021      18912      19467       0     676 6d 13:32:27 Establ
  RI-CUSTOMER-E-100005.inet.0: 8/8/8/0
10.9.0.2              65526          0          0       0       0 12w6d 2:57:25 Connect
172.16.0.1            65022      59594      57599       0       4 2w5d 9:35:56 Establ
  bgp.l3vpn.0: 99/179/126/0
  RI-CUSTOMER-F-100006.inet.0: 10/38/20/0
`

// sampleRouteSummaryTableOutput mirrors real "show route summary table
// <table>" output (self ASN replaced with a documentation-safe value):
// a multi-line preamble (autonomous system, router ID, highwater marks)
// precedes the actual summary line, and the per-protocol breakdown lines
// use "<N> routes, <M> active" wording rather than two bare numbers — the
// template only captures the single summary line, so both are exercised
// here to prove the preamble/breakdown lines are harmlessly skipped rather
// than mismatched into the wrong fields.
const sampleRouteSummaryTableOutput = `Autonomous system number: 65000
Router ID: 172.16.252.37

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 41853 at 2026-04-16 11:08:40 / 39158
    RIB routes                   : 131435 at 2026-06-18 17:38:26 / 117670
    FIB routes                   : 18970 at 2026-07-11 00:02:28 / 18811
    VRF type routing instances   : 179 at 2026-07-13 09:50:15

RI-CUSTOMER-G-300001.inet.0: 20 destinations, 23 routes (20 active, 0 holddown, 0 hidden)
              Direct:      5 routes,      5 active
               Local:      5 routes,      5 active
                 BGP:     10 routes,      8 active
              Static:      3 routes,      2 active
`

// sampleInterfaceStatsOutput mirrors real "show interfaces <iface> | match
// \"Description:|Input :|Output:\"" output (RI name genericized to match
// the rest of this file). This replaced an earlier, wrong guess at the
// command/format entirely: real Junos interface statistics (without
// "extensive") are a Packets/pps/Bytes/bps table under "Input :"/"Output:"
// labels — not the "N second input rate X bits/sec" text this template
// originally assumed. Note the labels' padding: "Input :" has an extra
// space before the colon so it lines up with "Output:", one character
// shorter.
const sampleInterfaceStatsOutput = `    Description: ## Customer G circuit - vrf RI-CUSTOMER-G-300001 ##
    Statistics        Packets        pps         Bytes          bps
        Input :     477256470         42   58731637663        21368
        Output:       1807957          0     126245902            0
`

// sampleRouteTableOutput is trimmed from real "show route table <table>"
// output (self/foreign ASNs and one public prefix replaced with
// documentation-safe values), covering cases a synthetic fixture had
// gotten wrong: a default route with 3 ECMP BGP paths, each ending in a
// trailing MPLS label annotation (", Push 160") that must not prevent the
// next-hop match; a 4th, lower-preference Static "Discard" alternative
// with no "to"/"via" at all (correctly not captured as a route — there is
// no real next hop to report); and Local routes, which read
// "Local via <iface>" rather than a bare "via <iface>".
const sampleRouteTableOutput = `RI-CUSTOMER-H-300002.inet.0: 21 destinations, 24 routes (21 active, 0 holddown, 0 hidden)
@ = Routing Use Only, # = Forwarding Use Only
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[BGP/170] 3d 00:19:50, MED 0, localpref 150, from 172.16.252.43
                      AS path: 65030 I, validation-state: unverified
                    >  to 172.16.254.43 via ae0.0, Push 160
                    [BGP/170] 3d 00:19:50, MED 0, localpref 150, from 172.16.252.44
                      AS path: 65030 I, validation-state: unverified
                    >  to 172.16.254.43 via ae0.0, Push 160
                    [BGP/170] 3d 00:19:50, MED 0, localpref 150, from 172.16.252.45
                      AS path: 65030 I, validation-state: unverified
                    >  to 172.16.254.43 via ae0.0, Push 160
                    [Static/4294967295] 12w6d 03:00:41
                       Discard
10.0.17.72/29      *[Static/5] 12w6d 02:52:20
                    >  to 10.0.110.233 via irb.360
10.0.110.160/32    *[BGP/170] 10w6d 11:29:57, localpref 100
                      AS path: 65376 I, validation-state: unverified
                    >  to 10.232.236.17 via ae72.360
10.0.110.192/29    *[Direct/0] 12w6d 02:48:06
                    >  via irb.363
10.0.110.193/32    *[Local/0] 12w6d 02:44:50
                       Local via irb.363
10.0.110.228/30    *[Direct/0] 3w4d 09:44:38
                    >  via ge-128/0/45.369
10.0.110.229/32    *[Local/0] 3w4d 09:44:38
                       Local via ge-128/0/45.369
198.51.100.34/32   *[BGP/170] 2w5d 06:19:39, localpref 100
                      AS path: 65376 I, validation-state: unverified
                    >  to 10.232.236.17 via ae72.360
`

const sampleReceiveProtocolOutput = `inet.0: 100 destinations, 105 routes (100 active, 0 holddown, 0 hidden)
  Prefix                  Nexthop              MED     Lclpref    AS path
* 10.0.0.0/24             10.1.1.1                            100        65000 65001 I
  10.0.2.0/24             10.1.1.1                              100        65000 I
`

const sampleAdvertisingProtocolOutput = `inet.0: 100 destinations, 105 routes (100 active, 0 holddown, 0 hidden)
  Prefix                  Nexthop              MED     Lclpref    AS path
* 10.0.0.0/24             Self                                    65000 I
`

// sampleDefaultRouteNextHopOutput mirrors real "show route table <table>
// 0/0 exact extensive | match \"Protocol next hop:\"" output: 3 ECMP BGP
// paths to the default route, each producing 2 matching lines (a summary
// "Protocol next hop: <ip>" line and a more detailed one with trailing
// "Metric:"/"ResolvState:" text) — one pair per route reflector that
// advertised the path, all carrying the same next-hop value here. The
// parser captures every occurrence; summarizeDefaultRouteNextHops
// (status.go) is what dedupes this down to the distinct value(s).
const sampleDefaultRouteNextHopOutput = `                Protocol next hop: 172.16.252.38

                        Protocol next hop: 172.16.252.38 Metric: 1 ResolvState: Resolved

                Protocol next hop: 172.16.252.38

                        Protocol next hop: 172.16.252.38 Metric: 1 ResolvState: Resolved

                Protocol next hop: 172.16.252.38

                        Protocol next hop: 172.16.252.38 Metric: 1 ResolvState: Resolved
`

func TestEmbeddedParsersLoad(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	for _, name := range []string{"junos_bgp_summary", "junos_route_table_summary", "junos_interface_stats", "junos_route_table", "junos_bgp_neighbor_routes", "junos_default_route_nexthop"} {
		if _, ok := parsers[name]; !ok {
			t.Fatalf("expected embedded parser %q to be defined", name)
		}
	}
}

func TestParseBGPSummary(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleBGPSummaryOutput, "junos_bgp_summary", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Neighbors []map[string]string `json:"neighbors"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Neighbors) != 10 {
		t.Fatalf("expected 10 peers (the \"Table\" section's two-line-wrapped summary rows must not be mistaken for peer lines), got %d: %s", len(decoded.Neighbors), parsed)
	}

	byNeighbor := map[string]map[string]string{}
	for _, n := range decoded.Neighbors {
		byNeighbor[n["NEIGHBOR"]] = n
	}

	weeksAndDays, ok := byNeighbor["10.0.10.50"]
	if !ok {
		t.Fatalf("expected a record for 10.0.10.50, got: %+v", byNeighbor)
	}
	if weeksAndDays["LASTUPDOWN"] != "12w6d 2:45:31" {
		t.Fatalf("expected weeks+days Last Up/Dwn %q, got %q", "12w6d 2:45:31", weeksAndDays["LASTUPDOWN"])
	}
	if weeksAndDays["STATE"] != "Establ" {
		t.Fatalf("expected state Establ, got %q", weeksAndDays["STATE"])
	}

	plainDay, ok := byNeighbor["10.28.0.2"]
	if !ok {
		t.Fatalf("expected a record for 10.28.0.2, got: %+v", byNeighbor)
	}
	if plainDay["LASTUPDOWN"] != "1d 6:06:03" {
		t.Fatalf("expected plain-day Last Up/Dwn %q, got %q", "1d 6:06:03", plainDay["LASTUPDOWN"])
	}

	fourByteASN, ok := byNeighbor["10.130.144.8"]
	if !ok {
		t.Fatalf("expected a record for 10.130.144.8, got: %+v", byNeighbor)
	}
	if fourByteASN["REMOTE_AS"] != "4200000001" {
		t.Fatalf("expected 4-byte ASN %q, got %q", "4200000001", fourByteASN["REMOTE_AS"])
	}

	idle, ok := byNeighbor["10.0.0.1"]
	if !ok || idle["STATE"] != "Idle" {
		t.Fatalf("expected 10.0.0.1 state Idle, got: %+v", idle)
	}
	connect, ok := byNeighbor["10.10.10.11"]
	if !ok || connect["STATE"] != "Connect" {
		t.Fatalf("expected 10.10.10.11 state Connect, got: %+v", connect)
	}

	// summarizeBGP (status.go) is the actual up/down counter this tool
	// relies on at runtime; exercise it directly against this same fixture
	// so the two never silently disagree about what "up" means. 7 Establ
	// (10.0.10.50, 10.0.17.85, 10.28.0.2, 10.116.0.6, 10.130.144.8,
	// 10.173.255.247, 172.16.163.1) of 10 total.
	if got := summarizeBGP(json.RawMessage(parsed)); got != "BGP 7/10 up" {
		t.Fatalf("expected summarizeBGP %q, got %q", "BGP 7/10 up", got)
	}
}

func TestParseRouteSummaryTable(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleRouteSummaryTableOutput, "junos_route_table_summary", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 1 {
		t.Fatalf("expected 1 record (the header line only), got %d: %s", len(decoded.Routes), parsed)
	}
	record := decoded.Routes[0]
	if record["TABLE"] != "RI-CUSTOMER-G-300001.inet.0" || record["DESTINATIONS"] != "20" || record["TOTAL_ROUTES"] != "23" || record["ACTIVE_ROUTES"] != "20" || record["HOLDDOWN"] != "0" || record["HIDDEN"] != "0" {
		t.Fatalf("unexpected record: %+v", record)
	}

	if got := summarizeRouteTotal(json.RawMessage(parsed)); got != "routes 23" {
		t.Fatalf("expected summarizeRouteTotal %q, got %q", "routes 23", got)
	}
}

func TestParseInterfaceStats(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleInterfaceStatsOutput, "junos_interface_stats", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Stats []map[string]string `json:"stats"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Stats) != 1 {
		t.Fatalf("expected 1 record, got %d: %s", len(decoded.Stats), parsed)
	}
	record := decoded.Stats[0]
	if record["DESCRIPTION"] != "## Customer G circuit - vrf RI-CUSTOMER-G-300001 ##" {
		t.Fatalf("unexpected description: %q", record["DESCRIPTION"])
	}
	if record["INPUT_RATE_BPS"] != "21368" || record["OUTPUT_RATE_BPS"] != "0" {
		t.Fatalf("unexpected rates (bps is the last column, not a separate \"rate\" line): %+v", record)
	}
	if record["INPUT_RATE_PPS"] != "42" || record["OUTPUT_RATE_PPS"] != "0" {
		t.Fatalf("unexpected packet rates: %+v", record)
	}
	if record["INPUT_PACKETS"] != "477256470" || record["INPUT_BYTES"] != "58731637663" {
		t.Fatalf("unexpected input totals: %+v", record)
	}
	if record["OUTPUT_PACKETS"] != "1807957" || record["OUTPUT_BYTES"] != "126245902" {
		t.Fatalf("unexpected output totals: %+v", record)
	}
}

func TestParseRouteTable(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleRouteTableOutput, "junos_route_table", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	// 3 ECMP BGP paths for 0.0.0.0/0 (the 4th, lower-preference Static
	// "Discard" alternative has no "to"/"via" line at all and is correctly
	// not captured) + 1 Static + 1 BGP + 1 Direct + 1 Local + 1 Direct
	// (slash-containing interface name) + 1 Local (same interface) + 1 BGP.
	if len(decoded.Routes) != 10 {
		t.Fatalf("expected 10 records, got %d: %s", len(decoded.Routes), parsed)
	}

	var defaultPrefixPaths []map[string]string
	for _, r := range decoded.Routes {
		if r["NETWORK"] == "0.0.0.0/0" {
			defaultPrefixPaths = append(defaultPrefixPaths, r)
		}
	}
	if len(defaultPrefixPaths) != 3 {
		t.Fatalf("expected 3 ECMP paths for 0.0.0.0/0 (the Discard alternative must not produce a 4th), got %d: %+v", len(defaultPrefixPaths), defaultPrefixPaths)
	}
	for _, r := range defaultPrefixPaths {
		// The trailing ", Push 160" MPLS label annotation on each of these
		// lines must not prevent the next hop from matching.
		if r["NEXTHOP"] != "172.16.254.43" {
			t.Fatalf("expected next hop 172.16.254.43 despite trailing MPLS label annotation, got: %+v", r)
		}
		// PROTOCOL must be Filldown: only the first ECMP path's line repeats
		// the network prefix and protocol ("0.0.0.0/0 *[BGP/170]..."); paths
		// 2 and 3 are indented continuation lines ("[BGP/170] ...") with no
		// prefix, so PROTOCOL must persist from the first path's match
		// rather than reset to empty.
		if r["PROTOCOL"] != "BGP" {
			t.Fatalf("expected PROTOCOL to persist as BGP across all ECMP paths via Filldown, got: %+v", r)
		}
	}

	byNetwork := map[string]map[string]string{}
	for _, r := range decoded.Routes {
		if r["NETWORK"] != "0.0.0.0/0" {
			byNetwork[r["NETWORK"]] = r
		}
	}
	static, ok := byNetwork["10.0.17.72/29"]
	if !ok || static["NEXTHOP"] != "10.0.110.233" || static["PROTOCOL"] != "Static" {
		t.Fatalf("unexpected static record: %+v", static)
	}
	direct, ok := byNetwork["10.0.110.192/29"]
	if !ok || direct["NEXTHOP"] != "irb.363" {
		t.Fatalf("expected Direct route next hop irb.363 (interface, no IP), got: %+v", direct)
	}
	local, ok := byNetwork["10.0.110.193/32"]
	if !ok || local["NEXTHOP"] != "irb.363" || local["PROTOCOL"] != "Local" {
		t.Fatalf("expected Local route (\"Local via <iface>\" wording, not bare \"via\") next hop irb.363, got: %+v", local)
	}
	directSlashIface, ok := byNetwork["10.0.110.228/30"]
	if !ok || directSlashIface["NEXTHOP"] != "ge-128/0/45.369" {
		t.Fatalf("expected Direct route next hop ge-128/0/45.369 (interface name containing '/'), got: %+v", directSlashIface)
	}
	localSlashIface, ok := byNetwork["10.0.110.229/32"]
	if !ok || localSlashIface["NEXTHOP"] != "ge-128/0/45.369" {
		t.Fatalf("expected Local route next hop ge-128/0/45.369, got: %+v", localSlashIface)
	}
}

func containsAll(haystack []string, wants ...string) bool {
	set := map[string]bool{}
	for _, v := range haystack {
		set[v] = true
	}
	for _, w := range wants {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestParseBGPNeighborRoutesReceiveProtocol(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleReceiveProtocolOutput, "junos_bgp_neighbor_routes", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 2 {
		t.Fatalf("expected 2 records, got %d: %s", len(decoded.Routes), parsed)
	}
	byNetwork := map[string]map[string]string{}
	for _, r := range decoded.Routes {
		byNetwork[r["NETWORK"]] = r
	}
	if byNetwork["10.0.0.0/24"]["NEXTHOP"] != "10.1.1.1" {
		t.Fatalf("unexpected record for 10.0.0.0/24: %+v", byNetwork["10.0.0.0/24"])
	}
	if byNetwork["10.0.2.0/24"]["NEXTHOP"] != "10.1.1.1" {
		t.Fatalf("unexpected record for 10.0.2.0/24: %+v", byNetwork["10.0.2.0/24"])
	}
}

func TestParseBGPNeighborRoutesAdvertisingProtocolSelfNextHop(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleAdvertisingProtocolOutput, "junos_bgp_neighbor_routes", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 1 {
		t.Fatalf("expected 1 record, got %d: %s", len(decoded.Routes), parsed)
	}
	if decoded.Routes[0]["NEXTHOP"] != "Self" {
		t.Fatalf("expected next hop %q, got %q", "Self", decoded.Routes[0]["NEXTHOP"])
	}
}

func TestParseDefaultRouteNextHop(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleDefaultRouteNextHopOutput, "junos_default_route_nexthop", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		NextHops []map[string]string `json:"next_hops"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	// 3 ECMP paths x 2 matching lines each (summary + detailed) = 6 raw
	// records; deduping down to the distinct next hop is
	// summarizeDefaultRouteNextHops's job (status.go), not this parser's.
	if len(decoded.NextHops) != 6 {
		t.Fatalf("expected 6 raw records, got %d: %s", len(decoded.NextHops), parsed)
	}
	for _, r := range decoded.NextHops {
		if r["NEXTHOP"] != "172.16.252.38" {
			t.Fatalf("expected every record's next hop to be 172.16.252.38 (including the detailed line with trailing Metric/ResolvState text), got: %+v", r)
		}
	}

	if got := summarizeDefaultRouteNextHops(json.RawMessage(parsed)); got != "172.16.252.38" {
		t.Fatalf("expected summarizeDefaultRouteNextHops to dedupe to a single value %q, got %q", "172.16.252.38", got)
	}
}
