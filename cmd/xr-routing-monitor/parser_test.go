package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Sample command output below is sanitized: hostnames, AS numbers, VRF/RD
// names, and public prefixes are replaced with documentation-safe values
// (RFC 5737 TEST-NET ranges, private ASNs) while preserving the exact
// column layout and edge cases (multipath, blank Metric, eBGP vs iBGP) that
// the real device output exercised.

const sampleInterfaceOutput = `RP/0/RSP0/CPU0:pe-router-1#show int BE100 | inc "rate|Description:"
Wed Jul  8 22:07:26.779 BST
  Description: ## Link Bundle to pe-router-2 (BE100) ##
  5 minute input rate 6200210000 bits/sec, 855583 packets/sec
  5 minute output rate 4067093000 bits/sec, 727374 packets/sec
RP/0/RSP0/CPU0:pe-router-1#
`

const sampleInterfaceOutput30Second = `RP/0/RSP0/CPU0:pe-router-1#show int BE45 | inc "Desc|rate"
Thu Jul  9 09:39:27.184 BST
  Description: ### Link to core-router-2 (2*10GiE) ###
  30 second input rate 124000 bits/sec, 178 packets/sec
  30 second output rate 180000 bits/sec, 203 packets/sec
RP/0/RSP0/CPU0:pe-router-1#
`

// sampleRouteVRFAllGatewaysOutput mirrors "show route vrf all | inc
// \"Gateway of last resort|VRF:\"" on a router with several system VRFs
// (**nVSatellite, **eint, **iid — Cisco-internal, never carry a default
// route), several numbered customer VRFs, and one named VRF. Only VRFs with
// an actual default route produce a "Gateway of last resort" line, which is
// the signal xr_route_vrf_all_gateways keys off — VRFs without one (all the
// system VRFs, plus 9000001/9000002/9000003/9000004/9000005/9000006/9000007
// here) must not appear in the parsed output at all.
const sampleRouteVRFAllGatewaysOutput = `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
Thu Jul  9 11:31:44.914 BST
VRF: **nVSatellite
VRF: 9000001
VRF: 9000002
VRF: 9000003
VRF: 9000004
VRF: 4000001
Gateway of last resort is 10.99.99.53 to network 0.0.0.0
VRF: 9000005
VRF: CUSTOMER-A-INTERNET
Gateway of last resort is 10.99.99.51 to network 0.0.0.0
VRF: 9000006
VRF: 9000007
VRF: **eint
VRF: **iid
RP/0/RSP0/CPU0:pe-router-1#
`

// sampleVRFDetailInterfacesOutput mirrors "show vrf <vrf> ipv4 detail": the
// "Interfaces:" section lists the interfaces actually assigned to the VRF.
// Discovery must parse only that section, not later indented non-interface
// details in the same command output.
const sampleVRFDetailInterfacesOutput = `RP/0/RSP1/CPU0:entthw-bpe-1a#show vrf 1115679 ipv4 detail
Thu Jul  9 21:52:46.033 BST

VRF 1115679; RD 56460:901115679; VPN ID not set
VRF mode: Regular
Description Sainsburys DDoS VRF
Interfaces:
  TenGigE0/7/0/18.38540079
  TenGigE0/7/0/19.39890079
  TenGigE0/0/0/22.11240078
  TenGigE0/7/0/18.38010079
  TenGigE0/7/0/18.39890079
  TenGigE0/7/0/18.39930079
Address family IPV4 Unicast
  Import VPN route-target communities:
    RT:35228:3000000
    RT:56460:1115679
  Export VPN route-target communities:
    RT:56460:1115679
  No import route policy
  No export route policy
RP/0/RSP1/CPU0:entthw-bpe-1a#
`

// sampleVRFDetailNoInterfacesOutput mirrors the same command for a VRF with
// no interfaces assigned at all (e.g. RI-INTERNET-ENTERPRISE on a device
// where it carries no local circuit) — an empty "Interfaces:" section
// immediately followed by "Address family ..." must parse to zero records,
// not one bogus empty one.
const sampleVRFDetailNoInterfacesOutput = `RP/0/RSP0/CPU0:pe-router-1#show vrf CUSTOMER-A-INTERNET ipv4 detail
Thu Jul  9 11:33:30.112 BST

VRF CUSTOMER-A-INTERNET; RD 65001:100; VPN ID not set
VRF mode: Regular
Interfaces:
Address family IPV4 Unicast
  Import VPN route-target communities:
    RT:65001:100
  Export VPN route-target communities:
    RT:65001:100
  No import route policy
  No export route policy
RP/0/RSP0/CPU0:pe-router-1#
`

const sampleRouteVRFSummaryOutput = `RP/0/RSP0/CPU0:pe-router-1#show route vrf CUSTOMER-A-INTERNET summary
Wed Jul  8 22:06:07.333 BST
Route Source                     Routes     Backup     Deleted     Memory(bytes)
static                           15         0          0           3240
connected                        20         0          0           4320
local                            20         0          0           4320
local HSRP                       3          0          0           648
dagr                             0          0          0           0
bgp 65001                        325        4          0           75024
mobile static route              2          0          0           432
Total                            385        4          0           87984

RP/0/RSP0/CPU0:pe-router-1#
`

const sampleBGPVPNv4SummaryOutput = `RP/0/RSP0/CPU0:pe-router-1#show bgp vpnv4 unicast summary
Wed Jul  8 22:05:37.334 BST
BGP router identifier 192.0.2.1, local AS number 65001
BGP generic scan interval 60 secs
Non-stop routing is enabled
BGP table state: Active
Table ID: 0x0
BGP main routing table version 1352209319
BGP NSR Initial initsync version 259 (Reached)
BGP NSR/ISSU Sync-Group versions 1352209319/0
BGP scan interval 60 secs

BGP is operating in STANDALONE mode.


Process       RcvTblVer   bRIB/RIB   LabelVer  ImportVer  SendTblVer  StandbyVer
Speaker       1352209319  1352209319  1352209319  1352209319  1352209319  1352209319

Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
198.51.100.10     0 65001 206444625  956009 1352209319    0    0    1y39w      59809
198.51.100.40     0 65001 260108109  956008 1352209319    0    0    1y39w      59809
198.51.100.70     0 65001 215478009  955958 1352209319    0    0    1y39w      59802
198.51.100.101     0 65002 7753189 1857886 1352209319    0    0    1y18w        426
198.51.100.103     0 65002 7750997 1857906 1352209319    0    0    1y18w        426
198.51.100.105     0 65002 7730455 1857923 1352209319    0    0    1y19w        426

RP/0/RSP0/CPU0:pe-router-1#
`

// sampleBGPRouteTableOutput is an excerpt of `show bgp vrf <vrf>` /
// `show bgp vpnv4 unicast neighbors <ip> routes` covering: a multipath
// prefix (0.0.0.0/0, 4 paths, one best), a single-path iBGP prefix, a
// single-path eBGP prefix (no "i" flag), and a prefix with a blank Metric
// column (only LocPrf/Weight present before Path).
const sampleBGPRouteTableOutput = `RP/0/RSP0/CPU0:pe-router-1#show bgp vrf CUSTOMER-A-INTERNET
Wed Jul  8 22:08:36.271 BST
BGP VRF CUSTOMER-A-INTERNET, state: Active
BGP Route Distinguisher: 65002:100
Status codes: s suppressed, d damped, h history, * valid, > best
              i - internal, r RIB-failure, S stale, N Nexthop-discard
Origin codes: i - IGP, e - EGP, ? - incomplete
   Network            Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 65002:100 (default for vrf CUSTOMER-A-INTERNET)
Route Distinguisher Version: 1352205489
* i0.0.0.0/0          198.51.100.201            0    100      0 65003 i
*>i                   198.51.100.203            0    100      0 65003 i
* i                   198.51.100.202            0    100      0 65004 i
* i                   198.51.100.204            0    100      0 65004 i
*>i10.1.5.0/24        198.51.100.32            0    100      0 ?
*> 192.0.2.0/28       10.62.101.1                   210      0 65005 ?
*>i192.0.2.16/28      198.51.100.33                 600      0 65006 i

Processed 5 prefixes, 8 paths
RP/0/RSP0/CPU0:pe-router-1#
`

// sampleBGPAdvertisedRoutesOutput is an excerpt of
// `show bgp vpnv4 unicast neighbors <ip> advertised-routes`, which uses a
// different 4-column layout (no Metric/LocPrf/Weight) and no multipath
// continuation lines.
const sampleBGPAdvertisedRoutesOutput = `RP/0/RSP0/CPU0:pe-router-1#show bgp vpnv4 unicast neighbors 198.51.100.101 advertised-routes
Wed Jul  8 22:11:01.392 BST
Network            Next Hop        From            AS Path
Route Distinguisher: 65002:100
Route Distinguisher Version: 1352205489
192.0.2.0/28       198.51.100.64   10.62.101.1     65005?
192.0.2.32/32      198.51.100.64   10.62.101.40    65006 65006 65007?
192.0.2.40/29      198.51.100.64   Local           ?

Processed 48 prefixes, 48 paths
RP/0/RSP0/CPU0:pe-router-1#
`

// sampleBGPNeighborRoutesOutput is `show bgp vpnv4 unicast neighbors <ip>
// routes` specifically (as opposed to sampleBGPRouteTableOutput, which is
// `show bgp vrf <vrf>`) — distinct real captures that happen to share the
// same table layout, exercised separately here because snapshot.go parses
// the neighbor-routes command with the same xr_bgp_route_table parser and
// that path had no dedicated fixture. Covers a different multipath shape
// (two iBGP paths per prefix, blank Metric column) than the vrf-table
// sample.
const sampleBGPNeighborRoutesOutput = `RP/0/RSP0/CPU0:pe-router-1#show bgp vpnv4 unicast neighbors 198.51.100.101 routes
Wed Jul  8 22:11:09.147 BST
BGP router identifier 192.0.2.1, local AS number 65001
BGP generic scan interval 60 secs
Non-stop routing is enabled
BGP table state: Active

Status codes: s suppressed, d damped, h history, * valid, > best
              i - internal, r RIB-failure, S stale, N Nexthop-discard
Origin codes: i - IGP, e - EGP, ? - incomplete
   Network            Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 65002:100 (default for vrf CUSTOMER-A-INTERNET)
Route Distinguisher Version: 1352205489
*>i192.0.2.64/29      10.17.2.22                    200      0 i
* i                   10.17.2.23                    200      0 i
*>i192.0.2.72/29      10.17.2.24                    200      0 i
* i                   10.17.2.25                    200      0 i
*>i192.0.2.80/24      10.62.101.1              0    100      0 65008 i

Processed 3 prefixes, 5 paths
RP/0/RSP0/CPU0:pe-router-1#
`

// sampleRouteVRFDefaultDetailOutput is trimmed from real "show route vrf
// <vrf> 0.0.0.0/0 detail" output (self ASN and RD replaced with
// documentation-safe values). Unlike Junos's "extensive" output, this
// shows only the installed/best path under "Routing Descriptor Blocks" —
// no route-reflector-count duplication to dedupe here, though
// summarizeDefaultRouteNextHops still dedupes defensively for a genuine
// ECMP default route with more than one block.
const sampleRouteVRFDefaultDetailOutput = `RP/0/RSP0/CPU0:pe-router-1#show route vrf CUSTOMER-A-INTERNET 0.0.0.0/0 detail
Tue Jul 14 22:38:05.106 BST

Routing entry for 0.0.0.0/0
  Known via "bgp 65020", distance 200, metric 0, candidate default path
  Tag 64581, type internal
  Installed Jul 11 21:01:13.524 for 3d01h
  Routing Descriptor Blocks
    172.16.252.37, from 172.16.252.46
      Nexthop in Vrf: "default", Table: "default", IPv4 Unicast, Table Id: 0xe0000000
      Route metric is 0, Wt is 1
      Label: 0xbf (191)
      Tunnel ID: None
      Binding Label: None
      Extended communities count: 0
      Source RD attributes: 0x0000:65000:100000
      NHID: 0x0 (Ref: 0)
  Route version is 0x21 (33)
  No local label
  IP Precedence: Not Set
  QoS Group ID: Not Set
  Flow-tag: Not Set
  Fwd-class: Not Set
  Route Priority: RIB_PRIORITY_RECURSIVE (12) SVD Type RIB_SVD_TYPE_REMOTE
  Download Priority 3, Download Version 167019
  No advertising protos.
RP/0/RSP0/CPU0:pe-router-1#
`

func TestEmbeddedParsersLoad(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	for _, name := range []string{"xr_bgp_vpnv4_summary", "xr_route_vrf_summary", "xr_bundle_interface_stats", "xr_bgp_route_table", "xr_bgp_advertised_routes", "xr_route_vrf_default_nexthop"} {
		if _, ok := parsers[name]; !ok {
			t.Fatalf("expected embedded parser %q to be defined", name)
		}
	}
}

func TestParseBGPRouteTable(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleBGPRouteTableOutput, "xr_bgp_route_table", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 7 {
		t.Fatalf("expected 7 records (4 paths to 0.0.0.0/0 + 3 single-path prefixes), got %d: %s", len(decoded.Routes), parsed)
	}

	var defaultRoutePaths []map[string]string
	for _, record := range decoded.Routes {
		if record["NETWORK"] == "0.0.0.0/0" {
			defaultRoutePaths = append(defaultRoutePaths, record)
		}
	}
	if len(defaultRoutePaths) != 4 {
		t.Fatalf("expected 4 paths filled down to 0.0.0.0/0, got %d: %+v", len(defaultRoutePaths), defaultRoutePaths)
	}
	var bestCount int
	for _, record := range defaultRoutePaths {
		if record["NEXTHOP"] != "198.51.100.201" && record["NEXTHOP"] != "198.51.100.202" && record["NEXTHOP"] != "198.51.100.203" && record["NEXTHOP"] != "198.51.100.204" {
			t.Fatalf("unexpected next hop for 0.0.0.0/0 path: %+v", record)
		}
		if record["BEST"] == ">" {
			bestCount++
			if record["NEXTHOP"] != "198.51.100.203" {
				t.Fatalf("expected best path next hop 198.51.100.203, got %+v", record)
			}
		}
	}
	if bestCount != 1 {
		t.Fatalf("expected exactly 1 best path for 0.0.0.0/0, got %d", bestCount)
	}

	bySource := map[string]map[string]string{}
	for _, record := range decoded.Routes {
		if record["NETWORK"] != "0.0.0.0/0" {
			bySource[record["NETWORK"]] = record
		}
	}
	ebgp, ok := bySource["192.0.2.0/28"]
	if !ok {
		t.Fatalf("expected a record for 192.0.2.0/28, got: %+v", bySource)
	}
	if ebgp["INTERNAL"] != " " || ebgp["NEXTHOP"] != "10.62.101.1" {
		t.Fatalf("unexpected eBGP record (should have no internal flag): %+v", ebgp)
	}
	blankMetric, ok := bySource["192.0.2.16/28"]
	if !ok {
		t.Fatalf("expected a record for 192.0.2.16/28, got: %+v", bySource)
	}
	if !strings.Contains(blankMetric["ATTRIBUTES"], "65006") {
		t.Fatalf("expected attributes to contain the AS path, got %q", blankMetric["ATTRIBUTES"])
	}
}

func TestParseBGPNeighborRoutes(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleBGPNeighborRoutesOutput, "xr_bgp_route_table", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 5 {
		t.Fatalf("expected 5 records (2 paths x 2 prefixes + 1 single-path prefix), got %d: %s", len(decoded.Routes), parsed)
	}

	byNetwork := map[string][]map[string]string{}
	for _, record := range decoded.Routes {
		byNetwork[record["NETWORK"]] = append(byNetwork[record["NETWORK"]], record)
	}
	for _, network := range []string{"192.0.2.64/29", "192.0.2.72/29"} {
		paths, ok := byNetwork[network]
		if !ok || len(paths) != 2 {
			t.Fatalf("expected 2 filled-down paths for %s, got: %+v", network, paths)
		}
		var bestCount int
		for _, path := range paths {
			if path["BEST"] == ">" {
				bestCount++
			}
			if path["INTERNAL"] != "i" {
				t.Fatalf("expected all paths for %s to be iBGP, got: %+v", network, path)
			}
		}
		if bestCount != 1 {
			t.Fatalf("expected exactly 1 best path for %s, got %d", network, bestCount)
		}
	}

	single, ok := byNetwork["192.0.2.80/24"]
	if !ok || len(single) != 1 {
		t.Fatalf("expected exactly 1 record for 192.0.2.80/24, got: %+v", single)
	}
	if single[0]["NEXTHOP"] != "10.62.101.1" || !strings.Contains(single[0]["ATTRIBUTES"], "65008") {
		t.Fatalf("unexpected single-path record: %+v", single[0])
	}
}

func TestParseBGPAdvertisedRoutes(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleBGPAdvertisedRoutesOutput, "xr_bgp_advertised_routes", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 3 {
		t.Fatalf("expected 3 records, got %d: %s", len(decoded.Routes), parsed)
	}
	bySource := map[string]map[string]string{}
	for _, record := range decoded.Routes {
		bySource[record["NETWORK"]] = record
	}
	locallyOriginated, ok := bySource["192.0.2.40/29"]
	if !ok {
		t.Fatalf("expected a record for 192.0.2.40/29, got: %+v", bySource)
	}
	if locallyOriginated["FROM"] != "Local" || locallyOriginated["PATH"] != "?" {
		t.Fatalf("unexpected locally-originated record: %+v", locallyOriginated)
	}
	transit, ok := bySource["192.0.2.32/32"]
	if !ok {
		t.Fatalf("expected a record for 192.0.2.32/32, got: %+v", bySource)
	}
	if !strings.Contains(transit["PATH"], "65006 65006 65007") {
		t.Fatalf("unexpected AS path: %q", transit["PATH"])
	}
}

func TestParseBundleInterfaceStats(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleInterfaceOutput, "xr_bundle_interface_stats", parsers)
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
		t.Fatalf("expected exactly 1 record, got %d: %s", len(decoded.Stats), parsed)
	}
	record := decoded.Stats[0]
	if record["DESCRIPTION"] != "## Link Bundle to pe-router-2 (BE100) ##" {
		t.Fatalf("unexpected description: %q", record["DESCRIPTION"])
	}
	if record["INPUT_RATE_BPS"] != "6200210000" || record["INPUT_RATE_PPS"] != "855583" {
		t.Fatalf("unexpected input rate fields: %+v", record)
	}
	if record["OUTPUT_RATE_BPS"] != "4067093000" || record["OUTPUT_RATE_PPS"] != "727374" {
		t.Fatalf("unexpected output rate fields: %+v", record)
	}
}

// Interfaces with a 30-second load interval configured (instead of the XR
// default 5-minute interval) print "30 second input/output rate" lines. The
// template must not assume "5 minute" is the only possible interval label.
func TestParseBundleInterfaceStats30SecondInterval(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleInterfaceOutput30Second, "xr_bundle_interface_stats", parsers)
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
		t.Fatalf("expected exactly 1 record, got %d: %s", len(decoded.Stats), parsed)
	}
	record := decoded.Stats[0]
	if record["INPUT_RATE_BPS"] != "124000" || record["INPUT_RATE_PPS"] != "178" {
		t.Fatalf("unexpected input rate fields: %+v", record)
	}
	if record["OUTPUT_RATE_BPS"] != "180000" || record["OUTPUT_RATE_PPS"] != "203" {
		t.Fatalf("unexpected output rate fields: %+v", record)
	}
}

func TestParseRouteVRFSummary(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleRouteVRFSummaryOutput, "xr_route_vrf_summary", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Routes []map[string]string `json:"routes"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Routes) != 8 {
		t.Fatalf("expected 8 route source records (including Total), got %d: %s", len(decoded.Routes), parsed)
	}
	bySource := map[string]map[string]string{}
	for _, record := range decoded.Routes {
		bySource[record["SOURCE"]] = record
	}
	for _, name := range []string{"static", "connected", "local", "local HSRP", "dagr", "bgp 65001", "mobile static route", "Total"} {
		if _, ok := bySource[name]; !ok {
			t.Fatalf("expected a record for source %q, got sources: %+v", name, bySource)
		}
	}
	if bySource["bgp 65001"]["ROUTES"] != "325" || bySource["bgp 65001"]["BACKUP"] != "4" {
		t.Fatalf("unexpected bgp record: %+v", bySource["bgp 65001"])
	}
	// "mobile static route" is a synthetic 3-word source label added to prove
	// SOURCE isn't limited to one or two tokens (the real anchor is the 2+
	// space gap before the numeric columns, not word count).
	if bySource["mobile static route"]["ROUTES"] != "2" || bySource["mobile static route"]["MEMORY"] != "432" {
		t.Fatalf("unexpected multi-word source record: %+v", bySource["mobile static route"])
	}
	if bySource["Total"]["ROUTES"] != "385" || bySource["Total"]["MEMORY"] != "87984" {
		t.Fatalf("unexpected total record: %+v", bySource["Total"])
	}
}

func TestParseRouteVRFDefaultDetail(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleRouteVRFDefaultDetailOutput, "xr_route_vrf_default_nexthop", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		NextHops []map[string]string `json:"next_hops"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.NextHops) != 1 {
		t.Fatalf("expected 1 record (single installed path, no route-reflector duplication like Junos), got %d: %s", len(decoded.NextHops), parsed)
	}
	if decoded.NextHops[0]["NEXTHOP"] != "172.16.252.37" {
		t.Fatalf("expected next hop %q, got %q", "172.16.252.37", decoded.NextHops[0]["NEXTHOP"])
	}

	if got := summarizeDefaultRouteNextHops(json.RawMessage(parsed)); got != "172.16.252.37" {
		t.Fatalf("expected summarizeDefaultRouteNextHops %q, got %q", "172.16.252.37", got)
	}
}

func TestParseBGPVPNv4Summary(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleBGPVPNv4SummaryOutput, "xr_bgp_vpnv4_summary", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Neighbors []map[string]string `json:"neighbors"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Neighbors) != 6 {
		t.Fatalf("expected 6 neighbor records, got %d: %s", len(decoded.Neighbors), parsed)
	}
	byNeighbor := map[string]map[string]string{}
	for _, record := range decoded.Neighbors {
		byNeighbor[record["NEIGHBOR"]] = record
	}
	first, ok := byNeighbor["198.51.100.10"]
	if !ok {
		t.Fatalf("expected a record for neighbor 198.51.100.10, got: %+v", byNeighbor)
	}
	if first["REMOTE_AS"] != "65001" || first["MSGRCVD"] != "206444625" || first["MSGSENT"] != "956009" {
		t.Fatalf("unexpected neighbor fields: %+v", first)
	}
	if first["STATE_OR_PFXRCD"] != "59809" {
		t.Fatalf("expected established prefix count 59809, got %q", first["STATE_OR_PFXRCD"])
	}
	last, ok := byNeighbor["198.51.100.105"]
	if !ok {
		t.Fatalf("expected a record for neighbor 198.51.100.105, got: %+v", byNeighbor)
	}
	if last["REMOTE_AS"] != "65002" || last["STATE_OR_PFXRCD"] != "426" {
		t.Fatalf("unexpected last neighbor fields: %+v", last)
	}
}

func TestParseRouteVRFAllGateways(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleRouteVRFAllGatewaysOutput, "xr_route_vrf_all_gateways", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		VRFs []map[string]string `json:"vrfs"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.VRFs) != 2 {
		t.Fatalf("expected exactly 2 VRFs with a default route, got %d: %s", len(decoded.VRFs), parsed)
	}
	byVRF := map[string]string{}
	for _, record := range decoded.VRFs {
		byVRF[record["VRF"]] = record["GATEWAY"]
	}
	if byVRF["4000001"] != "10.99.99.53" {
		t.Fatalf("expected VRF 4000001 gateway 10.99.99.53, got: %+v", byVRF)
	}
	if byVRF["CUSTOMER-A-INTERNET"] != "10.99.99.51" {
		t.Fatalf("expected VRF CUSTOMER-A-INTERNET gateway 10.99.99.51, got: %+v", byVRF)
	}
	for _, systemVRF := range []string{"**nVSatellite", "9000001", "9000002", "9000003", "9000004", "9000005", "9000006", "9000007", "**eint", "**iid"} {
		if _, ok := byVRF[systemVRF]; ok {
			t.Fatalf("VRF %q has no default route and must not appear in the parsed output, got: %+v", systemVRF, byVRF)
		}
	}
}

// TestParseRouteVRFAllGatewaysSkipsGatewayLineWithNoPrecedingVRF covers a
// malformed/truncated capture where a "Gateway of last resort" line appears
// before any "VRF:" line has set a value. Value VRF is marked Required in
// the template specifically so gotextfsm skips this record entirely
// (SKIP_RECORD on an empty Required value) instead of emitting one with
// VRF="" — which would otherwise flow into a malformed "show route vrf  ..."
// command downstream.
func TestParseRouteVRFAllGatewaysSkipsGatewayLineWithNoPrecedingVRF(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	output := `RP/0/RSP0/CPU0:pe-router-1#show route vrf all | inc "Gateway of last resort|VRF:"
Gateway of last resort is 10.99.99.53 to network 0.0.0.0
VRF: CUSTOMER-A-INTERNET
Gateway of last resort is 10.99.99.51 to network 0.0.0.0
RP/0/RSP0/CPU0:pe-router-1#
`
	parsed, err := parseOutputWithModule(output, "xr_route_vrf_all_gateways", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		VRFs []map[string]string `json:"vrfs"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.VRFs) != 1 {
		t.Fatalf("expected exactly 1 record (the leading orphan Gateway line skipped), got %d: %s", len(decoded.VRFs), parsed)
	}
	if decoded.VRFs[0]["VRF"] != "CUSTOMER-A-INTERNET" {
		t.Fatalf("expected the surviving record to be CUSTOMER-A-INTERNET, got: %+v", decoded.VRFs[0])
	}
}

func TestParseVRFDetailInterfaces(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleVRFDetailInterfacesOutput, "xr_vrf_detail_interfaces", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Interfaces []map[string]string `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Interfaces) != 6 {
		t.Fatalf("expected 6 interface records, got %d: %s", len(decoded.Interfaces), parsed)
	}
	seen := map[string]bool{}
	for _, record := range decoded.Interfaces {
		seen[record["INTERFACE"]] = true
	}
	for _, want := range []string{
		"TenGigE0/7/0/18.38540079",
		"TenGigE0/7/0/19.39890079",
		"TenGigE0/0/0/22.11240078",
		"TenGigE0/7/0/18.38010079",
		"TenGigE0/7/0/18.39890079",
		"TenGigE0/7/0/18.39930079",
	} {
		if !seen[want] {
			t.Fatalf("expected interface %s to be present, got: %+v", want, seen)
		}
	}
	if seen["Import"] || seen["Export"] || seen["No"] {
		t.Fatalf("expected both interfaces to be present, got: %+v", seen)
	}
}

// TestParseVRFDetailInterfacesEmptySection guards against gotextfsm's
// implicit end-of-input record: a VRF with no interfaces assigned produces
// an "Interfaces:" section immediately followed by "Address family ..." —
// zero interface records, not one bogus empty one.
func TestParseVRFDetailInterfacesEmptySection(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleVRFDetailNoInterfacesOutput, "xr_vrf_detail_interfaces", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Interfaces []map[string]string `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	if len(decoded.Interfaces) != 0 {
		t.Fatalf("expected 0 interface records for a VRF with none assigned, got %d: %s", len(decoded.Interfaces), parsed)
	}
}

// TestParseVRFDetailInterfacesStopsAtAddressFamily guards against lines after
// the Interfaces section being mistaken for interface names.
func TestParseVRFDetailInterfacesStopsAtAddressFamily(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatalf("failed to load embedded parsers: %v", err)
	}
	parsed, err := parseOutputWithModule(sampleVRFDetailInterfacesOutput, "xr_vrf_detail_interfaces", parsers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		Interfaces []map[string]string `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(parsed), &decoded); err != nil {
		t.Fatalf("failed to decode parsed output: %v", err)
	}
	for _, record := range decoded.Interfaces {
		if record["INTERFACE"] == "Import" || record["INTERFACE"] == "Export" || record["INTERFACE"] == "Address" || record["INTERFACE"] == "No" {
			t.Fatalf("expected non-interface lines to never be captured as interfaces, got: %+v", decoded.Interfaces)
		}
	}
}
