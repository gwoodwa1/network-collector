package main

import (
	"strings"
	"testing"
)

// sampleRouteInformationXML mirrors the shape networkflow's
// parse_route_information expects from get-route-information: a
// route-table containing rt/rt-destination/rt-entry/nh, including a
// multi-next-hop (ECMP) destination — private/documentation address space
// throughout, matching this repo's existing fixture-sanitization
// convention.
const sampleRouteInformationXML = `<rpc-reply>
<route-information>
<route-table>
<table-name>CUSTOMER-A.inet.0</table-name>
<rt>
<rt-destination>192.0.2.0/24</rt-destination>
<rt-entry>
<protocol-name>BGP</protocol-name>
<nh>
<to>198.51.100.1</to>
</nh>
</rt-entry>
</rt>
<rt>
<rt-destination>203.0.113.0/24</rt-destination>
<rt-entry>
<protocol-name>BGP</protocol-name>
<nh>
<to>198.51.100.1</to>
</nh>
<nh>
<to>198.51.100.2</to>
</nh>
</rt-entry>
</rt>
</route-table>
</route-information>
</rpc-reply>`

func TestDecodeRouteInformationXML(t *testing.T) {
	encoded, err := decodeRouteInformationXML(sampleRouteInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeRouteRecords([]byte(encoded))
	if !ok {
		t.Fatalf("expected decodeRouteRecords to accept the encoded output: %s", encoded)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records (one destination + one ECMP destination with 2 next hops), got %d: %+v", len(records), records)
	}
	byNetwork := map[string][]map[string]string{}
	for _, r := range records {
		byNetwork[r["NETWORK"]] = append(byNetwork[r["NETWORK"]], r)
	}
	if len(byNetwork["192.0.2.0/24"]) != 1 || byNetwork["192.0.2.0/24"][0]["NEXTHOP"] != "198.51.100.1" {
		t.Fatalf("unexpected single-next-hop record: %+v", byNetwork["192.0.2.0/24"])
	}
	if len(byNetwork["203.0.113.0/24"]) != 2 {
		t.Fatalf("expected 2 ECMP records for 203.0.113.0/24, got %+v", byNetwork["203.0.113.0/24"])
	}
}

func TestDecodeRouteInformationXMLMalformed(t *testing.T) {
	if _, err := decodeRouteInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

// sampleRouteSummaryInformationXML mirrors get-route-summary-information's
// response shape confirmed against
// networkflow/build/lib/networkflow/core/parsers/juniper/routing.py.
const sampleRouteSummaryInformationXML = `<rpc-reply>
<route-information>
<route-table>
<table-name>CUSTOMER-A.inet.0</table-name>
<destination-count>12</destination-count>
<total-route-count>14</total-route-count>
<active-route-count>12</active-route-count>
<holddown-route-count>0</holddown-route-count>
<hidden-route-count>0</hidden-route-count>
</route-table>
</route-information>
</rpc-reply>`

func TestDecodeRouteSummaryXML(t *testing.T) {
	encoded, err := decodeRouteSummaryXML(sampleRouteSummaryInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(encoded, `"TABLE":"CUSTOMER-A.inet.0"`) ||
		!strings.Contains(encoded, `"TOTAL_ROUTES":"14"`) ||
		!strings.Contains(encoded, `"ACTIVE_ROUTES":"12"`) {
		t.Fatalf("unexpected encoded shape: %s", encoded)
	}
}

func TestDecodeRouteSummaryXMLMalformed(t *testing.T) {
	if _, err := decodeRouteSummaryXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}
