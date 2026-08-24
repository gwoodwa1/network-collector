package main

import (
	"strings"
	"testing"
)

// sampleBGPNeighborInformationXML mirrors get-bgp-neighbor-information's
// response shape confirmed against
// networkflow/build/lib/networkflow/core/parsers/juniper/bgp.py, including
// the "+<port>" suffix Junos appends to peer/local addresses and a peer
// with more than one bgp-rib (only the first should be surfaced).
// Private/documentation address and AS space throughout.
const sampleBGPNeighborInformationXML = `<rpc-reply>
<bgp-information>
<bgp-peer>
<peer-address>192.0.2.1+179</peer-address>
<peer-as>65000</peer-as>
<local-address>192.0.2.2+58810</local-address>
<local-as>65001</local-as>
<description>customer-a-edge</description>
<peer-type>External</peer-type>
<peer-state>Established</peer-state>
<holdtime>90</holdtime>
<preference>170</preference>
<bgp-rib>
<name>CUSTOMER-A.inet.0</name>
<active-prefix-count>4</active-prefix-count>
<received-prefix-count>4</received-prefix-count>
<accepted-prefix-count>4</accepted-prefix-count>
<suppressed-prefix-count>0</suppressed-prefix-count>
<advertised-prefix-count>1</advertised-prefix-count>
</bgp-rib>
<bgp-rib>
<name>CUSTOMER-A.inet6.0</name>
<active-prefix-count>0</active-prefix-count>
<received-prefix-count>0</received-prefix-count>
<accepted-prefix-count>0</accepted-prefix-count>
<suppressed-prefix-count>0</suppressed-prefix-count>
<advertised-prefix-count>0</advertised-prefix-count>
</bgp-rib>
</bgp-peer>
</bgp-information>
</rpc-reply>`

func TestDecodeBGPNeighborDetailXML(t *testing.T) {
	encoded, err := decodeBGPNeighborDetailXML(sampleBGPNeighborInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "bgp_neighbors")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one bgp_neighbors record, got ok=%v records=%+v (encoded=%s)", ok, records, encoded)
	}
	record := records[0]
	if record["PEER_ADDRESS"] != "192.0.2.1" {
		t.Fatalf("expected the +<port> suffix stripped from PEER_ADDRESS, got %q", record["PEER_ADDRESS"])
	}
	if record["LOCAL_ADDRESS"] != "192.0.2.2" {
		t.Fatalf("expected the +<port> suffix stripped from LOCAL_ADDRESS, got %q", record["LOCAL_ADDRESS"])
	}
	if record["PEER_STATE"] != "Established" || record["PEER_AS"] != "65000" {
		t.Fatalf("unexpected core fields: %+v", record)
	}
	if record["ACTIVE_PREFIX_COUNT"] != "4" {
		t.Fatalf("expected the first bgp-rib's prefix counts to be surfaced, got %+v", record)
	}
}

func TestDecodeBGPNeighborDetailXMLMalformed(t *testing.T) {
	if _, err := decodeBGPNeighborDetailXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

func TestStripPortSuffix(t *testing.T) {
	if got := stripPortSuffix("192.0.2.1+179"); got != "192.0.2.1" {
		t.Fatalf("expected port suffix stripped, got %q", got)
	}
	if got := stripPortSuffix("192.0.2.1"); got != "192.0.2.1" {
		t.Fatalf("expected an address with no port suffix to pass through unchanged, got %q", got)
	}
}

func TestDecodeBGPNeighborDetailXMLNoPeersProducesEmptyList(t *testing.T) {
	encoded, err := decodeBGPNeighborDetailXML(`<rpc-reply><bgp-information/></rpc-reply>`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(encoded, `"bgp_neighbors"`) {
		t.Fatalf("expected the bgp_neighbors root to be present even with zero peers, got %s", encoded)
	}
}
