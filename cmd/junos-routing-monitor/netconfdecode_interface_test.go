package main

import "testing"

const sampleInterfaceInformationXML = `<rpc-reply>
<interface-information>
<physical-interface>
<name>ae0</name>
<admin-status>up</admin-status>
<oper-status>up</oper-status>
<description>customer-a-uplink</description>
<mtu>1514</mtu>
<speed>10Gbps</speed>
<logical-interface>
<name>ae0.0</name>
<description>customer-a-uplink</description>
<encapsulation>ENET2</encapsulation>
<address-family>
<address-family-name>inet</address-family-name>
<interface-address>
<ifa-local>192.0.2.1/30</ifa-local>
</interface-address>
</address-family>
</logical-interface>
</physical-interface>
</interface-information>
</rpc-reply>`

func TestDecodeInterfaceInformationXML(t *testing.T) {
	encoded, err := decodeInterfaceInformationXML(sampleInterfaceInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "interfaces")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one interfaces record, got ok=%v records=%+v", ok, records)
	}
	record := records[0]
	if record["INTERFACE_NAME"] != "ae0" || record["ADMIN_STATUS"] != "up" || record["OPER_STATUS"] != "up" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record["LOGICAL_INTERFACES"] != "ae0.0[inet:192.0.2.1/30]" {
		t.Fatalf("unexpected LOGICAL_INTERFACES summary: %q", record["LOGICAL_INTERFACES"])
	}
}

func TestDecodeInterfaceInformationXMLMalformed(t *testing.T) {
	if _, err := decodeInterfaceInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

func TestDecodeInterfaceInformationXMLSkipsUnnamedInterface(t *testing.T) {
	encoded, err := decodeInterfaceInformationXML(`<rpc-reply><interface-information><physical-interface><admin-status>up</admin-status></physical-interface></interface-information></rpc-reply>`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "interfaces")
	if !ok {
		t.Fatalf("expected a decodable (if empty) interfaces list")
	}
	if len(records) != 0 {
		t.Fatalf("expected an interface with no name to be skipped, got %+v", records)
	}
}
