package main

import "testing"

const sampleISISAdjacencyXML = `<rpc-reply>
<isis-adjacency-information>
<isis-adjacency>
<interface-name>ae0.0</interface-name>
<system-name>pe-router-2</system-name>
<level>2</level>
<adjacency-state>Up</adjacency-state>
</isis-adjacency>
</isis-adjacency-information>
</rpc-reply>`

func TestDecodeISISAdjacenciesXML(t *testing.T) {
	encoded, err := decodeISISAdjacenciesXML(sampleISISAdjacencyXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "isis_adjacencies")
	if !ok || len(records) != 1 {
		t.Fatalf("expected one isis_adjacencies record, got ok=%v records=%+v", ok, records)
	}
	if records[0]["INTERFACE_NAME"] != "ae0.0" || records[0]["STATE"] != "Up" || records[0]["SYSTEM_NAME"] != "pe-router-2" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}

func TestDecodeISISAdjacenciesXMLMalformed(t *testing.T) {
	if _, err := decodeISISAdjacenciesXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const sampleLDPDatabaseXML = `<rpc-reply>
<ldp-database-information>
<ldp-database>
<ldp-database-type>Input</ldp-database-type>
<ldp-session-id>198.51.100.1:0--192.0.2.1:0</ldp-session-id>
<ldp-binding>
<ldp-prefix>203.0.113.0/24</ldp-prefix>
<ldp-label>299824</ldp-label>
</ldp-binding>
</ldp-database>
</ldp-database-information>
</rpc-reply>`

func TestDecodeLDPDatabaseXML(t *testing.T) {
	encoded, err := decodeLDPDatabaseXML(sampleLDPDatabaseXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "ldp_bindings")
	if !ok || len(records) != 1 {
		t.Fatalf("expected one ldp_bindings record, got ok=%v records=%+v", ok, records)
	}
	record := records[0]
	if record["PREFIX"] != "203.0.113.0/24" || record["LABEL"] != "299824" {
		t.Fatalf("unexpected record: %+v", record)
	}
	wantKey := "198.51.100.1:0--192.0.2.1:0|203.0.113.0/24"
	if record["KEY"] != wantKey {
		t.Fatalf("expected composite KEY %q, got %q", wantKey, record["KEY"])
	}
}

func TestDecodeLDPDatabaseXMLMalformed(t *testing.T) {
	if _, err := decodeLDPDatabaseXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const sampleMPLSLSPInformationXML = `<rpc-reply>
<mpls-lsp-information>
<rsvp-session-data>
<session-type>Ingress</session-type>
<count>3</count>
<display-count>3</display-count>
<up-count>3</up-count>
<down-count>0</down-count>
</rsvp-session-data>
</mpls-lsp-information>
</rpc-reply>`

func TestDecodeMPLSLSPInformationXML(t *testing.T) {
	encoded, err := decodeMPLSLSPInformationXML(sampleMPLSLSPInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "mpls_lsp_sessions")
	if !ok || len(records) != 1 {
		t.Fatalf("expected one mpls_lsp_sessions record, got ok=%v records=%+v", ok, records)
	}
	if records[0]["SESSION_TYPE"] != "Ingress" || records[0]["UP_COUNT"] != "3" || records[0]["DOWN_COUNT"] != "0" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}

func TestDecodeMPLSLSPInformationXMLMalformed(t *testing.T) {
	if _, err := decodeMPLSLSPInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}
