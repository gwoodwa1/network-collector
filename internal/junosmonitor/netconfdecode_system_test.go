package junosmonitor

import "testing"

const sampleSoftwareInformationXML = `<rpc-reply>
<software-information>
<host-name>pe-router-1</host-name>
<product-model>mx204</product-model>
<product-name>mx204</product-name>
<package-information>
<name>junos</name>
<comment>JUNOS Software Release [21.4R3.15]</comment>
</package-information>
<junos-version>21.4R3.15</junos-version>
</software-information>
</rpc-reply>`

func TestDecodeSoftwareInformationXML(t *testing.T) {
	encoded, err := decodeSoftwareInformationXML(sampleSoftwareInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "software")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one software record, got ok=%v records=%+v", ok, records)
	}
	record := records[0]
	if record["HOST_NAME"] != "pe-router-1" || record["JUNOS_VERSION"] != "21.4R3.15" || record["PRODUCT_MODEL"] != "mx204" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestDecodeSoftwareInformationXMLMalformed(t *testing.T) {
	if _, err := decodeSoftwareInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const sampleRouteEngineInformationXML = `<rpc-reply>
<route-engine-information>
<route-engine>
<slot>0</slot>
<mastership-state>master</mastership-state>
<mastership-priority>Master</mastership-priority>
<status>OK</status>
<model>RE-MX204</model>
</route-engine>
</route-engine-information>
</rpc-reply>`

func TestDecodeRouteEngineInformationXML(t *testing.T) {
	encoded, err := decodeRouteEngineInformationXML(sampleRouteEngineInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "route_engines")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one route_engines record, got ok=%v records=%+v", ok, records)
	}
	if records[0]["SLOT"] != "0" || records[0]["MASTERSHIP_STATE"] != "master" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}

func TestDecodeRouteEngineInformationXMLMalformed(t *testing.T) {
	if _, err := decodeRouteEngineInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const sampleFPCInformationXML = `<rpc-reply>
<fpc-information>
<fpc>
<slot>0</slot>
<state>Online</state>
<temperature>42 degrees C</temperature>
</fpc>
</fpc-information>
</rpc-reply>`

func TestDecodeFPCInformationXML(t *testing.T) {
	encoded, err := decodeFPCInformationXML(sampleFPCInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "fpc_information")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one fpc_information record, got ok=%v records=%+v", ok, records)
	}
	if records[0]["SLOT"] != "0" || records[0]["STATE"] != "Online" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}

func TestDecodeFPCInformationXMLMalformed(t *testing.T) {
	if _, err := decodeFPCInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const samplePICInformationXML = `<rpc-reply>
<fpc-information>
<fpc>
<slot>0</slot>
<state>Online</state>
<description>MX204</description>
<pic>
<pic-slot>0</pic-slot>
<pic-state>Online</pic-state>
<pic-type>4x 10G-4x1G</pic-type>
</pic>
</fpc>
</fpc-information>
</rpc-reply>`

func TestDecodePICInformationXML(t *testing.T) {
	encoded, err := decodePICInformationXML(samplePICInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "pic_information")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one pic_information record, got ok=%v records=%+v", ok, records)
	}
	record := records[0]
	if record["FPC_SLOT"] != "0" || record["PIC_SLOT"] != "0" || record["PIC_STATE"] != "Online" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record["KEY"] != "0/0" {
		t.Fatalf("expected composite KEY \"0/0\", got %q", record["KEY"])
	}
}

func TestDecodePICInformationXMLMalformed(t *testing.T) {
	if _, err := decodePICInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const sampleAlarmInformationXML = `<rpc-reply>
<alarm-information>
<alarm-detail>
<alarm-class>Minor</alarm-class>
<alarm-description>Fan removed</alarm-description>
<alarm-time>2026-07-10 08:00:00 UTC</alarm-time>
<alarm-type>Chassis</alarm-type>
</alarm-detail>
</alarm-information>
</rpc-reply>`

func TestDecodeAlarmInformationXML(t *testing.T) {
	encoded, err := decodeAlarmInformationXML(sampleAlarmInformationXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "alarms")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one alarms record, got ok=%v records=%+v", ok, records)
	}
	record := records[0]
	if record["ALARM_CLASS"] != "Minor" || record["ALARM_DESCRIPTION"] != "Fan removed" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record["KEY"] != "Minor|Fan removed" {
		t.Fatalf("expected composite KEY \"Minor|Fan removed\", got %q", record["KEY"])
	}
}

func TestDecodeAlarmInformationXMLMalformed(t *testing.T) {
	if _, err := decodeAlarmInformationXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

const sampleCoreDumpsXML = `<rpc-reply>
<directory-list>
<multi-routing-engine-item>
<re-name>re0</re-name>
<file-information>
<file-name>vmcore.0</file-name>
<file-permissions>644</file-permissions>
<file-owner>root</file-owner>
<file-group>wheel</file-group>
<file-links>1</file-links>
<file-size>104857600</file-size>
<file-date>Jul 10 08:00</file-date>
</file-information>
</multi-routing-engine-item>
</directory-list>
</rpc-reply>`

func TestDecodeCoreDumpsXML(t *testing.T) {
	encoded, err := decodeCoreDumpsXML(sampleCoreDumpsXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records, ok := decodeKeyedRecords([]byte(encoded), "core_dumps")
	if !ok || len(records) != 1 {
		t.Fatalf("expected exactly one core_dumps record, got ok=%v records=%+v", ok, records)
	}
	record := records[0]
	if record["RE_NAME"] != "re0" || record["FILE_NAME"] != "vmcore.0" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record["KEY"] != "re0|vmcore.0" {
		t.Fatalf("expected composite KEY \"re0|vmcore.0\", got %q", record["KEY"])
	}
}

func TestDecodeCoreDumpsXMLMalformed(t *testing.T) {
	if _, err := decodeCoreDumpsXML("<rpc-reply><unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}
