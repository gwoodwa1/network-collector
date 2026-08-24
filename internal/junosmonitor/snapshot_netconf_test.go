package junosmonitor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeNetconfExecutor scripts responses by RPC element name (a substring
// match against the request), standing in for a real NETCONF session in
// captureSnapshot tests — mirroring poll_test.go's fakeIdenticalDevice
// pattern for the SSH path.
type fakeNetconfExecutor struct {
	responses map[string]string // substring of the RPC -> canned <rpc-reply>
	calls     []string
}

func (f *fakeNetconfExecutor) Execute(cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	for substr, response := range f.responses {
		if strings.Contains(cmd, substr) {
			return response, nil
		}
	}
	return "<rpc-reply/>", nil
}

func (f *fakeNetconfExecutor) Close() error { return nil }

// TestCaptureSnapshotWithNetconfClientPopulatesNetconfDetail proves every
// NETCONF-sourced section lands under NetconfDetail when
// session.netconfClient is set, while the existing SSH-sourced route-table
// and neighbor-route sections are completely unaffected — reusing the
// realistic fixtures from the netconfdecode_*_test.go files so this test
// exercises the real decoders, not simplified inline XML.
func TestCaptureSnapshotWithNetconfClientPopulatesNetconfDetail(t *testing.T) {
	dir := t.TempDir()
	netconfClient := &fakeNetconfExecutor{responses: map[string]string{
		"get-route-information":          sampleRouteInformationXML,
		"get-route-summary-information":  sampleRouteSummaryInformationXML,
		"get-bgp-neighbor-information":   sampleBGPNeighborInformationXML,
		"get-isis-adjacency-information": sampleISISAdjacencyXML,
		"get-ldp-database-information":   sampleLDPDatabaseXML,
		"get-mpls-lsp-information":       sampleMPLSLSPInformationXML,
		"get-interface-information":      sampleInterfaceInformationXML,
		"get-software-information":       sampleSoftwareInformationXML,
		"get-route-engine-information":   sampleRouteEngineInformationXML,
		"get-fpc-information":            sampleFPCInformationXML,
		"get-pic-information":            samplePICInformationXML,
		"get-alarm-information":          sampleAlarmInformationXML,
		"show system core-dumps":         sampleCoreDumpsXML,
	}}
	session := &DeviceSession{
		hostname:      "pe-router-1",
		tables:        []string{"CUSTOMER-A.inet.0"},
		neighbors:     []string{"198.51.100.1"},
		client:        &genericFakeExecutor{},
		netconfClient: netconfClient,
	}
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	capturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	if err := captureSnapshot(session, "before", dir, "", capturedAt, parsers, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	base := snapshotFilenameBase("", "pe-router-1", "before", capturedAt)
	content, err := os.ReadFile(filepath.Join(dir, base+".json"))
	if err != nil {
		t.Fatalf("expected snapshot json written: %v", err)
	}
	var result snapshotResult
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatalf("failed to decode written snapshot: %v", err)
	}

	if result.NetconfDetail == nil {
		t.Fatal("expected NetconfDetail to be populated")
	}
	if _, ok := result.NetconfDetail.RouteInformation["CUSTOMER-A.inet.0"]; !ok {
		t.Fatalf("expected per-table NETCONF route information, got %+v", result.NetconfDetail.RouteInformation)
	}
	if _, ok := result.NetconfDetail.RouteSummary["CUSTOMER-A.inet.0"]; !ok {
		t.Fatalf("expected per-table NETCONF route summary, got %+v", result.NetconfDetail.RouteSummary)
	}
	for name, raw := range map[string]json.RawMessage{
		"BGPNeighborDetail":      result.NetconfDetail.BGPNeighborDetail,
		"ISISAdjacencies":        result.NetconfDetail.ISISAdjacencies,
		"LDPDatabase":            result.NetconfDetail.LDPDatabase,
		"MPLSLSPInformation":     result.NetconfDetail.MPLSLSPInformation,
		"InterfaceInformation":   result.NetconfDetail.InterfaceInformation,
		"SoftwareInformation":    result.NetconfDetail.SoftwareInformation,
		"RouteEngineInformation": result.NetconfDetail.RouteEngineInformation,
		"FPCInformation":         result.NetconfDetail.FPCInformation,
		"PICInformation":         result.NetconfDetail.PICInformation,
		"AlarmInformation":       result.NetconfDetail.AlarmInformation,
		"CoreDumps":              result.NetconfDetail.CoreDumps,
	} {
		if len(raw) == 0 {
			t.Errorf("expected NetconfDetail.%s to be populated, got empty", name)
		}
	}

	// The neighbor route-*prefix* capture must still come from SSH, not
	// NETCONF — captureSnapshot never routes it through netconfClient.
	if _, ok := result.Neighbors["198.51.100.1"]; !ok {
		t.Fatalf("expected the SSH-sourced neighbor section present, got %+v", result.Neighbors)
	}
}

// TestCaptureSnapshotWithoutNetconfClientLeavesNetconfDetailNil is the
// negative case: a device that never opted into NETCONF snapshot capture
// gets no NetconfDetail at all, and behaves exactly as it did before this
// feature existed.
func TestCaptureSnapshotWithoutNetconfClientLeavesNetconfDetailNil(t *testing.T) {
	dir := t.TempDir()
	session := &DeviceSession{hostname: "pe-router-1", tables: []string{"CUSTOMER-A.inet.0"}, client: &genericFakeExecutor{}}
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	capturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	if err := captureSnapshot(session, "before", dir, "", capturedAt, parsers, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	base := snapshotFilenameBase("", "pe-router-1", "before", capturedAt)
	content, err := os.ReadFile(filepath.Join(dir, base+".json"))
	if err != nil {
		t.Fatalf("expected snapshot json written: %v", err)
	}
	var result snapshotResult
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatalf("failed to decode written snapshot: %v", err)
	}
	if result.NetconfDetail != nil {
		t.Fatalf("expected nil NetconfDetail without a NETCONF connection, got %+v", result.NetconfDetail)
	}
}

// TestCaptureSnapshotNetconfOnlyDeviceStillWritesFiles proves a device with
// no tables and no neighbors, but NETCONF snapshot capture enabled, is no
// longer skipped entirely the way captureSnapshot's original "nothing to
// do" gate would have skipped it — device-wide NETCONF sections are still
// worth capturing even with nothing table/neighbor-scoped configured.
func TestCaptureSnapshotNetconfOnlyDeviceStillWritesFiles(t *testing.T) {
	dir := t.TempDir()
	netconfClient := &fakeNetconfExecutor{responses: map[string]string{
		"get-software-information": sampleSoftwareInformationXML,
	}}
	session := &DeviceSession{hostname: "pe-router-1", client: &genericFakeExecutor{}, netconfClient: netconfClient}
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	capturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	if err := captureSnapshot(session, "before", dir, "", capturedAt, parsers, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected a confirmation line to be written for a NETCONF-only device")
	}
}
