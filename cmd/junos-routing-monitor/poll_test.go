package main

import (
	"strings"
	"testing"
)

// fakeIdenticalDevice mimics a Junos node answering the per-tick commands
// with fixed output — two of these stand in for two identically-configured
// nodes listed in one --devices YAML file.
type fakeIdenticalDevice struct {
	calls []string
}

func (f *fakeIdenticalDevice) Execute(cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case strings.Contains(cmd, "0/0 exact"):
		return sampleDefaultRouteNextHopOutput, nil
	case strings.Contains(cmd, "show route summary"):
		return sampleRouteSummaryTableOutput, nil
	case strings.Contains(cmd, "show bgp summary"):
		return sampleBGPSummaryOutput, nil
	default:
		return "", nil
	}
}

func (f *fakeIdenticalDevice) Close() error { return nil }

// TestCollectTickTwoIdenticalDevicesBothReportNextHop runs the full
// per-tick pipeline (collectTick then tickHeaderLine) for two
// identically-configured devices in sequence, sharing the same loaded
// parsers — regression test for a field report of the second device's
// status line missing the nexthop clause. The shared compiled TextFSM
// templates must not leak state between devices' parses.
func TestCollectTickTwoIdenticalDevicesBothReportNextHop(t *testing.T) {
	parsers, err := loadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}
	tables := []string{"RI-CUSTOMER-G-300001.inet.0"}

	for i, host := range []string{"node-1", "node-2"} {
		session := &deviceSession{hostname: host, tables: tables, client: &fakeIdenticalDevice{}}
		result, alive := collectTick(session, parsers, defaultSpec)
		if !alive {
			t.Fatalf("device %d: session reported dead", i+1)
		}
		if len(result.Errors) > 0 {
			t.Fatalf("device %d: unexpected tick errors: %v", i+1, result.Errors)
		}
		header := tickHeaderLine(result, true)
		if !strings.Contains(header, "nexthop 192.0.2.9") {
			t.Errorf("device %d (%s): header line missing nexthop clause: %q", i+1, host, header)
		}
	}
}
