package drift

import "testing"

func TestCompareStructuredJSON(t *testing.T) {
	report, err := Compare([]byte(`{"interfaces":[{"name":"Ethernet1","state":"up"}],"uptime":10}`), []byte(`{"interfaces":[{"name":"Ethernet1","state":"down"}],"uptime":20}`), []string{"uptime"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Changed || len(report.Changes) != 1 || report.Changes[0].Path != "interfaces[0].state" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestCompareEquivalentObjectsIgnoresKeyOrder(t *testing.T) {
	report, err := Compare([]byte(`{"a":1,"b":2}`), []byte(`{"b":2,"a":1}`), nil)
	if err != nil || report.Changed {
		t.Fatalf("unexpected report=%+v error=%v", report, err)
	}
}
