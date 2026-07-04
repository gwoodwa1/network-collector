package facts

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeExecutor struct {
	output string
	err    error
	calls  []string
}

func (executor *fakeExecutor) Execute(command string) (string, error) {
	executor.calls = append(executor.calls, command)
	return executor.output, executor.err
}

func TestCollectorFallsBackFromNETCONFToSSHPerSubset(t *testing.T) {
	netconf := &fakeExecutor{err: errors.New("unsupported model")}
	ssh := &fakeExecutor{output: "ignored"}
	collector := Collector{Platform: "cisco_iosxr", NETCONF: netconf, SSH: ssh, Parse: func(_, parser string) (json.RawMessage, error) {
		if parser != "xr_facts_bgp" {
			t.Fatalf("unexpected parser %q", parser)
		}
		return json.RawMessage(`{"neighbors":[{"NEIGHBOR":"192.0.2.2","REMOTE_AS":"65002","STATE":"12","MSGRX":"5","MSGTX":"7"}]}`), nil
	}}
	result, err := collector.Collect(Config{Format: FormatBoth, Subsets: []string{"bgp"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.Subsets["bgp"].Source.Transport != "ssh" {
		t.Fatalf("expected SSH fallback: %+v", result.Metadata)
	}
	if len(result.Native["bgp"]) == 0 || result.OpenConfig[openConfigRoot["bgp"]] == nil {
		t.Fatalf("both formats were not returned: %+v", result)
	}
	if len(result.Metadata.Errors["bgp"]) != 1 || !strings.Contains(result.Metadata.Errors["bgp"][0], "unsupported model") {
		t.Fatalf("fallback error provenance missing: %+v", result.Metadata.Errors)
	}
}

func TestCollectorNativeFormatDoesNotNormalize(t *testing.T) {
	ssh := &fakeExecutor{output: "ignored"}
	collector := Collector{Platform: "cisco_iosxr", SSH: ssh, Parse: func(_, _ string) (json.RawMessage, error) { return json.RawMessage(`{"neighbors":[]}`), nil }}
	result, err := collector.Collect(Config{Format: FormatNative, Subsets: []string{"lldp"}, Transports: []string{"ssh"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.OpenConfig != nil {
		t.Fatalf("native format unexpectedly included OpenConfig: %+v", result.OpenConfig)
	}
	if len(result.Native["lldp"]) == 0 {
		t.Fatal("native result is empty")
	}
}

func TestXMLToJSONPreservesRepeatedElements(t *testing.T) {
	value, err := XMLToJSON(`<data><interfaces><interface><name>Gi0</name></interface><interface><name>Gi1</name></interface></interfaces></data>`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(value), `"interface":[`) {
		t.Fatalf("repeated XML element was not represented as an array: %s", value)
	}
}

func TestEmptyNETCONFSubsetFallsBackToSSH(t *testing.T) {
	netconf := &fakeExecutor{output: `<data/>`}
	ssh := &fakeExecutor{output: "ignored"}
	collector := Collector{Platform: "cisco_iosxr", NETCONF: netconf, SSH: ssh, Parse: func(_, _ string) (json.RawMessage, error) { return json.RawMessage(`{"interfaces":[]}`), nil }}
	result, err := collector.Collect(Config{Format: FormatBoth, Subsets: []string{"interfaces"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.Subsets["interfaces"].Source.Transport != "ssh" {
		t.Fatalf("empty NETCONF result did not fall back: %+v", result.Metadata)
	}
}

func TestNormalizeConfigRejectsUnknownSubset(t *testing.T) {
	_, err := NormalizeConfig(Config{Subsets: []string{"ospf"}})
	if err == nil {
		t.Fatal("expected unsupported subset error")
	}
}

func TestUnknownPlatformStillUsesGenericOpenConfigNETCONF(t *testing.T) {
	netconf := &fakeExecutor{output: `<data><system><state><hostname>edge-01</hostname></state></system></data>`}
	collector := Collector{Platform: "future_vendor", NETCONF: netconf}
	result, err := collector.Collect(Config{Format: FormatOpenConfig, Subsets: []string{"system"}, Transports: []string{"netconf"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.Subsets["system"].Source.Transport != "netconf" {
		t.Fatalf("generic NETCONF was not used: %+v", result.Metadata)
	}
}

func TestCollectorMergesRoutingSubsetsUnderNetworkInstances(t *testing.T) {
	ssh := &fakeExecutor{output: "ignored"}
	collector := Collector{Platform: "cisco_iosxr", SSH: ssh, Parse: func(_, parser string) (json.RawMessage, error) {
		switch parser {
		case "xr_facts_bgp":
			return json.RawMessage(`{"neighbors":[{"NEIGHBOR":"192.0.2.2","REMOTE_AS":"65002","STATE":"1"}]}`), nil
		case "xr_facts_isis":
			return json.RawMessage(`{"neighbors":[{"SYSTEM_ID":"core-02","STATE":"Up","LEVEL":"L2"}]}`), nil
		case "xr_facts_ldp":
			return json.RawMessage(`{"neighbors":[{"PEER_ID":"192.0.2.2:0","STATE":"Operational"}]}`), nil
		default:
			return nil, errors.New("unexpected parser")
		}
	}}
	result, err := collector.Collect(Config{Format: FormatOpenConfig, Subsets: []string{"bgp", "isis", "ldp"}, Transports: []string{"ssh"}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.OpenConfig[openConfigRoot["bgp"]])
	for _, expected := range []string{`"identifier":"openconfig-policy-types:BGP"`, `"identifier":"openconfig-policy-types:ISIS"`, `"mpls"`} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("routing subset %s was overwritten: %s", expected, encoded)
		}
	}
}
