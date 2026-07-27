package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	gnmidriver "github.com/gwoodwa1/network-collector/pkg/drivers/gnmi"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

func TestGNMITriggerMatchesPostSyncUpdateAndRunsNestedStep(t *testing.T) {
	failed := false
	validations := []deviceValidation{}
	var log bytes.Buffer
	ctx := &stepExecutionContext{
		hostname: "router-1", ip: "192.0.2.1", sessionLog: &log,
		variables: map[string]string{}, runFailed: &failed, aggregated: &validations,
		sshCommand: echoCommandExecutor{},
	}
	var client *ssh.Client
	handler, err := gnmiTriggerHandler(ctx, &client, []GNMITriggerConfig{{
		Name: "interface-up", Event: "update",
		PathRegex: `^/interfaces/interface\[name=.*\]/state/oper-status$`,
		Value:     "UP",
		Steps: []StepConfig{{
			Name:    "record-event",
			Command: "handled:{{gnmi_event_value}}",
		}},
	}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	event := gnmidriver.Event{Type: "update", Path: "/interfaces/interface[name=Ethernet1]/state/oper-status", Value: "UP"}
	initial := event
	initial.Initial = true
	if err := handler(initial); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "handled:UP") {
		t.Fatal("initial synchronization update unexpectedly triggered an action")
	}
	if err := handler(event); err != nil {
		t.Fatal(err)
	}
	if failed {
		t.Fatalf("trigger action failed:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "handled:UP") {
		t.Fatalf("trigger action did not run:\n%s", log.String())
	}
}

func TestGNMITriggerMatchesRouteDelete(t *testing.T) {
	failed := false
	validations := []deviceValidation{}
	ctx := &stepExecutionContext{
		hostname: "router-1", sessionLog: io.Discard, variables: map[string]string{},
		runFailed: &failed, aggregated: &validations,
	}
	handler, err := gnmiTriggerHandler(ctx, nil, []GNMITriggerConfig{{
		Name: "route-removed", Event: "delete", PathRegex: `/afts/.*`, IncludeInitial: true,
		Steps: []StepConfig{{Name: "route-action", Message: "route {{gnmi_event_path}} disappeared"}},
	}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler(gnmidriver.Event{Type: "delete", Path: "/network-instances/network-instance[name=default]/afts/ipv4-unicast/ipv4-entry[prefix=192.0.2.0/24]", Initial: true}); err != nil {
		t.Fatal(err)
	}
	if failed {
		t.Fatal("route delete action failed")
	}
}

func TestGNMICounterRateDropUsesAveragedBaseline(t *testing.T) {
	state := &gnmiNumericTriggerState{}
	config := GNMITriggerConfig{CounterRate: true, BaselineSamples: 2, MaxDropPercent: 10}
	events := []gnmidriver.Event{
		{Value: uint64(1000), Timestamp: int64(time.Second)},
		{Value: uint64(2000), Timestamp: int64(2 * time.Second)},
		{Value: uint64(3000), Timestamp: int64(3 * time.Second)},
		{Value: uint64(3800), Timestamp: int64(4 * time.Second)},
	}
	for index, event := range events {
		metric, baseline, threshold, ready, err := state.match(config, event, fmt.Sprint(event.Value))
		if err != nil {
			t.Fatal(err)
		}
		if index < 3 && ready {
			t.Fatalf("event %d fired while establishing baseline", index)
		}
		if index == 3 {
			if !ready || metric != "800.00" || baseline != "1000.00" || threshold != "900.00" {
				t.Fatalf("unexpected drop result: metric=%s baseline=%s threshold=%s ready=%t", metric, baseline, threshold, ready)
			}
		}
	}
}

func TestGNMINumericThreshold(t *testing.T) {
	threshold := 80.0
	state := &gnmiNumericTriggerState{}
	config := GNMITriggerConfig{Condition: "gte", Threshold: &threshold}
	_, _, _, ready, err := state.match(config, gnmidriver.Event{Value: 79}, "79")
	if err != nil || ready {
		t.Fatalf("79 unexpectedly met threshold: ready=%t error=%v", ready, err)
	}
	metric, _, limit, ready, err := state.match(config, gnmidriver.Event{Value: 80}, "80")
	if err != nil || !ready || metric != "80.00" || limit != "80.00" {
		t.Fatalf("80 did not meet threshold: metric=%s limit=%s ready=%t error=%v", metric, limit, ready, err)
	}
}

func TestGNMIAbsoluteDropSupportsNegativeDBM(t *testing.T) {
	maxDrop := 1.0
	state := &gnmiNumericTriggerState{}
	config := GNMITriggerConfig{BaselineSamples: 3, MaxDrop: &maxDrop}
	for index, reading := range []string{"-5.00", "-5.10", "-4.90"} {
		_, _, _, ready, err := state.match(config, gnmidriver.Event{Value: reading}, reading)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			t.Fatalf("baseline reading %d unexpectedly fired", index)
		}
	}
	metric, baseline, threshold, ready, err := state.match(config, gnmidriver.Event{Value: -6.1}, "-6.1")
	if err != nil {
		t.Fatal(err)
	}
	if !ready || metric != "-6.10" || baseline != "-5.00" || threshold != "-6.00" {
		t.Fatalf("unexpected optical drop result: metric=%s baseline=%s threshold=%s ready=%t", metric, baseline, threshold, ready)
	}
}

func TestGNMIWildcardTriggerMaintainsPerPathStateAndOnce(t *testing.T) {
	maxDrop := 1.0
	failed := false
	validations := []deviceValidation{}
	var log bytes.Buffer
	ctx := &stepExecutionContext{
		hostname: "router-1", ip: "192.0.2.1", sessionLog: &log,
		variables: map[string]string{}, runFailed: &failed, aggregated: &validations,
	}
	handler, err := gnmiTriggerHandler(ctx, nil, []GNMITriggerConfig{{
		Name: "rx-light", Event: "update", PathRegex: `/input-power/instant$`,
		BaselineSamples: 1, MaxDrop: &maxDrop, Once: true,
		Steps: []StepConfig{{Name: "record-optic", Message: "optic {{gnmi_event_path}} dropped"}},
	}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"/components/component[name=Optics0]/transceiver/physical-channels/channel[index=0]/state/input-power/instant",
		"/components/component[name=Optics1]/transceiver/physical-channels/channel[index=0]/state/input-power/instant",
	}
	for _, path := range paths {
		if err := handler(gnmidriver.Event{Type: "update", Path: path, Value: -5.0}); err != nil {
			t.Fatal(err)
		}
		if err := handler(gnmidriver.Event{Type: "update", Path: path, Value: -6.5}); err != nil {
			t.Fatal(err)
		}
		if err := handler(gnmidriver.Event{Type: "update", Path: path, Value: -7.0}); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Count(log.String(), "[gnmi:rx-light]"); got != 2 {
		t.Fatalf("got %d alarms, want one per optical path:\n%s", got, log.String())
	}
}

func TestGNMICounterIncrementCondition(t *testing.T) {
	threshold := 0.0
	state := &gnmiNumericTriggerState{}
	config := GNMITriggerConfig{CounterRate: true, Condition: "gt", Threshold: &threshold}
	tests := []struct {
		value     string
		timestamp time.Duration
		want      bool
	}{
		{value: "100", timestamp: time.Second, want: false},
		{value: "100", timestamp: 11 * time.Second, want: false},
		{value: "101", timestamp: 21 * time.Second, want: true},
	}
	for index, test := range tests {
		metric, _, limit, ready, err := state.match(config, gnmidriver.Event{Timestamp: int64(test.timestamp)}, test.value)
		if err != nil {
			t.Fatal(err)
		}
		if ready != test.want {
			t.Fatalf("sample %d: metric=%s limit=%s ready=%t want=%t", index, metric, limit, ready, test.want)
		}
	}
}

func TestGNMIValueNotMatchesUnhealthyStatePerNeighbor(t *testing.T) {
	failed := false
	validations := []deviceValidation{}
	var log bytes.Buffer
	ctx := &stepExecutionContext{
		hostname: "router-1", sessionLog: &log, variables: map[string]string{},
		runFailed: &failed, aggregated: &validations,
	}
	handler, err := gnmiTriggerHandler(ctx, nil, []GNMITriggerConfig{{
		Name: "bgp-not-established", Event: "update", PathRegex: `/session-state$`,
		ValueNot: "ESTABLISHED", IncludeInitial: true, Once: true,
		Steps: []StepConfig{{Name: "record-bgp", Message: "BGP {{gnmi_event_path}} is {{gnmi_event_value}}"}},
	}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	establishedPath := "/network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=default]/bgp/neighbors/neighbor[neighbor-address=192.0.2.1]/state/session-state"
	idlePath := "/network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=default]/bgp/neighbors/neighbor[neighbor-address=192.0.2.2]/state/session-state"
	if err := handler(gnmidriver.Event{Type: "update", Path: establishedPath, Value: "ESTABLISHED", Initial: true}); err != nil {
		t.Fatal(err)
	}
	if err := handler(gnmidriver.Event{Type: "update", Path: idlePath, Value: "IDLE", Initial: true}); err != nil {
		t.Fatal(err)
	}
	if err := handler(gnmidriver.Event{Type: "update", Path: idlePath, Value: "ACTIVE"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), establishedPath) {
		t.Fatalf("healthy BGP neighbor unexpectedly triggered:\n%s", log.String())
	}
	if got := strings.Count(log.String(), "[gnmi:bgp-not-established]"); got != 1 {
		t.Fatalf("got %d unhealthy alarms, want one per neighbor path:\n%s", got, log.String())
	}
}
