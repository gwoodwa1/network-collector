package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

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
	}
	var client *ssh.Client
	handler, err := gnmiTriggerHandler(ctx, &client, []GNMITriggerConfig{{
		Name: "interface-up", Event: "update",
		PathRegex: `^/interfaces/interface\[name=.*\]/state/oper-status$`,
		Value:     "UP",
		Steps: []StepConfig{{
			Name:  "record-event",
			Local: &LocalCommandConfig{Command: "printf", Args: []string{"handled:%s", "{{gnmi_event_value}}"}},
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
