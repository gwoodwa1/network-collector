package main

import (
	"io"
	"strings"
	"testing"
)

type factsPolicyExecutor struct {
	filters []string
}

func (executor *factsPolicyExecutor) Execute(filter string) (string, error) {
	executor.filters = append(executor.filters, filter)
	return `<data><system xmlns="http://openconfig.net/yang/system"><state><hostname>router-1</hostname></state></system></data>`, nil
}

func (executor *factsPolicyExecutor) ExecuteNETCONF(NETCONFStepConfig) (string, error) {
	return "", nil
}

func TestFactsReuseConfiguredNETCONFExecutor(t *testing.T) {
	failed := false
	validations := []deviceValidation{}
	executor := &factsPolicyExecutor{}
	ctx := &stepExecutionContext{
		hostname: "router-1", ip: "192.0.2.1", deviceType: "cisco_iosxr",
		sessionLog: io.Discard, variables: map[string]string{},
		runFailed: &failed, aggregated: &validations, netconf: executor,
	}
	step := StepConfig{Facts: &FactsConfig{
		Format: "native", Subsets: []string{"system"}, Transports: []string{"netconf"},
	}}
	if err := executeFactsStep(ctx, nil, step, "facts"); err != nil {
		t.Fatal(err)
	}
	if len(executor.filters) != 1 || !strings.Contains(executor.filters[0], "openconfig.net/yang/system") {
		t.Fatalf("facts did not reuse the configured NETCONF executor: %+v", executor.filters)
	}
}
