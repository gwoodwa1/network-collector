package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestExecuteLocalCommandMaterializesInputs(t *testing.T) {
	output, display, err := executeLocalCommand(LocalCommandConfig{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestLocalCommandHelper", "--", "{{pre_file}}"},
		Inputs:  map[string]string{"pre_file": "{{routes}}"},
	}, map[string]string{"routes": "<routes>baseline</routes>"})
	if err != nil {
		t.Fatalf("executeLocalCommand() error = %v", err)
	}
	if !strings.Contains(output, "<routes>baseline</routes>") {
		t.Fatalf("executeLocalCommand() output = %q", output)
	}
	if strings.Contains(display, "<routes>baseline</routes>") {
		t.Fatalf("display leaked input content: %q", display)
	}
}

func TestExecuteLocalCommandRejectsInvalidInputName(t *testing.T) {
	_, _, err := executeLocalCommand(LocalCommandConfig{
		Command: os.Args[0],
		Inputs:  map[string]string{"../routes": "data"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "valid template variable") {
		t.Fatalf("executeLocalCommand() error = %v", err)
	}
}

func TestRunPlaybookLocalStepsRunsOnceAndSharesVariables(t *testing.T) {
	helper := LocalCommandConfig{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestLocalCommandHelper", "--", "{{input_file}}"},
	}
	result := runPlaybookLocalSteps([]StepConfig{
		{
			Name:     "produce",
			Local:    &LocalCommandConfig{Command: helper.Command, Args: helper.Args, Inputs: map[string]string{"input_file": "baseline"}},
			Register: "first_result",
		},
		{
			Name:  "consume",
			Local: &LocalCommandConfig{Command: helper.Command, Args: helper.Args, Inputs: map[string]string{"input_file": "{{first_result}}"}},
			Validation: &ValidationConfig{
				Extractor: "regex", Pattern: `(baseline)`, Condition: "eq", Expected: "baseline",
			},
		},
	}, Config{}, true, nil, "", 0)

	if result.failed {
		t.Fatal("runPlaybookLocalSteps() unexpectedly failed")
	}
	if len(result.aggregated) != 1 || result.aggregated[0].Result.Status != "pass" {
		t.Fatalf("runPlaybookLocalSteps() validations = %#v", result.aggregated)
	}
	if result.hostname != "local_steps" {
		t.Fatalf("runPlaybookLocalSteps() hostname = %q", result.hostname)
	}
}

func TestLocalCommandHelper(t *testing.T) {
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(os.Args) {
		return
	}
	content, err := os.ReadFile(os.Args[separator+1])
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print(string(content))
	os.Exit(0)
}
