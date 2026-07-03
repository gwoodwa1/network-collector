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
