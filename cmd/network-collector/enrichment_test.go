package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrichJSONBuildsSummaryWithParameters(t *testing.T) {
	input := `{"records":[{"interface":"Gi0/0","crc_errors":0},{"interface":"Gi0/1","crc_errors":12}]}`
	expression := `. as $source
| [.records[] | select(.crc_errors > $params.error_threshold)
   | {rule: "interface-errors", interface, evidence: {crc_errors}}] as $issues
| $source + {"_summary": {"has_issues": (($issues | length) > 0), "issue_count": ($issues | length), "issues": $issues}}`

	output, err := enrichJSON(input, EnrichmentConfig{
		Expression: expression,
		Variables:  map[string]interface{}{"error_threshold": 0},
	}, "")
	if err != nil {
		t.Fatalf("enrichJSON() error = %v", err)
	}
	results, _, err := runStepValidations(output, []ValidationConfig{
		{Extractor: "gjson", JSONPath: "_summary.has_issues", Condition: "eq", Expected: true, ExpectedType: "bool"},
		{Extractor: "gjson", JSONPath: "_summary.issues.0.interface", Condition: "eq", Expected: "Gi0/1"},
	}, nil)
	if err != nil {
		t.Fatalf("validate enriched output: %v", err)
	}
	for index, result := range results {
		if !result.Pass {
			t.Fatalf("validation %d did not pass: %#v", index, result)
		}
	}
}

func TestEnrichJSONLoadsExpressionRelativeToConfig(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "summary.jq"), []byte(`. + {"_summary": {"has_issues": false}}`), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := enrichJSON(`{"records":[]}`, EnrichmentConfig{ExpressionFile: "summary.jq"}, directory)
	if err != nil {
		t.Fatalf("enrichJSON() error = %v", err)
	}
	if !strings.Contains(output, `"has_issues":false`) {
		t.Fatalf("enrichJSON() output = %s", output)
	}
}

func TestInterfaceErrorsExampleExpression(t *testing.T) {
	baseDir := filepath.Join("..", "..", "examples", "workflow-operations")
	output, err := enrichJSON(`{"input_errors":2,"crc_errors":1,"output_errors":0}`, EnrichmentConfig{
		ExpressionFile: filepath.Join("enrich", "interface-errors.jq"),
		Variables:      map[string]interface{}{"error_threshold": 0},
	}, baseDir)
	if err != nil {
		t.Fatalf("enrichJSON() error = %v", err)
	}
	if !strings.Contains(output, `"issue_count":1`) || !strings.Contains(output, `"crc_errors":1`) {
		t.Fatalf("enrichJSON() output = %s", output)
	}
}

func TestEnrichJSONRejectsMultipleResults(t *testing.T) {
	_, err := enrichJSON(`{"records":[1,2]}`, EnrichmentConfig{Expression: `.records[]`}, "")
	if err == nil || !strings.Contains(err.Error(), "exactly one result") {
		t.Fatalf("enrichJSON() error = %v", err)
	}
}

func TestEnrichJSONEnforcesOutputLimit(t *testing.T) {
	_, err := enrichJSON(`{"value":"long"}`, EnrichmentConfig{Expression: `.`, MaxOutputBytes: 5}, "")
	if err == nil || !strings.Contains(err.Error(), "exceeding limit") {
		t.Fatalf("enrichJSON() error = %v", err)
	}
}

func TestCommandStepEnrichesBeforeValidation(t *testing.T) {
	failed := false
	aggregated := []deviceValidation{}
	artifacts := []outputArtifact{}
	ctx := &stepExecutionContext{
		hostname: "router-01", sessionLog: io.Discard, variables: map[string]string{},
		runFailed: &failed, aggregated: &aggregated, artifacts: &artifacts,
		sshCommand: echoCommandExecutor{},
	}
	executeSteps(ctx, nil, []StepConfig{{
		Name:    "enrich-device-json",
		Command: `{"crc_errors":4}`,
		Enrich: &EnrichmentConfig{Expression: `. + {"_summary": {"has_issues": (.crc_errors > 0)}}`},
		Validation: &ValidationConfig{
			Extractor: "gjson", JSONPath: "_summary.has_issues", Condition: "eq", Expected: true, ExpectedType: "bool",
		},
	}})
	if failed {
		t.Fatal("enriched command step unexpectedly failed")
	}
	if len(aggregated) != 1 || !aggregated[0].Result.Pass {
		t.Fatalf("command-step validations = %#v", aggregated)
	}
}
