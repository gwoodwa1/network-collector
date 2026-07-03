package main

import (
	"strings"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/validation"
)

func TestRenderPrettyResults(t *testing.T) {
	results := []deviceRunResult{
		{index: 1, hostname: "edge-2", ip: "192.0.2.2", failed: true, duration: 2 * time.Second,
			aggregated: []deviceValidation{{Result: validation.ValidationResult{Status: "fail"}}}},
		{index: 0, hostname: "edge-1", ip: "192.0.2.1", duration: time.Second,
			aggregated: []deviceValidation{{Result: validation.ValidationResult{Status: "pass"}}}},
	}

	got := renderPrettyResults(results, true, 3*time.Second, false)
	for _, want := range []string{"edge-1", "✓ PASS", "edge-2", "✗ FAIL", "✗ Run failed", "2 device(s)"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "edge-1") > strings.Index(got, "edge-2") {
		t.Errorf("results are not in inventory order:\n%s", got)
	}
}

func TestRenderPrettyResultsColoursFailures(t *testing.T) {
	got := renderPrettyResults([]deviceRunResult{{hostname: "edge-1", failed: true}}, true, time.Second, true)
	if !strings.Contains(got, ansiRed) || !strings.Contains(got, "✗ FAIL") {
		t.Fatalf("failure was not rendered in red: %q", got)
	}
}
