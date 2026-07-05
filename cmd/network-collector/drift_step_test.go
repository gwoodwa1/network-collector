package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDriftCheckDetectsChange(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(baseline, []byte(`{"state":"up","counter":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	failed := false
	validations := []deviceValidation{}
	artifacts := []outputArtifact{}
	ctx := &stepExecutionContext{hostname: "router-1", ip: "192.0.2.1", sessionLog: io.Discard, runFailed: &failed, aggregated: &validations, runDir: dir, output: OutputConfig{}, artifacts: &artifacts}
	step := StepConfig{Drift: &DriftConfig{Baseline: baseline, Ignore: []string{"counter"}, FailOnChange: true}}
	if err := applyDriftCheck(ctx, step, "state", `{"state":"down","counter":2}`); err != nil {
		t.Fatal(err)
	}
	if !failed || len(validations) != 1 || validations[0].Result.Status != "fail" || len(artifacts) != 1 || artifacts[0].Kind != "drift" {
		t.Fatalf("unexpected result failed=%v validations=%+v artifacts=%+v", failed, validations, artifacts)
	}
}

func TestApplyDriftCheckCreatesRollingBaseline(t *testing.T) {
	dir := t.TempDir()
	failed := false
	validations := []deviceValidation{}
	ctx := &stepExecutionContext{hostname: "router-1", sessionLog: io.Discard, runFailed: &failed, aggregated: &validations, output: OutputConfig{Directory: dir}}
	if err := applyDriftCheck(ctx, StepConfig{Drift: &DriftConfig{Baseline: "previous", FailOnChange: true}}, "platform", `{"state":"up"}`); err != nil {
		t.Fatal(err)
	}
	if failed || len(validations) != 1 || !validations[0].Result.Pass {
		t.Fatalf("unexpected first baseline result: failed=%v validations=%+v", failed, validations)
	}
}
