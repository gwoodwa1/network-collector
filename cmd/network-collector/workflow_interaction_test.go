package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type trackedApprovalReader struct {
	data  *strings.Reader
	reads chan struct{}
}

func (r *trackedApprovalReader) Read(p []byte) (int, error) {
	select {
	case r.reads <- struct{}{}:
	default:
	}
	return r.data.Read(p)
}

func interactionContext(t *testing.T, variables map[string]string) (*stepExecutionContext, *bool) {
	t.Helper()
	failed := false
	validations := []deviceValidation{}
	artifacts := []outputArtifact{}
	return &stepExecutionContext{
		hostname: "router-01", ip: "192.0.2.10", jsonOut: true,
		sessionLog: io.Discard, failureLog: filepath.Join(t.TempDir(), "failures.txt"),
		variables: variables, aggregated: &validations, artifacts: &artifacts,
		runFailed: &failed, workflows: map[string]WorkflowConfig{},
	}, &failed
}

func TestApprovalInputWaitsUntilPrompt(t *testing.T) {
	reader := &trackedApprovalReader{
		data:  strings.NewReader("yes\n"),
		reads: make(chan struct{}, 1),
	}
	approvals := newApprovalInput(reader)

	select {
	case <-reader.reads:
		t.Fatal("approval input was read before an approval was requested")
	case <-time.After(25 * time.Millisecond):
	}

	ctx, _ := interactionContext(t, map[string]string{})
	ctx.approvalInput = approvals
	ctx.approvalWriter = io.Discard
	approved, err := requestApproval(ctx, ApprovalConfig{Message: "continue?"}, "gate")
	if err != nil || !approved {
		t.Fatalf("approval was not accepted: approved=%v err=%v", approved, err)
	}
	select {
	case <-reader.reads:
	default:
		t.Fatal("approval input was not read after the prompt")
	}
}

func TestInteractionApprovalAcrossRecurringSchedule(t *testing.T) {
	approvals := newApprovalInput(strings.NewReader("yes\nyes\n"))
	devices := []DeviceConfig{{Hostname: "router-01"}}
	runs := 0
	results, stopped := runRecurringSchedule(devices, ExecutionConfig{}, ScheduleConfig{Count: 2, IntervalSeconds: 1}, func(occurrence, index int, device DeviceConfig) deviceRunResult {
		ctx, failed := interactionContext(t, map[string]string{})
		ctx.approvalInput = approvals
		ctx.approvalWriter = io.Discard
		wasStopped := executeSteps(ctx, nil, []StepConfig{{Name: "gate", Approval: &ApprovalConfig{Message: fmt.Sprintf("occurrence %d", occurrence+1)}}})
		runs++
		return deviceRunResult{index: index, hostname: device.Hostname, failed: *failed || wasStopped}
	}, func(time.Duration) {})
	if stopped || runs != 2 || len(results) != 2 || results[0].failed || results[1].failed {
		t.Fatalf("approval/schedule interaction failed: stopped=%v runs=%d results=%+v", stopped, runs, results)
	}
}

func TestInteractionRecurringArtifactsNeverOverwrite(t *testing.T) {
	runDir := t.TempDir()
	devices := []DeviceConfig{{Hostname: "router-01"}}
	paths := []string{}
	results, stopped := runRecurringSchedule(devices, ExecutionConfig{}, ScheduleConfig{Count: 3, IntervalSeconds: 1}, func(occurrence, index int, device DeviceConfig) deviceRunResult {
		failed := false
		artifacts := []outputArtifact{}
		ctx := &stepExecutionContext{
			hostname: device.Hostname, deviceIndex: index, runDir: runDir,
			output: OutputConfig{SaveRaw: true}, runFailed: &failed, artifacts: &artifacts,
			artifactPrefix: fmt.Sprintf("schedule-%03d", occurrence+1),
		}
		if err := saveStepArtifact(ctx, StepConfig{}, "show-version", 1, "raw", fmt.Sprintf("occurrence-%d", occurrence+1)); err != nil {
			t.Fatalf("save occurrence artifact: %v", err)
		}
		paths = append(paths, artifacts[0].Path)
		return deviceRunResult{index: index, hostname: device.Hostname, artifacts: artifacts, failed: failed}
	}, func(time.Duration) {})
	if stopped || len(results) != 3 || len(paths) != 3 {
		t.Fatalf("unexpected recurring artifact results: %+v", results)
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			t.Fatalf("recurring artifact path reused: %s", path)
		}
		seen[path] = true
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("artifact missing %s: %v", path, err)
		}
	}
}

func TestInteractionRollbackRecoversValidationAndAlwaysRuns(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{})
	var log bytes.Buffer
	ctx.sessionLog = &log
	step := StepConfig{Name: "change", Block: &BlockConfig{
		Steps: []StepConfig{{
			Name: "verify", Local: &LocalCommandConfig{Command: "printf", Args: []string{"down"}},
			Validation: &ValidationConfig{Extractor: "regex", Pattern: `(.*)`, Condition: "eq", Expected: "up"},
		}},
		Rollback: []StepConfig{{Name: "rollback", Message: "state restored"}},
		Always:   []StepConfig{{Name: "evidence", Message: "final evidence collected"}},
	}}
	if executeSteps(ctx, nil, []StepConfig{step}) || *failed {
		t.Fatalf("successful rollback did not recover: failed=%v", *failed)
	}
	if len(*ctx.aggregated) != 1 || !(*ctx.aggregated)[0].Recovered {
		t.Fatalf("failed validation not marked recovered: %+v", *ctx.aggregated)
	}
	if !strings.Contains(log.String(), "state restored") || !strings.Contains(log.String(), "final evidence collected") {
		t.Fatalf("rollback/always log incomplete: %s", log.String())
	}
}

func TestInteractionParallelScopedVariablesMergeRegisteredValues(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{"site": "lon"})
	step := StepConfig{Name: "parallel", Parallel: &ParallelConfig{Steps: []StepConfig{
		{Name: "left", Local: &LocalCommandConfig{Command: "printf", Args: []string{"{{site}}-left"}}, Register: "left"},
		{Name: "right", Local: &LocalCommandConfig{Command: "printf", Args: []string{"{{site}}-right"}}, Register: "right"},
	}}}
	if executeSteps(ctx, nil, []StepConfig{step}) || *failed {
		t.Fatalf("parallel merge failed: %v", *failed)
	}
	if ctx.variables["left"] != "lon-left" || ctx.variables["right"] != "lon-right" || ctx.variables["site"] != "lon" {
		t.Fatalf("parallel scope/merge regression: %+v", ctx.variables)
	}
}
