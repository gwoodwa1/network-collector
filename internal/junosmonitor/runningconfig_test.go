package junosmonitor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptedConfigExecutor returns a fixed response for "show configuration",
// standing in for a real Junos session for CaptureRunningConfig tests.
type scriptedConfigExecutor struct {
	response string
}

func (e *scriptedConfigExecutor) Execute(cmd string) (string, error) { return e.response, nil }
func (e *scriptedConfigExecutor) Close() error                       { return nil }

type erroringConfigExecutor struct{ err error }

func (e *erroringConfigExecutor) Execute(cmd string) (string, error) { return "", e.err }
func (e *erroringConfigExecutor) Close() error                       { return nil }

// TestCaptureRunningConfigWritesFileAndConfirmation proves the running
// config is written to "<base>-running-config.txt" (sharing
// captureSnapshot's <base> naming, see snapshotFilenameBase) and a
// confirmation is written to the provided writer.
func TestCaptureRunningConfigWritesFileAndConfirmation(t *testing.T) {
	dir := t.TempDir()
	exec := &scriptedConfigExecutor{response: "interfaces {\n    ae0 {\n        description core;\n    }\n}\n"}
	session := &DeviceSession{hostname: "pe-router-1", client: exec}
	capturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	if err := CaptureRunningConfig(session, "before", dir, "CRQXXX", capturedAt, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantPath := filepath.Join(dir, "CRQXXX-pe-router-1-20260710-080000-before-running-config.txt")
	content, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("expected file at %s, got error: %v", wantPath, err)
	}
	if !strings.Contains(string(content), "description core;") {
		t.Fatalf("expected captured config content, got: %q", content)
	}
	if !strings.Contains(buf.String(), "before-change running-config captured for pe-router-1") {
		t.Fatalf("expected a confirmation line, got: %q", buf.String())
	}
}

func TestCaptureRunningConfigPropagatesExecuteFailure(t *testing.T) {
	dir := t.TempDir()
	failing := &erroringConfigExecutor{err: fmt.Errorf("channel closed")}
	session := &DeviceSession{hostname: "pe-router-1", client: failing}

	if err := CaptureRunningConfig(session, "before", dir, "", time.Now().UTC(), &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error when the running-config command fails")
	}
}

// TestRunConfigDiffReportsLineChanges proves RunConfigDiff produces a
// unified diff (added/removed lines, correctly ordered) rather than an
// unordered set diff — config text needs surrounding context and ordering
// to be readable, unlike the route-level snapshot diff.
func TestRunConfigDiffReportsLineChanges(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before-running-config.txt")
	afterPath := filepath.Join(dir, "after-running-config.txt")
	if err := os.WriteFile(beforePath, []byte("interfaces {\n    ae0 {\n        description core;\n    }\n}\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if err := os.WriteFile(afterPath, []byte("interfaces {\n    ae0 {\n        description core-updated;\n    }\n}\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var buf bytes.Buffer
	if err := RunConfigDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "description core;\n") && !strings.Contains(got, "-        description core;\n") {
		t.Fatalf("expected the removed line to be reported, got: %q", got)
	}
	if !strings.Contains(got, "description core-updated") {
		t.Fatalf("expected the added line to be reported, got: %q", got)
	}
}

func TestRunConfigDiffNoChanges(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before-running-config.txt")
	afterPath := filepath.Join(dir, "after-running-config.txt")
	content := []byte("interfaces {\n    ae0 {\n        description core;\n    }\n}\n")
	if err := os.WriteFile(beforePath, content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if err := os.WriteFile(afterPath, content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var buf bytes.Buffer
	if err := RunConfigDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no changes") {
		t.Fatalf("expected a no-changes report, got: %q", buf.String())
	}
}

func TestRunConfigDiffMissingFile(t *testing.T) {
	if err := RunConfigDiff(filepath.Join(t.TempDir(), "missing.txt"), filepath.Join(t.TempDir(), "also-missing.txt"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for a missing running-config file")
	}
}

// TestCaptureRunningConfigThenDiffReportsNoChangesForIdenticalConfig proves
// an unchanged device config produces "no changes", going through the real
// CaptureRunningConfig write path (not hand-written fixtures) for both
// sides. CaptureRunningConfig's header embeds the capture label ("before"
// vs "after") and timestamp, both of which necessarily differ between the
// two captures even when the underlying config is byte-for-byte identical
// — this is the regression test for that: without stripCaptureHeader in
// RunConfigDiff, this would always report a spurious diff.
func TestCaptureRunningConfigThenDiffReportsNoChangesForIdenticalConfig(t *testing.T) {
	dir := t.TempDir()
	config := "interfaces {\n    ae0 {\n        description core;\n    }\n}\n"
	session := &DeviceSession{hostname: "pe-router-1", client: &scriptedConfigExecutor{response: config}}

	if err := CaptureRunningConfig(session, "before", dir, "", time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC), &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error capturing before: %v", err)
	}
	if err := CaptureRunningConfig(session, "after", dir, "", time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC), &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error capturing after: %v", err)
	}

	beforePath := filepath.Join(dir, "pe-router-1-20260710-080000-before-running-config.txt")
	afterPath := filepath.Join(dir, "pe-router-1-20260710-090000-after-running-config.txt")

	var buf bytes.Buffer
	if err := RunConfigDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "no changes") {
		t.Fatalf("expected a no-changes report for an identical config, got: %q", got)
	}
}
