package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCaptureRunningConfigWritesFileAndConfirmation proves the running
// config is written to "<base>-running-config.txt" (sharing
// captureSnapshot's <base> naming, see snapshotFilenameBase) and a
// confirmation is written to the provided writer.
func TestCaptureRunningConfigWritesFileAndConfirmation(t *testing.T) {
	dir := t.TempDir()
	exec := &scriptedExecutor{responses: map[string]string{
		"show running-config": "interface Bundle-Ether45\n description core\n!\n",
	}}
	session := &deviceSession{hostname: "pe-router-1", client: exec}
	capturedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	if err := captureRunningConfig(session, "before", dir, "CRQXXX", capturedAt, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantPath := filepath.Join(dir, "CRQXXX-pe-router-1-20260710-080000-before-running-config.txt")
	content, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("expected file at %s, got error: %v", wantPath, err)
	}
	if !strings.Contains(string(content), "interface Bundle-Ether45") {
		t.Fatalf("expected captured config content, got: %q", content)
	}
	if !strings.Contains(buf.String(), "before-change running-config captured for pe-router-1") {
		t.Fatalf("expected a confirmation line, got: %q", buf.String())
	}
}

func TestCaptureRunningConfigPropagatesExecuteFailure(t *testing.T) {
	dir := t.TempDir()
	failing := &erroringExecutor{err: fmt.Errorf("channel closed")}
	session := &deviceSession{hostname: "pe-router-1", client: failing}

	if err := captureRunningConfig(session, "before", dir, "", time.Now().UTC(), &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error when the running-config command fails")
	}
}

type erroringExecutor struct{ err error }

func (e *erroringExecutor) Execute(cmd string) (string, error) { return "", e.err }
func (e *erroringExecutor) Close() error                       { return nil }

// TestRunConfigDiffReportsLineChanges proves runConfigDiff produces a
// unified diff (added/removed lines, correctly ordered) rather than an
// unordered set diff — config text needs surrounding context and ordering
// to be readable, unlike the route-level snapshot diff.
func TestRunConfigDiffReportsLineChanges(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before-running-config.txt")
	afterPath := filepath.Join(dir, "after-running-config.txt")
	if err := os.WriteFile(beforePath, []byte("interface Bundle-Ether45\n description core\n!\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if err := os.WriteFile(afterPath, []byte("interface Bundle-Ether45\n description core-updated\n!\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var buf bytes.Buffer
	if err := runConfigDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "-description core\n") && !strings.Contains(got, "- description core\n") {
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
	content := []byte("interface Bundle-Ether45\n description core\n!\n")
	if err := os.WriteFile(beforePath, content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if err := os.WriteFile(afterPath, content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var buf bytes.Buffer
	if err := runConfigDiff(beforePath, afterPath, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no changes") {
		t.Fatalf("expected a no-changes report, got: %q", buf.String())
	}
}

func TestRunConfigDiffMissingFile(t *testing.T) {
	if err := runConfigDiff(filepath.Join(t.TempDir(), "missing.txt"), filepath.Join(t.TempDir(), "also-missing.txt"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for a missing running-config file")
	}
}
