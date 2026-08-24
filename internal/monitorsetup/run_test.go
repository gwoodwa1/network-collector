package monitorsetup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetupRunUsesDevicesFileBasenameAsRunLabel(t *testing.T) {
	dir := t.TempDir()
	startedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	run, err := SetupRun(dir, filepath.Join("some", "path", "CRQXXX.yaml"), startedAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer run.SessionLogFile.Close()

	if run.RunLabel != "CRQXXX" {
		t.Fatalf("expected RunLabel CRQXXX, got %q", run.RunLabel)
	}
	wantDir := filepath.Join(dir, "CRQXXX")
	if run.OutputDir != wantDir {
		t.Fatalf("expected OutputDir %q, got %q", wantDir, run.OutputDir)
	}
	if _, err := os.Stat(run.OutputDir); err != nil {
		t.Fatalf("expected OutputDir to exist: %v", err)
	}
	wantLog := filepath.Join(wantDir, "CRQXXX-20260710-080000-session.log")
	if _, err := os.Stat(wantLog); err != nil {
		t.Fatalf("expected session log at %q: %v", wantLog, err)
	}
}

// TestSetupRunFallsBackToTimestampPIDWhenNoDevicesFile proves interactive
// (no --devices) runs still get a distinct, collision-resistant folder name.
func TestSetupRunFallsBackToTimestampPIDWhenNoDevicesFile(t *testing.T) {
	dir := t.TempDir()
	startedAt := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	run, err := SetupRun(dir, "", startedAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer run.SessionLogFile.Close()

	if run.RunLabel != "" {
		t.Fatalf("expected empty RunLabel for interactive-only onboarding, got %q", run.RunLabel)
	}
	wantPrefix := filepath.Join(dir, "20260710-080000-")
	if len(run.OutputDir) <= len(wantPrefix) || run.OutputDir[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("expected OutputDir to start with %q (timestamp-pid fallback), got %q", wantPrefix, run.OutputDir)
	}
}

func TestSetupRunWritersAreNonNil(t *testing.T) {
	dir := t.TempDir()
	run, err := SetupRun(dir, "", time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer run.SessionLogFile.Close()

	if run.HumanOutput == nil || run.SnapshotOut == nil || run.StatusBaseWriter == nil {
		t.Fatalf("expected all writers populated, got %+v", run)
	}
	if _, err := run.SnapshotOut.Write([]byte("test\n")); err != nil {
		t.Fatalf("unexpected error writing through SnapshotOut: %v", err)
	}
}
