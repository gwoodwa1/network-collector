package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAtomicWriteUsesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "result.json")
	if err := atomicWriteFile(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("file mode = %#o, want 0600", got)
		}
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := dirInfo.Mode().Perm(); got != 0700 {
			t.Fatalf("directory mode = %#o, want 0700", got)
		}
	}
}

func TestProtectedOutputIsOmittedByDefaultAndRedactedWhenEnabled(t *testing.T) {
	const sensitive = "username admin password=supersecret\n\x1b[31mrouter"
	var defaultLog bytes.Buffer
	writeProtectedOutput(&stepExecutionContext{jsonOut: true, sessionLog: &defaultLog}, "command", sensitive)
	if strings.Contains(defaultLog.String(), "supersecret") || !strings.Contains(defaultLog.String(), "output omitted") {
		t.Fatalf("default session log disclosed output: %s", defaultLog.String())
	}

	var transcript bytes.Buffer
	writeProtectedOutput(&stepExecutionContext{jsonOut: true, sessionOutput: true, sessionLog: &transcript}, "command", sensitive)
	if strings.Contains(transcript.String(), "supersecret") || strings.ContainsRune(transcript.String(), '\x1b') {
		t.Fatalf("protected transcript disclosed secret or terminal control: %q", transcript.String())
	}
	if !strings.Contains(transcript.String(), "[REDACTED]") {
		t.Fatalf("protected transcript did not record redaction: %q", transcript.String())
	}
}

func TestPruneManagedOutputsRemovesOnlyExpiredManagedEntries(t *testing.T) {
	dir := t.TempDir()
	oldRun := filepath.Join(dir, "run-old")
	newRun := filepath.Join(dir, "run-new")
	unmanaged := filepath.Join(dir, "keep")
	for _, path := range []string{oldRun, newRun, unmanaged} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(oldRun, old, old); err != nil {
		t.Fatal(err)
	}
	if err := pruneManagedOutputs(dir, "run-", 1, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldRun); !os.IsNotExist(err) {
		t.Fatalf("expired run still exists: %v", err)
	}
	for _, path := range []string{newRun, unmanaged} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unexpected removal of %s: %v", path, err)
		}
	}
}
