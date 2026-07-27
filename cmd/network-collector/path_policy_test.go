package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathPolicyRejectsAbsoluteAndTraversal(t *testing.T) {
	root := t.TempDir()
	for _, requested := range []string{filepath.Join(root, "absolute"), "../escape", "nested/../../escape"} {
		if _, err := resolveWriteWithin(root, requested); err == nil {
			t.Fatalf("write policy accepted %q", requested)
		}
	}
}

func TestPathPolicyRejectsReadSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveReadWithin(root, "link/secret"); err == nil {
		t.Fatal("read policy accepted symlink escape")
	}
	if _, err := resolveWriteWithin(root, "link/new"); err == nil {
		t.Fatal("write policy accepted symlink escape")
	}
}

func TestPathPolicyAllowsContainedPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "resources"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "resources", "input"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveReadWithin(root, "resources/input"); err != nil {
		t.Fatalf("contained read rejected: %v", err)
	}
	if _, err := resolveWriteWithin(root, "artifacts/result.json"); err != nil {
		t.Fatalf("contained write rejected: %v", err)
	}
}
