package safeyaml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnmarshalRejectsAnchorsAndAliases(t *testing.T) {
	var target map[string]interface{}
	err := Unmarshal([]byte("base: &base\n  value: one\ncopy: *base\n"), &target)
	if err == nil || !strings.Contains(err.Error(), "anchors and aliases") {
		t.Fatalf("anchor/alias input was not rejected: %v", err)
	}
}

func TestReadFileRejectsOversizedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.yaml")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized YAML was not rejected: %v", err)
	}
}
