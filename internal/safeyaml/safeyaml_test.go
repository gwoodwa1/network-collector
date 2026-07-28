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

func TestUnmarshalReportsNodeCount(t *testing.T) {
	var target map[string]interface{}
	nodes, err := UnmarshalWithNodeCount([]byte("items:\n  - one\n  - two\n"), &target)
	if err != nil {
		t.Fatal(err)
	}
	if nodes < 5 {
		t.Fatalf("node count = %d, want at least 5", nodes)
	}
}

func TestUnmarshalRejectsDocumentOverNodeLimitBeforeDecode(t *testing.T) {
	var target map[string]interface{}
	_, err := unmarshalWithNodeLimit([]byte("items:\n  - one\n  - two\n"), &target, 4)
	if err == nil || !strings.Contains(err.Error(), "4-node limit") {
		t.Fatalf("oversized YAML syntax tree was not rejected: %v", err)
	}
	if target != nil {
		t.Fatalf("target was decoded before the node limit was enforced: %#v", target)
	}
}
