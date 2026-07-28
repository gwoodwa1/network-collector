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

func TestUnmarshalByteBoundaryIsExact(t *testing.T) {
	atLimit := []byte(strings.Repeat("x", MaxFileBytes))
	var decoded string
	if err := Unmarshal(atLimit, &decoded); err != nil {
		t.Fatalf("YAML at exact byte limit was rejected: %v", err)
	}
	if len(decoded) != MaxFileBytes {
		t.Fatalf("decoded scalar length = %d, want %d", len(decoded), MaxFileBytes)
	}
	decoded = "unchanged"
	if err := Unmarshal(append(atLimit, 'x'), &decoded); err == nil {
		t.Fatal("YAML one byte over the limit was accepted")
	}
	if decoded != "unchanged" {
		t.Fatalf("over-limit YAML mutated decode target: %q", decoded)
	}
}

func TestNodeLimitBoundaryIsExactAndPrecedesDecode(t *testing.T) {
	content := []byte("items:\n  - one\n  - two\n")
	var probe map[string]interface{}
	nodes, err := unmarshalWithNodeLimit(content, &probe, MaxDocumentNodes)
	if err != nil {
		t.Fatal(err)
	}

	var exact map[string]interface{}
	if _, err := unmarshalWithNodeLimit(content, &exact, nodes); err != nil {
		t.Fatalf("document at exact node limit was rejected: %v", err)
	}
	var over map[string]interface{}
	if _, err := unmarshalWithNodeLimit(content, &over, nodes-1); err == nil {
		t.Fatal("document one node over the configured limit was accepted")
	}
	if over != nil {
		t.Fatalf("over-limit document mutated decode target: %#v", over)
	}
}

func TestDeepDocumentInspectionIsIterativeAndPanicFree(t *testing.T) {
	var builder strings.Builder
	for index := 0; index < 10_000; index++ {
		builder.WriteByte('[')
	}
	builder.WriteString("value")
	for index := 0; index < 10_000; index++ {
		builder.WriteByte(']')
	}
	var target interface{}
	_ = Unmarshal([]byte(builder.String()), &target)
}

func TestDuplicateMappingKeyIsRejected(t *testing.T) {
	target := map[string]string{"preserved": "value"}
	err := Unmarshal([]byte("key: first\nkey: second\n"), &target)
	if err == nil {
		t.Fatal("duplicate YAML mapping key was accepted")
	}
	if target["preserved"] != "value" {
		t.Fatalf("failed decode unexpectedly replaced target: %#v", target)
	}
}
