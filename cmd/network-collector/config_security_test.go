package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gwoodwa1/network-collector/internal/safeyaml"
)

func TestLoadConfigRejectsYAMLAnchorsAndAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workbook.yaml")
	content := `
vars:
  shared: &shared
    value: unsafe-expansion
  copied: *shared
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "anchors and aliases") {
		t.Fatalf("workbook YAML anchors/aliases were not rejected: %v", err)
	}
}

func TestInventoryLoader_RejectsAggregateNodeBomb(t *testing.T) {
	// Each mapping entry contributes a key and value node. Keep the document
	// below the byte limit while crossing the production decoded-node limit.
	entries := safeyaml.MaxDocumentNodes/2 + 1
	var content strings.Builder
	content.Grow(entries * 12)
	content.WriteString("hosts: []\n")
	for index := 0; index < entries; index++ {
		_, _ = fmt.Fprintf(&content, "n%06d: x\n", index)
	}
	if content.Len() >= safeyaml.MaxFileBytes {
		t.Fatalf("node-bomb fixture is %d bytes, must remain below %d", content.Len(), safeyaml.MaxFileBytes)
	}

	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInventory(path, ""); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("%d-node limit", safeyaml.MaxDocumentNodes)) {
		t.Fatalf("inventory loader did not reject a sub-byte-limit YAML node bomb: %v", err)
	}
}

func TestStandaloneInventoryAndParserLoadersRejectYAMLAnchors(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		load    func(string) error
	}{
		{
			name:    "inventory",
			content: "hosts:\n  - &host\n    name: router-1\n  - *host\n",
			load: func(path string) error {
				_, err := loadInventory(path, "")
				return err
			},
		},
		{
			name:    "parsers",
			content: "parsers:\n  shared: &parser\n    type: regex\n  copied: *parser\n",
			load: func(path string) error {
				_, err := loadParsers(path, "")
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), test.name+".yaml")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.load(path); err == nil || !strings.Contains(err.Error(), "anchors and aliases") {
				t.Fatalf("%s YAML anchors were not rejected: %v", test.name, err)
			}
		})
	}
}
