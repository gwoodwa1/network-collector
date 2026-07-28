package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
