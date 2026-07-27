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
