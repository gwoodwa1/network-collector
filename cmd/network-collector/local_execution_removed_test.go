package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRejectsRemovedLocalExecution(t *testing.T) {
	tests := map[string]string{
		"top-level": `
local_steps:
  - name: unsafe
    local:
      command: sh
`,
		"device-step": `
ssh:
  - hostname: router-01
    steps:
      - name: unsafe
        local:
          command: python3
`,
		"nested-trigger": `
ssh:
  - hostname: router-01
    steps:
      - name: watch
        gnmi_subscribe:
          paths: [/interfaces]
          triggers:
            - name: unsafe
              event: update
              steps:
                - local:
                    command: curl
`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workbook.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadConfig(path)
			if err == nil || !strings.Contains(err.Error(), "arbitrary local execution has been removed") {
				t.Fatalf("removed local execution was not rejected: %v", err)
			}
		})
	}
}

