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
		"repeat": `
ssh:
  - hostname: router-01
    steps:
      - repeat:
          count: 1
          steps:
            - local: {command: sh}
`,
		"foreach": `
ssh:
  - hostname: router-01
    steps:
      - foreach:
          items: [one]
          steps:
            - local: {command: sh}
`,
		"parallel": `
ssh:
  - hostname: router-01
    steps:
      - parallel:
          steps:
            - local: {command: sh}
`,
		"block-steps": `
ssh:
  - hostname: router-01
    steps:
      - block:
          steps:
            - local: {command: sh}
`,
		"block-rescue": `
ssh:
  - hostname: router-01
    steps:
      - block:
          rescue:
            - local: {command: sh}
`,
		"block-rollback": `
ssh:
  - hostname: router-01
    steps:
      - block:
          rollback:
            - local: {command: sh}
`,
		"block-always": `
ssh:
  - hostname: router-01
    steps:
      - block:
          always:
            - local: {command: sh}
`,
		"on-pass": `
ssh:
  - hostname: router-01
    steps:
      - cmd: show version
        on_pass:
          steps:
            - local: {command: sh}
`,
		"on-fail": `
ssh:
  - hostname: router-01
    steps:
      - cmd: show version
        on_fail:
          steps:
            - local: {command: sh}
`,
		"named-workflow": `
workflows:
  dormant:
    steps:
      - local: {command: sh}
`,
		"netconf": `
netconf:
  - hostname: router-01
    steps:
      - local: {command: sh}
`,
		"credential-command": `
credentials:
  provider: command
  command: [/bin/sh, -c, id]
`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workbook.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadConfig(path)
			if err == nil || !strings.Contains(err.Error(), "execution has been removed") {
				t.Fatalf("removed local execution was not rejected: %v", err)
			}
		})
	}
}

func TestLoadConfigRejectsRemovedLocalExecutionFromImport(t *testing.T) {
	dir := t.TempDir()
	imported := filepath.Join(dir, "imported.yaml")
	root := filepath.Join(dir, "workbook.yaml")
	if err := os.WriteFile(imported, []byte(`
workflows:
  dormant:
    steps:
      - parallel:
          steps:
            - local: {command: sh}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("imports: [imported.yaml]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadConfig(root)
	if err == nil || !strings.Contains(err.Error(), "execution has been removed") {
		t.Fatalf("removed local execution in an import was not rejected: %v", err)
	}
}

func TestLoadConfigRejectsCredentialBinarySelection(t *testing.T) {
	for name, content := range map[string]string{
		"vault": `
credentials:
  provider: hashicorp
  hashicorp:
    binary: /bin/sh
`,
		"onepassword": `
credentials:
  provider: 1password
  onepassword:
    binary: /bin/sh
`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workbook.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadConfig(path)
			if err == nil || !strings.Contains(err.Error(), "administrator-controlled") {
				t.Fatalf("credential binary selection was not rejected: %v", err)
			}
		})
	}
}
