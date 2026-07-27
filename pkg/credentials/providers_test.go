package credentials

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFileProviderProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	content := []byte("default:\n  username: default-user\n  password: default-pass\nprofiles:\n  edge:\n    username: edge-user\n    password: edge-pass\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Resolve(context.Background(), Target{Hostname: "edge-1", Profile: "edge"})
	if err != nil || got.Username != "edge-user" || got.Password != "edge-pass" {
		t.Fatalf("unexpected credentials=%+v error=%v", got, err)
	}
}

func TestFileProviderRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not portable")
	}
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte("default: {username: u, password: p}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileProvider(path); err == nil {
		t.Fatal("accepted credential file with group/other permissions")
	}
}

func TestCommandProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell helper is Unix-specific")
	}
	provider := CommandProvider{Command: []string{"sh", "-c", `printf '{"username":"%s","password":"secret"}' "$NET_CREDENTIAL_PROFILE"`}}
	got, err := provider.Resolve(context.Background(), Target{Hostname: "r1", Profile: "core"})
	if err != nil || got.Username != "core" {
		t.Fatalf("unexpected credentials=%+v error=%v", got, err)
	}
}

func TestCommandProviderTimeoutConfiguration(t *testing.T) {
	provider, err := NewProvider(ProviderConfig{
		Type: "command", Command: []string{"credential-helper"}, TimeoutSeconds: 45,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	command, ok := provider.(CommandProvider)
	if !ok || command.Timeout != 45*time.Second {
		t.Fatalf("unexpected command provider: %#v", provider)
	}
	for _, timeout := range []int{-1, 301} {
		if _, err := NewProvider(ProviderConfig{Type: "command", Command: []string{"helper"}, TimeoutSeconds: timeout}, nil, nil); err == nil {
			t.Fatalf("accepted invalid timeout_seconds=%d", timeout)
		}
	}
}

func TestExampleCredentialAdapters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("credential adapters are Bash scripts")
	}
	helperDir := t.TempDir()
	writeHelper := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("#!/bin/sh\nset -eu\n"+body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeHelper("vault", `printf '%s\n' '{"data":{"data":{"username":"vault-user","password":"vault-pass"}}}'`)
	writeHelper("op", `
case "$2" in
  */username) printf '%s\n' 'op-user' ;;
  */password) printf '%s\n' 'op-pass' ;;
  *) exit 2 ;;
esac`)
	writeHelper("curl", `printf '%s\n' '{"UserName":"cyberark-user","Content":"cyberark-pass"}'`)
	t.Setenv("PATH", helperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("VAULT_KV_MOUNT", "network")
	t.Setenv("VAULT_KV_PREFIX", "devices")
	t.Setenv("OP_VAULT", "Network Automation")
	t.Setenv("OP_ITEM_PREFIX", "collector-")
	t.Setenv("CYBERARK_CCP_URL", "https://ccp.example/AIMWebService/api/Accounts")
	t.Setenv("CYBERARK_APP_ID", "NetworkCollector")
	t.Setenv("CYBERARK_SAFE", "Network-Automation")
	t.Setenv("CYBERARK_OBJECT_PREFIX", "collector-")

	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		script, username, password string
	}{
		{"vault.sh", "vault-user", "vault-pass"},
		{"onepassword.sh", "op-user", "op-pass"},
		{"cyberark.sh", "cyberark-user", "cyberark-pass"},
	}
	for _, test := range tests {
		t.Run(test.script, func(t *testing.T) {
			provider := CommandProvider{
				Command: []string{filepath.Join(repositoryRoot, "examples", "credential-providers", test.script)},
				Timeout: 5 * time.Second,
			}
			got, resolveErr := provider.Resolve(context.Background(), Target{
				Hostname: "core-01", IP: "192.0.2.10", Profile: "datacenter",
			})
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if got.Username != test.username || got.Password != test.password {
				t.Fatalf("unexpected credentials: %#v", got)
			}
		})
	}
}
