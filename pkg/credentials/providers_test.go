package credentials

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

func TestCommandProviderIsRejected(t *testing.T) {
	_, err := NewProvider(ProviderConfig{Type: "command"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "process execution has been removed") {
		t.Fatalf("command provider was not rejected: %v", err)
	}
}
