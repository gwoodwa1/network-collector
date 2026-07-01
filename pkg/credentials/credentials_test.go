package credentials

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestResolveCredentialsUsesEnvironmentByDefault(t *testing.T) {
	t.Setenv("NET_USER", "env-user")
	t.Setenv("NET_PASSWORD", "env-pass")

	username, password, err := ResolveCredentials(false, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if username != "env-user" {
		t.Fatalf("expected username env-user, got %q", username)
	}
	if password != "env-pass" {
		t.Fatalf("expected password env-pass, got %q", password)
	}
}

func TestResolveCredentialsPromptsWhenRequested(t *testing.T) {
	t.Setenv("NET_USER", "env-user")
	t.Setenv("NET_PASSWORD", "env-pass")

	var output bytes.Buffer
	username, password, err := ResolveCredentials(true, strings.NewReader("alice\nsecret\n"), &output)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if username != "alice" {
		t.Fatalf("expected username alice, got %q", username)
	}
	if password != "secret" {
		t.Fatalf("expected password secret, got %q", password)
	}
	if !strings.Contains(output.String(), "Username:") || !strings.Contains(output.String(), "Password:") {
		t.Fatalf("expected prompts in output, got %q", output.String())
	}
}

func TestResolveCredentialsPreservesPasswordWhitespace(t *testing.T) {
	t.Setenv("NET_USER", "")
	t.Setenv("NET_PASSWORD", "")

	username, password, err := ResolveCredentials(true, strings.NewReader("alice\n secret phrase \n"), io.Discard)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if username != "alice" || password != " secret phrase " {
		t.Fatalf("unexpected credentials: username=%q password=%q", username, password)
	}
}

func TestResolveCredentialsReturnsInputError(t *testing.T) {
	t.Setenv("NET_USER", "")
	t.Setenv("NET_PASSWORD", "")

	_, _, err := ResolveCredentials(true, strings.NewReader("alice\n"), io.Discard)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF while reading password, got %v", err)
	}
}
