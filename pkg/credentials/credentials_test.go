package credentials

import (
	"bytes"
	"errors"
	"io"
	"os"
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
	gotOutput := output.String()
	for _, want := range []string{"Username:", "Password (input hidden):"} {
		if !strings.Contains(gotOutput, want) {
			t.Fatalf("expected prompt output to contain %q, got %q", want, gotOutput)
		}
	}
	if strings.Contains(gotOutput, "********") {
		t.Fatalf("prompt output displayed a misleading fixed password mask: %q", gotOutput)
	}
	if strings.Contains(gotOutput, "secret") {
		t.Fatalf("prompt output leaked the password: %q", gotOutput)
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

// TestResolveCredentialsWithTerminalFallsBackToBufferedReading covers the
// case a caller like xr-routing-monitor hits: input is a long-lived
// *bufio.Reader (not a *os.File), so ResolveCredentials's own
// input.(*os.File) check can never succeed and would always disable
// echo-suppressed password entry, even run interactively at a real
// terminal. ResolveCredentialsWithTerminal fixes that by taking the
// terminal file descriptor separately. Here terminal is a real *os.File but
// not a TTY (a regular temp file, as in any test environment), so this
// exercises the fallback to buffered line reading and confirms it still
// returns the right credentials — the terminal-mode path itself (raw
// echo-off reads) needs a real pty to exercise, which no unit test has.
func TestResolveCredentialsWithTerminalFallsBackToBufferedReading(t *testing.T) {
	t.Setenv("NET_USER", "")
	t.Setenv("NET_PASSWORD", "")

	notATTY, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer notATTY.Close()

	var output bytes.Buffer
	username, password, err := ResolveCredentialsWithTerminal(true, strings.NewReader("alice\nsecret\n"), notATTY, &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "alice" || password != "secret" {
		t.Fatalf("unexpected credentials: username=%q password=%q", username, password)
	}
}
