package monitorsetup

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func generateTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return sshPub
}

func TestPromptHostKeyMismatchAbortsWithoutTypingReplace(t *testing.T) {
	mismatch := &hostkey.Mismatch{Host: "router1", File: "/home/op/.ssh/known_hosts", OldKeys: []ssh.PublicKey{generateTestKey(t)}}
	fetchCalled := false
	fetch := func(host string, timeout time.Duration) (ssh.PublicKey, error) {
		fetchCalled = true
		return nil, nil
	}

	reader := bufio.NewReader(strings.NewReader("y\n")) // not the literal word REPLACE
	if got := PromptHostKeyMismatch(reader, mismatch, fetch); got {
		t.Fatal("expected PromptHostKeyMismatch to return false when the operator doesn't type REPLACE")
	}
	if fetchCalled {
		t.Fatal("expected fetchKey to never be called without an explicit REPLACE")
	}
}

func TestPromptHostKeyMismatchAbortsWhenFinalConfirmationDeclined(t *testing.T) {
	mismatch := &hostkey.Mismatch{Host: "router1", File: "/home/op/.ssh/known_hosts", OldKeys: []ssh.PublicKey{generateTestKey(t)}}
	newKey := generateTestKey(t)
	fetch := func(host string, timeout time.Duration) (ssh.PublicKey, error) {
		return newKey, nil
	}

	reader := bufio.NewReader(strings.NewReader("REPLACE\nn\n"))
	if got := PromptHostKeyMismatch(reader, mismatch, fetch); got {
		t.Fatal("expected PromptHostKeyMismatch to return false when the final y/N is declined")
	}
}

// TestPromptHostKeyMismatchTreatsATruncatedReplaceAsDeclined is the
// regression test for ignoring ReadString's error: input ending exactly at
// "REPLACE" with no trailing newline (e.g. stdin severed mid-input) must
// never be accepted as if it were cleanly typed and confirmed.
func TestPromptHostKeyMismatchTreatsATruncatedReplaceAsDeclined(t *testing.T) {
	mismatch := &hostkey.Mismatch{Host: "router1", File: "/home/op/.ssh/known_hosts", OldKeys: []ssh.PublicKey{generateTestKey(t)}}
	fetchCalled := false
	fetch := func(host string, timeout time.Duration) (ssh.PublicKey, error) {
		fetchCalled = true
		return nil, nil
	}

	reader := bufio.NewReader(strings.NewReader("REPLACE")) // no trailing newline: EOF, not a clean read
	if got := PromptHostKeyMismatch(reader, mismatch, fetch); got {
		t.Fatal("expected a truncated REPLACE (EOF before newline) to be treated as declined")
	}
	if fetchCalled {
		t.Fatal("expected fetchKey to never be called on a truncated confirmation")
	}
}

// TestPromptHostKeyMismatchTreatsATruncatedFinalYAsDeclined covers the
// second confirmation: "REPLACE\ny" with no trailing newline after "y" must
// not authorize the disk write just because the partial content happens to
// read as "y".
func TestPromptHostKeyMismatchTreatsATruncatedFinalYAsDeclined(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	content := knownhosts.Line([]string{"router1"}, oldKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	mismatch := &hostkey.Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	fetch := func(host string, timeout time.Duration) (ssh.PublicKey, error) {
		return newKey, nil
	}

	reader := bufio.NewReader(strings.NewReader("REPLACE\ny")) // "y" has no trailing newline: EOF, not a clean read
	if got := PromptHostKeyMismatch(reader, mismatch, fetch); got {
		t.Fatal("expected a truncated final confirmation (EOF before newline) to be treated as declined")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != content {
		t.Fatalf("expected known_hosts to be left untouched on a truncated confirmation, got:\n%s", string(got))
	}
}

func TestPromptHostKeyMismatchReturnsFalseWhenFetchFails(t *testing.T) {
	mismatch := &hostkey.Mismatch{Host: "router1", File: "/home/op/.ssh/known_hosts", OldKeys: []ssh.PublicKey{generateTestKey(t)}}
	fetch := func(host string, timeout time.Duration) (ssh.PublicKey, error) {
		return nil, fmt.Errorf("simulated dial failure")
	}

	reader := bufio.NewReader(strings.NewReader("REPLACE\n"))
	if got := PromptHostKeyMismatch(reader, mismatch, fetch); got {
		t.Fatal("expected false when the independent key fetch itself fails")
	}
}

// TestPromptHostKeyMismatchReplacesEntryOnFullConfirmation is the
// end-to-end happy path: REPLACE, then y, actually rewrites the known_hosts
// file via hostkey.ReplaceEntry and reports success.
func TestPromptHostKeyMismatchReplacesEntryOnFullConfirmation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	content := knownhosts.Line([]string{"router1"}, oldKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	mismatch := &hostkey.Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	fetch := func(host string, timeout time.Duration) (ssh.PublicKey, error) {
		return newKey, nil
	}

	reader := bufio.NewReader(strings.NewReader("REPLACE\ny\n"))
	if got := PromptHostKeyMismatch(reader, mismatch, fetch); !got {
		t.Fatal("expected PromptHostKeyMismatch to return true after full confirmation")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if strings.Contains(string(got), knownhosts.Line([]string{"router1"}, oldKey)) {
		t.Fatal("expected the stale entry to be replaced")
	}
	if !strings.Contains(string(got), knownhosts.Line([]string{knownhosts.Normalize("router1")}, newKey)) {
		t.Fatal("expected the new key's entry to be present")
	}
}
