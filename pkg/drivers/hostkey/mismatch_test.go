package hostkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func generateTestKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return signer, sshPub
}

func TestClassifyConnectErrorIgnoresUnknownKeyAndOtherFailures(t *testing.T) {
	if got := ClassifyConnectError("host1", fmt.Errorf("connection refused")); got != nil {
		t.Fatalf("expected nil for a non-host-key error, got %+v", got)
	}
	// Want empty means "host is unknown", not a mismatch — see KeyError's own doc comment.
	unknown := fmt.Errorf("failed to open driver: %w", &knownhosts.KeyError{})
	if got := ClassifyConnectError("host1", unknown); got != nil {
		t.Fatalf("expected nil for an unknown-key (Want empty) error, got %+v", got)
	}
}

func TestClassifyConnectErrorExtractsAMismatch(t *testing.T) {
	_, key1 := generateTestKey(t)
	_, key2 := generateTestKey(t)
	keyErr := &knownhosts.KeyError{Want: []knownhosts.KnownKey{
		{Key: key1, Filename: "/home/op/.ssh/known_hosts", Line: 3},
		{Key: key2, Filename: "/home/op/.ssh/known_hosts", Line: 7},
	}}
	// Wrapped the same way the real chain wraps it: driver.Open -> "ssh: handshake failed" -> KeyError.
	wrapped := fmt.Errorf("failed to open driver: %w", fmt.Errorf("ssh: handshake failed: %w", keyErr))

	m := ClassifyConnectError("router1", wrapped)
	if m == nil {
		t.Fatal("expected a non-nil Mismatch")
	}
	if m.Host != "router1" || m.File != "/home/op/.ssh/known_hosts" {
		t.Fatalf("unexpected Host/File: %+v", m)
	}
	if len(m.StaleLines) != 2 || m.StaleLines[0] != 7 || m.StaleLines[1] != 3 {
		t.Fatalf("expected stale lines in descending order [7 3], got %v", m.StaleLines)
	}
	if !bytes.Equal(m.OldKeys[0].Marshal(), key2.Marshal()) || !bytes.Equal(m.OldKeys[1].Marshal(), key1.Marshal()) {
		t.Fatal("expected OldKeys to stay paired with their StaleLines entry after the descending sort")
	}
}

func TestReplaceEntryRemovesStaleLinesPreservesOthersAndAppendsNewKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")

	_, oldKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	_, keepKey := generateTestKey(t)
	keepLine := knownhosts.Line([]string{"unrelated-host"}, keepKey)

	// Line numbers (1-indexed): 1=keep, 2=stale (router1 old key), 3=keep.
	content := keepLine + "\n" + knownhosts.Line([]string{"router1"}, oldKey) + "\n" + keepLine + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{2}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err != nil {
		t.Fatalf("ReplaceEntry: %v", err)
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	gotStr := string(got)

	if want := knownhosts.Line([]string{"router1"}, oldKey); bytes.Contains(got, []byte(want)) {
		t.Fatalf("expected the stale entry to be gone, got:\n%s", gotStr)
	}
	if wantNew := knownhosts.Line([]string{knownhosts.Normalize("router1")}, newKey); !bytes.Contains(got, []byte(wantNew)) {
		t.Fatalf("expected the new key's entry to be present, got:\n%s", gotStr)
	}
	keepCount := 0
	for _, line := range splitLines(gotStr) {
		if line == keepLine {
			keepCount++
		}
	}
	if keepCount != 2 {
		t.Fatalf("expected both unrelated lines preserved untouched, got %d occurrences in:\n%s", keepCount, gotStr)
	}

	// End-to-end: the rewritten file must actually verify newKey for router1
	// via the real knownhosts parser, and no longer accept oldKey.
	callback, err := knownhosts.New(file)
	if err != nil {
		t.Fatalf("parse rewritten known_hosts: %v", err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := callback("router1:22", addr, newKey); err != nil {
		t.Fatalf("expected the new key to verify, got: %v", err)
	}
	if err := callback("router1:22", addr, oldKey); err == nil {
		t.Fatal("expected the old key to be rejected after replacement")
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// TestReplaceEntryHandlesAHashedHostEntry proves lineBindsHostToKey
// correctly matches a hashed known_hosts entry ("|1|salt|hash", produced by
// ssh-keyscan -H or a manually hashed known_hosts file) against the plain
// hostname it was hashed from — a direct string comparison between the
// parsed host field and m.Host would never match here, since the field is
// an opaque hash, not the hostname itself.
func TestReplaceEntryHandlesAHashedHostEntry(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	_, oldKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	hashedHost := knownhosts.HashHostname("router1")
	content := knownhosts.Line([]string{hashedHost}, oldKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err != nil {
		t.Fatalf("expected ReplaceEntry to succeed against a hashed host entry, got: %v", err)
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if strings.Contains(string(got), hashedHost) {
		t.Fatalf("expected the hashed stale entry to be gone, got:\n%s", string(got))
	}
}

// TestReplaceEntryAbortsWhenFileChangedUnderneath is the regression test
// for a TOCTOU gap: StaleLines/OldKeys are captured when the mismatch is
// first detected, but the operator confirmation flow (REPLACE, fetch,
// final y/N) takes real wall time during which something else could edit
// known_hosts. If the recorded line no longer holds the expected key,
// ReplaceEntry must refuse to touch the file rather than deleting whatever
// now happens to be at that line number.
func TestReplaceEntryAbortsWhenFileChangedUnderneath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")

	_, oldKey := generateTestKey(t)
	_, unrelatedKey := generateTestKey(t)
	_, newKey := generateTestKey(t)

	// Someone else edited line 1 (originally router1/oldKey) to now hold an
	// entirely different, unrelated entry — same line number, different
	// content — before ReplaceEntry runs.
	content := knownhosts.Line([]string{"some-other-host"}, unrelatedKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err == nil {
		t.Fatal("expected ReplaceEntry to refuse a line that no longer holds the expected key")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != content {
		t.Fatalf("expected the file to be left completely untouched, got:\n%s", string(got))
	}
}

// TestReplaceEntryAbortsWhenLineNowBelongsToADifferentHostWithTheSameKey is
// the regression test for validating only the key and not the host
// binding: if the file changed so that the stale line now holds an
// *unrelated host* that merely happens to reuse the same key bytes as the
// original stale entry, a key-only comparison would wrongly accept it and
// delete that unrelated host's entry while leaving the real stale
// router1 entry (now shifted elsewhere in the file) untouched and still
// trusted. lineBindsHostToKey must catch this by checking the host
// binding too, not just the key.
func TestReplaceEntryAbortsWhenLineNowBelongsToADifferentHostWithTheSameKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")

	_, oldKey := generateTestKey(t)
	_, newKey := generateTestKey(t)

	// Line 1 now binds a completely different host ("unrelated-host") to
	// the *same* key bytes m.OldKeys[0] recorded for router1 — as if the
	// original router1 entry shifted to a later line and something else
	// wrote this one in its place.
	shiftedContent := knownhosts.Line([]string{"unrelated-host"}, oldKey) + "\n" +
		knownhosts.Line([]string{"router1"}, oldKey) + "\n"
	if err := os.WriteFile(file, []byte(shiftedContent), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// The mismatch still points at line 1 (where it was originally detected).
	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err == nil {
		t.Fatal("expected ReplaceEntry to refuse a line whose key matches but whose host does not")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != shiftedContent {
		t.Fatalf("expected the file to be left completely untouched, got:\n%s", string(got))
	}
}

// TestReplaceEntryAbortsWhenLineNoLongerExists covers the file having
// shrunk (e.g. someone else already removed that entry) since the mismatch
// was detected — the line number is simply out of range now.
func TestReplaceEntryAbortsWhenLineNoLongerExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	_, oldKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	if err := os.WriteFile(file, []byte("only-one-line\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{5}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err == nil {
		t.Fatal("expected ReplaceEntry to refuse an out-of-range stale line")
	}
}

// TestReplaceEntryRefusesALineSharedByOtherHosts is the regression test for
// silently dropping trust for a host that isn't even part of this refresh:
// a known_hosts line can bind one key to several comma-separated hosts, and
// deleting the whole line to replace router1's key would also un-trust
// router2, which never had anything wrong reported about it.
func TestReplaceEntryRefusesALineSharedByOtherHosts(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	_, sharedKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	content := knownhosts.Line([]string{"router1", "router2"}, sharedKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{sharedKey}}
	if err := ReplaceEntry(m, newKey); err == nil {
		t.Fatal("expected ReplaceEntry to refuse a line shared by multiple hosts")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != content {
		t.Fatalf("expected the file to be left completely untouched, got:\n%s", string(got))
	}
}

// TestReplaceEntryRefusesACertAuthorityMarkedLine covers an
// @cert-authority-marked entry: rewriting it as a plain trusted-key line
// would silently downgrade what it authorizes, so ReplaceEntry refuses it
// the same way it refuses a shared-host line.
func TestReplaceEntryRefusesACertAuthorityMarkedLine(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	_, oldKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	content := "@cert-authority " + knownhosts.Line([]string{"router1"}, oldKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err == nil {
		t.Fatal("expected ReplaceEntry to refuse an @cert-authority-marked line")
	}
}

// TestReplaceEntryRefusesAWildcardHostPattern is the regression test for a
// single-host-field entry that's still a wildcard: "*.example" has
// len(hosts) == 1 (it's one pattern token, not several comma-separated
// hosts), so the shared-hosts check alone doesn't catch it, but it still
// matches every *.example host — refreshing router1.example's key on this
// line would silently drop trust for router2.example and anything else
// matching the same pattern.
func TestReplaceEntryRefusesAWildcardHostPattern(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	_, wildcardKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	content := knownhosts.Line([]string{"*.example"}, wildcardKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1.example", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{wildcardKey}}
	if err := ReplaceEntry(m, newKey); err == nil {
		t.Fatal("expected ReplaceEntry to refuse a wildcard host pattern")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != content {
		t.Fatalf("expected the file to be left completely untouched, got:\n%s", string(got))
	}
}

func TestReplaceEntryPreservesFilePermissions(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	_, oldKey := generateTestKey(t)
	_, newKey := generateTestKey(t)
	content := knownhosts.Line([]string{"router1"}, oldKey) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := &Mismatch{Host: "router1", File: file, StaleLines: []int{1}, OldKeys: []ssh.PublicKey{oldKey}}
	if err := ReplaceEntry(m, newKey); err != nil {
		t.Fatalf("ReplaceEntry: %v", err)
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("expected mode 0640 preserved, got %v", info.Mode().Perm())
	}
}

// startTestSSHServer spins up a minimal local SSH server presenting hostKey,
// so FetchPresentedKey can be exercised against something real instead of a
// hand-built error. It never completes authentication — a real client here
// (FetchPresentedKey) is expected to abort right after capturing the host
// key, and the server side is left to fail its own handshake and exit,
// which is fine since the test only cares what the client captured.
func startTestSSHServer(t *testing.T) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	signer, pub := generateTestKey(t)

	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password auth not supported by this test server")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// The client (FetchPresentedKey) deliberately aborts right
				// after the host-key exchange, so this always ends in an
				// error — that's expected, not a test failure.
				_, _, _, _ = ssh.NewServerConn(c, config)
			}(conn)
		}
	}()

	return listener.Addr().String(), pub
}

func TestFetchPresentedKeyReturnsTheServersHostKey(t *testing.T) {
	addr, wantKey := startTestSSHServer(t)

	got, err := FetchPresentedKey(addr, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.Marshal(), wantKey.Marshal()) {
		t.Fatal("fetched key does not match the test server's host key")
	}
}

func TestFetchPresentedKeyNeverAuthenticates(t *testing.T) {
	authAttempted := false
	signer, _ := generateTestKey(t)
	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			authAttempted = true
			return nil, fmt.Errorf("auth rejected by test")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _, _ = ssh.NewServerConn(conn, config)
	}()

	if _, err := FetchPresentedKey(listener.Addr().String(), 5*time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authAttempted {
		t.Fatal("FetchPresentedKey must never reach the authentication phase")
	}
}

// TestFetchPresentedKeyBoundsTheFullHandshakeNotJustTCPConnect is the
// regression test for using ssh.ClientConfig.Timeout alone, which per its
// own doc comment only covers TCP establishment: a server that accepts the
// TCP connection but withholds its SSH version banner (accepts but never
// negotiates) would otherwise stall FetchPresentedKey indefinitely, well
// past timeout, since the handshake itself was never bounded.
func TestFetchPresentedKeyBoundsTheFullHandshakeNotJustTCPConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept the TCP connection, then just hold it open — never send
		// the SSH version banner the handshake is waiting on.
		time.Sleep(5 * time.Second)
	}()

	const timeout = 200 * time.Millisecond
	start := time.Now()
	_, err = FetchPresentedKey(listener.Addr().String(), timeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the server never completes the handshake")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected the handshake stall to be bounded by timeout (%v), took %v", timeout, elapsed)
	}
}

func TestFetchPresentedKeyFailsFastWhenNothingIsListening(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close() // now guaranteed nobody is listening on addr

	start := time.Now()
	_, err = FetchPresentedKey(addr, 5*time.Second)
	if err == nil {
		t.Fatal("expected an error when nothing is listening")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("expected a fast connection-refused failure, took %v", elapsed)
	}
}
