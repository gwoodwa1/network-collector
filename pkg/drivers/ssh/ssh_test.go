package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// startRealSSHServer spins up a minimal local SSH server presenting a
// generated host key, purely as a real handshake endpoint for this file's
// real-OS-ssh-binary tests to dial against. It never completes
// authentication — irrelevant here, since these tests only care about what
// happens at or before the host-key check — but passwordAttempted flips to
// true the moment the server's PasswordCallback actually runs, so a caller
// can assert that a connection got *past* the host-key check and genuinely
// reached authentication, rather than just observing "some non-host-key
// error" that could equally be produced by an unrelated connection failure.
func startRealSSHServer(t *testing.T) (host string, port int, hostKey cryptossh.PublicKey, passwordAttempted *atomic.Bool) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from host key: %v", err)
	}

	passwordAttempted = &atomic.Bool{}
	config := &cryptossh.ServerConfig{
		PasswordCallback: func(_ cryptossh.ConnMetadata, _ []byte) (*cryptossh.Permissions, error) {
			passwordAttempted.Store(true)
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
				// The real ssh client aborts right after the host-key
				// exchange when it doesn't match known_hosts, so this
				// always ends in an error on the server side too — that's
				// expected, not a test failure.
				_, _, _, _ = cryptossh.NewServerConn(c, config)
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, signer.PublicKey(), passwordAttempted
}

// TestChannelDiagnosticCaptureStopsRetainingBytesAfterConnectSetup is the
// regression test for capture growing unbounded across a long-running
// session: scrapligo keeps writing to whatever channel log
// connectWithProfile wires in for the life of the driver, not just during
// Open(), so without stop() every subsequent command response on a
// successful, long-running session would accumulate here forever. This
// proves writes before stop() are retained as expected, and writes after
// stop() — standing in for a successful session's ongoing command output —
// are silently dropped rather than growing the buffer.
func TestChannelDiagnosticCaptureStopsRetainingBytesAfterConnectSetup(t *testing.T) {
	capture := newChannelDiagnosticCapture()

	if _, err := capture.Write([]byte("connect-setup output\n")); err != nil {
		t.Fatalf("write before stop: %v", err)
	}
	if got := string(capture.bytes()); got != "connect-setup output\n" {
		t.Fatalf("expected pre-stop write to be retained, got %q", got)
	}

	capture.stop()
	if got := capture.bytes(); len(got) != 0 {
		t.Fatalf("expected stop() to release whatever was buffered, got %q", got)
	}
	// Reset() alone only zeroes length and keeps the existing backing array
	// allocated — checking length here wouldn't catch that regression, since
	// a Reset() buffer also reports len() == 0 while still holding memory.
	if capacity := capture.buf.Cap(); capacity != 0 {
		t.Fatalf("expected stop() to release the buffer's backing array (cap 0), got cap %d", capacity)
	}

	// Simulate a long-running successful session: many more "command
	// response" writes keep arriving on the same io.Writer after stop().
	large := bytes.Repeat([]byte("x"), 1<<20) // 1MiB per simulated response
	for i := 0; i < 50; i++ {
		if _, err := capture.Write(large); err != nil {
			t.Fatalf("write after stop (iteration %d): %v", i, err)
		}
	}
	if got := capture.bytes(); len(got) != 0 {
		t.Fatalf("expected writes after stop() to be silently dropped, buffer grew to %d bytes", len(got))
	}
	if capacity := capture.buf.Cap(); capacity != 0 {
		t.Fatalf("expected writes after stop() to never reallocate the backing array, got cap %d", capacity)
	}
}

// TestChannelDiagnosticCaptureBoundsSizeDuringSetupKeepingTheMostRecentBytes
// is the regression test for unbounded growth *during* the setup window
// itself (before stop() is ever called) — a device with an unusually large
// pre-auth banner/MOTD, or one that floods output before authentication,
// must not be able to grow this without limit just because the connection
// hasn't failed (or succeeded) yet. It also proves the bound trims from the
// front, not the back: the diagnostic recoverRacedChannelDiagnostic looks
// for is always the *last* thing written before the connection dies, so a
// naive "keep only the first maxCaptureBytes" bound would have thrown away
// exactly the part that matters whenever it's preceded by a large banner.
func TestChannelDiagnosticCaptureBoundsSizeDuringSetupKeepingTheMostRecentBytes(t *testing.T) {
	capture := newChannelDiagnosticCapture()

	oversizedBanner := bytes.Repeat([]byte("m"), maxCaptureBytes*3)
	if _, err := capture.Write(oversizedBanner); err != nil {
		t.Fatalf("write oversized banner: %v", err)
	}
	const diagnostic = "host key verification failed"
	if _, err := capture.Write([]byte(diagnostic)); err != nil {
		t.Fatalf("write diagnostic: %v", err)
	}

	got := capture.bytes()
	if len(got) > maxCaptureBytes {
		t.Fatalf("expected capture to stay bounded at %d bytes during setup, got %d", maxCaptureBytes, len(got))
	}
	if !bytes.Contains(got, []byte(diagnostic)) {
		t.Fatalf("expected the diagnostic (the most recently written bytes) to survive bounding behind an oversized banner, got %d bytes with none of them the diagnostic", len(got))
	}
	if capacity := capture.buf.Cap(); capacity > maxCaptureBytes {
		t.Fatalf("expected the backing array's capacity to stay bounded at maxCaptureBytes too, not grow to fit the whole oversized banner, got cap %d", capacity)
	}
}

// TestChannelDiagnosticCaptureStopIsSafeConcurrentWithWrites proves stop()
// can safely run while scrapligo's own channel-reader goroutine is still
// mid-write — exactly what connectWithProfile does, calling stop() the
// instant Open() returns with no guarantee the reader goroutine has already
// made its last write for that attempt — without a data race or panic.
func TestChannelDiagnosticCaptureStopIsSafeConcurrentWithWrites(t *testing.T) {
	capture := newChannelDiagnosticCapture()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			_, _ = capture.Write([]byte("x"))
		}
	}()
	capture.stop()
	<-done
}

// TestConnectDetectsARealHostKeyMismatchViaTheOSSSHBinary is the strongest
// available verification of the host-key-mismatch detection fix short of
// standing up a real sshd: it drives the actual production call path —
// Client.Connect, no dial/driver faking — against a real in-process
// golang.org/x/crypto/ssh server, so scrapligo's default "system" transport
// genuinely shells out to the real OS ssh binary and performs a real SSH
// handshake and a real host-key check against it. The known_hosts fixture
// binds the server's address to a different (stale) key than what it
// actually presents, so the real ssh process is expected to refuse and
// print "Host key verification failed." exactly as it would against a real
// mismatched device — proving both the exact error text scrapligo surfaces
// in production, and that hostkey.ClassifyConnectError correctly classifies
// that real error as a genuine mismatch rather than a hand-constructed
// stand-in for one.
func TestConnectDetectsARealHostKeyMismatchViaTheOSSSHBinary(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("real ssh binary not available on PATH")
	}

	host, port, _, passwordAttempted := startRealSSHServer(t)

	_, stalePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate stale key: %v", err)
	}
	staleSigner, err := cryptossh.NewSignerFromKey(stalePriv)
	if err != nil {
		t.Fatalf("stale signer: %v", err)
	}
	staleKey := staleSigner.PublicKey()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dir := t.TempDir()
	knownHostsFile := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHostsFile, []byte(knownhosts.Line([]string{addr}, staleKey)+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts fixture: %v", err)
	}

	client := NewClient(
		WithHostKeyPolicy("pinned", knownHostsFile),
		WithPort(port),
		WithConnectionTimeout(10*time.Second),
	)
	connErr := client.Connect(host, "testuser", "testpass", "cisco_iosxr")
	if connErr == nil {
		t.Fatal("expected a host-key mismatch error from the real ssh binary, got nil")
	}
	if !strings.Contains(strings.ToLower(connErr.Error()), "host key verification failed") {
		t.Fatalf("expected the real ssh binary to report a host key verification failure, got: %v", connErr)
	}
	if passwordAttempted.Load() {
		t.Fatal("expected the connection to abort at the host-key check, never reaching password authentication")
	}

	originalResolver := hostkey.KnownHostsFilesResolver
	hostkey.KnownHostsFilesResolver = func() ([]string, error) { return []string{knownHostsFile}, nil }
	t.Cleanup(func() { hostkey.KnownHostsFilesResolver = originalResolver })

	mismatch := hostkey.ClassifyConnectError(addr, connErr)
	if mismatch == nil {
		t.Fatalf("expected ClassifyConnectError to classify this real error as a mismatch, got nil for error: %v", connErr)
	}
	if mismatch.File != knownHostsFile {
		t.Fatalf("unexpected mismatch file: got %s want %s", mismatch.File, knownHostsFile)
	}
	if len(mismatch.OldKeys) != 1 || !bytes.Equal(mismatch.OldKeys[0].Marshal(), staleKey.Marshal()) {
		t.Fatal("expected OldKeys to hold the stale key recorded in the known_hosts fixture")
	}
}

type fakeSSHSession struct {
	output     []byte
	sendErr    error
	closeErr   error
	closePanic interface{}
	commands   []string
	closes     int
}

func (f *fakeSSHSession) SendInput(command string) ([]byte, error) {
	f.commands = append(f.commands, command)
	return f.output, f.sendErr
}

func (f *fakeSSHSession) Close() error {
	f.closes++
	if f.closePanic != nil {
		panic(f.closePanic)
	}
	return f.closeErr
}

func TestNormalizeSecurityProfileDefaultsToModern(t *testing.T) {
	profile, err := normalizeSecurityProfile("")
	if err != nil || profile != "modern" {
		t.Fatalf("unexpected default profile=%q error=%v", profile, err)
	}
	for _, value := range []string{"compatibility", "auto", "modern", "legacy"} {
		if _, err := normalizeSecurityProfile(value); err != nil {
			t.Fatalf("valid profile %q rejected: %v", value, err)
		}
	}
	if _, err := normalizeSecurityProfile("unsafe"); err == nil {
		t.Fatal("invalid profile accepted")
	}
}

func TestAlgorithmNegotiationErrorClassification(t *testing.T) {
	for _, message := range []string{"ssh: no common algorithm", "no matching key exchange method found", "unable to negotiate with host: no matching cipher"} {
		if !isAlgorithmNegotiationError(errors.New(message)) {
			t.Fatalf("negotiation error not recognized: %s", message)
		}
	}
	for _, message := range []string{"authentication failed", "host key mismatch", "i/o timeout", "connection refused"} {
		if isAlgorithmNegotiationError(errors.New(message)) {
			t.Fatalf("unsafe fallback classification for: %s", message)
		}
	}
}

func TestHostKeyPolicyValidation(t *testing.T) {
	for _, value := range []string{"", "insecure", "known_hosts"} {
		if _, err := normalizeHostKeyPolicy(value); err != nil {
			t.Fatalf("valid policy %q rejected: %v", value, err)
		}
	}
	if _, err := normalizeHostKeyPolicy("accept-new"); err == nil {
		t.Fatal("invalid policy accepted")
	}
}

func TestAutoProfileFallbackControlFlow(t *testing.T) {
	client := NewClient(WithSecurityProfile("auto"))
	profiles := []string{}
	client.connectProfile = func(_, _, _, _, profile, _ string) error {
		profiles = append(profiles, profile)
		if profile == "modern" {
			return errors.New("ssh: no common algorithm for key exchange")
		}
		return nil
	}
	if err := client.Connect("router", "user", "pass", "cisco_iosxr"); err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0] != "modern" || profiles[1] != "legacy" {
		t.Fatalf("unexpected profile attempts: %v", profiles)
	}
}

func TestAutoProfileDoesNotFallbackForSecurityOrTransportErrors(t *testing.T) {
	for _, message := range []string{"authentication failed", "host key mismatch", "i/o timeout", "connection refused"} {
		t.Run(message, func(t *testing.T) {
			client := NewClient(WithSecurityProfile("auto"))
			attempts := 0
			client.connectProfile = func(_, _, _, _, _, _ string) error { attempts++; return errors.New(message) }
			if err := client.Connect("router", "user", "pass", "cisco_iosxr"); err == nil {
				t.Fatal("expected connection error")
			}
			if attempts != 1 {
				t.Fatalf("unsafe fallback after %q: attempts=%d", message, attempts)
			}
		})
	}
}

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("expected new client instance")
	}
	if client.socketTimeout != 45*time.Second {
		t.Fatalf("expected default socket timeout 45s; got %v", client.socketTimeout)
	}
	if client.opsTimeout != 90*time.Second {
		t.Fatalf("expected default ops timeout 90s; got %v", client.opsTimeout)
	}
}

func TestNewClient_CustomOptions(t *testing.T) {
	connectTimeout := 10 * time.Second
	opsTimeout := 20 * time.Second
	client := NewClient(WithConnectionTimeout(connectTimeout), WithOperationTimeout(opsTimeout))

	if client.socketTimeout != connectTimeout {
		t.Fatalf("expected connection timeout %v; got %v", connectTimeout, client.socketTimeout)
	}
	if client.opsTimeout != opsTimeout {
		t.Fatalf("expected operation timeout %v; got %v", opsTimeout, client.opsTimeout)
	}
}

func TestConnectValidation(t *testing.T) {
	client := NewClient()
	err := client.Connect("", "user", "pass", "cisco_nxos")
	if err == nil {
		t.Fatal("expected error for empty host")
	}
	err = client.Connect("127.0.0.1", "", "pass", "cisco_nxos")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
	err = client.Connect("127.0.0.1", "user", "", "cisco_nxos")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
	err = client.Connect("127.0.0.1", "user", "pass", "")
	if err == nil {
		t.Fatal("expected error for empty driverName")
	}
}

func TestExecuteRoutesTrimmedCommandAndReturnsOutput(t *testing.T) {
	session := &fakeSSHSession{output: []byte("interface is up")}
	client := NewClient()
	client.network = session
	output, err := client.Execute("  show interfaces brief  ")
	if err != nil {
		t.Fatal(err)
	}
	if output != "interface is up" {
		t.Fatalf("output = %q", output)
	}
	if len(session.commands) != 1 || session.commands[0] != "show interfaces brief" {
		t.Fatalf("commands = %#v", session.commands)
	}
}

func TestExecuteEnforcesExactResponseBoundary(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, maxSSHResponseBytes+1)
	session := &fakeSSHSession{output: payload[:maxSSHResponseBytes]}
	client := NewClient()
	client.network = session

	if output, err := client.Execute("show exact-limit"); err != nil || len(output) != maxSSHResponseBytes {
		t.Fatalf("exact-limit response rejected: length=%d error=%v", len(output), err)
	}
	session.output = payload
	if output, err := client.Execute("show limit-plus-one"); err == nil ||
		!strings.Contains(err.Error(), "response exceeds") || output != "" {
		t.Fatalf("limit+1 response was not rejected cleanly: length=%d error=%v", len(output), err)
	}
}

func TestExecuteValidationAndDisconnectErrors(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Execute("show version"); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil execute error = %v", err)
	}
	client := NewClient()
	if _, err := client.Execute("show version"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("disconnected execute error = %v", err)
	}
	session := &fakeSSHSession{}
	client.network = session
	if _, err := client.Execute(" "); err == nil || !strings.Contains(err.Error(), "command is required") {
		t.Fatalf("empty execute error = %v", err)
	}
	session.sendErr = errors.New("remote side closed")
	if _, err := client.Execute("show version"); err == nil || !strings.Contains(err.Error(), "remote side closed") {
		t.Fatalf("disconnect error = %v", err)
	}
}

func TestCloseClearsStateOnDependencyErrorAndIsIdempotent(t *testing.T) {
	session := &fakeSSHSession{closeErr: errors.New("already closed")}
	client := NewClient()
	client.network = session
	err := client.Close()
	if err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("close error = %v", err)
	}
	if client.network != nil || client.platform != nil {
		t.Fatal("failed close retained stale SSH state")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
	if session.closes != 1 {
		t.Fatalf("close calls = %d, want 1", session.closes)
	}
}

func TestCloseRecoversDependencyPanicAndClearsState(t *testing.T) {
	session := &fakeSSHSession{closePanic: "double close"}
	client := NewClient()
	client.network = session
	err := client.Close()
	if err == nil || !strings.Contains(err.Error(), "panic while closing") {
		t.Fatalf("close panic error = %v", err)
	}
	if client.network != nil || client.platform != nil {
		t.Fatal("panic during close retained stale SSH state")
	}
}

func TestCloseNilAndSuccessfulSession(t *testing.T) {
	var nilClient *Client
	if err := nilClient.Close(); err != nil {
		t.Fatal(err)
	}
	client := NewClient()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	session := &fakeSSHSession{}
	client.network = session
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if session.closes != 1 || client.network != nil {
		t.Fatalf("successful close state: closes=%d network=%v", session.closes, client.network)
	}
}

func TestOptionNilReceiversAndSelectedProfile(t *testing.T) {
	var nilClient *Client
	for _, option := range []Option{
		WithSecurityProfile("legacy"),
		WithHostKeyPolicy("pinned", "known_hosts"),
		WithChannelLog(nil),
		WithConnectionTimeout(time.Second),
		WithOperationTimeout(time.Second),
		WithPasswordPattern(nil),
	} {
		option(nilClient)
	}
	if got := nilClient.SelectedSecurityProfile(); got != "" {
		t.Fatalf("nil selected profile = %q", got)
	}
	client := NewClient()
	client.selectedProfile = "modern"
	if got := client.SelectedSecurityProfile(); got != "modern" {
		t.Fatalf("selected profile = %q", got)
	}
}

// TestConnectSucceedsPastHostKeyCheckWhenKnownHostsMatches is the control
// for TestConnectDetectsARealHostKeyMismatchViaTheOSSSHBinary, proving the
// stale-key fixture is actually what drives that test's failure rather than
// every real connection through this path failing the same way regardless
// of known_hosts content. It's not enough to check that the resulting error
// merely lacks "host key verification failed" text — a connection-level
// failure unrelated to host keys (dropped connection, malformed handshake)
// would also lack that text without proving the host-key check itself ever
// passed. So this asserts the stronger, unambiguous signal instead: the
// server's PasswordCallback actually ran, meaning the real ssh binary's
// host-key check passed and authentication was genuinely attempted (and
// then rejected, since this test server always refuses password auth).
func TestConnectSucceedsPastHostKeyCheckWhenKnownHostsMatches(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("real ssh binary not available on PATH")
	}

	host, port, realKey, passwordAttempted := startRealSSHServer(t)

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dir := t.TempDir()
	knownHostsFile := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHostsFile, []byte(knownhosts.Line([]string{addr}, realKey)+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts fixture: %v", err)
	}

	client := NewClient(
		WithHostKeyPolicy("pinned", knownHostsFile),
		WithPort(port),
		WithConnectionTimeout(10*time.Second),
	)
	connErr := client.Connect(host, "testuser", "testpass", "cisco_iosxr")
	if connErr == nil {
		t.Fatal("expected an error (this test server always rejects password auth), got nil")
	}
	if !passwordAttempted.Load() {
		t.Fatalf("expected the host-key check to pass and password authentication to actually be attempted against a matching known_hosts entry, got error: %v", connErr)
	}
	if strings.Contains(strings.ToLower(connErr.Error()), "host key verification failed") {
		t.Fatalf("expected the host-key check to pass against a matching known_hosts entry, got: %v", connErr)
	}
}
