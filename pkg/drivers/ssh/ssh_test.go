package ssh

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

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
