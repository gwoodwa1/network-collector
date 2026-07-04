package ssh

import (
	"errors"
	"testing"
	"time"
)

func TestNormalizeSecurityProfileDefaultsToCompatibility(t *testing.T) {
	profile, err := normalizeSecurityProfile("")
	if err != nil || profile != "compatibility" {
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
