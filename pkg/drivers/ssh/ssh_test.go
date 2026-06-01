package ssh

import (
	"testing"
	"time"
)

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
