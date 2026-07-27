package netconf

import (
	"strings"
	"testing"
	"time"
)

func TestValidationAndLifecycleErrors(t *testing.T) {
	var nilClient *ScrapligoNETCONF
	if err := nilClient.Connect("host", "user", "pass"); err == nil {
		t.Fatal("nil client connect accepted")
	}
	client := &ScrapligoNETCONF{}
	tests := []struct{ host, user, pass, want string }{{"", "user", "pass", "host is required"}, {"host", "", "pass", "username is required"}, {"host", "user", "", "password is required"}}
	for _, tc := range tests {
		if err := client.Connect(tc.host, tc.user, tc.pass); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("Connect error=%v want=%q", err, tc.want)
		}
	}
	if _, err := client.Execute("<get/>"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if _, err := client.EditConfig("candidate", "<config/>"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected edit-config error: %v", err)
	}
	if _, err := client.Commit(false, 0); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected commit error: %v", err)
	}
	if _, err := client.DiscardChanges(); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected discard-changes error: %v", err)
	}
	operations := []struct {
		name string
		call func() error
	}{
		{name: "lock", call: func() error { _, err := client.Lock("candidate"); return err }},
		{name: "unlock", call: func() error { _, err := client.Unlock("candidate"); return err }},
		{name: "validate", call: func() error { _, err := client.Validate("candidate"); return err }},
		{name: "get-config", call: func() error { _, err := client.GetConfig("running", ""); return err }},
		{name: "copy-config", call: func() error { _, err := client.CopyConfig("running", "startup"); return err }},
		{name: "delete-config", call: func() error { _, err := client.DeleteConfig("startup"); return err }},
		{name: "cancel-commit", call: func() error { _, err := client.CancelCommit("change-1"); return err }},
	}
	for _, operation := range operations {
		if err := operation.call(); err == nil || !strings.Contains(err.Error(), "not connected") {
			t.Fatalf("unexpected %s error: %v", operation.name, err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close disconnected client: %v", err)
	}
	if err := nilClient.Close(); err != nil {
		t.Fatalf("close nil client: %v", err)
	}
}

func TestTimeoutOptions(t *testing.T) {
	client := &ScrapligoNETCONF{}
	WithNetconfTimeouts(3*time.Second, 7*time.Second)(client)
	if client.socketTimeout != 3*time.Second || client.opsTimeout != 7*time.Second {
		t.Fatalf("timeouts not applied: socket=%s ops=%s", client.socketTimeout, client.opsTimeout)
	}
	WithNetconfTimeouts(0, 0)(client)
	if client.socketTimeout != 3*time.Second || client.opsTimeout != 7*time.Second {
		t.Fatal("non-positive timeout unexpectedly replaced values")
	}
}
