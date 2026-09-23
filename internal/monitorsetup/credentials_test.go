package monitorsetup

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestCredentialCacheValid(t *testing.T) {
	cases := []struct {
		name string
		c    *CredentialCache
		want bool
	}{
		{"nil cache", nil, false},
		{"never captured", &CredentialCache{Window: 45 * time.Second}, false},
		{"within window", &CredentialCache{capturedAt: time.Now(), Window: 45 * time.Second}, true},
		{"expired", &CredentialCache{capturedAt: time.Now().Add(-time.Minute), Window: 45 * time.Second}, false},
		{"reuse disabled (window 0)", &CredentialCache{capturedAt: time.Now(), Window: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.valid(); got != tc.want {
				t.Fatalf("valid() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolveCredentialsReusePromptHandlesNoVariants guards against a
// regression of the "reuse cached passcode? [Y/n]" prompt only recognizing a
// bare "n" as decline: answering the natural word "no" (in any case) must
// also decline reuse and prompt fresh, or a stale/rejected passcode gets
// silently reused against the next device.
func TestResolveCredentialsReusePromptHandlesNoVariants(t *testing.T) {
	cases := []struct {
		answer    string
		wantFresh bool
		wantUser  string
	}{
		{"\n", true, "bobuser"},
		{"y\n", false, "cached-user"},
		{"yes\n", false, "cached-user"},
		{"n\n", true, "bobuser"},
		{"N\n", true, "bobuser"},
		{"no\n", true, "bobuser"},
		{"NO\n", true, "bobuser"},
		{"No\n", true, "bobuser"},
	}
	for _, tc := range cases {
		t.Run(tc.answer, func(t *testing.T) {
			cache := &CredentialCache{username: "cached-user", password: "cached-pass", capturedAt: time.Now(), Window: 45 * time.Second}
			reader := bufio.NewReader(strings.NewReader(tc.answer + "bobuser\nbobpass\n"))
			username, _, fresh, err := ResolveCredentials(reader, cache, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fresh != tc.wantFresh {
				t.Fatalf("fresh = %v, want %v", fresh, tc.wantFresh)
			}
			if username != tc.wantUser {
				t.Fatalf("username = %q, want %q", username, tc.wantUser)
			}
		})
	}
}

// TestCredentialCacheRecordSuccessThenFailureInvalidatesButKeepsWindow
// proves the cross-platform reuse contract cmd/routing-monitor depends on:
// a successful capture is reusable until a failed connection wipes it, and
// wiping preserves Window rather than disabling reuse entirely.
func TestCredentialCacheRecordSuccessThenFailureInvalidatesButKeepsWindow(t *testing.T) {
	cache := NewCredentialCache(45 * time.Second)
	cache.RecordSuccess("alice", "s3cret")
	if !cache.valid() {
		t.Fatal("expected the cache to be valid immediately after a successful capture")
	}
	cache.RecordFailure()
	if cache.valid() {
		t.Fatal("expected a failed connection attempt to invalidate the cache")
	}
	if cache.Window != 45*time.Second {
		t.Fatalf("expected Window preserved across RecordFailure, got %v", cache.Window)
	}
}

func TestCredentialCacheRecordSuccessOnNilIsNoop(t *testing.T) {
	var cache *CredentialCache
	cache.RecordSuccess("alice", "s3cret") // must not panic
	cache.RecordFailure()                  // must not panic
}

// TestResolveCredentialsKeepsUsernameAfterASuccessfulConnection covers the
// actual multi-device scenario this is for: device 1 connects successfully,
// then device 2's passcode is rejected or has expired (RecordFailure). The
// next prompt should still default to "alice" (via RecordSuccess), so the
// operator only has to press Enter and type a fresh passcode. Window: 0
// disables the separate full-credential-reuse prompt so this isolates just
// the username-stickiness behavior.
func TestResolveCredentialsKeepsUsernameAfterASuccessfulConnection(t *testing.T) {
	cache := NewCredentialCache(0)

	reader := bufio.NewReader(strings.NewReader("alice\nfirstpasscode\n"))
	username, password, fresh, err := ResolveCredentials(reader, cache, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fresh || username != "alice" || password != "firstpasscode" {
		t.Fatalf("unexpected first prompt result: fresh=%v username=%q password=%q", fresh, username, password)
	}
	cache.RecordSuccess(username, password) // device 1 actually connected
	cache.RecordFailure()                   // device 2's passcode was rejected as expired

	// A blank line accepts the offered default ("alice"); only the passcode
	// needs to be typed for real.
	reader2 := bufio.NewReader(strings.NewReader("\nnewpasscode\n"))
	username2, password2, fresh2, err := ResolveCredentials(reader2, cache, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fresh2 || username2 != "alice" || password2 != "newpasscode" {
		t.Fatalf("unexpected second prompt result: fresh=%v username=%q password=%q", fresh2, username2, password2)
	}
}

// TestResolveCredentialsDoesNotStickAUsernameThatNeverConnected guards the
// regression this was written for: an operator mistakenly types a passcode
// into the username field (the read succeeds — it's just text — but the
// device connection then fails). That bad value must never be offered as
// the default on the next device; only a username that actually
// authenticated (RecordSuccess) gets remembered.
func TestResolveCredentialsDoesNotStickAUsernameThatNeverConnected(t *testing.T) {
	cache := NewCredentialCache(0)

	reader := bufio.NewReader(strings.NewReader("91896774\n\n"))
	username, _, fresh, err := ResolveCredentials(reader, cache, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fresh || username != "91896774" {
		t.Fatalf("unexpected first prompt result: fresh=%v username=%q", fresh, username)
	}
	cache.RecordFailure() // the device connection failed with that bad username

	reader2 := bufio.NewReader(strings.NewReader("mretz1\ngoodpasscode\n"))
	username2, _, _, err := ResolveCredentials(reader2, cache, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username2 != "mretz1" {
		t.Fatalf("expected a fresh username prompt with no poisoned default, got %q", username2)
	}
}
