package main

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestCredentialCacheValid(t *testing.T) {
	cases := []struct {
		name string
		c    *credentialCache
		want bool
	}{
		{"nil cache", nil, false},
		{"never captured", &credentialCache{window: 45 * time.Second}, false},
		{"within window", &credentialCache{capturedAt: time.Now(), window: 45 * time.Second}, true},
		{"expired", &credentialCache{capturedAt: time.Now().Add(-time.Minute), window: 45 * time.Second}, false},
		{"reuse disabled (window 0)", &credentialCache{capturedAt: time.Now(), window: 0}, false},
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
		{"\n", false, "cached-user"},
		{"y\n", false, "cached-user"},
		{"yes\n", false, "cached-user"},
		{"garbage\n", false, "cached-user"},
		{"n\n", true, "bobuser"},
		{"N\n", true, "bobuser"},
		{"no\n", true, "bobuser"},
		{"NO\n", true, "bobuser"},
		{"No\n", true, "bobuser"},
	}
	for _, tc := range cases {
		t.Run(tc.answer, func(t *testing.T) {
			cache := &credentialCache{username: "cached-user", password: "cached-pass", capturedAt: time.Now(), window: 45 * time.Second}
			reader := bufio.NewReader(strings.NewReader(tc.answer + "bobuser\nbobpass\n"))
			username, _, fresh, err := resolveCredentials(reader, cache)
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
