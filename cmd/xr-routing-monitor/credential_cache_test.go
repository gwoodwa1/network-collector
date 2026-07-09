package main

import (
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
