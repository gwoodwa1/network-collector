package monitorsetup

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestReuseRejectsEOFAndUnrecognisedInput(t *testing.T) {
	for _, answer := range []string{"", "yes", "garbage\n"} {
		cache := NewCredentialCache(time.Minute)
		cache.RecordSuccess("operator", "synthetic-passcode")
		u, p, _, err := ResolveCredentials(bufio.NewReader(strings.NewReader(answer)), cache)
		if err == nil || u != "" || p != "" || cache.valid() {
			t.Fatalf("input %q did not fail closed", answer)
		}
	}
}

type expiringConsent struct {
	cache *CredentialCache
	input *strings.Reader
}

func (r expiringConsent) Read(p []byte) (int, error) {
	r.cache.capturedAt = time.Now().Add(-2 * time.Minute)
	return r.input.Read(p)
}

func TestReuseRechecksExpiryAfterConsent(t *testing.T) {
	cache := NewCredentialCache(time.Minute)
	cache.RecordSuccess("operator", "old-passcode")
	reader := bufio.NewReader(expiringConsent{cache, strings.NewReader("yes\noperator\nfresh-passcode\n")})
	u, p, fresh, err := ResolveCredentials(reader, cache)
	if err != nil || !fresh || u != "operator" || p != "fresh-passcode" {
		t.Fatalf("expired credential was reused: fresh=%v err=%v", fresh, err)
	}
}
