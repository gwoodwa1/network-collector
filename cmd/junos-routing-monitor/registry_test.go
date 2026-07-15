package main

import "testing"

func TestHostnameRegistryHasAndClaim(t *testing.T) {
	r := newHostnameRegistry()

	if exists, _ := r.has("pe-router-1"); exists {
		t.Fatal("expected hostname not to exist before claim")
	}
	r.claim("pe-router-1")
	if exists, existing := r.has("pe-router-1"); !exists || existing != "pe-router-1" {
		t.Fatalf("expected hostname to exist after claim, got exists=%v existing=%q", exists, existing)
	}
}

func TestHostnameRegistryCaseInsensitive(t *testing.T) {
	r := newHostnameRegistry()
	r.claim("PE-Router-1")

	exists, existing := r.has("pe-router-1")
	if !exists {
		t.Fatal("expected case-insensitive match to find the hostname")
	}
	if existing != "PE-Router-1" {
		t.Fatalf("expected original spelling %q, got %q", "PE-Router-1", existing)
	}
}

// TestHostnameRegistryMatchesFilenameSanitizationEquivalence guards against
// the registry treating two hostnames as distinct while sanitizeFilename
// (poll.go) would still write them to the same output file — that mismatch
// let two concurrent pollDevice goroutines race on the same .jsonl/.json
// file, which is exactly the corruption this registry exists to prevent.
func TestHostnameRegistryMatchesFilenameSanitizationEquivalence(t *testing.T) {
	r := newHostnameRegistry()
	r.claim("pe-router:1")

	for _, colliding := range []string{"pe-router/1", "pe-router 1", "pe-router_1", "PE-ROUTER:1"} {
		if exists, _ := r.has(colliding); !exists {
			t.Fatalf("expected %q to collide with already-claimed \"pe-router:1\" (both sanitize to %q), but has() reported it as free", colliding, sanitizeFilename(colliding))
		}
	}
}

func TestHostnameRegistryFailedAttemptRemainsClaimable(t *testing.T) {
	// A connection attempt that fails must never call claim, so the
	// hostname stays eligible for a later deliberate retry.
	r := newHostnameRegistry()
	if exists, _ := r.has("pe-router-1"); exists {
		t.Fatal("expected hostname not to exist before any claim")
	}
	// Simulate: has() checked, connect failed, claim() never called.
	if exists, _ := r.has("pe-router-1"); exists {
		t.Fatal("expected hostname to remain unclaimed after a simulated failed connection")
	}
}
