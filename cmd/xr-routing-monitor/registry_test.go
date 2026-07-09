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
