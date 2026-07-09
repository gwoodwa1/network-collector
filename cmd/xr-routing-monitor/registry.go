package main

import "strings"

// hostnameRegistry rejects a second onboarding attempt for a hostname
// already connected — from --devices, interactive onboarding, or a mix of
// both. Without this, two independent pollDevice goroutines for the "same"
// device would append to the same <hostname>.jsonl and race on the same
// <hostname>-<label>.{txt,json} snapshot files (the latter written via
// os.WriteFile, i.e. last-writer-wins with no atomicity between the two
// writers at all). Onboarding is strictly sequential (single goroutine,
// both --devices and interactive processing happen one after another before
// any polling goroutine starts), so no locking is needed here.
type hostnameRegistry struct {
	seen map[string]string // normalized hostname -> first-seen original spelling
}

func newHostnameRegistry() *hostnameRegistry {
	return &hostnameRegistry{seen: map[string]string{}}
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// has reports whether host (case-insensitively) already has a successfully
// connected session, returning the original spelling it was first claimed
// with. It does not mutate the registry — callers should still call claim
// after a successful connection. Checking before connecting lets onboarding
// skip a known duplicate without wasting an RSA passcode attempt; not
// claiming until success means a hostname whose connection attempt failed
// remains eligible for a later deliberate retry (see connectDevice's "no
// automatic retry" note — this is what makes that manual retry possible).
func (r *hostnameRegistry) has(host string) (exists bool, existing string) {
	original, ok := r.seen[normalizeHostname(host)]
	return ok, original
}

// claim records host as successfully connected.
func (r *hostnameRegistry) claim(host string) {
	r.seen[normalizeHostname(host)] = host
}
