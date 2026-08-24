// Package monitorsetup holds the onboarding infrastructure shared by
// cmd/xr-routing-monitor, cmd/junos-routing-monitor, and cmd/routing-monitor
// (the mixed-fleet front-end): hostname deduplication, one-time-passcode
// reuse across devices, and output-folder/session-log setup. It is
// deliberately narrow — only pieces confirmed structurally identical across
// both platform tools live here; everything platform-specific (VRF/table
// auto-detection, command sets, parsers) stays in internal/xrmonitor and
// internal/junosmonitor.
package monitorsetup

import "strings"

// HostnameRegistry rejects a second onboarding attempt for a hostname
// already connected — from --devices, interactive onboarding, or a mix of
// both, and (for cmd/routing-monitor) across platforms too: the same
// hostname must not be claimed under both a cisco_iosxr and a
// juniper_junos section. Without this, two independent poll goroutines for
// the "same" device would append to the same <hostname>.jsonl and race on
// the same <hostname>-<label>.{txt,json} snapshot files. Onboarding is
// strictly sequential (single goroutine; both --devices and interactive
// processing, and for a mixed fleet both platform sections, happen one
// after another before any polling goroutine starts), so no locking is
// needed here.
type HostnameRegistry struct {
	seen map[string]string // normalized hostname -> first-seen original spelling
}

func NewHostnameRegistry() *HostnameRegistry {
	return &HostnameRegistry{seen: map[string]string{}}
}

// normalizeHostname must treat two hostnames as the same device whenever
// SanitizeFilename would write them to the same output file — otherwise two
// "distinct" registry entries can still race on one .jsonl/.json/.txt file,
// which is exactly the corruption this registry exists to prevent. It
// reuses SanitizeFilename itself rather than its own separate equivalence
// rule so the two can never drift apart again.
func normalizeHostname(host string) string {
	return strings.ToLower(SanitizeFilename(host))
}

// SanitizeFilename replaces filesystem-hostile characters in a hostname (or
// any other string destined for a filename) with underscores. Duplicated
// (rather than imported) into each of internal/xrmonitor and
// internal/junosmonitor for their own output-filename construction — this
// copy exists specifically so HostnameRegistry's equivalence rule can never
// drift out of sync with theirs; keep all three identical if this ever
// changes.
func SanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", " ", "_")
	return replacer.Replace(strings.TrimSpace(name))
}

// Has reports whether host (case-insensitively) already has a successfully
// connected session, returning the original spelling it was first claimed
// with. It does not mutate the registry — callers should still call Claim
// after a successful connection. Checking before connecting lets onboarding
// skip a known duplicate without wasting a one-time-passcode attempt; not
// claiming until success means a hostname whose connection attempt failed
// remains eligible for a later deliberate retry.
func (r *HostnameRegistry) Has(host string) (exists bool, existing string) {
	original, ok := r.seen[normalizeHostname(host)]
	return ok, original
}

// Claim records host as successfully connected.
func (r *HostnameRegistry) Claim(host string) {
	r.seen[normalizeHostname(host)] = host
}
