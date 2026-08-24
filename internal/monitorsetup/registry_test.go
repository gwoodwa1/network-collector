package monitorsetup

import "testing"

func TestHostnameRegistryHasAndClaim(t *testing.T) {
	r := NewHostnameRegistry()
	if exists, _ := r.Has("router-1"); exists {
		t.Fatal("expected an unclaimed hostname to report not-exists")
	}
	r.Claim("router-1")
	exists, existing := r.Has("router-1")
	if !exists || existing != "router-1" {
		t.Fatalf("expected router-1 claimed, got exists=%v existing=%q", exists, existing)
	}
}

func TestHostnameRegistryCaseInsensitive(t *testing.T) {
	r := NewHostnameRegistry()
	r.Claim("Router-1")
	exists, existing := r.Has("router-1")
	if !exists || existing != "Router-1" {
		t.Fatalf("expected case-insensitive match returning original spelling, got exists=%v existing=%q", exists, existing)
	}
}

// TestHostnameRegistryCrossPlatformDedup proves the registry doesn't care
// which platform claimed a hostname first — this is exactly the property
// cmd/routing-monitor needs to catch the same hostname listed under both a
// cisco_iosxr and a juniper_junos section.
func TestHostnameRegistryCrossPlatformDedup(t *testing.T) {
	r := NewHostnameRegistry()
	r.Claim("pe-router-1")
	if exists, _ := r.Has("pe-router-1"); !exists {
		t.Fatal("expected the second platform's onboarding pass to see the first platform's claim")
	}
}

func TestHostnameRegistryMatchesSanitizeFilenameEquivalence(t *testing.T) {
	r := NewHostnameRegistry()
	r.Claim("router one:mgmt")
	if exists, _ := r.Has("Router One:Mgmt"); !exists {
		t.Fatal("expected hostnames equivalent after SanitizeFilename+lowercasing to be treated as the same device")
	}
}
