package main

import (
	"bufio"
	"strings"
	"testing"
)

// fakeConnect simulates connectDevice's contract for onboarding tests
// without a real SSH/NETCONF connection: it records which netconfSnapshot
// value each host was called with, and returns a NETCONF client only when
// netconfFailsFor doesn't name the host — mirroring connectDevice's real
// behavior of a failed NETCONF dial never failing the SSH connection or the
// device's onboarding overall (see connectDevice's doc comment).
type fakeConnect struct {
	netconfFailsFor map[string]bool
	calls           map[string]bool // host -> netconfSnapshot value it was called with
}

func (f *fakeConnect) connect(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *credentialCache) (sessionExecutor, sessionExecutor, error) {
	if f.calls == nil {
		f.calls = map[string]bool{}
	}
	f.calls[host] = netconfSnapshot
	client := &genericFakeExecutor{}
	if !netconfSnapshot || f.netconfFailsFor[host] {
		return client, nil, nil
	}
	return client, &genericFakeExecutor{}, nil
}

// TestOnboardDevicesFromSpecsThreadsPerDeviceNetconfSnapshotOverride proves
// each device's resolvedNetconfSnapshot (fleet default vs. per-device
// override) is what actually reaches connect, and that the resulting
// deviceSession.netconfClient reflects it.
func TestOnboardDevicesFromSpecsThreadsPerDeviceNetconfSnapshotOverride(t *testing.T) {
	specs := []deviceSpec{
		{Hostname: "pe-router-1"},                                  // inherits fleet default (true)
		{Hostname: "pe-router-2", NetconfSnapshot: boolPtr(false)}, // opts out
	}
	fake := &fakeConnect{}
	registry := newHostnameRegistry()
	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "juniper_junos", true, &credentialCache{}, registry, fake.connect)

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if !fake.calls["pe-router-1"] {
		t.Fatalf("expected pe-router-1 to inherit the fleet default (true), got calls=%v", fake.calls)
	}
	if fake.calls["pe-router-2"] {
		t.Fatalf("expected pe-router-2's explicit override (false) to win, got calls=%v", fake.calls)
	}
	byHost := map[string]*deviceSession{}
	for _, s := range sessions {
		byHost[s.hostname] = s
	}
	if byHost["pe-router-1"].netconfClient == nil {
		t.Fatal("expected pe-router-1 to have a NETCONF client (fleet default true, dial succeeds)")
	}
	if byHost["pe-router-2"].netconfClient != nil {
		t.Fatal("expected pe-router-2 to have no NETCONF client (opted out)")
	}
}

// TestOnboardDevicesFromSpecsNetconfDialFailureStillProducesSession proves
// a NETCONF dial failure degrades gracefully: the device still gets a
// working session (SSH client set), just with netconfClient left nil,
// rather than the whole device being skipped the way an SSH failure would
// skip it.
func TestOnboardDevicesFromSpecsNetconfDialFailureStillProducesSession(t *testing.T) {
	specs := []deviceSpec{{Hostname: "pe-router-1"}}
	fake := &fakeConnect{netconfFailsFor: map[string]bool{"pe-router-1": true}}
	registry := newHostnameRegistry()
	sessions := onboardDevicesFromSpecs(bufio.NewReader(strings.NewReader("")), specs, "juniper_junos", true, &credentialCache{}, registry, fake.connect)

	if len(sessions) != 1 {
		t.Fatalf("expected the device to still onboard despite the NETCONF dial failure, got %d sessions", len(sessions))
	}
	if sessions[0].client == nil {
		t.Fatal("expected the SSH client to still be set")
	}
	if sessions[0].netconfClient != nil {
		t.Fatal("expected netconfClient to be nil after a simulated NETCONF dial failure")
	}
}
