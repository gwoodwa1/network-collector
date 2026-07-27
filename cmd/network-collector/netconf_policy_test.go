package main

import (
	"testing"
	"time"
)

func TestLazyNETCONFExecutorPreservesConnectionPolicy(t *testing.T) {
	policy := netconfConnectionPolicy{
		timeout:        47 * time.Second,
		hostKeyPolicy:  "known_hosts",
		knownHostsFile: "/etc/network-collector/known_hosts",
	}
	executor := newLazyNETCONFExecutor("192.0.2.10", "collector", "secret", policy)

	if executor.timeout != policy.timeout {
		t.Fatalf("timeout = %s, want %s", executor.timeout, policy.timeout)
	}
	if executor.hostKeyPolicy != policy.hostKeyPolicy {
		t.Fatalf("host-key policy = %q, want %q", executor.hostKeyPolicy, policy.hostKeyPolicy)
	}
	if executor.knownHostsFile != policy.knownHostsFile {
		t.Fatalf("known-hosts file = %q, want %q", executor.knownHostsFile, policy.knownHostsFile)
	}
}
