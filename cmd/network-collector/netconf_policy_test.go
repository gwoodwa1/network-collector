package main

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
)

func captureNETCONFConnect(t *testing.T, executor *lazyNETCONFExecutor) netconfConnectionPolicy {
	t.Helper()
	var captured netconfConnectionPolicy
	executor.connectClient = func(host, username, password string, policy netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error) {
		if host != "192.0.2.10" || username != "collector" || password != "secret" {
			t.Fatalf("unexpected connector identity: host=%q username=%q password=%q", host, username, password)
		}
		captured = policy
		return &netconf.ScrapligoNETCONF{}, nil
	}
	if err := executor.connect(); err != nil {
		t.Fatal(err)
	}
	return captured
}

func assertNETCONFPolicy(t *testing.T, got, want netconfConnectionPolicy) {
	t.Helper()
	if got != want {
		t.Fatalf("connector policy = %+v, want %+v", got, want)
	}
}

func TestSequentialAndParallelNETCONFFinalConnectorReceiveEffectivePolicy(t *testing.T) {
	device := DeviceConfig{
		OperationTimeout: 47,
		SSHSecurity: &SSHSecurityConfig{
			HostKeyPolicy:  "known_hosts",
			KnownHostsFile: "/etc/network-collector/device-known-hosts",
		},
	}
	policy := effectiveNETCONFPolicy(SSHSecurityConfig{
		HostKeyPolicy:  "known_hosts",
		KnownHostsFile: "/etc/network-collector/global-known-hosts",
	}, device)
	want := netconfConnectionPolicy{
		timeout:        47 * time.Second,
		hostKeyPolicy:  "known_hosts",
		knownHostsFile: "/etc/network-collector/device-known-hosts",
	}

	sequential := newLazyNETCONFExecutor("192.0.2.10", "collector", "secret", policy)
	assertNETCONFPolicy(t, captureNETCONFConnect(t, sequential), want)

	parallel := newParallelNETCONFExecutor(&stepExecutionContext{
		ip: "192.0.2.10", username: "collector", password: "secret", netconfPolicy: policy,
	})
	assertNETCONFPolicy(t, captureNETCONFConnect(t, parallel), want)
}

func TestNestedParallelNETCONFLeafReceivesEffectivePolicyAtFinalConnector(t *testing.T) {
	var log bytes.Buffer
	ctx, failed := newControlTestContext(t, &log, map[string]string{})
	ctx.ip = "192.0.2.10"
	ctx.username = "collector"
	ctx.password = "secret"
	ctx.netconfPolicy = netconfConnectionPolicy{
		timeout:        53 * time.Second,
		hostKeyPolicy:  "known_hosts",
		knownHostsFile: "/etc/network-collector/nested-known-hosts",
	}
	var mu sync.Mutex
	var captured []netconfConnectionPolicy
	ctx.netconfConnector = func(host, username, password string, policy netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error) {
		if host != ctx.ip || username != ctx.username || password != ctx.password {
			t.Errorf("unexpected connector identity: host=%q username=%q password=%q", host, username, password)
		}
		mu.Lock()
		captured = append(captured, policy)
		mu.Unlock()
		return nil, errors.New("test connector stopped before network dial")
	}

	step := StepConfig{Name: "outer", Parallel: &ParallelConfig{Steps: []StepConfig{{
		Name: "inner", Parallel: &ParallelConfig{Steps: []StepConfig{{
			Name: "leaf",
			NETCONF: &NETCONFStepConfig{
				Operation: "rpc",
				Payload:   "<get/>",
			},
		}}},
	}}}}
	executeSteps(ctx, nil, []StepConfig{step})

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 1 {
		t.Fatalf("final connector calls = %d, want 1", len(captured))
	}
	assertNETCONFPolicy(t, captured[0], ctx.netconfPolicy)
	if !*failed {
		t.Fatal("test connector error did not fail the nested leaf")
	}
}
