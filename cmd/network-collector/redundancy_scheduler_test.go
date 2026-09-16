package main

import (
	"sync"
	"testing"
	"time"
)

func TestSerialByFailureDomainPreventsConcurrentDomainWork(t *testing.T) {
	devices := []DeviceConfig{
		{Hostname: "a1", FailureDomain: "pair-a"}, {Hostname: "a2", FailureDomain: "pair-a"},
		{Hostname: "b1", FailureDomain: "pair-b"},
	}
	var mu sync.Mutex
	active := map[string]int{}
	maxActive := map[string]int{}
	runner := func(_ int, device DeviceConfig) deviceRunResult {
		mu.Lock()
		active[device.FailureDomain]++
		if active[device.FailureDomain] > maxActive[device.FailureDomain] {
			maxActive[device.FailureDomain] = active[device.FailureDomain]
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		active[device.FailureDomain]--
		mu.Unlock()
		return deviceRunResult{}
	}
	if _, stopped := runScheduledDevices(devices, ExecutionConfig{MaxParallel: 3, SerialBy: "failure_domain"}, runner); stopped {
		t.Fatal("scheduler stopped")
	}
	if maxActive["pair-a"] != 1 {
		t.Fatalf("same failure domain ran concurrently: %d", maxActive["pair-a"])
	}
}

func TestValidateSerialDomainsRequiresExplicitInventoryMetadata(t *testing.T) {
	if err := validateSerialDomains([]DeviceConfig{{Hostname: "edge-1"}}, "ha_pair"); err == nil {
		t.Fatal("missing ha_pair was accepted")
	}
	if err := validateSerialDomains([]DeviceConfig{{Hostname: "edge-1", HAPair: "edge"}}, "ha_pair"); err != nil {
		t.Fatal(err)
	}
}
