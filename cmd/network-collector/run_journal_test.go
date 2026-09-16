package main

import (
	"strings"
	"testing"
)

func TestRunManifestBindsResumeToConfigInventoryAndPlan(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/change.yaml"
	inventoryPath := dir + "/inventory.yaml"
	if err := atomicWriteFile(configPath, []byte("name_playbook: change\n")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(inventoryPath, []byte("hosts: []\n")); err != nil {
		t.Fatal(err)
	}
	config := Config{NamePlaybook: "change", InventoryFile: "inventory.yaml"}
	devices := []DeviceConfig{{Hostname: "edge-1", IP: "192.0.2.1", Steps: []StepConfig{{Name: "ensure-ntp", Ensure: &EnsureConfig{Resource: "ntp", State: "present"}}}}}
	if _, err := writeRunManifest(dir, "run-test", configPath, config, devices); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := verifyResumeManifest(dir, configPath, config, devices); err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
	if err := atomicWriteFile(configPath, []byte("name_playbook: changed-after-interruption\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyResumeManifest(dir, configPath, config, devices); err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("expected config digest mismatch, got %v", err)
	}
}

func TestJournalLeavesIncompleteMutationUncertain(t *testing.T) {
	journal, err := newRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	intent := runJournalEntry{State: "intent", Hostname: "edge-1", IP: "192.0.2.1", Step: "change-route", Occurrence: 0, Kind: "ssh_command"}
	if err := journal.append(intent); err != nil {
		t.Fatal(err)
	}
	uncertain, err := uncertainJournalEntries(strings.TrimSuffix(journal.path, "/"+runJournalFilename))
	if err != nil || len(uncertain) != 1 || uncertain[0].Step != "change-route" {
		t.Fatalf("uncertain entries = %#v, %v", uncertain, err)
	}
	if err := journal.append(runJournalEntry{State: "completed", Hostname: intent.Hostname, IP: intent.IP, Step: intent.Step, Occurrence: intent.Occurrence, Kind: intent.Kind}); err != nil {
		t.Fatal(err)
	}
	uncertain, err = uncertainJournalEntries(strings.TrimSuffix(journal.path, "/"+runJournalFilename))
	if err != nil || len(uncertain) != 0 {
		t.Fatalf("completed mutation remained uncertain: %#v, %v", uncertain, err)
	}
}

func TestResumableMutationKindIsConservative(t *testing.T) {
	if got := resumableMutationKind(StepConfig{NETCONF: &NETCONFStepConfig{Operation: "get-config"}}); got != "" {
		t.Fatalf("read-only NETCONF = %q", got)
	}
	if got := resumableMutationKind(StepConfig{Command: "show version"}); got != "ssh_command" {
		t.Fatalf("imperative SSH = %q", got)
	}
	if got := resumableMutationKind(StepConfig{Ensure: &EnsureConfig{}}); got != "ensure" {
		t.Fatalf("ensure = %q", got)
	}
}
