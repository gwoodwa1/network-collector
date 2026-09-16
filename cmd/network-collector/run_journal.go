package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

const (
	runManifestFilename = "run-manifest.json"
	runJournalFilename  = "run-journal.jsonl"
)

// runManifest binds a resumable run to the exact resolved scope. Digests are
// deliberately over public configuration only; credentials and command output
// never enter this file.
type runManifest struct {
	FormatVersion   int       `json:"format_version"`
	RunID           string    `json:"run_id"`
	CreatedAt       time.Time `json:"created_at"`
	ConfigDigest    string    `json:"config_digest"`
	InventoryDigest string    `json:"inventory_digest,omitempty"`
	PlanDigest      string    `json:"plan_digest"`
}

// runJournalEntry is append-only write-ahead state. An intent without a later
// completed record is uncertain, which is the only safe interpretation after
// process loss or an interrupted transport.
type runJournalEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	State      string    `json:"state"`
	Hostname   string    `json:"hostname"`
	IP         string    `json:"ip"`
	Step       string    `json:"step"`
	Occurrence int       `json:"occurrence"`
	Kind       string    `json:"kind,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

type runJournal struct {
	mu   sync.Mutex
	path string
}

func newRunJournal(runDir string) (*runJournal, error) {
	if strings.TrimSpace(runDir) == "" {
		return nil, fmt.Errorf("resumable runs require an output directory")
	}
	path, err := resolveWriteWithin(runDir, runJournalFilename)
	if err != nil {
		return nil, err
	}
	return &runJournal{path: path}, nil
}

func (j *runJournal) append(entry runJournalEntry) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := secureartifact.EnsureDir(filepath.Dir(j.path)); err != nil {
		return err
	}
	file, err := secureartifact.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func fileDigest(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeRunManifest(runDir, runID, configFile string, config Config, devices []DeviceConfig) (runManifest, error) {
	configDigest, err := fileDigest(configFile)
	if err != nil {
		return runManifest{}, fmt.Errorf("digest config: %w", err)
	}
	inventoryPath := strings.TrimSpace(config.InventoryFile)
	if inventoryPath != "" {
		inventoryPath = resolveInventoryPath(inventoryPath, configFile)
	}
	inventoryDigest, err := fileDigest(inventoryPath)
	if err != nil {
		return runManifest{}, fmt.Errorf("digest inventory: %w", err)
	}
	plan := buildOfflinePlan(config, devices)
	manifest := runManifest{FormatVersion: 1, RunID: runID, CreatedAt: time.Now().UTC(), ConfigDigest: configDigest, InventoryDigest: inventoryDigest, PlanDigest: plan.ResolutionDigest}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return runManifest{}, err
	}
	path, err := resolveWriteWithin(runDir, runManifestFilename)
	if err != nil {
		return runManifest{}, err
	}
	if err := atomicWriteFile(path, append(encoded, '\n')); err != nil {
		return runManifest{}, err
	}
	return manifest, nil
}

func loadRunManifest(runDir string) (runManifest, error) {
	path, err := resolveWriteWithin(runDir, runManifestFilename)
	if err != nil {
		return runManifest{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return runManifest{}, err
	}
	var manifest runManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return runManifest{}, err
	}
	if manifest.FormatVersion != 1 || manifest.RunID == "" || manifest.ConfigDigest == "" || manifest.PlanDigest == "" {
		return runManifest{}, fmt.Errorf("invalid run manifest")
	}
	return manifest, nil
}

func verifyResumeManifest(runDir, configFile string, config Config, devices []DeviceConfig) (runManifest, error) {
	manifest, err := loadRunManifest(runDir)
	if err != nil {
		return runManifest{}, fmt.Errorf("load resume manifest: %w", err)
	}
	configDigest, err := fileDigest(configFile)
	if err != nil {
		return runManifest{}, err
	}
	inventoryPath := strings.TrimSpace(config.InventoryFile)
	if inventoryPath != "" {
		inventoryPath = resolveInventoryPath(inventoryPath, configFile)
	}
	inventoryDigest, err := fileDigest(inventoryPath)
	if err != nil {
		return runManifest{}, err
	}
	actualPlan := buildOfflinePlan(config, devices).ResolutionDigest
	differences := []string{}
	if manifest.ConfigDigest != configDigest {
		differences = append(differences, "config")
	}
	if manifest.InventoryDigest != inventoryDigest {
		differences = append(differences, "inventory")
	}
	if manifest.PlanDigest != actualPlan {
		differences = append(differences, "plan")
	}
	if len(differences) > 0 {
		return runManifest{}, fmt.Errorf("resume manifest does not match current %s digest(s)", strings.Join(differences, ", "))
	}
	return manifest, nil
}

func uncertainJournalEntries(runDir string) ([]runJournalEntry, error) {
	path, err := resolveWriteWithin(runDir, runJournalFilename)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries := map[string]runJournalEntry{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry runJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode run journal: %w", err)
		}
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%d", entry.Hostname, entry.IP, entry.Step, entry.Occurrence)
		switch entry.State {
		case "intent":
			entries[key] = entry
		case "completed":
			delete(entries, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	uncertain := make([]runJournalEntry, 0, len(entries))
	for _, entry := range entries {
		uncertain = append(uncertain, entry)
	}
	sort.Slice(uncertain, func(i, k int) bool {
		return uncertain[i].Hostname+uncertain[i].Step < uncertain[k].Hostname+uncertain[k].Step
	})
	return uncertain, nil
}

func journalEntryKey(entry runJournalEntry) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", entry.Hostname, entry.IP, entry.Step, entry.Occurrence)
}

func completedJournalEntries(runDir string) (map[string]bool, error) {
	path, err := resolveWriteWithin(runDir, runJournalFilename)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	completed := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry runJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode run journal: %w", err)
		}
		if entry.State == "completed" {
			completed[journalEntryKey(entry)] = true
		}
	}
	return completed, scanner.Err()
}

// resumableMutationKind is intentionally conservative. Any imperative SSH
// command is treated as a mutation because its safety cannot be inferred from
// vendor syntax. Read-only NETCONF operations do not need a write-ahead
// record; all other NETCONF actions and declarative ensure operations do.
func resumableMutationKind(step StepConfig) string {
	if step.Ensure != nil {
		return "ensure"
	}
	if step.NETCONF != nil {
		op := strings.ToLower(strings.TrimSpace(step.NETCONF.Operation))
		if op == "get" || op == "get-config" || op == "validate" {
			return ""
		}
		return "netconf"
	}
	if strings.TrimSpace(step.Command) != "" {
		return "ssh_command"
	}
	return ""
}
