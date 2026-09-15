package monitorsetup

import (
	"fmt"

	"github.com/gwoodwa1/network-collector/internal/safeyaml"
)

// LoadTACACSTimeoutReminders reads the optional top-level YAML schedule shared
// by the monitor tools. Validation is performed by monitoring when installing
// it into the run context, keeping the package independent from the monitor
// implementation.
func LoadTACACSTimeoutReminders(path string) ([]int, error) {
	if path == "" {
		return nil, nil
	}
	b, err := safeyaml.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Reminders []int `yaml:"tacacs_timeout_reminder"`
	}
	if err := safeyaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc.Reminders, nil
}
