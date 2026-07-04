package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

type deviceSelector func(DeviceConfig) bool

func orchestrationTarget(device DeviceConfig) orchestrator.Target {
	return orchestrator.Target{
		Hostname: device.Hostname,
		IP:       device.IP,
		Platform: device.Type,
		Labels:   device.Labels,
	}
}

func parseDeviceSelector(input string) (deviceSelector, error) {
	selector, err := orchestrator.CompileSelector(input)
	if err != nil || selector == nil {
		return nil, err
	}
	return func(device DeviceConfig) bool { return selector(orchestrationTarget(device)) }, nil
}

func filterDevices(devices []DeviceConfig, include, exclude deviceSelector, replay map[string]bool) []DeviceConfig {
	filtered := make([]DeviceConfig, 0, len(devices))
	for _, device := range devices {
		if include != nil && !include(device) {
			continue
		}
		if exclude != nil && exclude(device) {
			continue
		}
		if replay != nil && !replay[device.Hostname] && !replay[device.IP] {
			continue
		}
		filtered = append(filtered, device)
	}
	return filtered
}

func loadFailedDevices(path string) (map[string]bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var summary runSummary
	if err := json.Unmarshal(content, &summary); err != nil {
		return nil, fmt.Errorf("decode previous run summary: %w", err)
	}
	failed := map[string]bool{}
	for _, device := range summary.Devices {
		if device.Failed {
			failed[device.Hostname] = true
			failed[device.IP] = true
		}
	}
	if len(summary.Devices) == 0 {
		for _, item := range summary.Validations {
			if !item.Recovered && (item.Result.Status == "fail" || item.Result.Status == "error") {
				failed[item.Hostname] = true
				failed[item.IP] = true
			}
		}
	}
	delete(failed, "")
	return failed, nil
}
