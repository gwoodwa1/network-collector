package main

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParserModules(f *testing.F) {
	parsers, err := loadParsers(filepath.Join("..", "..", "parsers.yaml"), "")
	if err != nil {
		f.Fatal(err)
	}
	seedFiles := []string{
		"xr_show_interfaces_brief.txt", "xr_show_platform.txt", "xr_show_route_summary.txt",
		"xr_show_ntp_associations_synced.txt", "xr_show_ntp_status_synced.txt", "xr_show_alarms_brief_system_active.txt",
	}
	for _, name := range seedFiles {
		data, err := os.ReadFile(filepath.Join("testdata", "cli", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	parserNames := []string{
		"xr_show_interfaces_brief_records", "xr_show_interfaces_brief_textfsm", "xr_show_platform", "xr_show_route_summary", "xr_show_ntp_associations", "xr_show_ntp_status", "xr_show_alarms_brief_system_active",
		"eos_facts_system", "eos_facts_platform", "eos_facts_interfaces", "eos_facts_lldp", "eos_facts_bgp",
		"junos_facts_system", "junos_facts_platform", "junos_facts_interfaces", "junos_facts_lldp", "junos_facts_bgp",
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		for _, name := range parserNames {
			_, _ = parseOutputWithModule(string(data), name, parsers.Parsers)
		}
	})
}
