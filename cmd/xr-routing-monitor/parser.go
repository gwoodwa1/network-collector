package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirikothe/gotextfsm"
	"gopkg.in/yaml.v3"
)

// embeddedFS bundles this binary's own parsers.yaml and TextFSM templates
// directly into the compiled executable, so a single file can be copied to a
// jumphost with no accompanying config to carry alongside it. Pass --parsers
// to load an external file instead.
//
//go:embed parsers.yaml templates
var embeddedFS embed.FS

// parserModule describes one named entry from parsers.yaml. This is a
// standalone, minimal reader kept local to this binary rather than reusing
// cmd/network-collector's parser engine, so this tool never has to modify
// files in that command. Only the "textfsm" type is supported: the commands
// this tool collects (BGP VPNv4 summary, per-VRF route summary, interface
// stats) all follow the TextFSM convention already used for
// xr_facts_bgp/xr_show_route_summary/xr_show_interfaces_brief_textfsm in the
// repo's parsers.yaml.
type parserModule struct {
	Type     string `yaml:"type"`
	Template string `yaml:"template"`
	Root     string `yaml:"root"`
	baseDir  string
	source   fs.FS // nil reads Template from disk relative to baseDir; set reads it from this fs.FS instead
}

type parsersDocument struct {
	Parsers map[string]parserModule `yaml:"parsers"`
}

// loadDefaultParsers loads this binary's embedded parser definitions.
func loadDefaultParsers() (map[string]parserModule, error) {
	b, err := embeddedFS.ReadFile("parsers.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded parsers.yaml: %w", err)
	}
	var parsed parsersDocument
	if err := yaml.Unmarshal(b, &parsed); err != nil {
		return nil, fmt.Errorf("parse embedded parsers.yaml: %w", err)
	}
	for name, module := range parsed.Parsers {
		module.source = embeddedFS
		parsed.Parsers[name] = module
	}
	return parsed.Parsers, nil
}

// loadParsers reads an external parsers.yaml file from disk. A missing file
// is not an error: it returns an empty set, so this tool still runs (falling
// back to raw output) if the path is wrong.
func loadParsers(path string) (map[string]parserModule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]parserModule{}, nil
		}
		return nil, err
	}
	var parsed parsersDocument
	if err := yaml.Unmarshal(b, &parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	baseDir := filepath.Dir(path)
	for name, module := range parsed.Parsers {
		module.baseDir = baseDir
		parsed.Parsers[name] = module
	}
	return parsed.Parsers, nil
}

func readTemplate(module parserModule) ([]byte, error) {
	templatePath := strings.TrimSpace(module.Template)
	if templatePath == "" {
		return nil, fmt.Errorf("missing template")
	}
	if module.source != nil {
		return fs.ReadFile(module.source, templatePath)
	}
	if !filepath.IsAbs(templatePath) {
		templatePath = filepath.Join(module.baseDir, templatePath)
	}
	return os.ReadFile(templatePath)
}

// parseOutputWithModule parses raw CLI output using the named TextFSM
// parser module. An empty parserName returns output unchanged.
func parseOutputWithModule(output, parserName string, parsers map[string]parserModule) (string, error) {
	parserName = strings.TrimSpace(parserName)
	if parserName == "" {
		return output, nil
	}
	module, ok := parsers[parserName]
	if !ok {
		return "", fmt.Errorf("parser %q not found", parserName)
	}
	if strings.ToLower(strings.TrimSpace(module.Type)) != "textfsm" {
		return "", fmt.Errorf("parser %q has unsupported type %q (this tool only supports textfsm)", parserName, module.Type)
	}

	templateBytes, err := readTemplate(module)
	if err != nil {
		return "", fmt.Errorf("read textfsm template for parser %q: %w", parserName, err)
	}

	var fsm gotextfsm.TextFSM
	if err := fsm.ParseString(string(templateBytes)); err != nil {
		return "", fmt.Errorf("invalid textfsm template for parser %q: %w", parserName, err)
	}
	var result gotextfsm.ParserOutput
	if err := result.ParseTextString(output, fsm, true); err != nil {
		return "", fmt.Errorf("textfsm parse failed for parser %q: %w", parserName, err)
	}

	root := strings.TrimSpace(module.Root)
	if root == "" {
		root = "records"
	}
	encoded, err := json.Marshal(map[string]interface{}{root: result.Dict})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
