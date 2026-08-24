package junosmonitor

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gwoodwa1/network-collector/internal/safeyaml"
	"github.com/gwoodwa1/network-collector/pkg/textfsm"
)

// embeddedFS bundles this binary's own parsers.yaml and TextFSM templates
// directly into the compiled executable, so a single file can be copied to a
// jumphost with no accompanying config to carry alongside it. Pass --parsers
// to load an external file instead.
//
//go:embed parsers.yaml templates
var embeddedFS embed.FS

// ParserModule describes one named entry from parsers.yaml. This is a
// standalone, minimal reader kept local to this binary rather than reusing
// cmd/network-collector's parser engine, so this tool never has to modify
// files in that command. Only the "textfsm" type is supported: the commands
// this tool collects (BGP summary, per-table route summary, interface
// stats, route tables, neighbor routes) all follow the TextFSM convention
// already used elsewhere in this repo's parsers.yaml files.
type ParserModule struct {
	Type     string `yaml:"type"`
	Template string `yaml:"template"`
	Root     string `yaml:"root"`
	baseDir  string
	source   fs.FS // nil reads Template from disk relative to baseDir; set reads it from this fs.FS instead
	// compiled is populated once, at load time (see compileModule), rather
	// than on every parseOutputWithModule call: this parser runs in the
	// per-tick, per-table, per-interface polling hot loop for the lifetime of
	// a multi-hour change window, and recompiling the same template's
	// regexes thousands of times over that window is pure waste.
	compiled *textfsm.Compiled
}

type parsersDocument struct {
	Parsers map[string]ParserModule `yaml:"parsers"`
}

// LoadDefaultParsers loads this binary's embedded parser definitions.
func LoadDefaultParsers() (map[string]ParserModule, error) {
	b, err := embeddedFS.ReadFile("parsers.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded parsers.yaml: %w", err)
	}
	var parsed parsersDocument
	if err := safeyaml.Unmarshal(b, &parsed); err != nil {
		return nil, fmt.Errorf("parse embedded parsers.yaml: %w", err)
	}
	for name, module := range parsed.Parsers {
		module.source = embeddedFS
		if err := compileModule(&module); err != nil {
			return nil, fmt.Errorf("parser %q: %w", name, err)
		}
		parsed.Parsers[name] = module
	}
	return parsed.Parsers, nil
}

// LoadParsers reads an external parsers.yaml file from disk. A missing file
// is not an error: it returns an empty set, so this tool still runs (falling
// back to raw output) if the path is wrong.
func LoadParsers(path string) (map[string]ParserModule, error) {
	b, err := safeyaml.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]ParserModule{}, nil
		}
		return nil, err
	}
	var parsed parsersDocument
	if err := safeyaml.Unmarshal(b, &parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	baseDir := filepath.Dir(path)
	for name, module := range parsed.Parsers {
		module.baseDir = baseDir
		if err := compileModule(&module); err != nil {
			return nil, fmt.Errorf("parser %q: %w", name, err)
		}
		parsed.Parsers[name] = module
	}
	return parsed.Parsers, nil
}

// compileModule reads and compiles module's TextFSM template once, at load
// time, so parseOutputWithModule never has to touch disk or recompile the
// same regex set again for the lifetime of the run.
func compileModule(module *ParserModule) error {
	if strings.ToLower(strings.TrimSpace(module.Type)) != "textfsm" {
		return nil
	}
	templateBytes, err := readTemplate(*module)
	if err != nil {
		return fmt.Errorf("read textfsm template: %w", err)
	}
	compiled, err := textfsm.Compile(templateBytes)
	if err != nil {
		return fmt.Errorf("invalid textfsm template: %w", err)
	}
	module.compiled = compiled
	return nil
}

func readTemplate(module ParserModule) ([]byte, error) {
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
func parseOutputWithModule(output, parserName string, parsers map[string]ParserModule) (string, error) {
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
	if module.compiled == nil {
		return "", fmt.Errorf("parser %q was not compiled at load time", parserName)
	}

	result, err := module.compiled.Run(output, module.Root)
	if err != nil {
		return "", fmt.Errorf("parser %q: %w", parserName, err)
	}
	return result, nil
}
