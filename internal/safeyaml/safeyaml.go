// Package safeyaml provides bounded YAML loading without anchors or aliases.
package safeyaml

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const MaxFileBytes = 4 * 1024 * 1024

func ReadFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > MaxFileBytes {
		return nil, fmt.Errorf("YAML file exceeds the %d-byte limit", MaxFileBytes)
	}
	return content, nil
}

func Unmarshal(content []byte, target interface{}) error {
	if len(content) > MaxFileBytes {
		return fmt.Errorf("YAML input exceeds the %d-byte limit", MaxFileBytes)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return err
	}
	if err := rejectAliases(&document); err != nil {
		return err
	}
	return document.Decode(target)
}

func rejectAliases(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("YAML anchors and aliases are not supported")
	}
	for _, child := range node.Content {
		if err := rejectAliases(child); err != nil {
			return err
		}
	}
	return nil
}
