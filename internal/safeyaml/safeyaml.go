// Package safeyaml provides bounded YAML loading without anchors or aliases.
package safeyaml

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	MaxFileBytes     = 4 * 1024 * 1024
	MaxDocumentNodes = 500_000
)

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
	_, err := UnmarshalWithNodeCount(content, target)
	return err
}

// UnmarshalWithNodeCount decodes YAML and returns the number of syntax-tree
// nodes consumed so callers can enforce an aggregate multi-file budget.
func UnmarshalWithNodeCount(content []byte, target interface{}) (int, error) {
	return unmarshalWithNodeLimit(content, target, MaxDocumentNodes)
}

func unmarshalWithNodeLimit(content []byte, target interface{}, maxNodes int) (int, error) {
	if len(content) > MaxFileBytes {
		return 0, fmt.Errorf("YAML input exceeds the %d-byte limit", MaxFileBytes)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return 0, err
	}
	nodes, err := inspectDocument(&document, maxNodes)
	if err != nil {
		return 0, err
	}
	if err := document.Decode(target); err != nil {
		return 0, err
	}
	return nodes, nil
}

func inspectDocument(root *yaml.Node, maxNodes int) (int, error) {
	nodes := 0
	pending := []*yaml.Node{root}
	for len(pending) > 0 {
		index := len(pending) - 1
		node := pending[index]
		pending = pending[:index]
		if node == nil {
			continue
		}
		nodes++
		if nodes > maxNodes {
			return 0, fmt.Errorf("YAML document exceeds the %d-node limit", maxNodes)
		}
		if node.Kind == yaml.AliasNode || node.Anchor != "" {
			return 0, fmt.Errorf("YAML anchors and aliases are not supported")
		}
		pending = append(pending, node.Content...)
	}
	return nodes, nil
}
