// Package facts gathers operational data through NETCONF or SSH and exposes
// both parser-native data and a stable OpenConfig-shaped representation.
package facts

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Format string

const (
	FormatOpenConfig Format = "openconfig"
	FormatNative     Format = "native"
	FormatBoth       Format = "both"
)

var defaultSubsets = []string{"system", "platform", "interfaces", "lldp", "bgp", "isis", "ldp"}

type Config struct {
	Format     Format
	Subsets    []string
	Transports []string
}

type Executor interface {
	Execute(string) (string, error)
}

type Parser func(output, parser string) (json.RawMessage, error)

type Source struct {
	Transport string `json:"transport"`
	Parser    string `json:"parser,omitempty"`
	Command   string `json:"command,omitempty"`
}

type SubsetMetadata struct {
	Source             Source   `json:"source"`
	OpenConfigComplete bool     `json:"openconfig_complete"`
	UnmappedFields     []string `json:"unmapped_fields,omitempty"`
}

type Metadata struct {
	Platform string                    `json:"platform"`
	Subsets  map[string]SubsetMetadata `json:"subsets"`
	Errors   map[string][]string       `json:"errors,omitempty"`
}

type Result struct {
	OpenConfig map[string]any             `json:"openconfig,omitempty"`
	Native     map[string]json.RawMessage `json:"native,omitempty"`
	Metadata   Metadata                   `json:"metadata"`
}

type Definition struct {
	Command       string
	Parser        string
	NETCONFFilter string
}

type Collector struct {
	Platform string
	NETCONF  Executor
	SSH      Executor
	Parse    Parser
}

func NormalizeConfig(config Config) (Config, error) {
	if config.Format == "" {
		config.Format = FormatBoth
	}
	switch config.Format {
	case FormatOpenConfig, FormatNative, FormatBoth:
	default:
		return config, fmt.Errorf("unsupported facts format %q", config.Format)
	}
	if len(config.Subsets) == 0 {
		config.Subsets = append([]string(nil), defaultSubsets...)
	}
	seen := map[string]bool{}
	for i, subset := range config.Subsets {
		subset = strings.ToLower(strings.TrimSpace(subset))
		if _, ok := openConfigRoot[subset]; !ok {
			return config, fmt.Errorf("unsupported facts subset %q", subset)
		}
		if seen[subset] {
			return config, fmt.Errorf("duplicate facts subset %q", subset)
		}
		seen[subset] = true
		config.Subsets[i] = subset
	}
	if len(config.Transports) == 0 {
		config.Transports = []string{"netconf", "ssh"}
	}
	for i, transport := range config.Transports {
		transport = strings.ToLower(strings.TrimSpace(transport))
		if transport != "netconf" && transport != "ssh" {
			return config, fmt.Errorf("unsupported facts transport %q", transport)
		}
		config.Transports[i] = transport
	}
	return config, nil
}

func (c Collector) Collect(config Config) (Result, error) {
	config, err := NormalizeConfig(config)
	if err != nil {
		return Result{}, err
	}
	result := Result{Metadata: Metadata{Platform: canonicalPlatform(c.Platform), Subsets: map[string]SubsetMetadata{}, Errors: map[string][]string{}}}
	if config.Format != FormatNative {
		result.OpenConfig = map[string]any{}
	}
	if config.Format != FormatOpenConfig {
		result.Native = map[string]json.RawMessage{}
	}

	for _, subset := range config.Subsets {
		definition, ok := lookup(c.Platform, subset)
		if !ok {
			result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "no facts definition for platform")
			continue
		}
		var native json.RawMessage
		var source Source
		for _, transport := range config.Transports {
			switch transport {
			case "netconf":
				if c.NETCONF == nil || definition.NETCONFFilter == "" {
					continue
				}
				output, executeErr := c.NETCONF.Execute(definition.NETCONFFilter)
				if executeErr != nil {
					result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "netconf: "+executeErr.Error())
					continue
				}
				native, executeErr = XMLToJSON(output)
				if executeErr != nil {
					result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "netconf decode: "+executeErr.Error())
					continue
				}
				if !XMLContainsSubset(output, subset) {
					result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "netconf: OpenConfig subset absent from response")
					native = nil
					continue
				}
				source = Source{Transport: "netconf", Parser: "openconfig-xml"}
			case "ssh":
				if c.SSH == nil || c.Parse == nil || definition.Command == "" || definition.Parser == "" {
					continue
				}
				output, executeErr := c.SSH.Execute(definition.Command)
				if executeErr != nil {
					result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "ssh: "+executeErr.Error())
					continue
				}
				native, executeErr = c.Parse(output, definition.Parser)
				if executeErr != nil {
					result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "ssh parser: "+executeErr.Error())
					continue
				}
				source = Source{Transport: "ssh", Parser: definition.Parser, Command: definition.Command}
			}
			if len(native) != 0 {
				break
			}
		}
		if len(native) == 0 {
			continue
		}
		if result.Native != nil {
			result.Native[subset] = native
		}
		metadata := SubsetMetadata{Source: source}
		if result.OpenConfig != nil {
			root, normalized, complete, unmapped, normalizeErr := Normalize(subset, native, source.Transport)
			if normalizeErr != nil {
				result.Metadata.Errors[subset] = append(result.Metadata.Errors[subset], "openconfig normalization: "+normalizeErr.Error())
			} else {
				if existing, ok := result.OpenConfig[root]; ok {
					result.OpenConfig[root] = mergeOpenConfig(existing, normalized)
				} else {
					result.OpenConfig[root] = normalized
				}
				metadata.OpenConfigComplete = complete
				metadata.UnmappedFields = unmapped
			}
		}
		result.Metadata.Subsets[subset] = metadata
	}
	if len(result.Metadata.Errors) == 0 {
		result.Metadata.Errors = nil
	}
	if len(result.Metadata.Subsets) == 0 {
		return result, errors.New("facts collection produced no subsets")
	}
	return result, nil
}

// mergeOpenConfig combines subsets which share an OpenConfig root. BGP,
// IS-IS, and LDP all live below network-instances and must not overwrite one
// another when gathered in the same step.
func mergeOpenConfig(left, right any) any {
	leftMap, leftOK := left.(map[string]any)
	rightMap, rightOK := right.(map[string]any)
	if leftOK && rightOK {
		for key, rightValue := range rightMap {
			if leftValue, ok := leftMap[key]; ok {
				leftMap[key] = mergeOpenConfig(leftValue, rightValue)
			} else {
				leftMap[key] = rightValue
			}
		}
		return leftMap
	}
	leftList, leftOK := left.([]any)
	rightList, rightOK := right.([]any)
	if leftOK && rightOK {
		for _, rightItem := range rightList {
			identity := listIdentity(rightItem)
			merged := false
			if identity != "" {
				for index, leftItem := range leftList {
					if listIdentity(leftItem) == identity {
						leftList[index] = mergeOpenConfig(leftItem, rightItem)
						merged = true
						break
					}
				}
			}
			if !merged {
				leftList = append(leftList, rightItem)
			}
		}
		return leftList
	}
	return right
}

func listIdentity(value any) string {
	record, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"name", "identifier", "neighbor-address", "system-id", "lsr-id", "interface-id", "level-number", "id"} {
		if item, ok := record[key]; ok {
			return key + "=" + fmt.Sprint(item)
		}
	}
	return ""
}

func XMLToJSON(input string) (json.RawMessage, error) {
	decoder := xml.NewDecoder(strings.NewReader(input))
	var root map[string]any
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		value, err := decodeElement(decoder, start)
		if err != nil {
			return nil, err
		}
		root = map[string]any{start.Name.Local: value}
		break
	}
	if root == nil {
		return nil, errors.New("empty XML response")
	}
	encoded, err := json.Marshal(root)
	return encoded, err
}

func XMLContainsSubset(input, subset string) bool {
	wanted := map[string]string{"system": "system", "platform": "components", "interfaces": "interfaces", "lldp": "lldp", "bgp": "bgp", "isis": "isis", "ldp": "ldp"}[subset]
	if wanted == "" {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(input))
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if start, ok := token.(xml.StartElement); ok && strings.EqualFold(start.Name.Local, wanted) {
			return true
		}
	}
}

func decodeElement(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	children := map[string]any{}
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			child, err := decodeElement(decoder, value)
			if err != nil {
				return nil, err
			}
			if existing, ok := children[value.Name.Local]; ok {
				switch list := existing.(type) {
				case []any:
					children[value.Name.Local] = append(list, child)
				default:
					children[value.Name.Local] = []any{list, child}
				}
			} else {
				children[value.Name.Local] = child
			}
		case xml.CharData:
			text.Write([]byte(value))
		case xml.EndElement:
			if value.Name == start.Name {
				trimmed := strings.TrimSpace(text.String())
				if len(children) == 0 {
					return trimmed, nil
				}
				if trimmed != "" {
					children["#text"] = trimmed
				}
				return children, nil
			}
		}
	}
}

func sortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
