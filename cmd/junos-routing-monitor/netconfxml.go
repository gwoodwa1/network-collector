package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

// xmlElement is a namespace-agnostic parsed XML element: its local name
// (namespace prefix/URI stripped), direct text content, and children in
// document order. NETCONF decoders (netconfdecode_*.go) walk this instead of
// unmarshaling into nested Go structs with a hardcoded element-nesting
// chain, because the exact wrapper depth of a Junos RPC reply (e.g. whether
// <route-table> sits directly under <route-information> or one level
// deeper) is not confirmed against a real device — see the "unverified"
// caveat in each decoder file. This mirrors the reference implementation's
// own approach (networkflow's Python parsers use lxml's
// ".//*[local-name()='tag']", which finds an element by name at any depth
// regardless of namespace), so a decoder written against this type is
// resilient to exactly the kind of nesting surprise that would otherwise
// require a real device to discover and fix.
type xmlElement struct {
	Name     string
	Text     string
	Children []*xmlElement
}

// parseXMLElement parses a complete XML document (e.g. one <rpc-reply>...
// body returned by sessionExecutor.Execute) into an xmlElement tree rooted
// at the document's single top-level element.
func parseXMLElement(data string) (*xmlElement, error) {
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []*xmlElement
	var root *xmlElement
	for {
		tok, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("parse xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			el := &xmlElement{Name: t.Name.Local}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, el)
			}
			stack = append(stack, el)
			if root == nil {
				root = el
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("parse xml: no root element found")
	}
	return root, nil
}

// find returns every descendant of e, at any depth (not just direct
// children), whose local name equals name — the Go equivalent of the
// reference implementation's ".//*[local-name()='name']".
func (e *xmlElement) find(name string) []*xmlElement {
	var out []*xmlElement
	var walk func(*xmlElement)
	walk = func(el *xmlElement) {
		for _, child := range el.Children {
			if child.Name == name {
				out = append(out, child)
			}
			walk(child)
		}
	}
	walk(e)
	return out
}

// child returns the first direct child of e named name, or nil.
func (e *xmlElement) child(name string) *xmlElement {
	for _, c := range e.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// text returns e's own trimmed text content.
func (e *xmlElement) text() string {
	return strings.TrimSpace(e.Text)
}

// childText returns the trimmed text of the first direct child of e named
// name, or "" if there is no such child.
func (e *xmlElement) childText(name string) string {
	if c := e.child(name); c != nil {
		return c.text()
	}
	return ""
}

// encodeRecords marshals records into {"<root>": [...]} JSON, matching
// pkg/textfsm.Compiled.Run's exact marshaling convention
// (map[string]interface{}{root: records}) so a NETCONF-decoded section is
// byte-shape-identical to its TextFSM counterpart wherever one exists, and
// every new NETCONF-only section still follows the same one convention.
func encodeRecords(root string, records []map[string]string) (string, error) {
	encoded, err := json.Marshal(map[string]interface{}{root: records})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// rawFallback marshals rpcReply as {"raw": rpcReply}, the same shape
// parseOrRaw (poll.go) falls back to on a TextFSM parse failure.
func rawFallback(rpcReply string) json.RawMessage {
	encoded, err := json.Marshal(map[string]string{"raw": rpcReply})
	if err != nil {
		return json.RawMessage(`{"raw":""}`)
	}
	return json.RawMessage(encoded)
}

// decodeNetconfOrRaw runs one NETCONF decoder function against rpcReply,
// mirroring parseOrRaw's exact fallback contract for the SSH/TextFSM path:
// on any decode error, the error is appended to errs and rpcReply is
// wrapped as {"raw": rpcReply} instead — a malformed or unexpected response
// (see the "unverified against a real device" caveat on every decoder file)
// degrades to raw text rather than crashing or aborting the whole snapshot
// capture, and status.go's existing raw-fallback detection (which only
// looks for the "raw" key) needs no changes to also cover NETCONF failures.
func decodeNetconfOrRaw(rpcReply string, decode func(string) (string, error), errs *[]string, label string) json.RawMessage {
	decoded, err := decode(rpcReply)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s: %v", label, err))
		return rawFallback(rpcReply)
	}
	return json.RawMessage(decoded)
}
