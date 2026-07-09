// Package textfsm wraps gotextfsm with the compile-once/parse-many split and
// the {root: records} JSON convention shared by every TextFSM-backed parser
// in this repo (cmd/network-collector and cmd/xr-routing-monitor).
package textfsm

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/sirikothe/gotextfsm"
)

// Compiled is a TextFSM template whose rules/regexes have already been
// parsed, so it can be run against CLI output repeatedly without
// recompiling on every call — the difference matters on a polling hot path
// that parses the same template many times over a long-running session.
//
// gotextfsm.TextFSM.Values is a map, and ParseTextString mutates it in place
// (clearRecord/checkLine/appendRecord all write back into fsm.Values) even
// though the fsm parameter is passed "by value" — a map value is a header
// pointing at shared storage, so every caller sharing one TextFSM mutates
// the same underlying map. Concurrent Run() calls on a shared Compiled
// therefore race on that map (observed as a live "fatal error: concurrent
// map iteration and map write" panic when two devices' poll goroutines
// parsed BGP/route output at the same instant). mu serializes Run() to keep
// the load-time compile-once benefit without reintroducing that race; it
// only contends between concurrent parses of the *same* named parser, not
// across different templates.
type Compiled struct {
	mu  sync.Mutex
	fsm gotextfsm.TextFSM
}

// Compile parses a TextFSM template's rules once.
func Compile(template []byte) (*Compiled, error) {
	var fsm gotextfsm.TextFSM
	if err := fsm.ParseString(string(template)); err != nil {
		return nil, fmt.Errorf("invalid textfsm template: %w", err)
	}
	return &Compiled{fsm: fsm}, nil
}

// Run executes the compiled template against output, wrapping the parsed
// records as JSON under the given root key (defaulting to "records").
func (c *Compiled) Run(output, root string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("textfsm template is not compiled")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var parsed gotextfsm.ParserOutput
	if err := parsed.ParseTextString(output, c.fsm, true); err != nil {
		return "", fmt.Errorf("textfsm parse failed: %w", err)
	}
	if root == "" {
		root = "records"
	}
	encoded, err := json.Marshal(map[string]interface{}{root: parsed.Dict})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// Parse compiles template and runs it against output in one step, for
// callers that parse infrequently enough that recompiling the template on
// every call isn't worth caching a *Compiled themselves.
func Parse(output string, template []byte, root string) (string, error) {
	compiled, err := Compile(template)
	if err != nil {
		return "", err
	}
	return compiled.Run(output, root)
}
