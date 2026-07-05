// Package drift compares structured JSON state while allowing unstable paths
// to be ignored.
package drift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Change struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}
type Report struct {
	Changed bool     `json:"changed"`
	Changes []Change `json:"changes"`
}

func Compare(baseline, current []byte, ignore []string) (Report, error) {
	var before, after any
	bd := json.NewDecoder(bytes.NewReader(baseline))
	bd.UseNumber()
	if err := bd.Decode(&before); err != nil {
		return Report{}, fmt.Errorf("decode baseline: %w", err)
	}
	ad := json.NewDecoder(bytes.NewReader(current))
	ad.UseNumber()
	if err := ad.Decode(&after); err != nil {
		return Report{}, fmt.Errorf("decode current state: %w", err)
	}
	report := Report{}
	diff("", before, after, ignore, &report.Changes)
	report.Changed = len(report.Changes) > 0
	return report, nil
}

func diff(path string, before, after any, ignore []string, changes *[]Change) {
	if ignored(path, ignore) {
		return
	}
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if bok && aok {
		keys := map[string]bool{}
		for k := range bm {
			keys[k] = true
		}
		for k := range am {
			keys[k] = true
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, k := range ordered {
			child := join(path, k)
			bv, be := bm[k]
			av, ae := am[k]
			if !be {
				if !ignored(child, ignore) {
					*changes = append(*changes, Change{Path: child, Kind: "added", After: av})
				}
				continue
			}
			if !ae {
				if !ignored(child, ignore) {
					*changes = append(*changes, Change{Path: child, Kind: "removed", Before: bv})
				}
				continue
			}
			diff(child, bv, av, ignore, changes)
		}
		return
	}
	ba, bok := before.([]any)
	aa, aok := after.([]any)
	if bok && aok {
		max := len(ba)
		if len(aa) > max {
			max = len(aa)
		}
		for i := 0; i < max; i++ {
			child := fmt.Sprintf("%s[%d]", path, i)
			if i >= len(ba) {
				*changes = append(*changes, Change{Path: child, Kind: "added", After: aa[i]})
			} else if i >= len(aa) {
				*changes = append(*changes, Change{Path: child, Kind: "removed", Before: ba[i]})
			} else {
				diff(child, ba[i], aa[i], ignore, changes)
			}
		}
		return
	}
	if fmt.Sprint(before) != fmt.Sprint(after) {
		*changes = append(*changes, Change{Path: path, Kind: "changed", Before: before, After: after})
	}
}

func join(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}
func ignored(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if match(strings.TrimSpace(pattern), path) {
			return true
		}
	}
	return false
}
func match(pattern, value string) bool {
	value = normalizeIndexes(value)
	if pattern == value {
		return true
	}
	pp, vp := strings.Split(pattern, "."), strings.Split(value, ".")
	if len(pp) != len(vp) {
		return false
	}
	for i := range pp {
		if pp[i] != "*" && pp[i] != vp[i] {
			return false
		}
	}
	return true
}

func normalizeIndexes(value string) string {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == '[' {
			end := strings.IndexByte(value[index:], ']')
			if end > 0 {
				result.WriteString(".*")
				index += end
				continue
			}
		}
		result.WriteByte(value[index])
	}
	return result.String()
}
