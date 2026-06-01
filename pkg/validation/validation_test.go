package validation

import (
	"testing"
)

func TestRegexStringEq(t *testing.T) {
	out := "System state: RUNNING"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      "System state:\\s+(\\\")]",
		Condition:    "eq",
		Expected:     "RUNNING",
		ExpectedType: "string",
	}
	// Fix pattern above (escaped in test string) — use simpler approach
	rule.Pattern = `System state:\s+(\w+)`
	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestRegexIntEq(t *testing.T) {
	out := "Total memory: 100MB"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `Total memory:\s+(\d+)MB`,
		Condition:    "eq",
		Expected:     100,
		ExpectedType: "int",
	}
	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestRegexIntMismatchType(t *testing.T) {
	out := "Total memory: 100MB"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `Total memory:\s+(\d+)MB`,
		Condition:    "eq",
		Expected:     "100",
		ExpectedType: "int",
	}
	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass after coercion, got: %+v", res)
	}
}

func TestGJSONContains(t *testing.T) {
	out := `{"interfaces":[{"interface":[{"subinterfaces":[{"subinterface":[{"state":{"description":"up on port"}}]}]}]}]}`
	rule := ValidationRule{
		Extractor:    "gjson",
		JSONPath:     "interfaces.0.interface.0.subinterfaces.0.subinterface.0.state.description",
		Condition:    "contains",
		Expected:     "up",
		ExpectedType: "string",
	}
	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestRegexWithoutCaptureUsesWholeMatch(t *testing.T) {
	out := "address-family ipv4 unicast overload"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `address-family ipv4 unicast overload`,
		Condition:    "contains",
		Expected:     "overload",
		ExpectedType: "string",
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
	if res.RawExtract != out {
		t.Fatalf("expected whole match as raw extract, got %q", res.RawExtract)
	}
}

func TestNotEqual(t *testing.T) {
	out := "System state: RUNNING"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `System state:\s+(\w+)`,
		Condition:    "neq",
		Expected:     "FAILED",
		ExpectedType: "string",
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestNotContains(t *testing.T) {
	out := "System state: RUNNING"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `System state:\s+(\w+)`,
		Condition:    "not_contains",
		Expected:     "FAIL",
		ExpectedType: "string",
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestGreaterThanOrEqual(t *testing.T) {
	out := "Total routes: 100"
	rule := ValidationRule{
		Extractor: "regex",
		Pattern:   `Total routes:\s+(\d+)`,
		Condition: "gte",
		Expected:  100,
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestLessThanOrEqual(t *testing.T) {
	out := "CPU: 80"
	rule := ValidationRule{
		Extractor: "regex",
		Pattern:   `CPU:\s+(\d+)`,
		Condition: "lte",
		Expected:  80,
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestMatches(t *testing.T) {
	out := "Version: 17.9.4"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `Version:\s+(.+)`,
		Condition:    "matches",
		Expected:     `^\d+\.\d+\.\d+$`,
		ExpectedType: "string",
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestLengthComparison(t *testing.T) {
	out := "Peers: abcde"
	rule := ValidationRule{
		Extractor:    "regex",
		Pattern:      `Peers:\s+(\w+)`,
		Condition:    "gte",
		Expected:     5,
		ExpectedType: "length",
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
}

func TestGJSONArrayLengthComparison(t *testing.T) {
	out := `{"neighbors":["leaf1","leaf2","leaf3"]}`
	rule := ValidationRule{
		Extractor:    "gjson",
		JSONPath:     "neighbors",
		Condition:    "eq",
		Expected:     3,
		ExpectedType: "length",
	}

	res, err := ValidateOutput(out, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pass {
		t.Fatalf("expected pass, got: %+v", res)
	}
	if res.Value != 3 {
		t.Fatalf("expected length value 3, got %#v", res.Value)
	}
}
