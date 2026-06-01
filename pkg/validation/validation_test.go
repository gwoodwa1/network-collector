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
