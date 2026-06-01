package validation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// ValidationRule is a user-provided rule describing how to extract and validate a value.
type ValidationRule struct {
	Extractor    string      `json:"extractor" yaml:"extractor"`                             // regex | gjson
	Pattern      string      `json:"pattern,omitempty" yaml:"pattern,omitempty"`             // regex pattern
	JSONPath     string      `json:"json_path,omitempty" yaml:"json_path,omitempty"`         // gjson path
	Condition    string      `json:"condition" yaml:"condition"`                             // eq | neq | contains | not_contains | gt | gte | lt | lte | matches
	Expected     interface{} `json:"expected" yaml:"expected"`                               // comparison value or regex pattern for matches
	ExpectedType string      `json:"expected_type,omitempty" yaml:"expected_type,omitempty"` // string | int | length
}

// ValidationResult contains the detailed outcome of running a single ValidationRule against output.
type ValidationResult struct {
	Pass          bool        `json:"pass"`
	Status        string      `json:"status"` // pass | fail | error
	Extractor     string      `json:"extractor"`
	PatternOrPath string      `json:"pattern_or_path"`
	RawExtract    string      `json:"raw_extract"`
	Value         interface{} `json:"value,omitempty"`
	Expected      interface{} `json:"expected,omitempty"`
	ExpectedType  string      `json:"expected_type,omitempty"`
	Condition     string      `json:"condition,omitempty"`
	Message       string      `json:"message,omitempty"`
	Err           string      `json:"err,omitempty"`
	Timestamp     time.Time   `json:"timestamp,omitempty"`
}

type extractedValue struct {
	raw    string
	length *int
}

// ValidateOutput runs the given rule against the provided output and returns a ValidationResult.
func ValidateOutput(output string, rule ValidationRule) (ValidationResult, error) {
	res := ValidationResult{
		Extractor:     rule.Extractor,
		PatternOrPath: rule.Pattern,
		Expected:      rule.Expected,
		ExpectedType:  rule.ExpectedType,
		Condition:     rule.Condition,
		Timestamp:     time.Now(),
	}

	extracted, ok, err := extractValue(output, rule, &res)
	if err != nil || !ok {
		return res, err
	}

	val, ok := coerceValue(extracted, rule, &res)
	if !ok {
		return res, nil
	}
	res.Value = val

	compareValue(val, rule, &res)
	return res, nil
}

func extractValue(output string, rule ValidationRule, res *ValidationResult) (extractedValue, bool, error) {
	switch strings.ToLower(rule.Extractor) {
	case "regex":
		if rule.Pattern == "" {
			res.Status = "error"
			res.Err = "missing regex pattern"
			res.Message = "no regex pattern provided"
			return extractedValue{}, false, nil
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			res.Status = "error"
			res.Err = fmt.Sprintf("invalid regex: %v", err)
			res.Message = res.Err
			return extractedValue{}, false, nil
		}
		m := re.FindStringSubmatch(output)
		if len(m) == 0 {
			res.Status = "fail"
			res.Message = "no match found"
			return extractedValue{}, false, nil
		}
		raw := m[0]
		if len(m) > 1 {
			raw = m[1]
		}
		res.RawExtract = raw
		return extractedValue{raw: raw}, true, nil
	case "gjson":
		if rule.JSONPath == "" {
			res.Status = "error"
			res.Err = "missing json_path"
			res.Message = "no json_path provided"
			return extractedValue{}, false, nil
		}
		res.PatternOrPath = rule.JSONPath
		v := gjson.Get(output, rule.JSONPath)
		if !v.Exists() {
			res.Status = "fail"
			res.Message = "json path not found"
			return extractedValue{}, false, nil
		}
		raw := v.String()
		res.RawExtract = raw
		extracted := extractedValue{raw: raw}
		if v.IsArray() {
			length := len(v.Array())
			extracted.length = &length
		} else if v.IsObject() {
			length := len(v.Map())
			extracted.length = &length
		}
		return extracted, true, nil
	default:
		return extractedValue{}, false, fmt.Errorf("unsupported extractor: %s", rule.Extractor)
	}
}

func coerceValue(extracted extractedValue, rule ValidationRule, res *ValidationResult) (interface{}, bool) {
	et := strings.ToLower(rule.ExpectedType)
	cond := strings.ToLower(rule.Condition)
	isNumericCond := cond == "gt" || cond == "gte" || cond == "lt" || cond == "lte"

	if et == "" && isNumericCond {
		et = "int"
	}

	switch et {
	case "", "string":
		return extracted.raw, true
	case "int":
		i, err := strconv.Atoi(strings.TrimSpace(extracted.raw))
		if err != nil {
			res.Status = "error"
			res.Err = fmt.Sprintf("failed to coerce value to int: %v", err)
			res.Message = res.Err
			return nil, false
		}
		return i, true
	case "length":
		if extracted.length != nil {
			return *extracted.length, true
		}
		return len(extracted.raw), true
	default:
		res.Status = "error"
		res.Err = fmt.Sprintf("unsupported expected_type: %s", rule.ExpectedType)
		res.Message = res.Err
		return nil, false
	}
}

func compareValue(val interface{}, rule ValidationRule, res *ValidationResult) {
	switch strings.ToLower(rule.Condition) {
	case "eq", "neq":
		compareEquality(val, rule, res)
	case "contains", "not_contains":
		compareContains(val, rule, res)
	case "matches":
		compareMatches(val, rule, res)
	case "gt", "gte", "lt", "lte":
		compareNumeric(val, rule, res)
	default:
		res.Status = "error"
		res.Err = fmt.Sprintf("unsupported condition: %s", rule.Condition)
		res.Message = res.Err
	}
}

func compareEquality(val interface{}, rule ValidationRule, res *ValidationResult) {
	negated := strings.EqualFold(rule.Condition, "neq")
	equal := false

	if strings.EqualFold(rule.ExpectedType, "int") || strings.EqualFold(rule.ExpectedType, "length") {
		expectedInt, ok := toInt(rule.Expected)
		if !ok {
			res.Status = "error"
			res.Err = "expected value is not an int"
			res.Message = res.Err
			return
		}
		actualInt, ok := val.(int)
		if !ok {
			res.Status = "error"
			res.Err = "extracted value is not an int"
			res.Message = res.Err
			return
		}
		equal = actualInt == expectedInt
	} else {
		equal = fmt.Sprintf("%v", val) == fmt.Sprintf("%v", rule.Expected)
	}

	passMessage := "values equal"
	failMessage := "values differ"
	if negated {
		passMessage = "values differ"
		failMessage = "values equal"
	}
	setComparisonResult(res, equal != negated, passMessage, failMessage, fmt.Sprintf("got=%v want=%v", val, rule.Expected))
}

func compareContains(val interface{}, rule ValidationRule, res *ValidationResult) {
	negated := strings.EqualFold(rule.Condition, "not_contains")
	actual := fmt.Sprintf("%v", val)
	expected := fmt.Sprintf("%v", rule.Expected)
	contains := strings.Contains(actual, expected)
	passMessage := "value contains expected"
	failMessage := "value does not contain expected"
	if negated {
		passMessage = "value does not contain expected"
		failMessage = "value contains expected"
	}
	setComparisonResult(res, contains != negated, passMessage, failMessage, fmt.Sprintf("%q vs %q", actual, expected))
}

func compareMatches(val interface{}, rule ValidationRule, res *ValidationResult) {
	pattern := fmt.Sprintf("%v", rule.Expected)
	re, err := regexp.Compile(pattern)
	if err != nil {
		res.Status = "error"
		res.Err = fmt.Sprintf("invalid expected regex: %v", err)
		res.Message = res.Err
		return
	}

	actual := fmt.Sprintf("%v", val)
	setComparisonResult(res, re.MatchString(actual), "value matches expected regex", "value does not match expected regex", fmt.Sprintf("%q vs %q", actual, pattern))
}

func compareNumeric(val interface{}, rule ValidationRule, res *ValidationResult) {
	expectedInt, ok := toInt(rule.Expected)
	if !ok {
		res.Status = "error"
		res.Err = "expected value is not an int for numeric comparison"
		res.Message = res.Err
		return
	}
	actualInt, ok := val.(int)
	if !ok {
		res.Status = "error"
		res.Err = "extracted value is not an int for numeric comparison"
		res.Message = res.Err
		return
	}

	var pass bool
	switch strings.ToLower(rule.Condition) {
	case "gt":
		pass = actualInt > expectedInt
	case "gte":
		pass = actualInt >= expectedInt
	case "lt":
		pass = actualInt < expectedInt
	case "lte":
		pass = actualInt <= expectedInt
	}

	setComparisonResult(res, pass, "numeric comparison passed", "numeric comparison failed", fmt.Sprintf("got=%d want=%s %d", actualInt, rule.Condition, expectedInt))
}

func setComparisonResult(res *ValidationResult, pass bool, passMessage, failMessage, detail string) {
	res.Pass = pass
	if pass {
		res.Status = "pass"
		res.Message = passMessage
		return
	}
	res.Status = "fail"
	res.Message = fmt.Sprintf("%s: %s", failMessage, detail)
}

// toInt attempts to convert an interface{} to int.
func toInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}
