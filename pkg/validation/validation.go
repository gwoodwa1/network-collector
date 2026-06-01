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
    Extractor    string      `json:"extractor" yaml:"extractor"`     // regex | gjson
    Pattern      string      `json:"pattern,omitempty" yaml:"pattern,omitempty"`   // regex pattern
    JSONPath     string      `json:"json_path,omitempty" yaml:"json_path,omitempty"` // gjson path
    Condition    string      `json:"condition" yaml:"condition"`       // eq | contains | gt | lt
    Expected     interface{} `json:"expected" yaml:"expected"`
    ExpectedType string      `json:"expected_type,omitempty" yaml:"expected_type,omitempty"` // string | int
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

    // Extract raw value
    var raw string
    switch strings.ToLower(rule.Extractor) {
    case "regex":
        if rule.Pattern == "" {
            res.Status = "error"
            res.Err = "missing regex pattern"
            res.Message = "no regex pattern provided"
            return res, nil
        }
        re, err := regexp.Compile(rule.Pattern)
        if err != nil {
            res.Status = "error"
            res.Err = fmt.Sprintf("invalid regex: %v", err)
            res.Message = res.Err
            return res, nil
        }
        m := re.FindStringSubmatch(output)
        if len(m) < 2 {
            res.Status = "fail"
            res.Message = "no match found"
            return res, nil
        }
        raw = m[1]
        res.RawExtract = raw
    case "gjson":
        if rule.JSONPath == "" {
            res.Status = "error"
            res.Err = "missing json_path"
            res.Message = "no json_path provided"
            return res, nil
        }
        v := gjson.Get(output, rule.JSONPath)
        if !v.Exists() {
            res.Status = "fail"
            res.Message = "json path not found"
            return res, nil
        }
        raw = v.Raw
        // gjson.Raw may be a JSON literal; normalize to string without quotes when possible
        res.RawExtract = v.String()
    default:
        return res, fmt.Errorf("unsupported extractor: %s", rule.Extractor)
    }

    // Coerce raw to typed value according to ExpectedType.
    // If ExpectedType is unspecified but the condition is numeric (gt/lt),
    // attempt to coerce the extracted value to int automatically.
    var val interface{}
    et := strings.ToLower(rule.ExpectedType)
    cond := strings.ToLower(rule.Condition)
    isNumericCond := cond == "gt" || cond == "lt"

    if et == "" && isNumericCond {
        // try to coerce to int
        i, err := strconv.Atoi(strings.TrimSpace(raw))
        if err != nil {
            res.Status = "error"
            res.Err = fmt.Sprintf("failed to coerce value to int for numeric comparison: %v", err)
            res.Message = res.Err
            return res, nil
        }
        val = i
    } else {
        switch et {
        case "", "string":
            val = raw
        case "int":
            i, err := strconv.Atoi(strings.TrimSpace(raw))
            if err != nil {
                res.Status = "error"
                res.Err = fmt.Sprintf("failed to coerce value to int: %v", err)
                res.Message = res.Err
                return res, nil
            }
            val = i
        default:
            res.Status = "error"
            res.Err = fmt.Sprintf("unsupported expected_type: %s", rule.ExpectedType)
            res.Message = res.Err
            return res, nil
        }
    }
    res.Value = val

    // Perform comparison
    switch strings.ToLower(rule.Condition) {
    case "eq":
        switch expected := rule.Expected.(type) {
        default:
            // normalize expected according to expected type
            if et == "int" {
                expectedInt, ok := toInt(expected)
                if !ok {
                    res.Status = "error"
                    res.Err = "expected value is not an int"
                    res.Message = res.Err
                    return res, nil
                }
                if vi, ok := val.(int); ok && vi == expectedInt {
                    res.Pass = true
                    res.Status = "pass"
                    res.Message = "values equal"
                    return res, nil
                }
                res.Pass = false
                res.Status = "fail"
                res.Message = fmt.Sprintf("int mismatch: got=%v want=%v", val, expectedInt)
                return res, nil
            }
            // string compare
            sExp := fmt.Sprintf("%v", expected)
            if vs, ok := val.(string); ok && vs == sExp {
                res.Pass = true
                res.Status = "pass"
                res.Message = "values equal"
                return res, nil
            }
            res.Pass = false
            res.Status = "fail"
            res.Message = fmt.Sprintf("string mismatch: got=%v want=%v", val, sExp)
            return res, nil
        }
    case "contains":
        // contains operates on string form
        sVal := fmt.Sprintf("%v", val)
        sExp := fmt.Sprintf("%v", rule.Expected)
        if strings.Contains(sVal, sExp) {
            res.Pass = true
            res.Status = "pass"
            res.Message = "value contains expected"
            return res, nil
        }
        res.Pass = false
        res.Status = "fail"
        res.Message = fmt.Sprintf("%q does not contain %q", sVal, sExp)
        return res, nil
    case "gt", "lt":
        // numeric comparison only
        expectedInt, ok := toInt(rule.Expected)
        if !ok {
            res.Status = "error"
            res.Err = "expected value is not an int for numeric comparison"
            res.Message = res.Err
            return res, nil
        }
        vi, ok := val.(int)
        if !ok {
            res.Status = "error"
            res.Err = "extracted value is not an int for numeric comparison"
            res.Message = res.Err
            return res, nil
        }
        if strings.ToLower(rule.Condition) == "gt" {
            if vi > expectedInt {
                res.Pass = true
                res.Status = "pass"
                res.Message = "value greater than expected"
                return res, nil
            }
            res.Pass = false
            res.Status = "fail"
            res.Message = fmt.Sprintf("%d is not greater than %d", vi, expectedInt)
            return res, nil
        }
        // lt
        if vi < expectedInt {
            res.Pass = true
            res.Status = "pass"
            res.Message = "value less than expected"
            return res, nil
        }
        res.Pass = false
        res.Status = "fail"
        res.Message = fmt.Sprintf("%d is not less than %d", vi, expectedInt)
        return res, nil
    default:
        res.Status = "error"
        res.Err = fmt.Sprintf("unsupported condition: %s", rule.Condition)
        res.Message = res.Err
        return res, nil
    }
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
