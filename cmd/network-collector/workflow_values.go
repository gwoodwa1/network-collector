package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/validation"
)

var templateVariablePattern = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

func newApprovalInput(reader io.Reader) *approvalInput {
	return &approvalInput{scanner: bufio.NewScanner(reader)}
}

func readApprovalAnswer(input *approvalInput) approvalAnswer {
	if input.scanner.Scan() {
		return approvalAnswer{text: input.scanner.Text()}
	}
	err := input.scanner.Err()
	if err == nil {
		err = io.EOF
	}
	return approvalAnswer{err: err}
}

func renderTemplate(input string, vars map[string]string) (string, error) {
	missing := map[string]bool{}

	output := templateVariablePattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := templateVariablePattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		name := parts[1]
		value, ok := vars[name]
		if !ok {
			missing[name] = true
			return match
		}
		return value
	})

	if len(missing) > 0 {
		keys := make([]string, 0, len(missing))
		for key := range missing {
			keys = append(keys, key)
		}
		return output, fmt.Errorf("undefined variables: %s", strings.Join(keys, ", "))
	}

	return output, nil
}

func renderExpectedValue(expected interface{}, vars map[string]string) (interface{}, error) {
	if s, ok := expected.(string); ok && strings.Contains(s, "{{") {
		rendered, err := renderTemplate(s, vars)
		if err != nil {
			return nil, err
		}
		return rendered, nil
	}
	return expected, nil
}

func evaluateWhen(config *WhenConfig, vars map[string]string) (bool, error) {
	if config == nil {
		return true, nil
	}
	name := strings.TrimSpace(config.Variable)
	if name == "" {
		return false, fmt.Errorf("when.variable cannot be empty")
	}
	actual, ok := vars[name]
	if !ok {
		return false, fmt.Errorf("when references undefined variable %q", name)
	}
	expected, err := renderExpectedValue(config.Expected, vars)
	if err != nil {
		return false, fmt.Errorf("render when.expected: %w", err)
	}
	condition := strings.TrimSpace(config.Condition)
	if condition == "" {
		condition = "eq"
	}
	result, err := validation.ValidateOutput(actual, validation.ValidationRule{
		Extractor: "regex", Pattern: `(?s)^(.*)$`, Condition: condition,
		Expected: expected, ExpectedType: config.ExpectedType,
	})
	if err != nil {
		return false, err
	}
	if result.Status == "error" {
		return false, fmt.Errorf("invalid when condition: %s", result.Message)
	}
	return result.Pass, nil
}

func variableString(value interface{}) (string, error) {
	if value == nil {
		return "", nil
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	switch value.(type) {
	case map[string]interface{}, []interface{}, map[interface{}]interface{}:
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	default:
		return fmt.Sprintf("%v", value), nil
	}
}

func scopedVariables(vars map[string]string, values map[string]string, run func() bool) bool {
	type previous struct {
		value  string
		exists bool
	}
	saved := make(map[string]previous, len(values))
	for name, value := range values {
		old, ok := vars[name]
		saved[name] = previous{old, ok}
		vars[name] = value
	}
	stopped := run()
	for name, old := range saved {
		if old.exists {
			vars[name] = old.value
		} else {
			delete(vars, name)
		}
	}
	return stopped
}

func cloneVariables(vars map[string]string) map[string]string {
	cloned := make(map[string]string, len(vars))
	for key, value := range vars {
		cloned[key] = value
	}
	return cloned
}

func requestApproval(ctx *stepExecutionContext, config ApprovalConfig, stepName string) (bool, error) {
	if config.TimeoutSeconds < 0 {
		return false, fmt.Errorf("approval.timeout_seconds must be greater than or equal to 0")
	}
	message, err := renderTemplate(strings.TrimSpace(config.Message), ctx.variables)
	if err != nil {
		return false, err
	}
	if message == "" {
		message = "Approve this workflow step?"
	}
	if ctx.approveAll {
		writeSessionf(ctx.sessionLog, "[step:%s] approval granted by --approve-all: %s\n", stepName, message)
		return true, nil
	}
	if ctx.approvalInput == nil {
		return false, fmt.Errorf("approval requires an interactive terminal or --approve-all")
	}
	ctx.approvalInput.mu.Lock()
	defer ctx.approvalInput.mu.Unlock()
	if ctx.approvalInput.expired {
		return false, fmt.Errorf("approval input disabled after a previous timeout")
	}
	writer := ctx.approvalWriter
	if writer == nil {
		writer = io.Discard
	}
	fmt.Fprintf(writer, "device=%s step=%s %s [y/N] ", ctx.hostname, stepName, message)
	var response approvalAnswer
	if config.TimeoutSeconds > 0 {
		answers := make(chan approvalAnswer, 1)
		go func() {
			answers <- readApprovalAnswer(ctx.approvalInput)
		}()
		select {
		case response = <-answers:
		case <-time.After(time.Duration(config.TimeoutSeconds) * time.Second):
			ctx.approvalInput.expired = true
			return false, fmt.Errorf("approval timed out after %d seconds", config.TimeoutSeconds)
		}
	} else {
		response = readApprovalAnswer(ctx.approvalInput)
	}
	if response.err != nil && response.err != io.EOF {
		return false, fmt.Errorf("read approval: %w", response.err)
	}
	approved := strings.EqualFold(strings.TrimSpace(response.text), "y") || strings.EqualFold(strings.TrimSpace(response.text), "yes")
	if !approved {
		return false, fmt.Errorf("approval denied")
	}
	writeSessionf(ctx.sessionLog, "[step:%s] approval granted: %s\n", stepName, message)
	return true, nil
}
