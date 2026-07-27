package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	gnmidriver "github.com/gwoodwa1/network-collector/pkg/drivers/gnmi"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
	"github.com/gwoodwa1/network-collector/pkg/validation"
)

func waitDuration(waitSeconds int) (time.Duration, error) {
	if waitSeconds < 0 {
		return 0, fmt.Errorf("wait_seconds must be greater than or equal to 0")
	}
	return time.Duration(waitSeconds) * time.Second, nil
}

func shouldReturnToPrompt(returnToPrompt *bool) bool {
	return returnToPrompt == nil || *returnToPrompt
}

func validationActionForResult(step StepConfig, result validation.ValidationResult) *ValidationActionConfig {
	if result.Status == "pass" {
		return step.OnPass
	}
	if result.Status == "fail" || result.Status == "error" {
		return step.OnFail
	}
	return nil
}

func stepValidations(step StepConfig) []ValidationConfig {
	validations := []ValidationConfig{}
	if step.Validation != nil {
		validations = append(validations, *step.Validation)
	}
	validations = append(validations, step.Validations...)
	return validations
}

func registerParserOutput(vars map[string]string, step StepConfig, parsedOutput string) bool {
	name := strings.TrimSpace(step.Register)
	if name == "" {
		return false
	}
	vars[name] = parsedOutput
	return true
}

func variableScopeKey(hostname, ip string) string {
	return strings.TrimSpace(hostname) + "\x00" + strings.TrimSpace(ip)
}

func overallValidationResult(results []validation.ValidationResult) validation.ValidationResult {
	if len(results) == 0 {
		return validation.ValidationResult{}
	}

	overall := validation.ValidationResult{
		Pass:      true,
		Status:    "pass",
		Message:   "all validations passed",
		Timestamp: time.Now(),
	}
	for _, result := range results {
		if result.Status == "error" {
			overall.Pass = false
			overall.Status = "error"
			overall.Message = "one or more validations errored"
			return overall
		}
		if !result.Pass || result.Status == "fail" {
			overall.Pass = false
			overall.Status = "fail"
			overall.Message = "one or more validations failed"
			return overall
		}
	}
	return overall
}

func isFailureResult(result validation.ValidationResult) bool {
	return result.Status == "fail" || result.Status == "error" || !result.Pass && result.Status != ""
}

func recordStepFailure(ctx *stepExecutionContext, stepName, message string) {
	if ctx == nil {
		return
	}
	if err := appendFailureMessage(ctx, stepName, "error", message); err != nil {
		if ctx.runFailed != nil {
			*ctx.runFailed = true
		}
		slog.Error("error writing failure log", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
		writeSessionf(ctx.sessionLog, "[step:%s] failed to write failure log: %v\n", stepName, err)
	}
}

func validationErrorResult(err error) validation.ValidationResult {
	return validation.ValidationResult{
		Pass:      false,
		Status:    "error",
		Message:   err.Error(),
		Err:       err.Error(),
		Timestamp: time.Now(),
	}
}

func runStepValidations(output string, rules []ValidationConfig, vars map[string]string) ([]validation.ValidationResult, validation.ValidationResult, error) {
	results := []validation.ValidationResult{}
	for _, cfg := range rules {
		pattern, err := renderTemplate(cfg.Pattern, vars)
		if err != nil {
			wrapped := fmt.Errorf("error rendering validation pattern: %w", err)
			results = append(results, validationErrorResult(wrapped))
			return results, overallValidationResult(results), wrapped
		}

		jsonPath, err := renderTemplate(cfg.JSONPath, vars)
		if err != nil {
			wrapped := fmt.Errorf("error rendering validation json_path: %w", err)
			results = append(results, validationErrorResult(wrapped))
			return results, overallValidationResult(results), wrapped
		}

		expected, err := renderExpectedValue(cfg.Expected, vars)
		if err != nil {
			wrapped := fmt.Errorf("error rendering validation expected value: %w", err)
			results = append(results, validationErrorResult(wrapped))
			return results, overallValidationResult(results), wrapped
		}

		rule := validation.ValidationRule{
			Extractor:    cfg.Extractor,
			Pattern:      pattern,
			JSONPath:     jsonPath,
			Condition:    cfg.Condition,
			Expected:     expected,
			ExpectedType: cfg.ExpectedType,
		}

		vres, verr := validation.ValidateOutput(output, rule)
		if verr != nil {
			if vres.Status == "" {
				vres = validationErrorResult(verr)
			}
			results = append(results, vres)
			return results, overallValidationResult(results), verr
		}
		results = append(results, vres)
	}
	return results, overallValidationResult(results), nil
}

func stringToBoolDecodeHook(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
	if from.Kind() != reflect.String || to.Kind() != reflect.Bool {
		return data, nil
	}

	switch strings.ToLower(strings.TrimSpace(data.(string))) {
	case "yes", "y":
		return true, nil
	case "no", "n":
		return false, nil
	default:
		value, err := strconv.ParseBool(strings.TrimSpace(data.(string)))
		if err != nil {
			return data, nil
		}
		return value, nil
	}
}

type resolvedSSHProbe struct {
	Port     int
	Interval time.Duration
	Attempts int
	Timeout  time.Duration
	PostWait time.Duration
}

func resolveSSHProbeConfig(cfg *SSHProbeConfig) (resolvedSSHProbe, error) {
	probe := resolvedSSHProbe{
		Port:     22,
		Interval: 30 * time.Second,
		Attempts: 20,
		Timeout:  5 * time.Second,
	}
	if cfg == nil {
		return probe, nil
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return probe, fmt.Errorf("ssh_probe.port must be between 1 and 65535")
	}
	if cfg.Port > 0 {
		probe.Port = cfg.Port
	}
	if cfg.IntervalSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.interval_seconds must be greater than or equal to 0")
	}
	if cfg.IntervalSeconds > 0 {
		probe.Interval = time.Duration(cfg.IntervalSeconds) * time.Second
	}
	if cfg.MaxAttempts < 0 {
		return probe, fmt.Errorf("ssh_probe.max_attempts must be greater than or equal to 0")
	}
	if cfg.MaxAttempts > 0 {
		probe.Attempts = cfg.MaxAttempts
	}
	if cfg.TimeoutSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.timeout_seconds must be greater than or equal to 0")
	}
	if cfg.TimeoutSeconds > 0 {
		probe.Timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	if cfg.PostWaitSeconds < 0 {
		return probe, fmt.Errorf("ssh_probe.post_wait_seconds must be greater than or equal to 0")
	}
	if cfg.PostWaitSeconds > 0 {
		probe.PostWait = time.Duration(cfg.PostWaitSeconds) * time.Second
	}
	return probe, nil
}

func sshProbeAddress(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

func waitForSSHPort(host string, cfg *SSHProbeConfig) error {
	probe, err := resolveSSHProbeConfig(cfg)
	if err != nil {
		return err
	}

	address := sshProbeAddress(host, probe.Port)
	var lastErr error
	for attempt := 1; attempt <= probe.Attempts; attempt++ {
		conn, err := net.DialTimeout("tcp", address, probe.Timeout)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		if attempt < probe.Attempts {
			time.Sleep(probe.Interval)
		}
	}
	return fmt.Errorf("ssh probe failed for %s after %d attempts: %w", address, probe.Attempts, lastErr)
}

func closeSSHClient(client *ssh.Client) error {
	if client == nil {
		return nil
	}
	return client.Close()
}

func commandExecutor(ctx *stepExecutionContext, client **ssh.Client) sshEnsureCommandExecutor {
	if ctx != nil && ctx.sshCommand != nil {
		return ctx.sshCommand
	}
	if client == nil || *client == nil {
		return nil
	}
	return *client
}

type validationActionOutcome struct {
	StopDevice bool
	RunFailed  bool
}

func executeValidationAction(ctx *stepExecutionContext, client **ssh.Client, action *ValidationActionConfig, stepName string) (validationActionOutcome, error) {
	if action == nil {
		return validationActionOutcome{}, nil
	}

	if strings.TrimSpace(action.Message) != "" {
		message, err := renderTemplate(action.Message, ctx.variables)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action message: %w", err)
		}
		writeSessionf(ctx.sessionLog, "[step:%s] action: %s\n", stepName, protectHumanOutput(message))
		if !ctx.jsonOut {
			fmt.Printf("device=%s step=%s action=%q\n", ctx.hostname, stepName, protectHumanOutput(message))
		}
	}

	actionName := strings.ToLower(strings.TrimSpace(action.Action))
	if actionName == "" && strings.TrimSpace(action.Command) != "" {
		actionName = "cmd"
	}
	if actionName == "" && len(action.Steps) > 0 {
		actionName = "steps"
	}

	switch actionName {
	case "", "none", "noop", "no_op":
		return validationActionOutcome{}, nil
	case "exit", "stop":
		return validationActionOutcome{StopDevice: true}, nil
	case "fail":
		return validationActionOutcome{StopDevice: true, RunFailed: true}, nil
	case "cmd", "command", "run":
		if client == nil || *client == nil {
			return validationActionOutcome{}, fmt.Errorf("cannot run validation action command without an active SSH session")
		}
		cmd, err := renderTemplate(strings.TrimSpace(action.Command), ctx.variables)
		if err != nil {
			return validationActionOutcome{}, fmt.Errorf("error rendering action command: %w", err)
		}
		if cmd == "" {
			return validationActionOutcome{}, fmt.Errorf("validation action command cannot be empty")
		}
		output, err := (*client).Execute(cmd)
		if err != nil {
			return validationActionOutcome{}, err
		}
		writeProtectedOutput(ctx, fmt.Sprintf("[step:%s] action command=%q", stepName, cmd), output)
		if err := saveStepArtifact(ctx, StepConfig{Output: action.Output}, stepName+"-action", 1, "raw", output); err != nil {
			return validationActionOutcome{}, err
		}
		if len(action.Steps) == 0 {
			return validationActionOutcome{}, nil
		}
		fallthrough
	case "steps":
		if len(action.Steps) == 0 {
			return validationActionOutcome{}, nil
		}
		if executeSteps(ctx, client, action.Steps) {
			return validationActionOutcome{StopDevice: true}, nil
		}
		return validationActionOutcome{}, nil
	default:
		return validationActionOutcome{}, fmt.Errorf("unsupported validation action: %s", action.Action)
	}
}

const (
	maxRepeatCount   = 1000
	maxRepeatDepth   = 3
	maxWorkflowDepth = 20
)

func repeatStopsOnFailure(config RepeatConfig) bool {
	return config.StopOnFailure == nil || *config.StopOnFailure
}

func validateRepeatConfig(config RepeatConfig, depth int) error {
	if depth > maxRepeatDepth {
		return fmt.Errorf("repeat nesting exceeds maximum depth of %d", maxRepeatDepth)
	}
	if config.Count < 1 {
		return fmt.Errorf("repeat.count must be at least 1")
	}
	if config.Count > maxRepeatCount {
		return fmt.Errorf("repeat.count must not exceed %d", maxRepeatCount)
	}
	if config.Count > 1 && config.IntervalSeconds < 1 {
		return fmt.Errorf("repeat.interval_seconds must be at least 1 when count is greater than 1")
	}
	if config.IntervalSeconds < 0 {
		return fmt.Errorf("repeat.interval_seconds must be greater than or equal to 0")
	}
	if len(config.Steps) == 0 {
		return fmt.Errorf("repeat.steps must contain at least one step")
	}
	for _, step := range config.Steps {
		if step.Retry != nil && step.Retry.UntilPass && step.Retry.MaxAttempts < 1 {
			return fmt.Errorf("repeat step %q uses retry.until_pass without a finite max_attempts", strings.TrimSpace(step.Name))
		}
		if step.Repeat != nil {
			if err := validateRepeatConfig(*step.Repeat, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func executeRepeat(ctx *stepExecutionContext, client **ssh.Client, config RepeatConfig, stepName string, depth int, sleep func(time.Duration)) bool {
	if err := validateRepeatConfig(config, depth); err != nil {
		*ctx.runFailed = true
		slog.Error("invalid repeat step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
		recordStepFailure(ctx, stepName, fmt.Sprintf("invalid repeat step: %v", err))
		return true
	}

	interval := time.Duration(config.IntervalSeconds) * time.Second
	for iteration := 1; iteration <= config.Count; iteration++ {
		slog.Info("starting repeat iteration", "hostname", ctx.hostname, "step", stepName, "iteration", iteration, "count", config.Count)
		writeSessionf(ctx.sessionLog, "[step:%s] repeat iteration %d/%d\n", stepName, iteration, config.Count)

		iterationFailed := false
		iterationCtx := *ctx
		iterationCtx.runFailed = &iterationFailed
		iterationStopped := executeStepsAtDepth(&iterationCtx, client, config.Steps, depth)
		ctx.artifactSeq = iterationCtx.artifactSeq
		if iterationStopped {
			if iterationFailed {
				*ctx.runFailed = true
			}
			return true
		}
		if iterationFailed {
			*ctx.runFailed = true
			if repeatStopsOnFailure(config) {
				slog.Warn("stopping repeat after failed iteration", "hostname", ctx.hostname, "step", stepName, "iteration", iteration)
				writeSessionf(ctx.sessionLog, "[step:%s] repeat stopped after failed iteration %d/%d\n", stepName, iteration, config.Count)
				break
			}
		}

		if iteration < config.Count {
			slog.Info("waiting between repeat iterations", "hostname", ctx.hostname, "step", stepName, "duration", interval)
			writeSessionf(ctx.sessionLog, "[step:%s] waiting %s before repeat iteration %d/%d\n", stepName, interval, iteration+1, config.Count)
			sleep(interval)
		}
	}
	return false
}

func executeSteps(ctx *stepExecutionContext, client **ssh.Client, steps []StepConfig) bool {
	return executeStepsAtDepth(ctx, client, steps, 0)
}

func foreachItems(config ForeachConfig, vars map[string]string) ([]interface{}, error) {
	if len(config.Items) > 0 && strings.TrimSpace(config.From) != "" {
		return nil, fmt.Errorf("foreach cannot define both items and from")
	}
	if strings.TrimSpace(config.From) != "" {
		raw, ok := vars[strings.TrimSpace(config.From)]
		if !ok {
			return nil, fmt.Errorf("foreach.from references undefined variable %q", config.From)
		}
		var items []interface{}
		if err := json.Unmarshal([]byte(raw), &items); err != nil {
			return nil, fmt.Errorf("foreach.from variable %q must contain a JSON array: %w", config.From, err)
		}
		return items, nil
	}
	if config.Items == nil {
		return nil, fmt.Errorf("foreach requires items or from")
	}
	return config.Items, nil
}

func executeForeach(ctx *stepExecutionContext, client **ssh.Client, config ForeachConfig, stepName string, depth int) bool {
	if len(config.Steps) == 0 {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, "foreach.steps must contain at least one step")
		return false
	}
	items, err := foreachItems(config, ctx.variables)
	if err != nil {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, err.Error())
		return false
	}
	itemName, indexName := strings.TrimSpace(config.Item), strings.TrimSpace(config.Index)
	if itemName == "" {
		itemName = "item"
	}
	if indexName == "" {
		indexName = "index"
	}
	validName := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if !validName.MatchString(itemName) || !validName.MatchString(indexName) || itemName == indexName {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, "foreach item and index must be distinct valid variable names")
		return false
	}
	stopOnFailure := config.StopOnFailure == nil || *config.StopOnFailure
	for index, item := range items {
		value, err := variableString(item)
		if err != nil {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, err.Error())
			break
		}
		iterationFailed := false
		iterationCtx := *ctx
		iterationCtx.runFailed = &iterationFailed
		stopped := scopedVariables(ctx.variables, map[string]string{itemName: value, indexName: strconv.Itoa(index)}, func() bool {
			return executeStepsAtDepth(&iterationCtx, client, config.Steps, depth)
		})
		ctx.artifactSeq = iterationCtx.artifactSeq
		if iterationFailed {
			*ctx.runFailed = true
		}
		if stopped {
			return true
		}
		if iterationFailed && stopOnFailure {
			break
		}
	}
	return false
}

func executeWorkflow(ctx *stepExecutionContext, client **ssh.Client, step StepConfig, stepName string, depth int) bool {
	name := strings.TrimSpace(step.Use)
	workflow, ok := ctx.workflows[name]
	if !ok {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, fmt.Sprintf("unknown workflow %q", name))
		return false
	}
	if depth > maxWorkflowDepth {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, fmt.Sprintf("workflow nesting exceeds %d", maxWorkflowDepth))
		return true
	}
	bindings := map[string]string{}
	allowed := map[string]bool{}
	for _, parameter := range workflow.Parameters {
		parameter = strings.TrimSpace(parameter)
		allowed[parameter] = true
		value, exists := step.With[parameter]
		if !exists {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, fmt.Sprintf("workflow %q missing parameter %q", name, parameter))
			return false
		}
		text, err := variableString(value)
		if err != nil {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, err.Error())
			return false
		}
		text, err = renderTemplate(text, ctx.variables)
		if err != nil {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, err.Error())
			return false
		}
		bindings[parameter] = text
	}
	for parameter := range step.With {
		if !allowed[parameter] {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, fmt.Sprintf("workflow %q has no parameter %q", name, parameter))
			return false
		}
	}
	return scopedVariables(ctx.variables, bindings, func() bool { return executeStepsAtDepth(ctx, client, workflow.Steps, depth) })
}

func stepsNeedSSH(steps []StepConfig, workflows map[string]WorkflowConfig, seen map[string]bool) bool {
	for _, step := range steps {
		if ensureUsesSSH(step.Ensure) {
			return true
		}
		if step.Facts != nil {
			return true
		}
		if strings.TrimSpace(step.Command) != "" {
			return true
		}
		if step.SSHProbe != nil {
			return true
		}
		if step.GNMISubscribe != nil {
			for _, trigger := range step.GNMISubscribe.Triggers {
				if stepsNeedSSH(trigger.Steps, workflows, seen) {
					return true
				}
			}
		}
		if step.Repeat != nil && stepsNeedSSH(step.Repeat.Steps, workflows, seen) {
			return true
		}
		if step.Foreach != nil && stepsNeedSSH(step.Foreach.Steps, workflows, seen) {
			return true
		}
		if step.Block != nil && (stepsNeedSSH(step.Block.Steps, workflows, seen) || stepsNeedSSH(step.Block.Rescue, workflows, seen) || stepsNeedSSH(step.Block.Rollback, workflows, seen) || stepsNeedSSH(step.Block.Always, workflows, seen)) {
			return true
		}
		if step.Parallel != nil && stepsNeedSSH(step.Parallel.Steps, workflows, seen) {
			return true
		}
		name := strings.TrimSpace(step.Use)
		if name != "" && !seen[name] {
			seen[name] = true
			workflow, ok := workflows[name]
			if ok && stepsNeedSSH(workflow.Steps, workflows, seen) {
				return true
			}
		}
	}
	return false
}

func stepsNeedSSHInCheck(steps []StepConfig, workflows map[string]WorkflowConfig, seen map[string]bool) bool {
	for _, step := range steps {
		if ensureUsesSSH(step.Ensure) {
			return true
		}
		if step.GNMISubscribe != nil {
			for _, trigger := range step.GNMISubscribe.Triggers {
				if stepsNeedSSHInCheck(trigger.Steps, workflows, seen) {
					return true
				}
			}
		}
		if step.Repeat != nil && stepsNeedSSHInCheck(step.Repeat.Steps, workflows, seen) {
			return true
		}
		if step.Foreach != nil && stepsNeedSSHInCheck(step.Foreach.Steps, workflows, seen) {
			return true
		}
		if step.Block != nil && (stepsNeedSSHInCheck(step.Block.Steps, workflows, seen) || stepsNeedSSHInCheck(step.Block.Rescue, workflows, seen) || stepsNeedSSHInCheck(step.Block.Rollback, workflows, seen) || stepsNeedSSHInCheck(step.Block.Always, workflows, seen)) {
			return true
		}
		if step.Parallel != nil && stepsNeedSSHInCheck(step.Parallel.Steps, workflows, seen) {
			return true
		}
		name := strings.TrimSpace(step.Use)
		if name != "" && !seen[name] {
			seen[name] = true
			workflow, ok := workflows[name]
			if ok && stepsNeedSSHInCheck(workflow.Steps, workflows, seen) {
				return true
			}
		}
	}
	return false
}

func ensureUsesSSH(config *EnsureConfig) bool {
	return config != nil && strings.EqualFold(strings.TrimSpace(config.Transport), "ssh")
}

type parallelBranchResult struct {
	index           int
	failed, stopped bool
	variables       map[string]string
	validations     []deviceValidation
	artifacts       []outputArtifact
	log             string
}

func executeParallel(ctx *stepExecutionContext, config ParallelConfig, stepName string, depth int) bool {
	if depth > maxWorkflowDepth {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, fmt.Sprintf("parallel nesting exceeds %d control levels", maxWorkflowDepth))
		return true
	}
	if len(config.Steps) == 0 {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, "parallel.steps must contain at least one step")
		return false
	}
	limit := config.MaxParallel
	if limit == 0 || limit > len(config.Steps) {
		limit = len(config.Steps)
	}
	if limit < 1 || limit > 16 {
		*ctx.runFailed = true
		recordStepFailure(ctx, stepName, "parallel.max_parallel must be between 1 and 16")
		return false
	}
	base := cloneVariables(ctx.variables)
	results := make(chan parallelBranchResult, len(config.Steps))
	semaphore := make(chan struct{}, limit)
	for index, branch := range config.Steps {
		go func(index int, branch StepConfig) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			failed := false
			validations := []deviceValidation{}
			artifacts := []outputArtifact{}
			var log bytes.Buffer
			branchCtx := *ctx
			branchCtx.variables = cloneVariables(base)
			branchCtx.runFailed = &failed
			branchCtx.aggregated = &validations
			branchCtx.artifacts = &artifacts
			branchCtx.sessionLog = &log
			branchCtx.artifactSeq = 0
			branchCtx.artifactPrefix = fmt.Sprintf("parallel-%02d", index+1)
			branchNETCONF := &lazyNETCONFExecutor{
				host: ctx.ip, username: ctx.username, password: ctx.password, timeout: 30 * time.Second,
			}
			branchCtx.netconf = branchNETCONF
			var client *ssh.Client
			needsSSH := ctx.sshCommand == nil && stepsNeedSSH([]StepConfig{branch}, ctx.workflows, map[string]bool{})
			if ctx.checkMode {
				needsSSH = ctx.sshCommand == nil && stepsNeedSSHInCheck([]StepConfig{branch}, ctx.workflows, map[string]bool{})
			}
			if needsSSH {
				client = ssh.NewClient(ctx.opts...)
				if err := client.Connect(ctx.ip, ctx.username, ctx.password, ctx.deviceType); err != nil {
					failed = true
					writeSessionf(&log, "parallel SSH connection failed: %v\n", err)
				}
			}
			stopped := false
			if !failed {
				stopped = executeStepsAtDepth(&branchCtx, &client, []StepConfig{branch}, depth)
			}
			if client != nil {
				if err := closeSSHClient(client); err != nil {
					failed = true
					writeSessionf(&log, "parallel SSH close failed: %v\n", err)
				}
			}
			if err := branchNETCONF.Close(); err != nil {
				failed = true
				writeSessionf(&log, "parallel NETCONF close failed: %v\n", err)
			}
			if hasUnrecoveredValidationFailure(&validations, 0) {
				failed = true
			}
			results <- parallelBranchResult{index: index, failed: failed, stopped: stopped, variables: branchCtx.variables, validations: validations, artifacts: artifacts, log: log.String()}
		}(index, branch)
	}
	ordered := make([]parallelBranchResult, len(config.Steps))
	for range config.Steps {
		result := <-results
		ordered[result.index] = result
	}
	changed := map[string]string{}
	stop := false
	for _, result := range ordered {
		writeSessionf(ctx.sessionLog, "[step:%s] parallel branch %d\n%s", stepName, result.index+1, result.log)
		*ctx.aggregated = append(*ctx.aggregated, result.validations...)
		if ctx.artifacts != nil {
			*ctx.artifacts = append(*ctx.artifacts, result.artifacts...)
		}
		if result.failed {
			*ctx.runFailed = true
		}
		stop = stop || result.stopped
		for key, value := range result.variables {
			if original, exists := base[key]; exists && original == value {
				continue
			}
			if prior, exists := changed[key]; exists && prior != value {
				*ctx.runFailed = true
				recordStepFailure(ctx, stepName, fmt.Sprintf("parallel branches produced conflicting values for %q", key))
				continue
			}
			changed[key] = value
		}
	}
	for key, value := range changed {
		ctx.variables[key] = value
	}
	return stop
}

func hasUnrecoveredValidationFailure(validations *[]deviceValidation, start int) bool {
	if validations == nil {
		return false
	}
	for index := start; index < len(*validations); index++ {
		if !(*validations)[index].Recovered && isFailureResult((*validations)[index].Result) {
			return true
		}
	}
	return false
}

func executeBlock(ctx *stepExecutionContext, client **ssh.Client, config BlockConfig, depth int) bool {
	if len(config.Rescue) > 0 && len(config.Rollback) > 0 {
		*ctx.runFailed = true
		recordStepFailure(ctx, "block", "block cannot define both rescue and rollback")
		return false
	}
	validationStart := 0
	if ctx.aggregated != nil {
		validationStart = len(*ctx.aggregated)
	}
	blockFailed := false
	blockCtx := *ctx
	blockCtx.runFailed = &blockFailed
	stopped := executeStepsAtDepth(&blockCtx, client, config.Steps, depth)
	ctx.artifactSeq = blockCtx.artifactSeq
	blockFailed = blockFailed || hasUnrecoveredValidationFailure(ctx.aggregated, validationStart)
	recovery := config.Rescue
	if len(config.Rollback) > 0 {
		recovery = config.Rollback
		writeSessionf(ctx.sessionLog, "[block] starting rollback\n")
	}
	if blockFailed && len(recovery) > 0 {
		validationEnd := validationStart
		if ctx.aggregated != nil {
			validationEnd = len(*ctx.aggregated)
		}
		rescueFailed := false
		rescueCtx := *ctx
		rescueCtx.runFailed = &rescueFailed
		rescueStopped := executeStepsAtDepth(&rescueCtx, client, recovery, depth)
		ctx.artifactSeq = rescueCtx.artifactSeq
		rescueFailed = rescueFailed || hasUnrecoveredValidationFailure(ctx.aggregated, validationEnd)
		blockFailed = rescueFailed
		if !rescueFailed && ctx.aggregated != nil {
			for index := validationStart; index < validationEnd; index++ {
				if isFailureResult((*ctx.aggregated)[index].Result) {
					(*ctx.aggregated)[index].Recovered = true
				}
			}
		}
		stopped = stopped || rescueStopped
	}
	if len(config.Always) > 0 {
		alwaysStart := 0
		if ctx.aggregated != nil {
			alwaysStart = len(*ctx.aggregated)
		}
		alwaysFailed := false
		alwaysCtx := *ctx
		alwaysCtx.runFailed = &alwaysFailed
		alwaysStopped := executeStepsAtDepth(&alwaysCtx, client, config.Always, depth)
		ctx.artifactSeq = alwaysCtx.artifactSeq
		alwaysFailed = alwaysFailed || hasUnrecoveredValidationFailure(ctx.aggregated, alwaysStart)
		blockFailed = blockFailed || alwaysFailed
		stopped = stopped || alwaysStopped
	}
	if blockFailed {
		*ctx.runFailed = true
	}
	return stopped
}

func executeStepsAtDepth(ctx *stepExecutionContext, client **ssh.Client, steps []StepConfig, depth int) bool {
	stopDeviceSteps := false
	for _, step := range steps {
		stepName := strings.TrimSpace(step.Name)
		if stepName == "" {
			stepName = "unnamed"
		}
		ctx.events.emit(lifecycleEvent{Type: "step.started", Hostname: ctx.hostname, IP: ctx.ip, Step: stepName})

		run, err := evaluateWhen(step.When, ctx.variables)
		if err != nil {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, err.Error())
			continue
		}
		if !run {
			writeSessionf(ctx.sessionLog, "[step:%s] skipped by when condition\n", stepName)
			continue
		}

		if err := logStepMessage(ctx, stepName, step.Message); err != nil {
			*ctx.runFailed = true
			slog.Error("error rendering step message", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			writeSessionf(ctx.sessionLog, "[step:%s] message error: %v\n", stepName, err)
			recordStepFailure(ctx, stepName, fmt.Sprintf("message error: %v", err))
			continue
		}

		if step.Approval != nil {
			if strings.TrimSpace(step.Command) != "" || step.Facts != nil || step.GNMISubscribe != nil || step.NETCONF != nil || step.Ensure != nil || step.Drift != nil || step.Repeat != nil || step.Foreach != nil || strings.TrimSpace(step.Use) != "" || step.Block != nil || step.Parallel != nil || step.SSHProbe != nil || step.WaitSeconds != 0 || len(stepValidations(step)) > 0 {
				*ctx.runFailed = true
				recordStepFailure(ctx, stepName, "approval step cannot define executable or other control fields")
				continue
			}
			if ctx.checkMode {
				writeSessionf(ctx.sessionLog, "[step:%s] [check] approval gate skipped\n", stepName)
				continue
			}
			if _, err := requestApproval(ctx, *step.Approval, stepName); err != nil {
				*ctx.runFailed = true
				recordStepFailure(ctx, stepName, err.Error())
				return true
			}
			continue
		}

		controlCount := 0
		if step.Repeat != nil {
			controlCount++
		}
		if step.Foreach != nil {
			controlCount++
		}
		if strings.TrimSpace(step.Use) != "" {
			controlCount++
		}
		if step.Block != nil {
			controlCount++
		}
		if step.Parallel != nil {
			controlCount++
		}
		if controlCount > 1 || (controlCount > 0 && (strings.TrimSpace(step.Command) != "" || step.Facts != nil || step.GNMISubscribe != nil || step.NETCONF != nil || step.Ensure != nil || step.Drift != nil || step.WaitSeconds != 0 || step.SSHProbe != nil || len(stepValidations(step)) > 0)) {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, "control step must define exactly one of repeat, foreach, use, block, or parallel and no executable fields")
			continue
		}
		if step.Foreach != nil {
			if executeForeach(ctx, client, *step.Foreach, stepName, depth+1) {
				return true
			}
			continue
		}
		if strings.TrimSpace(step.Use) != "" {
			if executeWorkflow(ctx, client, step, stepName, depth+1) {
				return true
			}
			continue
		}
		if step.Block != nil {
			if executeBlock(ctx, client, *step.Block, depth+1) {
				return true
			}
			continue
		}
		if step.Parallel != nil {
			if executeParallel(ctx, *step.Parallel, stepName, depth+1) {
				return true
			}
			continue
		}

		if step.Repeat != nil {
			if strings.TrimSpace(step.Command) != "" || step.Facts != nil || step.GNMISubscribe != nil || step.NETCONF != nil || step.Ensure != nil || step.Drift != nil || step.WaitSeconds != 0 || step.SSHProbe != nil || len(stepValidations(step)) > 0 {
				*ctx.runFailed = true
				stopDeviceSteps = true
				err := fmt.Errorf("repeat step cannot also define cmd, local, wait_seconds, ssh_probe, or validations")
				slog.Error("invalid repeat step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				recordStepFailure(ctx, stepName, err.Error())
				break
			}
			if executeRepeat(ctx, client, *step.Repeat, stepName, depth+1, time.Sleep) {
				stopDeviceSteps = true
				break
			}
			continue
		}

		if step.Facts != nil {
			if strings.TrimSpace(step.Command) != "" || step.GNMISubscribe != nil || step.NETCONF != nil || step.Ensure != nil || step.WaitSeconds != 0 || step.SSHProbe != nil || len(stepValidations(step)) > 0 {
				*ctx.runFailed = true
				recordStepFailure(ctx, stepName, "facts step cannot also define cmd, local, wait_seconds, ssh_probe, or validations")
				continue
			}
			if ctx.checkMode {
				writeSessionf(ctx.sessionLog, "[step:%s] [check] facts collection skipped\n", stepName)
				continue
			}
			if err := executeFactsStep(ctx, client, step, stepName); err != nil {
				*ctx.runFailed = true
				recordStepFailure(ctx, stepName, err.Error())
			}
			continue
		}
		if step.GNMISubscribe != nil && (strings.TrimSpace(step.Command) != "" || step.WaitSeconds != 0 || step.SSHProbe != nil) {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, "gnmi_subscribe step cannot also define cmd, local, wait_seconds, or ssh_probe")
			continue
		}
		if step.NETCONF != nil && (strings.TrimSpace(step.Command) != "" || step.GNMISubscribe != nil || step.Ensure != nil || step.WaitSeconds != 0 || step.SSHProbe != nil) {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, "netconf step cannot also define cmd, local, gnmi_subscribe, wait_seconds, or ssh_probe")
			continue
		}
		if step.Ensure != nil && (strings.TrimSpace(step.Command) != "" || step.GNMISubscribe != nil || step.NETCONF != nil || step.WaitSeconds != 0 || step.SSHProbe != nil) {
			*ctx.runFailed = true
			recordStepFailure(ctx, stepName, "ensure step cannot also define cmd, local, gnmi_subscribe, netconf, wait_seconds, or ssh_probe")
			continue
		}

		wait, err := waitDuration(step.WaitSeconds)
		if err != nil {
			*ctx.runFailed = true
			slog.Error("invalid wait step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			recordStepFailure(ctx, stepName, fmt.Sprintf("invalid wait step: %v", err))
			continue
		}
		if wait > 0 {
			if ctx.checkMode {
				writeSessionf(ctx.sessionLog, "\n[step:%s] [check] wait %s skipped\n", stepName, wait)
				wait = 0
			}
		}
		if wait > 0 {
			slog.Info("waiting before step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "duration", wait)
			writeSessionf(ctx.sessionLog, "\n[step:%s] waiting %s\n", stepName, wait)
			time.Sleep(wait)
		}

		if step.SSHProbe != nil {
			if ctx.checkMode {
				writeSessionf(ctx.sessionLog, "[step:%s] [check] SSH probe skipped\n", stepName)
				continue
			}
			probe, err := resolveSSHProbeConfig(step.SSHProbe)
			if err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("invalid SSH probe step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("invalid SSH probe step: %v", err))
				break
			}

			if err := closeSSHClient(*client); err != nil {
				slog.Warn("error closing stale SSH connection before probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] warning: failed to close stale SSH connection before probe: %v\n", stepName, err)
			}
			*client = nil

			slog.Info("probing SSH port", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			writeSessionf(ctx.sessionLog, "\n[step:%s] probing SSH port on %s\n", stepName, ctx.ip)
			if err := waitForSSHPort(ctx.ip, step.SSHProbe); err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("SSH probe failed", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] SSH probe failed: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("SSH probe failed: %v", err))
				break
			}
			writeSessionf(ctx.sessionLog, "[step:%s] SSH probe succeeded\n", stepName)

			if probe.PostWait > 0 {
				slog.Info("waiting after successful SSH probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "duration", probe.PostWait)
				writeSessionf(ctx.sessionLog, "[step:%s] waiting %s after successful SSH probe\n", stepName, probe.PostWait)
				time.Sleep(probe.PostWait)
			}

			*client = ssh.NewClient(ctx.opts...)
			username, password := ctx.username, ctx.password
			if ctx.reauthenticate != nil {
				username, password, err = ctx.reauthenticate()
				if err != nil {
					*ctx.runFailed = true
					stopDeviceSteps = true
					recordStepFailure(ctx, stepName, fmt.Sprintf("RSA re-authentication failed: %v", err))
					break
				}
			}
			if err := (*client).Connect(ctx.ip, username, password, ctx.deviceType); err != nil {
				*ctx.runFailed = true
				stopDeviceSteps = true
				slog.Error("error reconnecting to SSH device after probe", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] failed to reconnect after SSH probe: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("failed to reconnect after SSH probe: %v", err))
				break
			}
			writeSessionf(ctx.sessionLog, "[step:%s] SSH session re-established\n", stepName)
		}

		executableCount := 0
		if strings.TrimSpace(step.Command) != "" {
			executableCount++
		}
		if step.GNMISubscribe != nil {
			executableCount++
		}
		if step.NETCONF != nil {
			executableCount++
		}
		if step.Ensure != nil {
			executableCount++
		}
		if executableCount > 1 {
			*ctx.runFailed = true
			err := fmt.Errorf("step must define at most one of cmd, gnmi_subscribe, netconf, or ensure")
			slog.Error("invalid step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
			recordStepFailure(ctx, stepName, err.Error())
			continue
		}
		cmd := ""
		if step.GNMISubscribe == nil && step.NETCONF == nil && step.Ensure == nil {
			cmd, err = renderTemplate(strings.TrimSpace(step.Command), ctx.variables)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("error rendering command", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("command render error: %v", err))
				continue
			}
		}
		if cmd == "" && step.GNMISubscribe == nil && step.NETCONF == nil && step.Ensure == nil {
			if wait > 0 || step.SSHProbe != nil || strings.TrimSpace(step.Message) != "" {
				continue
			}
			*ctx.runFailed = true
			slog.Warn("skipping empty step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			recordStepFailure(ctx, stepName, "empty step command")
			continue
		}
		if ctx.checkMode && step.NETCONF == nil && step.Ensure == nil {
			kind := "SSH command"
			detail := cmd
			if step.GNMISubscribe != nil {
				kind = "gNMI subscription"
				detail = strings.Join(step.GNMISubscribe.Paths, ",")
			}
			message := fmt.Sprintf("[check] skipped %s %q", kind, strings.TrimSpace(detail))
			writeSessionf(ctx.sessionLog, "[step:%s] %s\n", stepName, message)
			if !ctx.jsonOut {
				fmt.Printf("device=%s step=%s %s\n", ctx.hostname, stepName, message)
			}
			continue
		}

		var finalResult validation.ValidationResult
		var finalValidationResults []validation.ValidationResult
		previewOnly := false
		if ctx.checkMode && step.NETCONF != nil {
			renderedNETCONF, renderErr := renderNETCONFStep(*step.NETCONF, ctx.variables, ctx.configBaseDir)
			if renderErr == nil {
				operation := strings.ToLower(strings.TrimSpace(renderedNETCONF.Operation))
				if operation == "" {
					operation = "rpc"
				}
				previewOnly = netconfCheckSkips(operation, renderedNETCONF.Payload)
			}
		}
		attempt := 0
		stepExecutionFailed := false
		for {
			attempt++

			sshExecutor := commandExecutor(ctx, client)
			if step.GNMISubscribe == nil && step.NETCONF == nil && step.Ensure == nil && sshExecutor == nil {
				*ctx.runFailed = true
				slog.Error("cannot execute step without an active SSH session", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
				writeSessionf(ctx.sessionLog, "\n[step:%s] command error: no active SSH session\n", stepName)
				recordStepFailure(ctx, stepName, "command error: no active SSH session")
				break
			}

			var output string
			var commandDisplay string
			if step.GNMISubscribe != nil {
				commandDisplay = strings.Join(step.GNMISubscribe.Paths, ",")
				output, err = executeGNMISubscribe(ctx, client, *step.GNMISubscribe, depth)
			} else if step.NETCONF != nil {
				output, commandDisplay, err = executeNETCONFStep(ctx, *step.NETCONF)
			} else if step.Ensure != nil {
				ensureExecutor := ctx.sshEnsure
				if ensureExecutor == nil && client != nil && *client != nil {
					ensureExecutor = *client
				}
				output, commandDisplay, err = executeEnsureStep(ctx, ensureExecutor, *step.Ensure)
			} else {
				commandDisplay = cmd
				output, err = sshExecutor.Execute(cmd)
			}
			if err != nil {
				if step.Ensure != nil && ctx.reportEnabled && strings.TrimSpace(output) != "" {
					if artifactErr := saveStepArtifact(ctx, step, stepName, attempt, "raw", output); artifactErr != nil {
						*ctx.runFailed = true
						slog.Error("error saving failed ensure plan", "hostname", ctx.hostname, "step", stepName, "error", artifactErr)
						writeSessionf(ctx.sessionLog, "[step:%s] report evidence error: %v\n", stepName, artifactErr)
					}
				}
				if step.GNMISubscribe == nil && step.NETCONF == nil && step.Ensure == nil && !shouldReturnToPrompt(step.ReturnToPrompt) {
					slog.Info("step ended without prompt as expected", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "\n[step:%s] command ended without prompt as expected: %v\n", stepName, err)
					if err := closeSSHClient(*client); err != nil {
						slog.Warn("error closing SSH connection after no-prompt step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
						writeSessionf(ctx.sessionLog, "[step:%s] warning: failed to close SSH connection after no-prompt step: %v\n", stepName, err)
					}
					*client = nil
					break
				}
				*ctx.runFailed = true
				stepExecutionFailed = true
				slog.Error("error executing step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeProtectedOutput(ctx, fmt.Sprintf("[step:%s] command error: %v", stepName, err), output)
				recordStepFailure(ctx, stepName, fmt.Sprintf("command error: %v", err))
				break
			}

			commandKind := "device"
			if step.GNMISubscribe != nil {
				commandKind = "gnmi_subscribe"
			} else if step.NETCONF != nil {
				commandKind = "netconf"
			} else if step.Ensure != nil {
				commandKind = "ensure"
			}
			writeProtectedOutput(ctx, fmt.Sprintf("[step:%s] %s command=%q", stepName, commandKind, commandDisplay), output)
			if err := saveStepArtifact(ctx, step, stepName, attempt, "raw", output); err != nil {
				*ctx.runFailed = true
				slog.Error("error saving raw command output", "hostname", ctx.hostname, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] output error: %v\n", stepName, err)
			}
			if previewOnly {
				break
			}

			validationOutput := output
			if strings.TrimSpace(step.Parser) != "" {
				parsedOutput, err := parseOutputWithModule(output, step.Parser, ctx.parsers)
				if err != nil {
					*ctx.runFailed = true
					slog.Error("parser error", "hostname", ctx.hostname, "step", stepName, "parser", step.Parser, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] parser %q error: %v\n", stepName, step.Parser, err)
					recordStepFailure(ctx, stepName, fmt.Sprintf("parser %q error: %v", step.Parser, err))
					break
				}
				validationOutput = parsedOutput
				writeProtectedOutput(ctx, fmt.Sprintf("[step:%s] parser %q output:", stepName, step.Parser), parsedOutput)
			}
			if step.Enrich != nil {
				enrichedOutput, err := enrichJSON(validationOutput, *step.Enrich, ctx.configBaseDir)
				if err != nil {
					*ctx.runFailed = true
					slog.Error("enrichment error", "hostname", ctx.hostname, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] enrichment error: %v\n", stepName, err)
					recordStepFailure(ctx, stepName, fmt.Sprintf("enrichment error: %v", err))
					break
				}
				validationOutput = enrichedOutput
				writeProtectedOutput(ctx, fmt.Sprintf("[step:%s] enriched output:", stepName), enrichedOutput)
			}
			if strings.TrimSpace(step.Parser) != "" || step.Enrich != nil {
				if err := saveStepArtifact(ctx, step, stepName, attempt, "parsed", validationOutput); err != nil {
					*ctx.runFailed = true
					slog.Error("error saving structured command output", "hostname", ctx.hostname, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] output error: %v\n", stepName, err)
				}
				if !ctx.jsonOut && ctx.consoleOutput {
					fmt.Printf("structured output for %s step=%s:\n%s\n", ctx.hostname, stepName, protectHumanOutput(validationOutput))
				}
			}
			if registerParserOutput(ctx.variables, step, validationOutput) {
				slog.Info("registered step output", "hostname", ctx.hostname, "step", stepName, "variable", strings.TrimSpace(step.Register), "metadata", outputMetadata(validationOutput))
			}
			if step.Drift != nil {
				if err := applyDriftCheck(ctx, step, stepName, validationOutput); err != nil {
					*ctx.runFailed = true
					recordStepFailure(ctx, stepName, fmt.Sprintf("drift check failed: %v", err))
					break
				}
			}

			validations := stepValidations(step)
			if len(validations) == 0 {
				break
			}

			results, overall, verr := runStepValidations(validationOutput, validations, ctx.variables)
			if verr != nil {
				*ctx.runFailed = true
				slog.Error("validation error", "hostname", ctx.hostname, "step", stepName, "error", verr)
			}

			finalResult = overall
			finalValidationResults = results

			for idx, vres := range results {
				if !ctx.jsonOut && ctx.consoleOutput {
					jb, _ := json.MarshalIndent(vres, "", "  ")
					fmt.Printf("validation result for %s step=%s validation=%d:\n%s\n", ctx.hostname, stepName, idx+1, protectHumanOutput(string(jb)))
				} else if !ctx.jsonOut {
					fmt.Printf("validation result for %s step=%s validation=%d status=%s pass=%t\n", ctx.hostname, stepName, idx+1, vres.Status, vres.Pass)
				}
				jb, _ := json.MarshalIndent(vres, "", "  ")
				if ctx.sessionOutput {
					writeSessionf(ctx.sessionLog, "[step:%s] validation result %d:\n%s\n", stepName, idx+1, protectHumanOutput(string(jb)))
				} else {
					writeSessionf(ctx.sessionLog, "[step:%s] validation result %d status=%s pass=%t %s\n", stepName, idx+1, vres.Status, vres.Pass, outputMetadata(string(jb)))
				}
				*ctx.aggregated = append(*ctx.aggregated, deviceValidation{Hostname: ctx.hostname, IP: ctx.ip, Result: vres})
				ctx.events.emit(lifecycleEvent{Type: "validation.completed", Hostname: ctx.hostname, IP: ctx.ip, Step: stepName, Data: map[string]interface{}{"status": vres.Status, "pass": vres.Pass}})
			}

			for _, vres := range results {
				if step.Register != "" && vres.RawExtract != "" {
					ctx.variables[step.Register] = vres.RawExtract
					slog.Info("registered variable", "hostname", ctx.hostname, "step", stepName, "variable", step.Register, "metadata", outputMetadata(vres.RawExtract))
					break
				}
			}

			retryCfg := step.Retry
			if retryCfg != nil && retryCfg.UntilPass && finalResult.Status == "fail" {
				if retryCfg.MaxAttempts > 0 && attempt >= retryCfg.MaxAttempts {
					slog.Warn("step reached max attempts", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "max_attempts", retryCfg.MaxAttempts)
					break
				}

				interval := time.Duration(retryCfg.IntervalSeconds) * time.Second
				if interval <= 0 {
					interval = 60 * time.Second
				}
				slog.Info("retrying step", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "interval", interval, "attempt", attempt+1)
				time.Sleep(interval)
				continue
			}

			break
		}

		if stepExecutionFailed && step.Ensure != nil {
			stopDeviceSteps = true
			slog.Info("stopping remaining steps after declarative ensure failure", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
			break
		}

		if !previewOnly && len(stepValidations(step)) > 0 {
			if isFailureResult(finalResult) {
				if err := appendFailureLog(ctx, stepName, finalResult, finalValidationResults); err != nil {
					*ctx.runFailed = true
					slog.Error("error writing failure log", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
					writeSessionf(ctx.sessionLog, "[step:%s] failed to write failure log: %v\n", stepName, err)
				}
			}

			action := validationActionForResult(step, finalResult)
			outcome, err := executeValidationAction(ctx, client, action, stepName)
			if err != nil {
				*ctx.runFailed = true
				slog.Error("validation action failed", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName, "error", err)
				writeSessionf(ctx.sessionLog, "[step:%s] validation action failed: %v\n", stepName, err)
				recordStepFailure(ctx, stepName, fmt.Sprintf("validation action failed: %v", err))
				break
			}
			if outcome.RunFailed {
				*ctx.runFailed = true
			}
			if outcome.StopDevice {
				stopDeviceSteps = true
				slog.Info("stopping remaining SSH steps after validation action", "hostname", ctx.hostname, "ip", ctx.ip, "step", stepName)
				break
			}
		}
	}
	return stopDeviceSteps
}

func executeGNMISubscribe(ctx *stepExecutionContext, sshClient **ssh.Client, config GNMISubscribeConfig, depth int) (string, error) {
	maxTriggerFires, triggerCooldown, err := validateGNMIExecutionBudget(config)
	if err != nil {
		return "", err
	}
	port := config.Port
	if port <= 0 && ctx.gnmi != nil {
		port = ctx.gnmi.Port
	}
	if port <= 0 {
		port = 57400
	}
	address := net.JoinHostPort(ctx.ip, strconv.Itoa(port))
	options := []gnmidriver.Option{}
	if ctx.gnmi != nil {
		if ctx.gnmi.Insecure != nil && *ctx.gnmi.Insecure && (ctx.gnmi.CAFile != "" || ctx.gnmi.CertFile != "" || ctx.gnmi.KeyFile != "" || ctx.gnmi.ServerName != "") {
			return "", fmt.Errorf("gNMI insecure plaintext mode cannot be combined with TLS certificate settings")
		}
		if ctx.gnmi.Insecure != nil {
			options = append(options, gnmidriver.WithInsecure(*ctx.gnmi.Insecure))
		}
		if ctx.gnmi.SkipVerify != nil {
			options = append(options, gnmidriver.WithSkipVerify(*ctx.gnmi.SkipVerify))
		}
		if ctx.gnmi.CAFile != "" || ctx.gnmi.CertFile != "" || ctx.gnmi.KeyFile != "" || ctx.gnmi.ServerName != "" {
			if (ctx.gnmi.CertFile == "") != (ctx.gnmi.KeyFile == "") {
				return "", fmt.Errorf("gNMI cert_file and key_file must be configured together")
			}
			options = append(options, gnmidriver.WithTLSCredentials(ctx.gnmi.CAFile, ctx.gnmi.CertFile, ctx.gnmi.KeyFile, ctx.gnmi.ServerName))
		}
	}
	if config.SkipTLS {
		options = append(options, gnmidriver.WithSkipTLS())
	}
	timeoutSeconds := config.TimeoutSeconds
	if timeoutSeconds <= 0 && ctx.gnmi != nil {
		timeoutSeconds = ctx.gnmi.TimeoutSeconds
	}
	if timeoutSeconds > 0 {
		options = append(options, gnmidriver.WithRequestTimeout(time.Duration(timeoutSeconds)*time.Second))
	}
	client := &gnmidriver.GNMIClient{}
	if err := client.Connect(address, ctx.username, ctx.password, options...); err != nil {
		return "", err
	}
	defer client.Close()
	subscription := gnmidriver.Subscription{
		Paths: config.Paths, Mode: config.Mode, StreamMode: config.StreamMode,
		SampleInterval:   time.Duration(config.SampleIntervalSeconds) * time.Second,
		Duration:         time.Duration(config.DurationSeconds) * time.Second,
		MaxUpdates:       config.MaxUpdates,
		MaxResponseBytes: config.MaxResponseBytes,
		MaxResponseCount: config.MaxResponseCount,
	}
	handler, err := gnmiTriggerHandlerWithBudget(ctx, sshClient, config.Triggers, depth, maxTriggerFires, triggerCooldown)
	if err != nil {
		return "", err
	}
	return client.SubscribeEvents(context.Background(), subscription, handler)
}

func gnmiTriggerHandler(ctx *stepExecutionContext, sshClient **ssh.Client, triggers []GNMITriggerConfig, depth int) (gnmidriver.EventHandler, error) {
	return gnmiTriggerHandlerWithBudget(ctx, sshClient, triggers, depth, defaultGNMITriggerFires, 0)
}

const (
	defaultGNMITriggerFires    = 5
	maxGNMITriggerFires        = 100
	defaultGNMITriggerCooldown = 30 * time.Second
	minGNMITriggerCooldown     = time.Second
	maxGNMITriggerCooldown     = time.Hour
	maxGNMIDeviceTriggerFires  = 100
)

func claimGNMIDeviceTriggerFire(ctx *stepExecutionContext) error {
	if ctx.gnmiActionBudget == nil {
		ctx.gnmiActionBudget = &gnmiDeviceActionBudget{}
	}
	ctx.gnmiActionBudget.mu.Lock()
	defer ctx.gnmiActionBudget.mu.Unlock()
	if ctx.gnmiActionBudget.fires >= maxGNMIDeviceTriggerFires {
		return fmt.Errorf("gNMI triggers exceeded the %d-fire per-device execution budget", maxGNMIDeviceTriggerFires)
	}
	ctx.gnmiActionBudget.fires++
	return nil
}

func validateGNMIExecutionBudget(config GNMISubscribeConfig) (int, time.Duration, error) {
	duration := time.Duration(config.DurationSeconds) * time.Second
	if config.DurationSeconds < 0 || duration > gnmidriver.MaxSubscriptionDuration {
		return 0, 0, fmt.Errorf("gnmi_subscribe.duration_seconds must be between 1 and %d", int(gnmidriver.MaxSubscriptionDuration/time.Second))
	}
	if config.MaxUpdates < 0 || config.MaxUpdates > gnmidriver.MaxSubscriptionUpdates {
		return 0, 0, fmt.Errorf("gnmi_subscribe.max_updates must be between 1 and %d", gnmidriver.MaxSubscriptionUpdates)
	}
	if config.MaxResponseBytes < 0 || config.MaxResponseBytes > gnmidriver.MaxSubscriptionResponseBytes {
		return 0, 0, fmt.Errorf("gnmi_subscribe.max_response_bytes must be between 1 and %d", gnmidriver.MaxSubscriptionResponseBytes)
	}
	if config.MaxResponseCount < 0 || config.MaxResponseCount > gnmidriver.MaxSubscriptionResponses {
		return 0, 0, fmt.Errorf("gnmi_subscribe.max_response_count must be between 1 and %d", gnmidriver.MaxSubscriptionResponses)
	}
	maxFires := config.MaxTriggerFires
	if maxFires == 0 {
		maxFires = defaultGNMITriggerFires
	}
	if maxFires < 1 || maxFires > maxGNMITriggerFires {
		return 0, 0, fmt.Errorf("gnmi_subscribe.max_trigger_fires must be between 1 and %d", maxGNMITriggerFires)
	}
	cooldown := time.Duration(config.TriggerCooldownSeconds) * time.Second
	if config.TriggerCooldownSeconds == 0 {
		cooldown = defaultGNMITriggerCooldown
	}
	if cooldown < minGNMITriggerCooldown || cooldown > maxGNMITriggerCooldown {
		return 0, 0, fmt.Errorf("gnmi_subscribe.trigger_cooldown_seconds must be between %d and %d", int(minGNMITriggerCooldown/time.Second), int(maxGNMITriggerCooldown/time.Second))
	}
	for _, trigger := range config.Triggers {
		if trigger.Once && trigger.Repeat {
			return 0, 0, fmt.Errorf("gNMI trigger %q cannot combine once and repeat", trigger.Name)
		}
	}
	return maxFires, cooldown, nil
}

func gnmiTriggerHandlerWithBudget(ctx *stepExecutionContext, sshClient **ssh.Client, triggers []GNMITriggerConfig, depth, maxFires int, cooldown time.Duration) (gnmidriver.EventHandler, error) {
	if len(triggers) == 0 {
		return nil, nil
	}
	if depth >= maxWorkflowDepth {
		return nil, fmt.Errorf("gNMI trigger nesting exceeds %d control levels", maxWorkflowDepth)
	}
	pathPatterns := make([]*regexp.Regexp, len(triggers))
	valuePatterns := make([]*regexp.Regexp, len(triggers))
	numericStates := make([]map[string]*gnmiNumericTriggerState, len(triggers))
	for index, trigger := range triggers {
		numericStates[index] = map[string]*gnmiNumericTriggerState{}
		if len(trigger.Steps) == 0 && !trigger.Fail {
			return nil, fmt.Errorf("gNMI trigger %q must contain at least one step", trigger.Name)
		}
		eventType := strings.ToLower(strings.TrimSpace(trigger.Event))
		if eventType != "" && eventType != "update" && eventType != "delete" {
			return nil, fmt.Errorf("gNMI trigger %q event must be update or delete", trigger.Name)
		}
		if strings.TrimSpace(trigger.Path) == "" && strings.TrimSpace(trigger.PathRegex) == "" {
			return nil, fmt.Errorf("gNMI trigger %q must define path or path_regex", trigger.Name)
		}
		if strings.TrimSpace(trigger.ValueNot) != "" && (strings.TrimSpace(trigger.Value) != "" || strings.TrimSpace(trigger.ValueRegex) != "") {
			return nil, fmt.Errorf("gNMI trigger %q value_not cannot be combined with value or value_regex", trigger.Name)
		}
		condition := strings.ToLower(strings.TrimSpace(trigger.Condition))
		if condition != "" && condition != "gt" && condition != "gte" && condition != "lt" && condition != "lte" && condition != "eq" && condition != "neq" {
			return nil, fmt.Errorf("gNMI trigger %q condition must be gt, gte, lt, lte, eq, or neq", trigger.Name)
		}
		if condition != "" && trigger.Threshold == nil {
			return nil, fmt.Errorf("gNMI trigger %q condition requires threshold", trigger.Name)
		}
		if condition == "" && trigger.Threshold != nil {
			return nil, fmt.Errorf("gNMI trigger %q threshold requires condition", trigger.Name)
		}
		if trigger.MaxDropPercent < 0 || trigger.MaxDropPercent > 100 {
			return nil, fmt.Errorf("gNMI trigger %q max_drop_percent must be greater than 0 and at most 100", trigger.Name)
		}
		if trigger.MaxDropPercent > 0 && condition != "" {
			return nil, fmt.Errorf("gNMI trigger %q cannot combine max_drop_percent with condition", trigger.Name)
		}
		if trigger.MaxDrop != nil && *trigger.MaxDrop <= 0 {
			return nil, fmt.Errorf("gNMI trigger %q max_drop must be greater than 0", trigger.Name)
		}
		if trigger.MaxDrop != nil && (trigger.MaxDropPercent > 0 || condition != "") {
			return nil, fmt.Errorf("gNMI trigger %q cannot combine max_drop with max_drop_percent or condition", trigger.Name)
		}
		if trigger.BaselineSamples < 0 {
			return nil, fmt.Errorf("gNMI trigger %q baseline_samples cannot be negative", trigger.Name)
		}
		if trigger.CounterRate && eventType == "delete" {
			return nil, fmt.Errorf("gNMI trigger %q counter_rate requires update events", trigger.Name)
		}
		if trigger.Once && trigger.Repeat {
			return nil, fmt.Errorf("gNMI trigger %q cannot combine once and repeat", trigger.Name)
		}
		var err error
		if pattern := strings.TrimSpace(trigger.PathRegex); pattern != "" {
			pathPatterns[index], err = regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("gNMI trigger %q has invalid path_regex: %w", trigger.Name, err)
			}
		}
		if pattern := strings.TrimSpace(trigger.ValueRegex); pattern != "" {
			valuePatterns[index], err = regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("gNMI trigger %q has invalid value_regex: %w", trigger.Name, err)
			}
		}
	}

	fired := make([]map[string]bool, len(triggers))
	for index := range fired {
		fired[index] = map[string]bool{}
	}
	fireCounts := make([]int, len(triggers))
	lastFired := make([]time.Time, len(triggers))
	return func(event gnmidriver.Event) error {
		for index, trigger := range triggers {
			effectiveOnce := trigger.Once || !trigger.Repeat
			if effectiveOnce && fired[index][event.Path] {
				continue
			}
			if event.Initial && !trigger.IncludeInitial {
				continue
			}
			eventType := strings.ToLower(strings.TrimSpace(trigger.Event))
			if eventType == "" {
				eventType = "update"
			}
			if event.Type != eventType {
				continue
			}
			if exact := strings.TrimSpace(trigger.Path); exact != "" && event.Path != exact {
				continue
			}
			if pathPatterns[index] != nil && !pathPatterns[index].MatchString(event.Path) {
				continue
			}
			valueText := fmt.Sprint(event.Value)
			if trigger.Value != "" && valueText != trigger.Value {
				continue
			}
			if trigger.ValueNot != "" && valueText == trigger.ValueNot {
				continue
			}
			if valuePatterns[index] != nil && !valuePatterns[index].MatchString(valueText) {
				continue
			}
			state := numericStates[index][event.Path]
			if state == nil {
				state = &gnmiNumericTriggerState{}
				numericStates[index][event.Path] = state
			}
			metricValue, baselineValue, thresholdValue, ready, err := state.match(trigger, event, valueText)
			if err != nil {
				return fmt.Errorf("gNMI trigger %q: %w", trigger.Name, err)
			}
			if !ready {
				continue
			}
			if fireCounts[index] >= maxFires {
				return fmt.Errorf("gNMI trigger %q exceeded its %d-fire execution budget", trigger.Name, maxFires)
			}
			now := time.Now()
			if trigger.Repeat && !lastFired[index].IsZero() && now.Sub(lastFired[index]) < cooldown {
				continue
			}
			if err := claimGNMIDeviceTriggerFire(ctx); err != nil {
				return err
			}

			fired[index][event.Path] = true
			fireCounts[index]++
			lastFired[index] = now
			eventJSON, err := json.Marshal(event)
			if err != nil {
				return err
			}
			name := strings.TrimSpace(trigger.Name)
			if name == "" {
				name = fmt.Sprintf("trigger-%d", index+1)
			}
			ctx.events.emit(lifecycleEvent{
				Type: "gnmi.triggered", Hostname: ctx.hostname, IP: ctx.ip, Step: name,
				Data: map[string]interface{}{
					"event": event.Type, "path": event.Path, "value_metadata": outputMetadata(valueText), "initial": event.Initial,
					"metric_value": metricValue, "baseline_value": baselineValue, "threshold_value": thresholdValue,
				},
			})
			eventValue := outputMetadata(valueText)
			if ctx.sessionOutput {
				eventValue = protectHumanOutput(valueText)
			}
			writeSessionf(ctx.sessionLog, "[gnmi:%s] event=%s path=%s value=%s metric=%s baseline=%s threshold=%s initial=%t\n", name, event.Type, event.Path, eventValue, metricValue, baselineValue, thresholdValue, event.Initial)
			bindings := map[string]string{
				"gnmi_event": string(eventJSON), "gnmi_event_type": event.Type,
				"gnmi_event_path": event.Path, "gnmi_event_value": valueText,
				"gnmi_metric_value": metricValue, "gnmi_baseline_value": baselineValue,
				"gnmi_threshold_value": thresholdValue,
			}
			if trigger.Fail {
				*ctx.runFailed = true
				recordStepFailure(ctx, name, fmt.Sprintf("gNMI trigger fired: path=%s metric=%s threshold=%s", event.Path, metricValue, thresholdValue))
			}
			scopedVariables(ctx.variables, bindings, func() bool {
				return executeStepsAtDepth(ctx, sshClient, trigger.Steps, depth+1)
			})
		}
		return nil
	}, nil
}

type gnmiNumericTriggerState struct {
	previousValue     float64
	previousTimestamp int64
	hasPrevious       bool
	baselineSum       float64
	baselineCount     int
	baseline          float64
}

func (state *gnmiNumericTriggerState) match(config GNMITriggerConfig, event gnmidriver.Event, valueText string) (metric, baseline, threshold string, ready bool, err error) {
	numeric := config.CounterRate || config.MaxDropPercent > 0 || config.MaxDrop != nil || strings.TrimSpace(config.Condition) != ""
	if !numeric {
		return valueText, "", "", true, nil
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(valueText), 64)
	if err != nil {
		return "", "", "", false, fmt.Errorf("value %q is not numeric", valueText)
	}
	metricValue := value
	if config.CounterRate {
		if !state.hasPrevious {
			state.previousValue = value
			state.previousTimestamp = event.Timestamp
			state.hasPrevious = true
			return "", "", "", false, nil
		}
		elapsed := float64(event.Timestamp-state.previousTimestamp) / float64(time.Second)
		delta := value - state.previousValue
		state.previousValue = value
		state.previousTimestamp = event.Timestamp
		if elapsed <= 0 {
			return "", "", "", false, fmt.Errorf("counter_rate requires increasing gNMI timestamps")
		}
		if delta < 0 {
			return "", "", "", false, nil
		}
		metricValue = delta / elapsed
	}
	metric = strconv.FormatFloat(metricValue, 'f', 2, 64)

	if config.MaxDropPercent > 0 || config.MaxDrop != nil {
		samples := config.BaselineSamples
		if samples == 0 {
			samples = 3
		}
		if state.baselineCount < samples {
			state.baselineSum += metricValue
			state.baselineCount++
			if state.baselineCount == samples {
				state.baseline = state.baselineSum / float64(samples)
			}
			return metric, strconv.FormatFloat(state.baseline, 'f', 2, 64), "", false, nil
		}
		limit := state.baseline
		if config.MaxDrop != nil {
			limit -= *config.MaxDrop
		} else {
			limit *= 1 - config.MaxDropPercent/100
		}
		baseline = strconv.FormatFloat(state.baseline, 'f', 2, 64)
		threshold = strconv.FormatFloat(limit, 'f', 2, 64)
		return metric, baseline, threshold, metricValue < limit, nil
	}

	limit := *config.Threshold
	threshold = strconv.FormatFloat(limit, 'f', 2, 64)
	switch strings.ToLower(strings.TrimSpace(config.Condition)) {
	case "gt":
		ready = metricValue > limit
	case "gte":
		ready = metricValue >= limit
	case "lt":
		ready = metricValue < limit
	case "lte":
		ready = metricValue <= limit
	case "eq":
		ready = metricValue == limit
	case "neq":
		ready = metricValue != limit
	}
	return metric, "", threshold, ready, nil
}
