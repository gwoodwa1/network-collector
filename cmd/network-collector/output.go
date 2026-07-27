package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/validation"
)

func sanitizeLogName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		isSafe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if isSafe {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}

	sanitized := strings.Trim(b.String(), "_")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

func outputEnabled(config Config, devices []DeviceConfig) bool {
	if config.Output.SaveRaw || config.Output.SaveParsed || strings.TrimSpace(config.Output.SummaryFile) != "" || strings.TrimSpace(config.Output.EventsFile) != "" || len(config.Output.EventSinks) > 0 {
		return true
	}
	for _, device := range devices {
		for _, step := range device.Steps {
			if step.Output != nil && (step.Output.SaveRaw != nil || step.Output.SaveParsed != nil) {
				return true
			}
		}
	}
	return false
}

func prepareRunOutput(config OutputConfig, runID string) (string, error) {
	directory := strings.TrimSpace(config.Directory)
	if directory == "" {
		directory = "artifacts"
	}
	if config.RetentionDays < 0 {
		return "", fmt.Errorf("output.retention_days must be greater than or equal to 0")
	}
	runDir, err := resolveWriteWithin(".", filepath.Join(directory, runID))
	if err != nil {
		return "", fmt.Errorf("resolve output directory: %w", err)
	}
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	if err := os.Chmod(runDir, 0700); err != nil {
		return "", fmt.Errorf("failed to secure output directory: %w", err)
	}
	if config.RetentionDays > 0 {
		if err := pruneManagedOutputs(filepath.Dir(runDir), "run-", config.RetentionDays, time.Now()); err != nil {
			return "", fmt.Errorf("prune expired run outputs: %w", err)
		}
	}
	return runDir, nil
}

func pruneManagedOutputs(directory, prefix string, retentionDays int, now time.Time) error {
	if retentionDays <= 0 {
		return nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			if err := os.Remove(path); err != nil {
				return err
			}
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func pruneSessionLogs(retentionDays int, now time.Time) error {
	if retentionDays <= 0 {
		return nil
	}
	checkPath, err := resolveWriteWithin(".", filepath.Join("session_logs", ".retention-check"))
	if err != nil {
		return fmt.Errorf("resolve session log directory: %w", err)
	}
	return pruneManagedOutputs(filepath.Dir(checkPath), "", retentionDays, now)
}

func stepOutputEnabled(global bool, override *bool) bool {
	if override != nil {
		return *override
	}
	return global
}

func atomicWriteFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".network-collector-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func saveStepArtifact(ctx *stepExecutionContext, step StepConfig, stepName string, attempt int, kind, content string) error {
	if ctx == nil || strings.TrimSpace(ctx.runDir) == "" {
		return nil
	}
	enabled := ctx.output.SaveRaw
	extension := "raw.txt"
	artifactKind := kind
	var override *bool
	if step.Output != nil {
		override = step.Output.SaveRaw
	}
	if kind == "parsed" {
		enabled = ctx.output.SaveParsed
		extension = "parsed.json"
		if step.Output != nil {
			override = step.Output.SaveParsed
		}
	}
	if kind == "drift" {
		enabled = true
		extension = "drift.json"
		override = nil
	}
	if kind == "raw" && step.Ensure != nil && ctx.reportEnabled {
		enabled = true
		extension = "plan.json"
		artifactKind = "plan"
		override = nil
	}
	if !stepOutputEnabled(enabled, override) {
		return nil
	}

	deviceDir := fmt.Sprintf("%03d-%s", ctx.deviceIndex+1, sanitizeLogName(ctx.hostname))
	ctx.artifactSeq++
	prefix := ""
	if ctx.artifactPrefix != "" {
		prefix = sanitizeLogName(ctx.artifactPrefix) + "."
	}
	filename := fmt.Sprintf("%s%s.artifact-%03d.attempt-%03d.%s", prefix, sanitizeLogName(stepName), ctx.artifactSeq, attempt, extension)
	path := filepath.Join(ctx.runDir, deviceDir, filename)
	if err := atomicWriteFile(path, []byte(content)); err != nil {
		return fmt.Errorf("failed to save %s output: %w", kind, err)
	}
	if ctx.artifacts != nil {
		*ctx.artifacts = append(*ctx.artifacts, outputArtifact{
			Hostname: ctx.hostname, IP: ctx.ip, Step: stepName, Attempt: attempt, Kind: artifactKind, Path: path,
		})
	}
	ctx.events.emit(lifecycleEvent{Type: "artifact.written", Hostname: ctx.hostname, IP: ctx.ip, Step: stepName, Data: map[string]interface{}{"attempt": attempt, "kind": artifactKind, "path": path}})
	return nil
}

func writeRunSummary(config OutputConfig, runDir string, summary runSummary) (string, error) {
	filename := strings.TrimSpace(config.SummaryFile)
	if filename == "" {
		return "", nil
	}
	path, err := resolveWriteWithin(runDir, filename)
	if err != nil {
		return "", fmt.Errorf("resolve summary output: %w", err)
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := atomicWriteFile(path, encoded); err != nil {
		return "", err
	}
	return path, nil
}

func formatSessionBanner(playbookName, hostname string, started time.Time) string {
	title := strings.TrimSpace(playbookName)
	if title == "" {
		title = "Network Collector Session"
	}

	width := 78
	line := strings.Repeat("=", width)
	return fmt.Sprintf(
		"%s\n%s\n%s\nHostname: %s\nStarted:  %s\n%s\n\n",
		line,
		centerASCII(title, width),
		line,
		strings.TrimSpace(hostname),
		started.Format(time.RFC3339),
		line,
	)
}

func centerASCII(value string, width int) string {
	if len(value) >= width {
		return value
	}
	left := (width - len(value)) / 2
	return strings.Repeat(" ", left) + value
}

func openSessionLog(hostname, playbookName string, started time.Time) (*os.File, string, error) {
	if _, err := resolveWriteWithin(".", filepath.Join("session_logs", ".permission-check")); err != nil {
		return nil, "", fmt.Errorf("resolve session log directory: %w", err)
	}
	if err := os.MkdirAll("session_logs", 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create session log directory: %w", err)
	}
	if err := os.Chmod("session_logs", 0700); err != nil {
		return nil, "", fmt.Errorf("failed to secure session log directory: %w", err)
	}
	if err := ensureFailureLog(failureLogPath()); err != nil {
		return nil, "", err
	}

	filename := fmt.Sprintf("%s_%s.log", sanitizeLogName(hostname), started.Format("20060102_150405"))
	path := "session_logs/" + filename
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create session log file: %w", err)
	}

	if _, err := file.WriteString(formatSessionBanner(playbookName, hostname, started)); err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("failed to write session log banner: %w", err)
	}

	return file, path, nil
}

func failureLogPath() string {
	return filepath.Join("session_logs", "FAILURES.txt")
}

func ensureFailureLog(path string) error {
	if strings.TrimSpace(path) == "" {
		path = failureLogPath()
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create failure log file: %w", err)
	}
	return file.Close()
}

func formatFailureLogEntry(ctx *stepExecutionContext, stepName string, overall validation.ValidationResult, results []validation.ValidationResult) string {
	return formatFailureRecord(ctx.hostname, ctx.ip, stepName, overall, results)
}

func formatFailureRecord(hostname, ip, stepName string, overall validation.ValidationResult, results []validation.ValidationResult) string {
	var b strings.Builder
	b.WriteString(strings.Repeat("=", 78))
	b.WriteByte('\n')
	b.WriteString(fmt.Sprintf("Time:     %s\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	b.WriteString(fmt.Sprintf("IP:       %s\n", ip))
	if strings.TrimSpace(stepName) != "" {
		b.WriteString(fmt.Sprintf("Step:     %s\n", stepName))
	}
	b.WriteString(fmt.Sprintf("Status:   %s\n", overall.Status))
	if strings.TrimSpace(overall.Message) != "" {
		b.WriteString(fmt.Sprintf("Message:  %s\n", overall.Message))
	}

	failed := make([]validation.ValidationResult, 0, len(results))
	for _, result := range results {
		if isFailureResult(result) {
			failed = append(failed, result)
		}
	}
	if len(failed) > 0 {
		b.WriteString("Validation results:\n")
		for idx, result := range failed {
			jb, _ := json.MarshalIndent(result, "  ", "  ")
			b.WriteString(fmt.Sprintf("  [%d]\n%s\n", idx+1, string(jb)))
		}
	}
	b.WriteByte('\n')
	return b.String()
}

func appendFailureRecord(path, hostname, ip, stepName, status, message string, results []validation.ValidationResult) error {
	failureLogMu.Lock()
	defer failureLogMu.Unlock()

	if strings.TrimSpace(path) == "" {
		path = failureLogPath()
	}
	if strings.TrimSpace(status) == "" {
		status = "error"
	}
	overall := validation.ValidationResult{
		Pass:      false,
		Status:    status,
		Message:   strings.TrimSpace(message),
		Timestamp: time.Now(),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create failure log directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to secure failure log directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open failure log file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(protectHumanOutput(formatFailureRecord(hostname, ip, stepName, overall, results))); err != nil {
		return fmt.Errorf("failed to write failure log entry: %w", err)
	}
	return nil
}

func appendFailureLog(ctx *stepExecutionContext, stepName string, overall validation.ValidationResult, results []validation.ValidationResult) error {
	if ctx == nil {
		return nil
	}
	path := strings.TrimSpace(ctx.failureLog)
	if path == "" {
		path = failureLogPath()
	}
	return appendFailureRecord(path, ctx.hostname, ctx.ip, stepName, overall.Status, overall.Message, results)
}

func appendFailureMessage(ctx *stepExecutionContext, stepName, status, message string) error {
	if ctx == nil {
		return nil
	}
	return appendFailureRecord(ctx.failureLog, ctx.hostname, ctx.ip, stepName, status, message, nil)
}

func writeSessionf(writer io.Writer, format string, args ...interface{}) {
	if writer == nil {
		return
	}
	_, _ = fmt.Fprintf(writer, format, args...)
}

var sensitiveLogPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(password|passwd|secret|community|token)\b(\s*[:=]\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?is)<(?:password|secret|community|token)(?:\s[^>]*)?>.*?</(?:password|secret|community|token)>`),
}

func protectHumanOutput(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 && r != 0x7f {
			return r
		}
		return -1
	}, value)
	for _, pattern := range sensitiveLogPatterns {
		value = pattern.ReplaceAllString(value, "$1$2[REDACTED]")
	}
	return value
}

func outputMetadata(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("[output omitted; bytes=%d sha256=%x]", len(value), digest)
}

func writeProtectedOutput(ctx *stepExecutionContext, header, value string) {
	if ctx == nil {
		return
	}
	display := outputMetadata(value)
	if ctx.sessionOutput {
		display = protectHumanOutput(value)
	}
	writeSessionf(ctx.sessionLog, "%s\n%s\n", protectHumanOutput(header), display)
	if !ctx.jsonOut {
		console := outputMetadata(value)
		if ctx.consoleOutput {
			console = protectHumanOutput(value)
		}
		fmt.Printf("%s\n%s\n", protectHumanOutput(header), console)
	}
}

func logStepMessage(ctx *stepExecutionContext, stepName, messageTemplate string) error {
	if strings.TrimSpace(messageTemplate) == "" {
		return nil
	}
	message, err := renderTemplate(messageTemplate, ctx.variables)
	if err != nil {
		return err
	}
	writeSessionf(ctx.sessionLog, "[step:%s] message: %s\n", stepName, protectHumanOutput(message))
	if !ctx.jsonOut {
		fmt.Printf("device=%s step=%s message=%q\n", ctx.hostname, stepName, protectHumanOutput(message))
	}
	return nil
}
