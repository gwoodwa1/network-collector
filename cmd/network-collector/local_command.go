package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func executeLocalCommand(config LocalCommandConfig, vars map[string]string) (string, string, error) {
	if config.TimeoutSeconds < 0 {
		return "", "", fmt.Errorf("local.timeout_seconds must be greater than or equal to 0")
	}
	tempDir, err := os.MkdirTemp("", "network-collector-local-*")
	if err != nil {
		return "", "", fmt.Errorf("create local command workspace: %w", err)
	}
	defer os.RemoveAll(tempDir)

	localVars := make(map[string]string, len(vars)+len(config.Inputs))
	for key, value := range vars {
		localVars[key] = value
	}
	inputNames := make([]string, 0, len(config.Inputs))
	for name := range config.Inputs {
		inputNames = append(inputNames, name)
	}
	sort.Strings(inputNames)
	validName := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	for _, name := range inputNames {
		if !validName.MatchString(name) {
			return "", "", fmt.Errorf("local input name %q must be a valid template variable", name)
		}
		content, err := renderTemplate(config.Inputs[name], vars)
		if err != nil {
			return "", "", fmt.Errorf("render local input %q: %w", name, err)
		}
		path := filepath.Join(tempDir, name+".input")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return "", "", fmt.Errorf("write local input %q: %w", name, err)
		}
		localVars[name] = path
	}

	command, err := renderTemplate(strings.TrimSpace(config.Command), localVars)
	if err != nil {
		return "", "", fmt.Errorf("render local command: %w", err)
	}
	if command == "" {
		return "", "", fmt.Errorf("local.command cannot be empty")
	}
	args := make([]string, len(config.Args))
	for index, arg := range config.Args {
		args[index], err = renderTemplate(arg, localVars)
		if err != nil {
			return "", "", fmt.Errorf("render local argument %d: %w", index+1, err)
		}
	}

	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = tempDir
	output, runErr := cmd.CombinedOutput()
	display := strings.Join(append([]string{command}, args...), " ")
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), display, fmt.Errorf("local command timed out after %s", timeout)
	}
	if runErr != nil {
		return string(output), display, fmt.Errorf("local command failed: %w", runErr)
	}
	return string(output), display, nil
}
