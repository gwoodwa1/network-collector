package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/itchyny/gojq"
)

const (
	defaultEnrichmentTimeout   = 2 * time.Second
	defaultEnrichmentMaxOutput = 1024 * 1024
	maxEnrichmentExpression    = 1024 * 1024
)

func enrichmentExpression(config EnrichmentConfig, baseDir string) (string, error) {
	inline := strings.TrimSpace(config.Expression)
	file := strings.TrimSpace(config.ExpressionFile)
	if inline != "" && file != "" {
		return "", fmt.Errorf("enrich.expression and enrich.expression_file are mutually exclusive")
	}
	if inline != "" {
		if len(inline) > maxEnrichmentExpression {
			return "", fmt.Errorf("inline enrichment expression exceeds %d bytes", maxEnrichmentExpression)
		}
		return inline, nil
	}
	if file == "" {
		return "", fmt.Errorf("enrich requires expression or expression_file")
	}
	file, err := resolveReadWithin(baseDir, file)
	if err != nil {
		return "", fmt.Errorf("resolve enrichment expression %q: %w", config.ExpressionFile, err)
	}
	info, err := os.Stat(file)
	if err != nil {
		return "", fmt.Errorf("read enrichment expression %q: %w", file, err)
	}
	if info.Size() > maxEnrichmentExpression {
		return "", fmt.Errorf("enrichment expression %q exceeds %d bytes", file, maxEnrichmentExpression)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read enrichment expression %q: %w", file, err)
	}
	if strings.TrimSpace(string(content)) == "" {
		return "", fmt.Errorf("enrichment expression %q is empty", file)
	}
	return string(content), nil
}

func enrichJSON(input string, config EnrichmentConfig, baseDir string) (string, error) {
	engine := strings.ToLower(strings.TrimSpace(config.Engine))
	if engine != "" && engine != "gojq" {
		return "", fmt.Errorf("unsupported enrichment engine %q", config.Engine)
	}
	if config.TimeoutSeconds < 0 {
		return "", fmt.Errorf("enrich.timeout_seconds must be greater than or equal to 0")
	}
	if config.MaxOutputBytes < 0 {
		return "", fmt.Errorf("enrich.max_output_bytes must be greater than or equal to 0")
	}

	var document interface{}
	if err := json.Unmarshal([]byte(input), &document); err != nil {
		return "", fmt.Errorf("enrichment input is not valid JSON: %w", err)
	}
	expression, err := enrichmentExpression(config, baseDir)
	if err != nil {
		return "", err
	}
	query, err := gojq.Parse(expression)
	if err != nil {
		return "", fmt.Errorf("parse gojq enrichment expression: %w", err)
	}
	code, err := gojq.Compile(query, gojq.WithVariables([]string{"$params"}))
	if err != nil {
		return "", fmt.Errorf("compile gojq enrichment expression: %w", err)
	}

	timeout := defaultEnrichmentTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	iter := code.RunWithContext(ctx, document, config.Variables)
	result, ok := iter.Next()
	if !ok {
		return "", fmt.Errorf("gojq enrichment expression produced no result")
	}
	if evalErr, ok := result.(error); ok {
		return "", fmt.Errorf("evaluate gojq enrichment expression: %w", evalErr)
	}
	if extra, ok := iter.Next(); ok {
		if evalErr, isErr := extra.(error); isErr {
			return "", fmt.Errorf("evaluate gojq enrichment expression: %w", evalErr)
		}
		return "", fmt.Errorf("gojq enrichment expression must produce exactly one result")
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("gojq enrichment expression timed out after %s", timeout)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode enriched JSON: %w", err)
	}
	maxOutput := config.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = defaultEnrichmentMaxOutput
	}
	if len(encoded) > maxOutput {
		return "", fmt.Errorf("enriched JSON is %d bytes, exceeding limit of %d bytes", len(encoded), maxOutput)
	}
	return string(encoded), nil
}
