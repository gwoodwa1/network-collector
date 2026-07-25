package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type netconfStepExecutor interface {
	ExecuteNETCONF(NETCONFStepConfig) (string, error)
}

func renderNETCONFStep(config NETCONFStepConfig, vars map[string]string, baseDir string) (NETCONFStepConfig, error) {
	var err error
	config.Operation, err = renderTemplate(strings.TrimSpace(config.Operation), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF operation: %w", err)
	}
	config.Target, err = renderTemplate(strings.TrimSpace(config.Target), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF target: %w", err)
	}
	config.PayloadFile, err = renderTemplate(strings.TrimSpace(config.PayloadFile), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF payload_file: %w", err)
	}
	if strings.TrimSpace(config.Payload) != "" && config.PayloadFile != "" {
		return NETCONFStepConfig{}, fmt.Errorf("netconf.payload and netconf.payload_file are mutually exclusive")
	}
	if config.PayloadFile != "" {
		path := config.PayloadFile
		if !filepath.IsAbs(path) && strings.TrimSpace(baseDir) != "" {
			path = filepath.Join(baseDir, path)
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return NETCONFStepConfig{}, fmt.Errorf("read NETCONF payload_file %q: %w", config.PayloadFile, readErr)
		}
		config.Payload = string(payload)
	}
	config.Payload, err = renderTemplate(strings.TrimSpace(config.Payload), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF payload: %w", err)
	}
	return config, nil
}

func validateNETCONFStep(config NETCONFStepConfig) error {
	operation := strings.ToLower(strings.TrimSpace(config.Operation))
	if operation == "" {
		operation = "rpc"
	}
	switch operation {
	case "rpc":
		if config.Payload == "" {
			return fmt.Errorf("netconf.payload or netconf.payload_file is required for rpc")
		}
		if config.Target != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 {
			return fmt.Errorf("NETCONF rpc does not support target or confirmed-commit fields")
		}
	case "edit-config", "edit_config":
		if config.Payload == "" {
			return fmt.Errorf("netconf.payload or netconf.payload_file is required for edit-config")
		}
		target := strings.ToLower(strings.TrimSpace(config.Target))
		if target != "" && target != "candidate" && target != "running" {
			return fmt.Errorf("unsupported NETCONF edit-config target %q", config.Target)
		}
		if config.Confirmed || config.ConfirmTimeoutSeconds != 0 {
			return fmt.Errorf("NETCONF edit-config does not support confirmed-commit fields")
		}
	case "commit":
		if config.Payload != "" || config.PayloadFile != "" || config.Target != "" {
			return fmt.Errorf("NETCONF commit does not support payload, payload_file, or target")
		}
		if config.ConfirmTimeoutSeconds < 0 {
			return fmt.Errorf("netconf.confirm_timeout_seconds must be greater than or equal to 0")
		}
		if config.ConfirmTimeoutSeconds > 0 && !config.Confirmed {
			return fmt.Errorf("netconf.confirmed must be true when confirm_timeout_seconds is set")
		}
	case "discard", "discard-changes", "discard_changes":
		if config.Payload != "" || config.PayloadFile != "" || config.Target != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 {
			return fmt.Errorf("NETCONF discard-changes does not support payload, payload_file, target, or confirmed-commit fields")
		}
	default:
		return fmt.Errorf("unsupported NETCONF operation %q", config.Operation)
	}
	return nil
}

func executeNETCONFStep(ctx *stepExecutionContext, config NETCONFStepConfig) (string, string, error) {
	rendered, err := renderNETCONFStep(config, ctx.variables, ctx.configBaseDir)
	if err != nil {
		return "", "", err
	}
	if err := validateNETCONFStep(rendered); err != nil {
		return "", "", err
	}
	if ctx.netconf == nil {
		return "", "", fmt.Errorf("NETCONF executor is not configured")
	}
	operation := strings.ToLower(strings.TrimSpace(rendered.Operation))
	if operation == "" {
		operation = "rpc"
	}
	display := "netconf " + operation
	if rendered.Target != "" {
		display += " target=" + rendered.Target
	}
	output, err := ctx.netconf.ExecuteNETCONF(rendered)
	return output, display, err
}
