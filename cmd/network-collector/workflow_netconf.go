package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

type netconfStepExecutor interface {
	Execute(string) (string, error)
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
	config.Source, err = renderTemplate(strings.TrimSpace(config.Source), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF source: %w", err)
	}
	config.Persist, err = renderTemplate(strings.TrimSpace(config.Persist), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF persist: %w", err)
	}
	config.PersistID, err = renderTemplate(strings.TrimSpace(config.PersistID), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF persist_id: %w", err)
	}
	config.PayloadFile, err = renderTemplate(strings.TrimSpace(config.PayloadFile), vars)
	if err != nil {
		return NETCONFStepConfig{}, fmt.Errorf("render NETCONF payload_file: %w", err)
	}
	if strings.TrimSpace(config.Payload) != "" && config.PayloadFile != "" {
		return NETCONFStepConfig{}, fmt.Errorf("netconf.payload and netconf.payload_file are mutually exclusive")
	}
	if config.PayloadFile != "" {
		path, pathErr := resolveReadWithin(baseDir, config.PayloadFile)
		if pathErr != nil {
			return NETCONFStepConfig{}, fmt.Errorf("resolve NETCONF payload_file %q: %w", config.PayloadFile, pathErr)
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
		if hasNETCONFControlFields(config) {
			return fmt.Errorf("NETCONF rpc does not support datastore or confirmed-commit fields")
		}
	case "edit-config", "edit_config":
		if config.Payload == "" {
			return fmt.Errorf("netconf.payload or netconf.payload_file is required for edit-config")
		}
		target := strings.ToLower(strings.TrimSpace(config.Target))
		if target != "" && target != "candidate" && target != "running" {
			return fmt.Errorf("unsupported NETCONF edit-config target %q", config.Target)
		}
		if config.Source != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != "" {
			return fmt.Errorf("NETCONF edit-config does not support source or confirmed-commit fields")
		}
	case "commit":
		if config.Payload != "" || config.PayloadFile != "" || config.Target != "" || config.Source != "" {
			return fmt.Errorf("NETCONF commit does not support payload, payload_file, target, or source")
		}
		if config.ConfirmTimeoutSeconds < 0 {
			return fmt.Errorf("netconf.confirm_timeout_seconds must be greater than or equal to 0")
		}
		if config.ConfirmTimeoutSeconds > 0 && !config.Confirmed {
			return fmt.Errorf("netconf.confirmed must be true when confirm_timeout_seconds is set")
		}
		if config.Persist != "" && !config.Confirmed {
			return fmt.Errorf("netconf.persist requires confirmed: true")
		}
		if config.PersistID != "" && config.Confirmed {
			return fmt.Errorf("netconf.persist_id confirms an existing persistent commit and cannot set confirmed: true")
		}
		if config.Persist != "" && config.PersistID != "" {
			return fmt.Errorf("netconf.persist and netconf.persist_id are mutually exclusive")
		}
	case "discard", "discard-changes", "discard_changes", "rollback":
		if hasAnyNETCONFArguments(config) {
			return fmt.Errorf("NETCONF discard-changes does not support additional fields")
		}
	case "lock", "unlock":
		if config.Source != "" || config.Payload != "" || config.PayloadFile != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != "" {
			return fmt.Errorf("NETCONF %s supports only target", operation)
		}
		if err := validateNETCONFDatastore("target", config.Target, "candidate", "running", "startup"); err != nil {
			return err
		}
	case "validate":
		if config.Target != "" || config.Payload != "" || config.PayloadFile != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != "" {
			return fmt.Errorf("NETCONF validate supports only source")
		}
		if err := validateNETCONFDatastore("source", config.Source, "candidate", "running", "startup"); err != nil {
			return err
		}
	case "get-config", "get_config":
		if config.Target != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != "" {
			return fmt.Errorf("NETCONF get-config supports source and an optional filter payload")
		}
		if err := validateNETCONFDatastore("source", config.Source, "running", "candidate", "startup"); err != nil {
			return err
		}
	case "copy-config", "copy_config":
		if config.Payload != "" || config.PayloadFile != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != "" {
			return fmt.Errorf("NETCONF copy-config supports only source and target")
		}
		if strings.TrimSpace(config.Source) == "" || strings.TrimSpace(config.Target) == "" {
			return fmt.Errorf("netconf.source and netconf.target are required for copy-config")
		}
		if err := validateNETCONFDatastore("source", config.Source, "running", "candidate", "startup"); err != nil {
			return err
		}
		if err := validateNETCONFDatastore("target", config.Target, "running", "candidate", "startup"); err != nil {
			return err
		}
	case "delete-config", "delete_config":
		if config.Source != "" || config.Payload != "" || config.PayloadFile != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != "" {
			return fmt.Errorf("NETCONF delete-config supports only target")
		}
		if strings.ToLower(strings.TrimSpace(config.Target)) != "startup" {
			return fmt.Errorf("NETCONF delete-config target must be startup")
		}
	case "cancel-commit", "cancel_commit":
		if config.Target != "" || config.Source != "" || config.Payload != "" || config.PayloadFile != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" {
			return fmt.Errorf("NETCONF cancel-commit supports only persist_id")
		}
	default:
		return fmt.Errorf("unsupported NETCONF operation %q", config.Operation)
	}
	return nil
}

func hasNETCONFControlFields(config NETCONFStepConfig) bool {
	return config.Target != "" || config.Source != "" || config.Confirmed || config.ConfirmTimeoutSeconds != 0 || config.Persist != "" || config.PersistID != ""
}

func hasAnyNETCONFArguments(config NETCONFStepConfig) bool {
	return config.Payload != "" || config.PayloadFile != "" || hasNETCONFControlFields(config)
}

func validateNETCONFDatastore(field, value string, defaultsAndAllowed ...string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	for _, allowed := range defaultsAndAllowed {
		if value == allowed {
			return nil
		}
	}
	return fmt.Errorf("unsupported NETCONF %s datastore %q", field, value)
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
	if rendered.Source != "" {
		display += " source=" + rendered.Source
	}
	if ctx.checkMode && netconfCheckSkips(operation, rendered.Payload) {
		message := fmt.Sprintf("[check] would execute %s", display)
		if rendered.Payload != "" {
			message += "\n" + rendered.Payload
		}
		return message, display, nil
	}
	output, err := ctx.netconf.ExecuteNETCONF(rendered)
	return output, display, err
}

func netconfCheckSkips(operation, payload string) bool {
	if netconfOperationMutates(operation) {
		return true
	}
	if operation != "rpc" {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(payload))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return true
		}
		if start, ok := token.(xml.StartElement); ok {
			return start.Name.Local != "get" && start.Name.Local != "get-config"
		}
	}
}

func netconfOperationMutates(operation string) bool {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "edit-config", "edit_config", "commit", "discard", "discard-changes", "discard_changes", "rollback",
		"lock", "unlock", "copy-config", "copy_config", "delete-config", "delete_config", "cancel-commit", "cancel_commit":
		return true
	default:
		return false
	}
}
