package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	internalfacts "github.com/gwoodwa1/network-collector/internal/facts"
	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

type lazyNETCONFExecutor struct {
	once           sync.Once
	client         *netconf.ScrapligoNETCONF
	host           string
	username       string
	password       string
	timeout        time.Duration
	hostKeyPolicy  string
	knownHostsFile string
	err            error
}

func (executor *lazyNETCONFExecutor) connect() error {
	executor.once.Do(func() {
		executor.client = &netconf.ScrapligoNETCONF{}
		executor.err = executor.client.Connect(
			executor.host,
			executor.username,
			executor.password,
			netconf.WithNetconfTimeouts(executor.timeout, executor.timeout),
			netconf.WithHostKeyPolicy(executor.hostKeyPolicy, executor.knownHostsFile),
		)
	})
	return executor.err
}

func (executor *lazyNETCONFExecutor) Execute(filter string) (string, error) {
	if err := executor.connect(); err != nil {
		return "", err
	}
	return executor.client.Execute(filter)
}

func (executor *lazyNETCONFExecutor) ExecuteNETCONF(config NETCONFStepConfig) (string, error) {
	if err := executor.connect(); err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(config.Operation)) {
	case "", "rpc":
		return executor.client.RPC(config.Payload)
	case "edit-config", "edit_config":
		return executor.client.EditConfig(config.Target, config.Payload)
	case "commit":
		return executor.client.CommitPersistent(config.Confirmed, config.ConfirmTimeoutSeconds, config.Persist, config.PersistID)
	case "discard", "discard-changes", "discard_changes", "rollback":
		return executor.client.DiscardChanges()
	case "lock":
		return executor.client.Lock(config.Target)
	case "unlock":
		return executor.client.Unlock(config.Target)
	case "validate":
		return executor.client.Validate(config.Source)
	case "get-config", "get_config":
		return executor.client.GetConfig(config.Source, config.Payload)
	case "copy-config", "copy_config":
		return executor.client.CopyConfig(config.Source, config.Target)
	case "delete-config", "delete_config":
		return executor.client.DeleteConfig(config.Target)
	case "cancel-commit", "cancel_commit":
		return executor.client.CancelCommit(config.PersistID)
	default:
		return "", fmt.Errorf("unsupported NETCONF operation %q", config.Operation)
	}
}

func (executor *lazyNETCONFExecutor) Close() error {
	if executor.client == nil {
		return nil
	}
	return executor.client.Close()
}

type sshFactsExecutor struct{ client **ssh.Client }

func (executor sshFactsExecutor) Execute(command string) (string, error) {
	if executor.client == nil || *executor.client == nil {
		return "", fmt.Errorf("no active SSH session")
	}
	return (*executor.client).Execute(command)
}

func executeFactsStep(ctx *stepExecutionContext, client **ssh.Client, step StepConfig, stepName string) error {
	format := strings.TrimSpace(step.Facts.Format)
	if format == "" {
		format = strings.TrimSpace(ctx.factsDefaults.DefaultFormat)
	}
	subsets := step.Facts.Subsets
	if len(subsets) == 0 {
		subsets = ctx.factsDefaults.DefaultSubsets
	}
	transports := step.Facts.Transports
	if len(transports) == 0 {
		transports = ctx.factsDefaults.DefaultTransports
	}
	config := internalfacts.Config{Format: internalfacts.Format(strings.ToLower(format)), Subsets: subsets, Transports: transports}
	timeout := 30 * time.Second
	netconfExecutor := &lazyNETCONFExecutor{host: ctx.ip, username: ctx.username, password: ctx.password, timeout: timeout}
	defer func() {
		if err := netconfExecutor.Close(); err != nil {
			slog.Warn("error closing facts NETCONF session", "hostname", ctx.hostname, "error", err)
		}
	}()
	collector := internalfacts.Collector{
		Platform: ctx.deviceType,
		NETCONF:  netconfExecutor,
		SSH:      sshFactsExecutor{client: client},
		Parse: func(output, parser string) (json.RawMessage, error) {
			parsed, err := parseOutputWithModule(output, parser, ctx.parsers)
			return json.RawMessage(parsed), err
		},
	}
	result, err := collector.Collect(config)
	if err != nil {
		return fmt.Errorf("facts collection failed: %w", err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode facts: %w", err)
	}
	writeProtectedOutput(ctx, fmt.Sprintf("[step:%s] facts output:", stepName), string(encoded))
	if register := strings.TrimSpace(step.Register); register != "" {
		ctx.variables[register] = string(encoded)
	}
	if err := saveStepArtifact(ctx, step, stepName, 1, "parsed", string(encoded)); err != nil {
		return fmt.Errorf("save facts artifact: %w", err)
	}
	if step.Drift != nil {
		if err := applyDriftCheck(ctx, step, stepName, string(encoded)); err != nil {
			return fmt.Errorf("facts drift check: %w", err)
		}
	}
	return nil
}
