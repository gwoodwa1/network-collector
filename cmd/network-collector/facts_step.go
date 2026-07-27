package main

import (
	"encoding/json"
	"fmt"
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
	connectClient  func(string, string, string, netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error)
	err            error
}

type netconfConnectionPolicy struct {
	timeout        time.Duration
	hostKeyPolicy  string
	knownHostsFile string
}

func newLazyNETCONFExecutor(host, username, password string, policy netconfConnectionPolicy) *lazyNETCONFExecutor {
	return &lazyNETCONFExecutor{
		host:           host,
		username:       username,
		password:       password,
		timeout:        policy.timeout,
		hostKeyPolicy:  policy.hostKeyPolicy,
		knownHostsFile: policy.knownHostsFile,
	}
}

func connectScrapligoNETCONF(host, username, password string, policy netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error) {
	client := &netconf.ScrapligoNETCONF{}
	err := client.Connect(
		host,
		username,
		password,
		netconf.WithNetconfTimeouts(policy.timeout, policy.timeout),
		netconf.WithHostKeyPolicy(policy.hostKeyPolicy, policy.knownHostsFile),
	)
	return client, err
}

func (executor *lazyNETCONFExecutor) connect() error {
	executor.once.Do(func() {
		connectClient := executor.connectClient
		if connectClient == nil {
			connectClient = connectScrapligoNETCONF
		}
		executor.client, executor.err = connectClient(
			executor.host,
			executor.username,
			executor.password,
			netconfConnectionPolicy{
				timeout:        executor.timeout,
				hostKeyPolicy:  executor.hostKeyPolicy,
				knownHostsFile: executor.knownHostsFile,
			},
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

type boundedFactsExecutor struct {
	executor internalfacts.Executor
	limit    int
}

func (executor boundedFactsExecutor) Execute(command string) (string, error) {
	if executor.executor == nil {
		return "", fmt.Errorf("facts transport is unavailable")
	}
	output, err := executor.executor.Execute(command)
	if err != nil {
		return "", err
	}
	if err := enforceDeviceOutputLimit(output, executor.limit); err != nil {
		return "", err
	}
	return output, nil
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
	outputLimit, err := deviceOutputLimit(step.MaxOutputBytes)
	if err != nil {
		return err
	}
	collector := internalfacts.Collector{
		Platform: ctx.deviceType,
		NETCONF:  boundedFactsExecutor{executor: ctx.netconf, limit: outputLimit},
		SSH:      boundedFactsExecutor{executor: sshFactsExecutor{client: client}, limit: outputLimit},
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
	if err := enforceDeviceOutputLimit(string(encoded), outputLimit); err != nil {
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
