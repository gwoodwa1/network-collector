package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

func effectiveNETCONFPolicy(global SSHSecurityConfig, device DeviceConfig) netconfConnectionPolicy {
	timeout := 30 * time.Second
	if device.OperationTimeout > 0 {
		timeout = time.Duration(device.OperationTimeout) * time.Second
	}
	security := effectiveSSHSecurity(global, device.SSHSecurity)
	return netconfConnectionPolicy{
		timeout:        timeout,
		hostKeyPolicy:  security.HostKeyPolicy,
		knownHostsFile: security.KnownHostsFile,
	}
}

func runSSHDevice(index, occurrence int, device DeviceConfig, config Config, username, password string, rsaAuth *rsaTokenAuth, jsonOut, pretty, approveAll bool, approvals *approvalInput, approvalWriter io.Writer, parsers map[string]ParserModuleConfig, variables map[string]string, runDir string, events *eventDispatcher) deviceRunResult {
	return runSSHDeviceContext(context.Background(), index, occurrence, device, config, username, password, rsaAuth, jsonOut, pretty, approveAll, approvals, approvalWriter, parsers, variables, runDir, events, nil, nil)
}

func runSSHDeviceContext(runContext context.Context, index, occurrence int, device DeviceConfig, config Config, username, password string, rsaAuth *rsaTokenAuth, jsonOut, pretty, approveAll bool, approvals *approvalInput, approvalWriter io.Writer, parsers map[string]ParserModuleConfig, variables map[string]string, runDir string, events *eventDispatcher, journal *runJournal, resumeCompleted map[string]bool) (result deviceRunResult) {
	startedAt := time.Now()
	hostname := strings.TrimSpace(device.Hostname)
	ip := strings.TrimSpace(device.IP)
	result = deviceRunResult{index: index, hostname: hostname, ip: ip}
	events.emit(lifecycleEvent{Type: "device.started", Hostname: hostname, IP: ip})
	defer func() {
		result.duration = time.Since(startedAt)
		failed := result.failed
		events.emit(lifecycleEvent{Type: "device.completed", Hostname: hostname, IP: ip, Failed: &failed, Data: map[string]interface{}{"duration_ns": result.duration.Nanoseconds()}})
	}()
	deviceType := strings.TrimSpace(device.Type)

	if hostname == "" || ip == "" || deviceType == "" {
		result.failed = true
		slog.Warn("skipping invalid device entry", "hostname", hostname, "ip", ip, "type", deviceType)
		if err := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", "skipping invalid device entry", nil); err != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", err)
		}
		return result
	}

	steps := device.Steps
	if len(steps) == 0 && strings.TrimSpace(device.Command) != "" {
		steps = []StepConfig{{
			Name: "default", Command: strings.TrimSpace(device.Command), Parser: strings.TrimSpace(device.Parser),
			Validation: device.Validation, Validations: device.Validations,
		}}
	}
	if len(steps) == 0 {
		result.failed = true
		slog.Warn("skipping device with no steps or command", "hostname", hostname, "ip", ip)
		if err := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", "skipping device with no steps or command", nil); err != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", err)
		}
		return result
	}

	started := time.Now()
	sessionLog, sessionLogPath, err := openSessionLog(hostname, config.NamePlaybook, started)
	if err != nil {
		result.failed = true
		slog.Error("error creating session log", "hostname", hostname, "ip", ip, "error", err)
		return result
	}
	slog.Info("recording device session", "hostname", hostname, "ip", ip, "path", sessionLogPath)

	opts := sshOptionsForDevice(device, config.SSHSecurity)
	if rsaAuth != nil {
		opts = append(opts, ssh.WithPasswordPattern(rsaPasscodePromptPattern))
	}
	channelLog := io.Discard
	if config.Output.SessionTranscript {
		channelLog = sessionLog
	}
	opts = append(opts, ssh.WithChannelLog(channelLog))

	// A scheduled occurrence starts a new session because the previous one was
	// closed. Never replay an old RSA passcode across that boundary.
	if rsaAuth != nil && occurrence > 0 {
		username, password, err = rsaAuth.prompt()
		if err != nil {
			result.failed = true
			slog.Error("error reading fresh RSA passcode", "hostname", hostname, "ip", ip, "error", err)
			_ = sessionLog.Close()
			return result
		}
	}
	var client *ssh.Client
	needsSSH := stepsNeedSSH(steps, config.Workflows, map[string]bool{})
	if config.checkMode {
		needsSSH = stepsNeedSSHInCheck(steps, config.Workflows, map[string]bool{})
	}
	if needsSSH {
		client = ssh.NewClient(opts...)
		if err := client.Connect(ip, username, password, deviceType); err != nil {
			result.failed = true
			slog.Error("error connecting to SSH device", "hostname", hostname, "ip", ip, "error", err)
			writeSessionf(sessionLog, "ERROR: failed to connect to %s (%s): %v\n", hostname, ip, err)
			if ferr := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", fmt.Sprintf("failed to connect to %s (%s): %v", hostname, ip, err), nil); ferr != nil {
				slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", ferr)
			}
			_ = sessionLog.Close()
			return result
		}
	}

	netconfPolicy := effectiveNETCONFPolicy(config.SSHSecurity, device)
	netconfExecutor := newLazyNETCONFExecutor(ip, username, password, netconfPolicy)
	ctx := stepExecutionContext{
		runContext: runContext,
		hostname:   hostname, ip: ip, deviceType: deviceType, username: username, password: password,
		opts: opts, jsonOut: jsonOut, consoleOutput: config.Output.ConsoleOutput,
		sessionOutput: config.Output.SessionTranscript, sessionLog: sessionLog, failureLog: failureLogPath(),
		variables: variables, aggregated: &result.aggregated, runFailed: &result.failed, parsers: parsers, workflows: config.Workflows,
		configBaseDir: config.baseDir,
		output:        config.Output, runDir: runDir, deviceIndex: index, artifacts: &result.artifacts,
		approveAll: approveAll, approvalInput: approvals, approvalWriter: approvalWriter,
		artifactPrefix:   fmt.Sprintf("schedule-%03d", occurrence+1),
		factsDefaults:    config.Facts,
		events:           events,
		netconf:          netconfExecutor,
		netconfPolicy:    netconfPolicy,
		gnmi:             device.GNMI,
		checkMode:        config.checkMode,
		reportEnabled:    config.Report.Enabled,
		gnmiActionBudget: &gnmiDeviceActionBudget{},
		journal:          journal,
		occurrence:       occurrence,
		resumeCompleted:  resumeCompleted,
	}
	if rsaAuth != nil {
		ctx.reauthenticate = rsaAuth.prompt
	}
	if executeSteps(&ctx, &client, steps) {
		slog.Warn("stopped remaining steps for device", "hostname", hostname, "ip", ip)
	}
	for _, deviceValidation := range result.aggregated {
		if !deviceValidation.Recovered && (deviceValidation.Result.Status == "fail" || deviceValidation.Result.Status == "error") {
			result.failed = true
			break
		}
	}
	if err := closeSSHClient(client); err != nil {
		result.failed = true
		slog.Error("error closing SSH connection", "hostname", hostname, "ip", ip, "error", err)
		writeSessionf(sessionLog, "ERROR: failed to close SSH connection: %v\n", err)
		if ferr := appendFailureRecord(failureLogPath(), hostname, ip, "", "error", fmt.Sprintf("failed to close SSH connection: %v", err), nil); ferr != nil {
			slog.Error("error writing failure log", "hostname", hostname, "ip", ip, "error", ferr)
		}
	}
	if err := netconfExecutor.Close(); err != nil {
		result.failed = true
		slog.Error("error closing NETCONF connection", "hostname", hostname, "ip", ip, "error", err)
		writeSessionf(sessionLog, "ERROR: failed to close NETCONF connection: %v\n", err)
	}
	writeSessionf(sessionLog, "\nSession complete: %s\n", time.Now().Format(time.RFC3339))
	if err := sessionLog.Close(); err != nil {
		result.failed = true
		slog.Error("error closing session log", "hostname", hostname, "ip", ip, "path", sessionLogPath, "error", err)
	}
	return result
}

func runScheduledDevices(devices []DeviceConfig, cfg ExecutionConfig, runner func(int, DeviceConfig) deviceRunResult) ([]deviceRunResult, bool) {
	return runScheduledDevicesContext(context.Background(), devices, cfg, runner)
}

func runScheduledDevicesContext(runContext context.Context, devices []DeviceConfig, cfg ExecutionConfig, runner func(int, DeviceConfig) deviceRunResult) ([]deviceRunResult, bool) {
	serialBy := strings.ToLower(strings.TrimSpace(cfg.SerialBy))
	var serialMu sync.Mutex
	serialLocks := map[string]*sync.Mutex{}
	serialLockFor := func(device DeviceConfig) *sync.Mutex {
		if serialBy == "" {
			return nil
		}
		key := serialDomainKey(device, serialBy)
		if key == "" {
			return nil
		}
		serialMu.Lock()
		defer serialMu.Unlock()
		if serialLocks[key] == nil {
			serialLocks[key] = &sync.Mutex{}
		}
		return serialLocks[key]
	}
	outcomes, stopped := orchestrator.Run(runContext, devices, orchestrator.Policy{
		MaxParallel:      cfg.MaxParallel,
		StartInterval:    time.Duration(cfg.StartIntervalSeconds) * time.Second,
		CanaryCount:      cfg.CanaryCount,
		FailureThreshold: cfg.FailureThreshold,
	}, func(ctx context.Context, index int, device DeviceConfig) orchestrator.Outcome[deviceRunResult] {
		lock := serialLockFor(device)
		if lock != nil {
			lock.Lock()
			defer lock.Unlock()
		}
		result := runner(index, device)
		return orchestrator.Outcome[deviceRunResult]{Index: index, Value: result, Failed: result.failed}
	})
	results := make([]deviceRunResult, 0, len(outcomes))
	for _, outcome := range outcomes {
		results = append(results, outcome.Value)
	}
	if stopped {
		slog.Error("scheduled execution stopped before all devices completed", "failure_threshold", cfg.FailureThreshold, "canary_count", cfg.CanaryCount)
	}
	return results, stopped
}

func serialDomainKey(device DeviceConfig, serialBy string) string {
	var value string
	switch serialBy {
	case "failure_domain":
		value = device.FailureDomain
	case "ha_pair":
		value = device.HAPair
	case "site":
		value = device.Site
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return serialBy + ":" + strings.ToLower(value)
}

func validateSerialDomains(devices []DeviceConfig, serialBy string) error {
	serialBy = strings.ToLower(strings.TrimSpace(serialBy))
	if serialBy == "" {
		return nil
	}
	for _, device := range devices {
		if serialDomainKey(device, serialBy) == "" {
			name := strings.TrimSpace(device.Hostname)
			if name == "" {
				name = strings.TrimSpace(device.IP)
			}
			return fmt.Errorf("device %q is missing inventory %s required by execution.serial_by", name, serialBy)
		}
	}
	return nil
}

func runRecurringSchedule(devices []DeviceConfig, execution ExecutionConfig, schedule ScheduleConfig, runner func(int, int, DeviceConfig) deviceRunResult, sleep func(time.Duration)) ([]deviceRunResult, bool) {
	return runRecurringScheduleContext(context.Background(), devices, execution, schedule, runner, sleep)
}

func runRecurringScheduleContext(runContext context.Context, devices []DeviceConfig, execution ExecutionConfig, schedule ScheduleConfig, runner func(int, int, DeviceConfig) deviceRunResult, sleep func(time.Duration)) ([]deviceRunResult, bool) {
	count := schedule.Count
	if count == 0 {
		count = 1
	}
	all := make([]deviceRunResult, 0, len(devices)*count)
	stopped := false
	for occurrence := 0; occurrence < count; occurrence++ {
		if runContext.Err() != nil {
			stopped = true
			break
		}
		results, occurrenceStopped := runScheduledDevicesContext(runContext, devices, execution, func(index int, device DeviceConfig) deviceRunResult { return runner(occurrence, index, device) })
		for index := range results {
			results[index].index += occurrence * len(devices)
		}
		all = append(all, results...)
		if occurrenceStopped {
			stopped = true
			break
		}
		if occurrence+1 < count {
			wait := time.Duration(schedule.IntervalSeconds) * time.Second
			if runContext == context.Background() {
				if sleep != nil {
					sleep(wait)
				}
				continue
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-runContext.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				stopped = true
			}
			if stopped {
				break
			}
		}
	}
	return all, stopped
}
