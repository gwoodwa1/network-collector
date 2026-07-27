package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

func runSSHDevice(index, occurrence int, device DeviceConfig, config Config, username, password string, rsaAuth *rsaTokenAuth, jsonOut, pretty, approveAll bool, approvals *approvalInput, approvalWriter io.Writer, parsers map[string]ParserModuleConfig, variables map[string]string, runDir string, events *eventDispatcher) (result deviceRunResult) {
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
	channelLog := io.Writer(sessionLog)
	if !jsonOut && !pretty {
		channelLog = io.MultiWriter(os.Stdout, sessionLog)
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

	netconfTimeout := 30 * time.Second
	if device.OperationTimeout > 0 {
		netconfTimeout = time.Duration(device.OperationTimeout) * time.Second
	}
	netconfExecutor := &lazyNETCONFExecutor{
		host: ip, username: username, password: password, timeout: netconfTimeout,
		hostKeyPolicy: effectiveSSHSecurity(config.SSHSecurity, device.SSHSecurity).HostKeyPolicy,
		knownHostsFile: effectiveSSHSecurity(config.SSHSecurity, device.SSHSecurity).KnownHostsFile,
	}
	ctx := stepExecutionContext{
		hostname: hostname, ip: ip, deviceType: deviceType, username: username, password: password,
		opts: opts, jsonOut: jsonOut, sessionLog: sessionLog, failureLog: failureLogPath(),
		variables: variables, aggregated: &result.aggregated, runFailed: &result.failed, parsers: parsers, workflows: config.Workflows,
		configBaseDir: config.baseDir,
		output:        config.Output, runDir: runDir, deviceIndex: index, artifacts: &result.artifacts,
		approveAll: approveAll, approvalInput: approvals, approvalWriter: approvalWriter,
		artifactPrefix: fmt.Sprintf("schedule-%03d", occurrence+1),
		factsDefaults:  config.Facts,
		events:         events,
		netconf:        netconfExecutor,
		gnmi:           device.GNMI,
		checkMode:      config.checkMode,
		reportEnabled:  config.Report.Enabled,
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
	outcomes, stopped := orchestrator.Run(context.Background(), devices, orchestrator.Policy{
		MaxParallel:      cfg.MaxParallel,
		StartInterval:    time.Duration(cfg.StartIntervalSeconds) * time.Second,
		CanaryCount:      cfg.CanaryCount,
		FailureThreshold: cfg.FailureThreshold,
	}, func(ctx context.Context, index int, device DeviceConfig) orchestrator.Outcome[deviceRunResult] {
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

func runRecurringSchedule(devices []DeviceConfig, execution ExecutionConfig, schedule ScheduleConfig, runner func(int, int, DeviceConfig) deviceRunResult, sleep func(time.Duration)) ([]deviceRunResult, bool) {
	count := schedule.Count
	if count == 0 {
		count = 1
	}
	all := make([]deviceRunResult, 0, len(devices)*count)
	stopped := false
	for occurrence := 0; occurrence < count; occurrence++ {
		results, occurrenceStopped := runScheduledDevices(devices, execution, func(index int, device DeviceConfig) deviceRunResult { return runner(occurrence, index, device) })
		for index := range results {
			results[index].index += occurrence * len(devices)
		}
		all = append(all, results...)
		if occurrenceStopped {
			stopped = true
			break
		}
		if occurrence+1 < count {
			sleep(time.Duration(schedule.IntervalSeconds) * time.Second)
		}
	}
	return all, stopped
}
