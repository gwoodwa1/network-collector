package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/internal/reporting"
	"github.com/gwoodwa1/network-collector/pkg/credentials"
	"golang.org/x/term"
)

func main() {
	// CLI flags
	var jsonOut bool
	var showVersion bool
	var cliFailOnFail bool
	var cliCredsInput bool
	var cliRSAToken bool
	var prettyOut bool
	var approveAll bool
	var checkMode bool
	var configFile string
	var cliInventoryFile string
	var cliParsersFile string
	var limitExpression string
	var excludeExpression string
	var rerunFailedFile string
	var eventsFile string
	flag.StringVar(&configFile, "config", "config.yaml", "path to config file")
	flag.StringVar(&cliInventoryFile, "inventory", "", "path to inventory file")
	flag.StringVar(&cliParsersFile, "parsers", "", "path to parser module file")
	flag.StringVar(&limitExpression, "limit", "", "inventory selector expression to include (for example: site=london and role=core)")
	flag.StringVar(&excludeExpression, "exclude", "", "inventory selector expression to exclude")
	flag.StringVar(&rerunFailedFile, "rerun-failed", "", "run only devices marked failed in a previous results.json")
	flag.StringVar(&eventsFile, "events-jsonl", "", "append lifecycle events as JSON Lines to this file")
	flag.BoolVar(&jsonOut, "json", false, "emit machine-readable JSON only")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&cliFailOnFail, "fail-on-fail", false, "exit non-zero if any validation fails or errors")
	flag.BoolVar(&cliCredsInput, "creds_input", false, "prompt for username and password interactively")
	flag.BoolVar(&cliRSAToken, "rsa-token", false, "use an interactive RSA passcode, reuse it for startup connections, and prompt again before reconnecting")
	flag.BoolVar(&prettyOut, "pretty", false, "show a coloured human-readable run summary")
	flag.BoolVar(&approveAll, "approve-all", false, "approve all manual workflow gates non-interactively")
	flag.BoolVar(&checkMode, "check", false, "preview changes without applying them")
	flag.BoolVar(&checkMode, "dry-run", false, "alias for --check")
	flag.Parse()
	if jsonOut {
		prettyOut = false
	}
	if showVersion {
		fmt.Printf("network-collector %s\n", version)
		return
	}

	config, failOnFail, err := loadConfig(configFile)
	if err != nil {
		slog.Error("error reading config", "config_file", configFile, "error", err)
		os.Exit(1)
	}
	config.checkMode = checkMode
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on-fail" {
			failOnFail = cliFailOnFail
		}
	})

	if strings.TrimSpace(cliInventoryFile) != "" {
		config.InventoryFile = cliInventoryFile
	}
	if strings.TrimSpace(cliParsersFile) != "" {
		config.ParsersFile = cliParsersFile
	}
	if strings.TrimSpace(eventsFile) != "" {
		config.Output.EventsFile = eventsFile
	}
	reportLogoFolder := strings.TrimSpace(config.Report.LogoFolder)
	if reportLogoFolder != "" && !filepath.IsAbs(reportLogoFolder) {
		reportLogoFolder = filepath.Join(config.baseDir, reportLogoFolder)
	}
	if config.Report.Enabled {
		format := strings.ToLower(strings.TrimSpace(config.Report.Format))
		if format != "" && format != "html" {
			slog.Error("invalid report configuration", "error", "report.format currently supports only html")
			os.Exit(1)
		}
		if strings.TrimSpace(config.Output.SummaryFile) == "" {
			config.Output.SummaryFile = "results.json"
		}
		if strings.TrimSpace(config.Output.EventsFile) == "" {
			config.Output.EventsFile = "events.jsonl"
		}
		if reportErr := reporting.ValidateBranding(reporting.Config{
			LogoFolder: reportLogoFolder, HeaderLogo: config.Report.HeaderLogo, FooterLogo: config.Report.FooterLogo,
		}); reportErr != nil {
			slog.Error("invalid report branding", "error", reportErr)
			os.Exit(1)
		}
		if reportErr := reporting.ValidateTemplate(reporting.Config{
			Template: config.Report.Template,
		}); reportErr != nil {
			slog.Error("invalid report template", "error", reportErr)
			os.Exit(1)
		}
	}

	inventory, err := loadOptionalInventory(config.InventoryFile, configFile)
	if err != nil {
		slog.Error("error reading inventory", "inventory_file", config.InventoryFile, "error", err)
		os.Exit(1)
	}

	sshDevices, err := resolveInventoryDevices(config.SSH, inventory)
	if err != nil {
		slog.Error("error resolving SSH inventory", "error", err)
		os.Exit(1)
	}
	netconfDevices, err := resolveInventoryDevices(config.NETCONF, inventory)
	if err != nil {
		slog.Error("error resolving NETCONF inventory", "error", err)
		os.Exit(1)
	}
	devices := append([]DeviceConfig(nil), sshDevices...)
	devices = append(devices, netconfDevices...)
	includeSelector, err := parseDeviceSelector(limitExpression)
	if err != nil {
		slog.Error("invalid --limit selector", "error", err)
		os.Exit(1)
	}
	excludeSelector, err := parseDeviceSelector(excludeExpression)
	if err != nil {
		slog.Error("invalid --exclude selector", "error", err)
		os.Exit(1)
	}
	var replayDevices map[string]bool
	if strings.TrimSpace(rerunFailedFile) != "" {
		replayDevices, err = loadFailedDevices(rerunFailedFile)
		if err != nil {
			slog.Error("error reading failed-device replay summary", "path", rerunFailedFile, "error", err)
			os.Exit(1)
		}
	}
	devices = filterDevices(devices, includeSelector, excludeSelector, replayDevices)
	if (includeSelector != nil || excludeSelector != nil || replayDevices != nil) && len(devices) == 0 {
		slog.Warn("inventory selection matched no devices")
	}

	initialVariables, err := configVariables(config.Vars)
	if err != nil {
		slog.Error("invalid playbook variables", "error", err)
		os.Exit(1)
	}
	variableStates := make(map[string]*deviceVariableState)
	for index, device := range devices {
		key := variableScopeKey(device.Hostname, device.IP)
		state, exists := variableStates[key]
		if !exists {
			deviceVariables, variableErr := mergeInventoryVariables(initialVariables, device.InventoryVars)
			if variableErr != nil {
				slog.Error("invalid inventory variables", "hostname", device.Hostname, "error", variableErr)
				os.Exit(1)
			}
			state = &deviceVariableState{variables: deviceVariables}
			state.cond = sync.NewCond(&state.mu)
			variableStates[key] = state
		}
		state.order = append(state.order, index)
		if variableErr := preflightDeviceVariables(device, config.Workflows, state.variables); variableErr != nil {
			slog.Error("variable preflight failed", "hostname", device.Hostname, "error", variableErr)
			os.Exit(1)
		}
	}
	rsaToken := cliRSAToken || config.Credentials.RSAToken
	deviceCredentials := make([]credentials.Credentials, len(devices))
	var rsaAuth *rsaTokenAuth
	if len(devices) > 0 {
		providerType := config.Credentials.Provider
		if cliCredsInput || rsaToken {
			providerType = "interactive"
		}
		credentialFile := strings.TrimSpace(config.Credentials.File)
		if credentialFile != "" && !filepath.IsAbs(credentialFile) {
			credentialFile = filepath.Join(filepath.Dir(configFile), credentialFile)
		}
		hashicorpConfig := config.Credentials.Hashicorp
		cyberArkConfig := config.Credentials.CyberArk
		for _, configuredPath := range []*string{
			&hashicorpConfig.CAFile, &hashicorpConfig.CertFile, &hashicorpConfig.KeyFile,
			&cyberArkConfig.CAFile, &cyberArkConfig.CertFile, &cyberArkConfig.KeyFile,
		} {
			if value := strings.TrimSpace(*configuredPath); value != "" && !filepath.IsAbs(value) {
				*configuredPath = filepath.Join(filepath.Dir(configFile), value)
			}
		}
		provider, providerErr := credentials.NewProvider(credentials.ProviderConfig{
			Type: providerType, File: credentialFile,
			TimeoutSeconds: config.Credentials.TimeoutSeconds,
			Hashicorp:      hashicorpConfig, OnePassword: config.Credentials.OnePassword,
			CyberArk: cyberArkConfig,
		}, os.Stdin, os.Stderr)
		if providerErr != nil {
			slog.Error("error configuring credential provider", "error", providerErr)
			os.Exit(1)
		}
		if strings.EqualFold(providerType, "interactive") || strings.EqualFold(providerType, "prompt") {
			shared, resolveErr := provider.Resolve(context.Background(), credentials.Target{Hostname: "selected inventory"})
			if resolveErr != nil {
				slog.Error("error resolving credentials", "error", resolveErr)
				os.Exit(1)
			}
			for index := range deviceCredentials {
				deviceCredentials[index] = shared
			}
			if rsaToken {
				rsaAuth = newRSATokenAuth(shared.Username, os.Stdin, os.Stderr)
			}
		} else {
			for index, device := range devices {
				deviceCredentials[index], err = provider.Resolve(context.Background(), credentials.Target{Hostname: device.Hostname, IP: device.IP, Profile: device.CredentialProfile})
				if err != nil {
					slog.Error("error resolving credentials", "hostname", device.Hostname, "error", err)
					os.Exit(1)
				}
			}
		}
	}
	sshTargets := make([]DeviceConfig, 0, len(devices))
	for _, device := range devices {
		if !stepsNeedSSH(device.Steps, config.Workflows, map[string]bool{}) && !(len(device.Steps) == 0 && strings.TrimSpace(device.Command) != "") {
			continue
		}
		sshTargets = append(sshTargets, device)
		if err := validateSSHSecurity(effectiveSSHSecurity(config.SSHSecurity, device.SSHSecurity)); err != nil {
			slog.Error("invalid SSH security configuration", "hostname", device.Hostname, "error", err)
			os.Exit(1)
		}
	}
	logSSHSecuritySummary(config.SSHSecurity, sshTargets)

	parserConfig, err := loadOptionalParsers(config.ParsersFile, configFile)
	if err != nil {
		slog.Error("error reading parser modules", "parsers_file", config.ParsersFile, "error", err)
		os.Exit(1)
	}
	parsers := map[string]ParserModuleConfig{}
	if parserConfig != nil && parserConfig.Parsers != nil {
		parsers = parserConfig.Parsers
	}

	runStarted := time.Now()
	runID := "run-" + runStarted.Format("20060102T150405.000000000")
	runDir := ""
	if outputEnabled(config, devices) {
		runDir, err = prepareRunOutput(config.Output, runID)
		if err != nil {
			slog.Error("error preparing structured output", "error", err)
			os.Exit(1)
		}
		slog.Info("recording structured output", "run_id", runID, "directory", runDir)
	}
	events := &eventDispatcher{runID: runID}
	eventPath := ""
	if configured := strings.TrimSpace(config.Output.EventsFile); configured != "" {
		eventPath = configured
		if !filepath.IsAbs(eventPath) && runDir != "" {
			eventPath = filepath.Join(runDir, eventPath)
		}
		sink, sinkErr := newJSONLEventSink(eventPath)
		if sinkErr != nil {
			slog.Error("error opening lifecycle event output", "path", eventPath, "error", sinkErr)
			os.Exit(1)
		}
		events.sinks = append(events.sinks, sink)
		slog.Info("recording lifecycle events", "path", eventPath)
	}
	for index, sinkConfig := range config.Output.EventSinks {
		sink, sinkErr := newNetworkEventSink(sinkConfig)
		if sinkErr != nil {
			slog.Error("error configuring lifecycle event sink", "index", index, "type", sinkConfig.Type, "error", sinkErr)
			os.Exit(1)
		}
		events.sinks = append(events.sinks, sink)
		slog.Info("configured lifecycle event sink", "type", strings.ToLower(strings.TrimSpace(sinkConfig.Type)))
	}
	events.emit(lifecycleEvent{Type: "run.started", Data: map[string]interface{}{"playbook": config.NamePlaybook, "device_count": len(devices)}})

	if err := validateExecutionConfig(config.Execution); err != nil {
		slog.Error("invalid execution configuration", "error", err)
		os.Exit(1)
	}
	if err := validateScheduleConfig(config.Schedule); err != nil {
		slog.Error("invalid schedule configuration", "error", err)
		os.Exit(1)
	}
	var approvals *approvalInput
	var approvalWriter io.Writer
	if term.IsTerminal(int(os.Stdin.Fd())) {
		approvals, approvalWriter = newApprovalInput(os.Stdin), os.Stdout
	}

	runner := func(occurrence, index int, device DeviceConfig) deviceRunResult {
		state := variableStates[variableScopeKey(device.Hostname, device.IP)]
		state.mu.Lock()
		for state.next < len(state.order) && state.order[state.next] != index {
			state.cond.Wait()
		}
		credential := deviceCredentials[index]
		result := runSSHDevice(index, occurrence, device, config, credential.Username, credential.Password, rsaAuth, jsonOut, prettyOut, approveAll, approvals, approvalWriter, parsers, state.variables, runDir, events)
		state.next++
		state.cond.Broadcast()
		state.mu.Unlock()
		return result
	}
	deviceResults, schedulingStopped := runRecurringSchedule(devices, config.Execution, config.Schedule, runner, time.Sleep)
	occurrences := config.Schedule.Count
	if occurrences == 0 {
		occurrences = 1
	}
	deviceResultCount := len(devices) * occurrences
	runFailed := schedulingStopped
	resultsByIndex := make(map[int]deviceRunResult, len(deviceResults))
	for _, result := range deviceResults {
		resultsByIndex[result.index] = result
		if result.failed {
			runFailed = true
		}
	}
	var aggregated []deviceValidation
	var artifacts []outputArtifact
	var outcomes []deviceOutcome
	for index := 0; index < deviceResultCount; index++ {
		if result, ok := resultsByIndex[index]; ok {
			aggregated = append(aggregated, result.aggregated...)
			artifacts = append(artifacts, result.artifacts...)
			outcomes = append(outcomes, deviceOutcome{Hostname: result.hostname, IP: result.ip, Failed: result.failed, Duration: result.duration})
		}
	}
	summaryPath := ""
	if runDir != "" {
		summaryPath, err = writeRunSummary(config.Output, runDir, runSummary{
			RunID: runID, Playbook: config.NamePlaybook, StartedAt: runStarted, CompletedAt: time.Now(),
			Failed: runFailed, Validations: aggregated, Artifacts: artifacts, Devices: outcomes,
		})
		if err != nil {
			runFailed = true
			slog.Error("error writing run summary", "error", err)
		} else if summaryPath != "" {
			slog.Info("wrote run summary", "path", summaryPath)
		}
	}
	failed := runFailed
	events.emit(lifecycleEvent{Type: "run.completed", Failed: &failed, Data: map[string]interface{}{"duration_ns": time.Since(runStarted).Nanoseconds(), "device_results": len(deviceResults)}})
	events.close()
	reportFailed := false
	if config.Report.Enabled {
		reportPath, reportErr := reporting.Generate(reporting.Config{
			RunDir: runDir, SummaryFile: summaryPath, EventsFile: eventPath,
			Output: config.Report.Output, Template: config.Report.Template, Title: config.Report.Title,
			ChangeReference: config.Report.ChangeReference, LogoFolder: reportLogoFolder,
			HeaderLogo: config.Report.HeaderLogo, FooterLogo: config.Report.FooterLogo,
		})
		if reportErr != nil {
			reportFailed = true
			slog.Error("error generating change report", "error", reportErr)
		} else {
			slog.Info("wrote change report", "path", reportPath)
		}
	}

	// Emit aggregated JSON if requested
	if jsonOut {
		out, _ := json.MarshalIndent(aggregated, "", "  ")
		fmt.Println(string(out))
	} else if prettyOut {
		fmt.Print(renderPrettyResults(deviceResults, runFailed, time.Since(runStarted), prettyColourEnabled(os.Stdout)))
	}

	// Exit non-zero if any validation failed or errored and flag set
	if reportFailed {
		os.Exit(1)
	}
	if failOnFail {
		if runFailed {
			os.Exit(2)
		}
		for _, dv := range aggregated {
			if !dv.Recovered && (dv.Result.Status == "fail" || dv.Result.Status == "error") {
				os.Exit(2)
			}
		}
	}
}
