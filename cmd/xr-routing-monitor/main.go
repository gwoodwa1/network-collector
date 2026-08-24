// Command xr-routing-monitor polls a set of IOS-XR routers for BGP, route
// table, and core-facing interface health during a change window. Each
// device is authenticated individually (RSA SecurID passcodes are
// single-use) and then polled repeatedly over that same persistent SSH
// session so no further authentication is required until the process exits.
//
// This is a thin wrapper: all collection/onboarding/reporting logic lives in
// internal/xrmonitor (shared with cmd/routing-monitor, the mixed-fleet
// front-end covering both this tool and cmd/junos-routing-monitor). Keeping
// this file to flag parsing and orchestration only means the two entry
// points can never drift apart from what internal/xrmonitor actually does.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorreport"
	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
	"github.com/gwoodwa1/network-collector/internal/reporting"
	"github.com/gwoodwa1/network-collector/internal/xrmonitor"
)

// version is replaced by GoReleaser at build time.
var version = "dev"

func main() {
	var interval time.Duration
	var outputDir string
	var parsersFile string
	var deviceType string
	var devicesFile string
	var passcodeReuseWindow time.Duration
	var diffBeforePath, diffAfterPath string
	var diffBeforeConfigPath, diffAfterConfigPath string
	var captureRunningConfigEnabled bool
	var showVersion bool
	var reportOutput, reportTitle, changeReference string
	var logoFolder, headerLogo, footerLogo string
	flag.DurationVar(&interval, "interval", 60*time.Second, "polling interval between collection ticks per device")
	flag.StringVar(&outputDir, "output-dir", "artifacts", "directory to write one <hostname>.jsonl file per device")
	flag.StringVar(&parsersFile, "parsers", "", "path to an external parser module file; defaults to this binary's embedded parser definitions")
	flag.StringVar(&deviceType, "type", "cisco_iosxr", "scrapligo platform/driver name for all onboarded devices")
	flag.StringVar(&devicesFile, "devices", "", "optional YAML file listing hostname/vrf/interfaces/neighbors per device; credentials are still always prompted interactively")
	flag.DurationVar(&passcodeReuseWindow, "passcode-reuse-window", 45*time.Second, "how long an entered RSA passcode may be offered for reuse on the next device, matching your ISE cache duration with a safety margin; 0 disables reuse")
	flag.BoolVar(&captureRunningConfigEnabled, "capture-running-config", false, "also capture \"show running-config\" before and after the change window, as a separate <base>-running-config.txt file per label; off by default since it's a heavier capture")
	flag.StringVar(&reportOutput, "report-output", "interface-traffic.html", "professional HTML report filename")
	flag.StringVar(&reportTitle, "report-title", "IOS XR Change Monitoring Report", "professional report title")
	flag.StringVar(&changeReference, "change-reference", "", "change/ticket reference shown in the report")
	flag.StringVar(&logoFolder, "logo-folder", "", "directory containing optional PNG report branding")
	flag.StringVar(&headerLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&footerLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.StringVar(&diffBeforePath, "diff-before", "", "path to a captured *-before.json snapshot; combine with -diff-after to print a route-level diff and exit, instead of connecting to any device")
	flag.StringVar(&diffAfterPath, "diff-after", "", "path to a captured *-after.json snapshot; combine with -diff-before")
	flag.StringVar(&diffBeforeConfigPath, "diff-before-config", "", "path to a captured *-before-running-config.txt file; combine with -diff-after-config to print a running-config diff and exit, instead of connecting to any device")
	flag.StringVar(&diffAfterConfigPath, "diff-after-config", "", "path to a captured *-after-running-config.txt file; combine with -diff-before-config")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Printf("xr-routing-monitor %s\n", version)
		return
	}
	snapshotDiffRequested := diffBeforePath != "" || diffAfterPath != ""
	configDiffRequested := diffBeforeConfigPath != "" || diffAfterConfigPath != ""
	if snapshotDiffRequested || configDiffRequested {
		if snapshotDiffRequested && (diffBeforePath == "" || diffAfterPath == "") {
			fmt.Fprintln(os.Stderr, "both -diff-before and -diff-after are required together")
			os.Exit(1)
		}
		if configDiffRequested && (diffBeforeConfigPath == "" || diffAfterConfigPath == "") {
			fmt.Fprintln(os.Stderr, "both -diff-before-config and -diff-after-config are required together")
			os.Exit(1)
		}
		if snapshotDiffRequested {
			if err := xrmonitor.RunSnapshotDiff(diffBeforePath, diffAfterPath, os.Stdout); err != nil {
				slog.Error("snapshot diff failed", "error", err)
				os.Exit(1)
			}
		}
		if configDiffRequested {
			if snapshotDiffRequested {
				fmt.Fprintln(os.Stdout)
			}
			if err := xrmonitor.RunConfigDiff(diffBeforeConfigPath, diffAfterConfigPath, os.Stdout); err != nil {
				slog.Error("running-config diff failed", "error", err)
				os.Exit(1)
			}
		}
		return
	}
	if err := reporting.ValidateBranding(reporting.Config{
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo,
	}); err != nil {
		slog.Error("invalid report branding", "error", err)
		os.Exit(1)
	}

	// Tracked so an interval set at the top of a --devices file can be
	// overridden by an explicit CLI flag, but not by its own default.
	intervalSetOnCLI := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "interval" {
			intervalSetOnCLI = true
		}
	})

	var parsers map[string]xrmonitor.ParserModule
	var err error
	if strings.TrimSpace(parsersFile) == "" {
		parsers, err = xrmonitor.LoadDefaultParsers()
	} else {
		parsers, err = xrmonitor.LoadParsers(parsersFile)
	}
	if err != nil {
		slog.Error("failed to load parser modules", "parsers_file", parsersFile, "error", err)
		os.Exit(1)
	}

	startedAt := time.Now().UTC()
	run, err := monitorsetup.SetupRun(outputDir, devicesFile, startedAt)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	defer run.SessionLogFile.Close()

	reader := bufio.NewReader(os.Stdin)
	cache := monitorsetup.NewCredentialCache(passcodeReuseWindow)
	registry := monitorsetup.NewHostnameRegistry()
	var sessions []*xrmonitor.DeviceSession
	var gatewayPrefix string
	var commands xrmonitor.CommandOverrides
	var excludeInterfacePrefixes []string
	var deviceSpecsFromFile []xrmonitor.DeviceSpec
	var haveDevicesFile bool
	var hubTopInterfacesConfigured *int
	if strings.TrimSpace(devicesFile) != "" {
		specs, fileInterval, fileGatewayPrefix, fileCommands, fileExcludePrefixes, fileHubTopInterfaces, err := xrmonitor.LoadDeviceSpecs(devicesFile)
		if err != nil {
			slog.Error("failed to load devices file", "devices_file", devicesFile, "error", err)
			os.Exit(1)
		}
		if fileInterval > 0 && !intervalSetOnCLI {
			interval = fileInterval
		}
		gatewayPrefix = fileGatewayPrefix
		commands = fileCommands
		excludeInterfacePrefixes = xrmonitor.ResolveExcludeInterfacePrefixes(fileExcludePrefixes)
		hubTopInterfacesConfigured = fileHubTopInterfaces
		deviceSpecsFromFile = specs
		haveDevicesFile = true
	} else {
		excludeInterfacePrefixes = xrmonitor.ResolveExcludeInterfacePrefixes(nil)
	}
	spec := xrmonitor.ResolveCollectionSpec(commands)
	hubTopInterfaces := xrmonitor.ResolveHubTopInterfaces(hubTopInterfacesConfigured)
	if haveDevicesFile {
		sessions = append(sessions, xrmonitor.OnboardDevicesFromSpecs(reader, deviceSpecsFromFile, deviceType, cache, registry, xrmonitor.ConnectDevice, parsers, gatewayPrefix, excludeInterfacePrefixes, spec, hubTopInterfaces)...)
	}
	sessions = append(sessions, xrmonitor.OnboardDevices(reader, deviceType, cache, registry, xrmonitor.ConnectDevice, parsers, gatewayPrefix, excludeInterfacePrefixes, spec, hubTopInterfaces)...)
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stderr, "no devices connected, exiting")
		return
	}

	statusOut := xrmonitor.NewTickStatusPrinter(monitorsetup.NewSyncWriter(run.StatusBaseWriter))
	fmt.Fprintf(os.Stderr, "\n%d device(s) connected; polling every %s, writing to %s/. Press Ctrl+C to stop.\n\n", len(sessions), interval, run.OutputDir)
	slog.Info("polling started", "device_count", len(sessions), "interval", interval.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, session := range sessions {
		wg.Add(1)
		go func(s *xrmonitor.DeviceSession) {
			defer wg.Done()
			xrmonitor.PollDevice(ctx, s, interval, run.OutputDir, parsers, statusOut, run.SnapshotOut, run.RunLabel, spec, captureRunningConfigEnabled)
		}(session)
	}
	wg.Wait()
	reportPath, reportErr := monitorreport.GenerateProfessionalInterfaceReport(run.OutputDir, startedAt, monitorreport.ProfessionalReportConfig{
		Output: reportOutput, Title: reportTitle, ChangeReference: changeReference,
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo, CompletedAt: time.Now(),
	})
	if reportErr != nil {
		slog.Warn("failed to write professional monitoring report", "error", reportErr)
	} else if reportPath != "" {
		fmt.Fprintf(run.SnapshotOut, "professional monitoring report written to %s\n", reportPath)
	}
	fmt.Fprintln(os.Stderr, "all device sessions stopped, exiting")
	slog.Info("all device sessions stopped")
}
