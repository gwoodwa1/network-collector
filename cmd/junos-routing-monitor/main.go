// Command junos-routing-monitor polls a set of Junos routers for BGP,
// routing-table, and interface health during a change window. Each device
// is authenticated individually (a one-time passcode is single-use, same
// assumption as cmd/xr-routing-monitor) and then polled repeatedly over
// that same persistent SSH session so no further authentication is
// required until the process exits.
//
// This is a thin wrapper: all collection/onboarding/reporting logic lives in
// internal/junosmonitor (shared with cmd/routing-monitor, the mixed-fleet
// front-end covering both this tool and cmd/xr-routing-monitor). Keeping
// this file to flag parsing and orchestration only means the two entry
// points can never drift apart from what internal/junosmonitor actually
// does.
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

	"github.com/gwoodwa1/network-collector/internal/junosmonitor"
	"github.com/gwoodwa1/network-collector/internal/monitorreport"
	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
	"github.com/gwoodwa1/network-collector/internal/reporting"
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
	var captureRunningConfigEnabled bool
	var netconfSnapshotEnabled bool
	var showVersion bool
	var reportOutput, reportTitle, changeReference string
	var logoFolder, headerLogo, footerLogo string
	flag.DurationVar(&interval, "interval", 60*time.Second, "polling interval between collection ticks per device")
	flag.StringVar(&outputDir, "output-dir", "artifacts", "directory to write one <hostname>.jsonl file per device")
	flag.StringVar(&parsersFile, "parsers", "", "path to an external parser module file; defaults to this binary's embedded parser definitions")
	flag.StringVar(&deviceType, "type", "juniper_junos", "scrapligo platform/driver name for all onboarded devices")
	flag.StringVar(&devicesFile, "devices", "", "optional YAML file listing hostname/tables/interfaces/neighbors per device; credentials are still always prompted interactively")
	flag.DurationVar(&passcodeReuseWindow, "passcode-reuse-window", 45*time.Second, "how long an entered one-time passcode may be offered for reuse on the next device; 0 disables reuse")
	flag.StringVar(&reportOutput, "report-output", "interface-traffic.html", "professional HTML report filename")
	flag.StringVar(&reportTitle, "report-title", "Junos Change Monitoring Report", "professional report title")
	flag.StringVar(&changeReference, "change-reference", "", "change/ticket reference shown in the report")
	flag.StringVar(&logoFolder, "logo-folder", "", "directory containing optional PNG report branding")
	flag.StringVar(&headerLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&footerLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.StringVar(&diffBeforePath, "diff-before", "", "path to a captured *-before.json snapshot; combine with -diff-after to print a route-level diff and exit, instead of connecting to any device")
	flag.StringVar(&diffAfterPath, "diff-after", "", "path to a captured *-after.json snapshot; combine with -diff-before")
	flag.BoolVar(&captureRunningConfigEnabled, "capture-running-config", false, "also capture \"show configuration\" before and after the change window; diffed automatically alongside the route snapshot when the window ends")
	flag.BoolVar(&netconfSnapshotEnabled, "netconf-snapshot", false, "also dial NETCONF (static credentials only, not RSA-passcode fleets) alongside SSH and use it for extra before/after snapshot sections (route info, BGP neighbor detail, ISIS/LDP/MPLS, interface/chassis/system health); fleet-wide default, overridable per device via --devices")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Printf("junos-routing-monitor %s\n", version)
		return
	}

	snapshotDiffRequested := diffBeforePath != "" || diffAfterPath != ""
	if snapshotDiffRequested {
		if diffBeforePath == "" || diffAfterPath == "" {
			fmt.Fprintln(os.Stderr, "both -diff-before and -diff-after are required together")
			os.Exit(1)
		}
		if err := junosmonitor.RunSnapshotDiff(diffBeforePath, diffAfterPath, os.Stdout); err != nil {
			slog.Error("snapshot diff failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := reporting.ValidateBranding(reporting.Config{
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo,
	}); err != nil {
		slog.Error("invalid report branding", "error", err)
		os.Exit(1)
	}

	// Tracked so an interval (or netconf-snapshot default) set at the top of
	// a --devices file can be overridden by an explicit CLI flag, but not by
	// its own default.
	intervalSetOnCLI := false
	netconfSnapshotSetOnCLI := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "interval":
			intervalSetOnCLI = true
		case "netconf-snapshot":
			netconfSnapshotSetOnCLI = true
		}
	})

	var parsers map[string]junosmonitor.ParserModule
	var err error
	if strings.TrimSpace(parsersFile) == "" {
		parsers, err = junosmonitor.LoadDefaultParsers()
	} else {
		parsers, err = junosmonitor.LoadParsers(parsersFile)
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
	var sessions []*junosmonitor.DeviceSession
	var commands junosmonitor.CommandOverrides
	var deviceSpecsFromFile []junosmonitor.DeviceSpec
	var haveDevicesFile bool
	if strings.TrimSpace(devicesFile) != "" {
		specs, fileInterval, fileCommands, fileNetconfSnapshot, err := junosmonitor.LoadDeviceSpecs(devicesFile)
		if err != nil {
			slog.Error("failed to load devices file", "devices_file", devicesFile, "error", err)
			os.Exit(1)
		}
		if fileInterval > 0 && !intervalSetOnCLI {
			interval = fileInterval
		}
		if !netconfSnapshotSetOnCLI {
			netconfSnapshotEnabled = junosmonitor.ResolveNetconfSnapshot(fileNetconfSnapshot, netconfSnapshotEnabled)
		}
		commands = fileCommands
		deviceSpecsFromFile = specs
		haveDevicesFile = true
	}
	spec := junosmonitor.ResolveCollectionSpec(commands)
	if haveDevicesFile {
		sessions = append(sessions, junosmonitor.OnboardDevicesFromSpecs(reader, deviceSpecsFromFile, deviceType, netconfSnapshotEnabled, cache, registry, junosmonitor.ConnectDevice)...)
	}
	sessions = append(sessions, junosmonitor.OnboardDevices(reader, deviceType, netconfSnapshotEnabled, cache, registry, junosmonitor.ConnectDevice)...)
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stderr, "no devices connected, exiting")
		return
	}

	statusOut := junosmonitor.NewTickStatusPrinter(monitorsetup.NewSyncWriter(run.StatusBaseWriter))
	fmt.Fprintf(os.Stderr, "\n%d device(s) connected; polling every %s, writing to %s/. Press Ctrl+C to stop.\n\n", len(sessions), interval, run.OutputDir)
	slog.Info("polling started", "device_count", len(sessions), "interval", interval.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, session := range sessions {
		wg.Add(1)
		go func(s *junosmonitor.DeviceSession) {
			defer wg.Done()
			junosmonitor.PollDevice(ctx, s, interval, run.OutputDir, parsers, statusOut, run.SnapshotOut, run.RunLabel, spec, captureRunningConfigEnabled)
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
