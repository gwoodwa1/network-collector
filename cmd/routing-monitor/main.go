// Command routing-monitor is the mixed-fleet front-end for
// cmd/xr-routing-monitor and cmd/junos-routing-monitor: it onboards a
// change window's Cisco IOS-XR and Juniper Junos devices from one combined
// --devices YAML file, polls both platforms concurrently, and writes every
// artifact (tick data, snapshots, session.log, the HTML report) into one
// shared output folder.
//
// Both platforms' onboarding still prompts for credentials interactively,
// one device at a time — this tool deliberately onboards the cisco_iosxr
// section fully before starting the juniper_junos section (not
// concurrently) specifically so those prompts never race on the same
// terminal input. Once onboarding finishes, every device (both platforms)
// polls concurrently for the rest of the run.
//
// This tool requires --devices; there is no interactive (no-YAML) mixed-
// fleet onboarding in this first pass — use xr-routing-monitor or
// junos-routing-monitor directly for a purely interactive single-platform
// session.
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
	"github.com/gwoodwa1/network-collector/internal/xrmonitor"
)

// version is replaced by GoReleaser at build time.
var version = "dev"

func main() {
	var interval time.Duration
	var outputDir string
	var devicesFile string
	var passcodeReuseWindow time.Duration
	var captureRunningConfigEnabled bool
	var netconfSnapshotEnabled bool
	var showVersion bool
	var reportOutput, reportTitle, changeReference string
	var logoFolder, headerLogo, footerLogo string
	flag.DurationVar(&interval, "interval", 60*time.Second, "polling interval between collection ticks per device, both platforms")
	flag.StringVar(&outputDir, "output-dir", "artifacts", "parent directory for this run's shared output folder")
	flag.StringVar(&devicesFile, "devices", "", "required: combined YAML file with cisco_iosxr and/or juniper_junos sections (see README)")
	flag.DurationVar(&passcodeReuseWindow, "passcode-reuse-window", 45*time.Second, "how long an entered passcode may be offered for reuse on the next device, across both platforms; 0 disables reuse")
	flag.BoolVar(&captureRunningConfigEnabled, "capture-running-config", false, "also capture the running configuration before and after the change window, for every device on both platforms")
	flag.BoolVar(&netconfSnapshotEnabled, "netconf-snapshot", false, "Junos devices only: also dial NETCONF (static credentials only, not RSA-passcode fleets) for extra before/after snapshot sections; no effect on IOS-XR devices")
	flag.StringVar(&reportOutput, "report-output", "interface-traffic.html", "professional HTML report filename")
	flag.StringVar(&reportTitle, "report-title", "Change Monitoring Report", "professional report title")
	flag.StringVar(&changeReference, "change-reference", "", "change/ticket reference shown in the report")
	flag.StringVar(&logoFolder, "logo-folder", "", "directory containing optional PNG report branding")
	flag.StringVar(&headerLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&footerLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Printf("routing-monitor %s\n", version)
		return
	}
	if strings.TrimSpace(devicesFile) == "" {
		fmt.Fprintln(os.Stderr, "-devices is required (a combined YAML file with cisco_iosxr and/or juniper_junos sections)")
		os.Exit(1)
	}
	if err := reporting.ValidateBranding(reporting.Config{
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo,
	}); err != nil {
		slog.Error("invalid report branding", "error", err)
		os.Exit(1)
	}

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

	xrParsers, err := xrmonitor.LoadDefaultParsers()
	if err != nil {
		slog.Error("failed to load embedded IOS-XR parser modules", "error", err)
		os.Exit(1)
	}
	junosParsers, err := junosmonitor.LoadDefaultParsers()
	if err != nil {
		slog.Error("failed to load embedded Junos parser modules", "error", err)
		os.Exit(1)
	}

	startedAt := time.Now().UTC()
	run, err := monitorsetup.SetupRun(outputDir, devicesFile, startedAt)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	defer run.SessionLogFile.Close()

	doc, fileInterval, err := loadMixedFleetDocument(devicesFile)
	if err != nil {
		slog.Error("failed to load devices file", "devices_file", devicesFile, "error", err)
		os.Exit(1)
	}
	if fileInterval > 0 && !intervalSetOnCLI {
		interval = fileInterval
	}

	reader := bufio.NewReader(os.Stdin)
	cache := monitorsetup.NewCredentialCache(passcodeReuseWindow)
	registry := monitorsetup.NewHostnameRegistry()

	// Onboarded strictly sequentially, platform by platform (not
	// concurrently): both tools' credential prompts read from os.Stdin one
	// device at a time, and running them concurrently would race on the
	// same terminal input. Once onboarding finishes below, every device
	// polls concurrently regardless of platform.
	var xrSessions []*xrmonitor.DeviceSession
	var xrSpec xrmonitor.CollectionSpec
	if doc.CiscoIOSXR != nil {
		excludeInterfacePrefixes := xrmonitor.ResolveExcludeInterfacePrefixes(doc.CiscoIOSXR.ExcludeInterfacePrefixes)
		hubTopInterfaces := xrmonitor.ResolveHubTopInterfaces(doc.CiscoIOSXR.HubTopInterfaces)
		xrSpec = xrmonitor.ResolveCollectionSpec(doc.CiscoIOSXR.Commands)
		xrSessions = xrmonitor.OnboardDevicesFromSpecs(reader, doc.CiscoIOSXR.Devices, "cisco_iosxr", cache, registry, xrmonitor.ConnectDevice, xrParsers, doc.CiscoIOSXR.CustomerGatewayPrefix, excludeInterfacePrefixes, xrSpec, hubTopInterfaces)
	}
	var junosSessions []*junosmonitor.DeviceSession
	var junosSpec junosmonitor.CollectionSpec
	if doc.JuniperJunos != nil {
		junosSpec = junosmonitor.ResolveCollectionSpec(doc.JuniperJunos.Commands)
		netconfSnapshotDefault := netconfSnapshotEnabled
		if !netconfSnapshotSetOnCLI {
			netconfSnapshotDefault = junosmonitor.ResolveNetconfSnapshot(doc.JuniperJunos.NetconfSnapshot, netconfSnapshotEnabled)
		}
		junosSessions = junosmonitor.OnboardDevicesFromSpecs(reader, doc.JuniperJunos.Devices, "juniper_junos", netconfSnapshotDefault, cache, registry, junosmonitor.ConnectDevice)
	}
	if len(xrSessions) == 0 && len(junosSessions) == 0 {
		fmt.Fprintln(os.Stderr, "no devices connected, exiting")
		return
	}

	// One shared SyncWriter for status output, passed to both platforms'
	// tick-status printers — using two separate SyncWriters here (even both
	// wrapping the same underlying writer) would only serialize each
	// platform's own devices against each other, not against the other
	// platform's concurrent status lines.
	statusWriter := monitorsetup.NewSyncWriter(run.StatusBaseWriter)
	xrStatusOut := xrmonitor.NewTickStatusPrinter(statusWriter)
	junosStatusOut := junosmonitor.NewTickStatusPrinter(statusWriter)

	fmt.Fprintf(os.Stderr, "\n%d device(s) connected (%d IOS-XR, %d Junos); polling every %s, writing to %s/. Press Ctrl+C to stop.\n\n", len(xrSessions)+len(junosSessions), len(xrSessions), len(junosSessions), interval, run.OutputDir)
	slog.Info("polling started", "xr_device_count", len(xrSessions), "junos_device_count", len(junosSessions), "interval", interval.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, session := range xrSessions {
		wg.Add(1)
		go func(s *xrmonitor.DeviceSession) {
			defer wg.Done()
			xrmonitor.PollDevice(ctx, s, interval, run.OutputDir, xrParsers, xrStatusOut, run.SnapshotOut, run.RunLabel, xrSpec, captureRunningConfigEnabled)
		}(session)
	}
	for _, session := range junosSessions {
		wg.Add(1)
		go func(s *junosmonitor.DeviceSession) {
			defer wg.Done()
			junosmonitor.PollDevice(ctx, s, interval, run.OutputDir, junosParsers, junosStatusOut, run.SnapshotOut, run.RunLabel, junosSpec, captureRunningConfigEnabled)
		}(session)
	}
	wg.Wait()

	// A single call: internal/monitorreport globs *.jsonl in OutputDir and
	// reads only fields (hostname, interfaces, default_route_next_hops)
	// both platforms' tick records already share identically, so one
	// report covers both platforms with no platform-aware code here at all.
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
