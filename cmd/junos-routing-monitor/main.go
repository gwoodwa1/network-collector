// Command junos-routing-monitor polls a set of Junos routers for BGP,
// routing-table, and interface health during a change window. Each device
// is authenticated individually (a one-time passcode is single-use, same
// assumption as cmd/xr-routing-monitor) and then polled repeatedly over
// that same persistent SSH session so no further authentication is
// required until the process exits.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorreport"
	"github.com/gwoodwa1/network-collector/internal/reporting"
	"github.com/gwoodwa1/network-collector/internal/safeoutput"
	"github.com/gwoodwa1/network-collector/internal/secureartifact"
	"github.com/gwoodwa1/network-collector/pkg/credentials"
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
		if err := runSnapshotDiff(diffBeforePath, diffAfterPath, os.Stdout); err != nil {
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

	var parsers map[string]parserModule
	var err error
	if strings.TrimSpace(parsersFile) == "" {
		parsers, err = loadDefaultParsers()
	} else {
		parsers, err = loadParsers(parsersFile)
	}
	if err != nil {
		slog.Error("failed to load parser modules", "parsers_file", parsersFile, "error", err)
		os.Exit(1)
	}

	// startedAt is this run's single "now" for every fallback timestamp
	// below (the change folder's name and the session log's filename) —
	// computed once, in UTC, so the two can never disagree on timezone or
	// skew by a second the way two independent time.Now() calls could.
	startedAt := time.Now().UTC()

	// runLabel identifies this change window: the --devices YAML's basename
	// (without extension), e.g. "CRQXXX" for --devices CRQXXX.yaml — empty
	// when devices were onboarded interactively instead. Computed here
	// (before outputDir is finalized) so every artifact this run produces
	// can be nested under one folder named for the change instead of a flat
	// directory of prefixed files.
	var runLabel string
	if trimmed := strings.TrimSpace(devicesFile); trimmed != "" {
		base := filepath.Base(trimmed)
		runLabel = strings.TrimSuffix(base, filepath.Ext(base))
	}

	// Every artifact this run produces (jsonl, snapshots, session.log) is
	// nested under <output-dir>/<changeDirName>/ — runLabel when a
	// --devices file named this change, or a start timestamp plus this
	// process's PID when onboarding was purely interactive (no file to name
	// the folder after); the PID guards against two such processes launched
	// within the same second landing on an identical folder name and
	// merging their artifacts. Re-running against the *same* --devices file,
	// by contrast, deliberately reuses the same folder every time — it's
	// named for the change, not the run — so its per-file timestamps (see
	// snapshotFilenameBase) are what keep repeat runs from overwriting each
	// other within it.
	changeDirName := runLabel
	if changeDirName == "" {
		changeDirName = fmt.Sprintf("%s-%d", startedAt.Format("20060102-150405"), os.Getpid())
	}
	outputDir = filepath.Join(outputDir, changeDirName)
	if err := secureartifact.EnsureDir(outputDir); err != nil {
		slog.Error("failed to create output directory", "output_dir", outputDir, "error", err)
		os.Exit(1)
	}

	// session.log mirrors every scrolling status line plus all slog events
	// (connects, drops, snapshot errors) to a durable file, so the terminal
	// output isn't the only record of what happened during the change
	// window. It deliberately never sees credential prompts or passcodes:
	// those stay on os.Stderr only, untouched by this file.
	var sessionLogNameParts []string
	if runLabel != "" {
		sessionLogNameParts = append(sessionLogNameParts, runLabel)
	}
	sessionLogNameParts = append(sessionLogNameParts, startedAt.Format("20060102-150405"), "session.log")
	sessionLogPath := filepath.Join(outputDir, strings.Join(sessionLogNameParts, "-"))
	sessionLogFile, err := secureartifact.OpenFile(sessionLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		slog.Error("failed to open session log", "path", sessionLogPath, "error", err)
		os.Exit(1)
	}
	defer sessionLogFile.Close()
	// slog's built-in handlers already serialize concurrent writes with
	// their own internal mutex (log/slog/handler.go), so this multi-writer
	// needs no extra locking. statusOut below is different: fmt.Fprintf and
	// io.MultiWriter provide no such guarantee on their own, so it's wrapped
	// in a real mutex to keep concurrent devices' status lines from
	// splicing together on the terminal or in session.log.
	humanOutput := safeoutput.NewWriter(io.MultiWriter(os.Stderr, sessionLogFile))
	slog.SetDefault(slog.New(slog.NewTextHandler(humanOutput, nil)))
	// Plain (non-slog) operational confirmations, like a snapshot having been
	// written — same style as the onboarding "connected to X" messages, but
	// mirrored to session.log too, since they happen during the change
	// window itself rather than during setup.
	snapshotOut := &syncWriter{w: humanOutput}

	reader := bufio.NewReader(os.Stdin)
	cache := &credentialCache{window: passcodeReuseWindow}
	registry := newHostnameRegistry()
	var sessions []*deviceSession
	var commands commandOverrides
	var deviceSpecsFromFile []deviceSpec
	var haveDevicesFile bool
	if strings.TrimSpace(devicesFile) != "" {
		specs, fileInterval, fileCommands, fileNetconfSnapshot, err := loadDeviceSpecs(devicesFile)
		if err != nil {
			slog.Error("failed to load devices file", "devices_file", devicesFile, "error", err)
			os.Exit(1)
		}
		// An explicit -interval/-netconf-snapshot flag always wins over the
		// file's default.
		if fileInterval > 0 && !intervalSetOnCLI {
			interval = fileInterval
		}
		if !netconfSnapshotSetOnCLI {
			netconfSnapshotEnabled = resolveNetconfSnapshot(fileNetconfSnapshot, netconfSnapshotEnabled)
		}
		commands = fileCommands
		deviceSpecsFromFile = specs
		haveDevicesFile = true
	}
	spec := resolveCollectionSpec(commands)
	if haveDevicesFile {
		sessions = append(sessions, onboardDevicesFromSpecs(reader, deviceSpecsFromFile, deviceType, netconfSnapshotEnabled, cache, registry, connectDevice)...)
	}
	// Always fall through to interactive onboarding afterward: blank
	// hostname finishes immediately if the file already covered everything,
	// or lets the operator add ad hoc devices not listed in it.
	sessions = append(sessions, onboardDevices(reader, deviceType, netconfSnapshotEnabled, cache, registry, connectDevice)...)
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stderr, "no devices connected, exiting")
		return
	}

	statusOut := newTickStatusPrinter(&syncWriter{w: safeoutput.NewWriter(io.MultiWriter(os.Stdout, sessionLogFile))})
	fmt.Fprintf(os.Stderr, "\n%d device(s) connected; polling every %s, writing to %s/. Press Ctrl+C to stop.\n\n", len(sessions), interval, outputDir)
	slog.Info("polling started", "device_count", len(sessions), "interval", interval.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, session := range sessions {
		wg.Add(1)
		go func(s *deviceSession) {
			defer wg.Done()
			pollDevice(ctx, s, interval, outputDir, parsers, statusOut, snapshotOut, runLabel, spec, captureRunningConfigEnabled)
		}(session)
	}
	wg.Wait()
	reportPath, reportErr := monitorreport.GenerateProfessionalInterfaceReport(outputDir, startedAt, monitorreport.ProfessionalReportConfig{
		Output: reportOutput, Title: reportTitle, ChangeReference: changeReference,
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo, CompletedAt: time.Now(),
	})
	if reportErr != nil {
		slog.Warn("failed to write professional monitoring report", "error", reportErr)
	} else if reportPath != "" {
		fmt.Fprintf(snapshotOut, "professional monitoring report written to %s\n", reportPath)
	}
	fmt.Fprintln(os.Stderr, "all device sessions stopped, exiting")
	slog.Info("all device sessions stopped")
}

// sessionExecutor is the subset of *ssh.Client that polling and onboarding
// need. Defining it as an interface (rather than depending on *ssh.Client
// directly) lets tests exercise onboarding/polling/shutdown logic with a
// fake session instead of a real SSH connection.
type sessionExecutor interface {
	Execute(cmd string) (string, error)
	Close() error
}

// connectFunc abstracts connectDevice so onboarding's claim-after-success,
// no-claim-on-failure sequencing (see hostnameRegistry and connectDevice's
// no-retry docs) can be tested end-to-end without a real SSH connection.
// netconfSnapshot requests a second, NETCONF connection alongside the
// always-required SSH one (see connectDevice); netconfClient is nil when
// netconfSnapshot was false, or when the NETCONF dial itself failed (a
// warning is logged, but that alone never fails the device's onboarding —
// see connectDevice).
type connectFunc func(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *credentialCache) (client sessionExecutor, netconfClient sessionExecutor, err error)

// deviceSession holds one device's already-authenticated persistent SSH
// session plus the collection parameters gathered for it during onboarding.
// tables holds every routing table to monitor for this device (e.g.
// "CUSTOMER-A.inet.0", "inet.0"); interfaces holds every interface to poll.
// There is no auto-detection here (unlike cmd/xr-routing-monitor's VRF
// auto-detect) — everything is exactly what the operator typed or listed in
// a --devices file.
//
// netconfClient is an optional second, NETCONF connection dialed alongside
// client (SSH) at onboarding, used only by captureSnapshot's NETCONF-sourced
// sections (see snapshot.go) — nil when NETCONF snapshot capture wasn't
// opted in for this device, or when the NETCONF dial failed. The periodic
// tick loop (poll.go) never touches it; it only ever uses client.
type deviceSession struct {
	hostname      string
	tables        []string
	interfaces    []string
	neighbors     []string
	client        sessionExecutor
	netconfClient sessionExecutor
}

func splitCommaList(line string) []string {
	var values []string
	for _, value := range strings.Split(line, ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

// onboardDevices interactively prompts for each device to monitor.
// netconfSnapshot is the fleet-wide default (-netconf-snapshot /
// devicesDocument.NetconfSnapshot, already resolved by the caller) applied
// to every device onboarded this way — interactive onboarding has no
// per-device override prompt for it, unlike tables/interfaces/neighbors; an
// operator who needs a per-device override should describe that device in a
// --devices file instead.
func onboardDevices(reader *bufio.Reader, deviceType string, netconfSnapshot bool, cache *credentialCache, registry *hostnameRegistry, connect connectFunc) []*deviceSession {
	var sessions []*deviceSession
	for {
		fmt.Fprintf(os.Stderr, "Router hostname/IP (blank to finish onboarding): ")
		host, _ := reader.ReadString('\n')
		host = strings.TrimSpace(host)
		if host == "" {
			break
		}
		if exists, existing := registry.has(host); exists {
			fmt.Fprintf(os.Stderr, "already connected to %s (as %q), skipping duplicate\n\n", host, existing)
			continue
		}

		fmt.Fprintf(os.Stderr, "Routing table(s) for route-summary polling on %s, comma-separated (e.g. CUSTOMER-A.inet.0; blank to skip): ", host)
		tableLine, _ := reader.ReadString('\n')
		tables := dedupeSorted(splitCommaList(tableLine))

		fmt.Fprintf(os.Stderr, "Interface(s) on %s, comma-separated (blank to skip): ", host)
		interfaceLine, _ := reader.ReadString('\n')
		interfaces := dedupeSorted(splitCommaList(interfaceLine))

		fmt.Fprintf(os.Stderr, "BGP neighbor IP(s) on %s to snapshot routes for before/after the change, comma-separated (blank to skip): ", host)
		neighborLine, _ := reader.ReadString('\n')
		neighbors := dedupeSorted(splitCommaList(neighborLine))

		client, netconfClient, err := connect(reader, host, deviceType, netconfSnapshot, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", host, err)
			continue
		}
		registry.claim(host)

		fmt.Fprintf(os.Stderr, "connected to %s\n\n", host)
		slog.Info("device connected", "hostname", host, "tables", tables, "interfaces", interfaces, "neighbors", neighbors)
		sessions = append(sessions, &deviceSession{hostname: host, tables: tables, interfaces: interfaces, neighbors: neighbors, client: client, netconfClient: netconfClient})
	}
	return sessions
}

// credentialCache remembers the last successfully-used username/passcode so
// it can be offered for reuse on the next device within window — one-time
// passcodes stay valid for a short time (commonly cached server-side by the
// auth backend), so the same code often authenticates a second device
// connected in quick succession. Reuse is always operator-confirmed, never
// silent, and window should be set with a safety margin under the real
// server-side cache duration.
type credentialCache struct {
	username   string
	password   string
	capturedAt time.Time
	window     time.Duration
}

func (c *credentialCache) valid() bool {
	return c != nil && !c.capturedAt.IsZero() && c.window > 0 && time.Since(c.capturedAt) < c.window
}

// resolveCredentials returns a username/password, offering reuse of a still
// valid cached passcode first. fresh reports whether a new prompt happened
// (as opposed to reuse), which the caller uses to decide whether to update
// the cache's capture time — reuse never extends the original window.
func resolveCredentials(reader *bufio.Reader, cache *credentialCache) (username, password string, fresh bool, err error) {
	if cache.valid() {
		remaining := cache.window - time.Since(cache.capturedAt)
		fmt.Fprintf(os.Stderr, "Reuse cached passcode for %s (~%s left in the cache window)? [Y/n]: ", cache.username, remaining.Round(time.Second))
		answer, _ := reader.ReadString('\n')
		declined := strings.EqualFold(strings.TrimSpace(answer), "n") || strings.EqualFold(strings.TrimSpace(answer), "no")
		if !declined {
			return cache.username, cache.password, false, nil
		}
	}
	username, password, err = credentials.ResolveCredentialsWithTerminal(true, reader, os.Stdin, os.Stderr)
	return username, password, true, err
}

// connectDevice prompts for credentials (offering passcode reuse via cache
// first) and makes exactly one SSH connection attempt. It deliberately does
// not retry on failure: a one-time-passcode backend commonly locks the
// account after a handful of consecutive bad attempts, so an easy inline
// "retry?" prompt is a real way to lock yourself out under pressure during a
// change window. A failed SSH attempt invalidates the cache (a rejected
// passcode is never trustworthy to reuse) and returns the error immediately
// — trying again for this host requires a fresh, deliberate onboarding
// attempt.
//
// When netconfSnapshot is true, a second connection is dialed immediately
// afterward via connectJunosNetconfDevice, using the exact same
// username/password that just authenticated the SSH session — no
// additional prompt, and safe for a one-time passcode specifically because
// it's reused within the same moment it was accepted, not later (see
// connectJunosNetconfDevice's doc comment). Unlike the SSH connection, a
// failed NETCONF dial does not fail the device's onboarding: it's an
// opt-in, additive capability, so a warning is logged and the device
// proceeds with netconfClient == nil — its snapshot capture falls back to
// SSH-only sections for that one device (see captureSnapshot).
func connectDevice(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *credentialCache) (client sessionExecutor, netconfClient sessionExecutor, err error) {
	username, password, fresh, err := resolveCredentials(reader, cache)
	if err != nil {
		return nil, nil, fmt.Errorf("read credentials: %w", err)
	}
	client, err = connectJunosDevice(host, username, password, deviceType)
	if err != nil {
		if cache != nil {
			*cache = credentialCache{window: cache.window}
		}
		return nil, nil, err
	}
	if cache != nil && fresh {
		*cache = credentialCache{username: username, password: password, capturedAt: time.Now(), window: cache.window}
	}
	if netconfSnapshot {
		nc, ncErr := connectJunosNetconfDevice(host, username, password)
		if ncErr != nil {
			slog.Warn("failed to establish NETCONF connection for snapshot capture; falling back to SSH-only snapshots for this device", "hostname", host, "error", ncErr)
		} else {
			netconfClient = nc
		}
	}
	return client, netconfClient, nil
}
