// Command xr-routing-monitor polls a set of IOS-XR routers for BGP, route
// table, and core-facing interface health during a change window. Each
// device is authenticated individually (RSA SecurID passcodes are
// single-use) and then polled repeatedly over that same persistent SSH
// session so no further authentication is required until the process exits.
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

	"github.com/gwoodwa1/network-collector/pkg/credentials"
)

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
	flag.DurationVar(&interval, "interval", 60*time.Second, "polling interval between collection ticks per device")
	flag.StringVar(&outputDir, "output-dir", "artifacts", "directory to write one <hostname>.jsonl file per device")
	flag.StringVar(&parsersFile, "parsers", "", "path to an external parser module file; defaults to this binary's embedded parser definitions")
	flag.StringVar(&deviceType, "type", "cisco_iosxr", "scrapligo platform/driver name for all onboarded devices")
	flag.StringVar(&devicesFile, "devices", "", "optional YAML file listing hostname/vrf/interfaces/neighbors per device; credentials are still always prompted interactively")
	flag.DurationVar(&passcodeReuseWindow, "passcode-reuse-window", 45*time.Second, "how long an entered RSA passcode may be offered for reuse on the next device, matching your ISE cache duration with a safety margin; 0 disables reuse")
	flag.BoolVar(&captureRunningConfigEnabled, "capture-running-config", false, "also capture \"show running-config\" before and after the change window, as a separate <base>-running-config.txt file per label; off by default since it's a heavier capture")
	flag.StringVar(&diffBeforePath, "diff-before", "", "path to a captured *-before.json snapshot; combine with -diff-after to print a route-level diff and exit, instead of connecting to any device")
	flag.StringVar(&diffAfterPath, "diff-after", "", "path to a captured *-after.json snapshot; combine with -diff-before")
	flag.StringVar(&diffBeforeConfigPath, "diff-before-config", "", "path to a captured *-before-running-config.txt file; combine with -diff-after-config to print a running-config diff and exit, instead of connecting to any device")
	flag.StringVar(&diffAfterConfigPath, "diff-after-config", "", "path to a captured *-after-running-config.txt file; combine with -diff-before-config")
	flag.Parse()

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
			if err := runSnapshotDiff(diffBeforePath, diffAfterPath, os.Stdout); err != nil {
				slog.Error("snapshot diff failed", "error", err)
				os.Exit(1)
			}
		}
		if configDiffRequested {
			if snapshotDiffRequested {
				fmt.Fprintln(os.Stdout)
			}
			if err := runConfigDiff(diffBeforeConfigPath, diffAfterConfigPath, os.Stdout); err != nil {
				slog.Error("running-config diff failed", "error", err)
				os.Exit(1)
			}
		}
		return
	}

	// Tracked so an interval set at the top of a --devices file can be
	// overridden by an explicit CLI flag, but not by its own default.
	intervalSetOnCLI := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "interval" {
			intervalSetOnCLI = true
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

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		slog.Error("failed to create output directory", "output_dir", outputDir, "error", err)
		os.Exit(1)
	}

	// runLabel identifies this change window: the --devices YAML's basename
	// (without extension), e.g. "CRQXXX" for --devices CRQXXX.yaml — empty
	// when devices were onboarded interactively instead. Computed here
	// (rather than after session-log setup, where it used to live) so the
	// session log filename below can use it too.
	var runLabel string
	if trimmed := strings.TrimSpace(devicesFile); trimmed != "" {
		base := filepath.Base(trimmed)
		runLabel = strings.TrimSuffix(base, filepath.Ext(base))
	}

	// session.log mirrors every scrolling status line plus all slog events
	// (connects, drops, snapshot errors) to a durable file, so the terminal
	// output isn't the only record of what happened during the change
	// window. It deliberately never sees credential prompts or passcodes:
	// those stay on os.Stderr only, untouched by this file.
	//
	// The filename is "[<runLabel>-]<start-timestamp>-session.log" rather
	// than a fixed "session.log" — this fleet now often runs one instance
	// per node (to keep each device's scrolling output on its own terminal)
	// pointed at a shared --output-dir, and a fixed filename would collide:
	// two processes appending to the very same file interleave their writes
	// line-by-line (the syncWriter mutex below only serializes goroutines
	// within one process), defeating the whole point of separating them.
	// The devices-file name plus a start timestamp keeps each run's log
	// distinct and identifiable, the same reasoning as snapshotFilenameBase.
	var sessionLogNameParts []string
	if runLabel != "" {
		sessionLogNameParts = append(sessionLogNameParts, runLabel)
	}
	sessionLogNameParts = append(sessionLogNameParts, time.Now().Format("20060102-150405"), "session.log")
	sessionLogPath := filepath.Join(outputDir, strings.Join(sessionLogNameParts, "-"))
	sessionLogFile, err := os.OpenFile(sessionLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
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
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, sessionLogFile), nil)))
	// Plain (non-slog) operational confirmations, like a snapshot having been
	// written — same style as the onboarding "connected to X" messages, but
	// mirrored to session.log too, since they happen during the change
	// window itself rather than during setup.
	snapshotOut := &syncWriter{w: io.MultiWriter(os.Stderr, sessionLogFile)}
	// runLabel (computed above, before session-log setup) also identifies
	// this change window in before/after snapshot filenames — see
	// snapshotFilenameBase.

	reader := bufio.NewReader(os.Stdin)
	cache := &credentialCache{window: passcodeReuseWindow}
	registry := newHostnameRegistry()
	var sessions []*deviceSession
	var gatewayPrefix string
	var commands commandOverrides
	var excludeInterfacePrefixes []string
	var deviceSpecsFromFile []deviceSpec
	var haveDevicesFile bool
	var hubTopInterfacesConfigured *int
	if strings.TrimSpace(devicesFile) != "" {
		specs, fileInterval, fileGatewayPrefix, fileCommands, fileExcludePrefixes, fileHubTopInterfaces, err := loadDeviceSpecs(devicesFile)
		if err != nil {
			slog.Error("failed to load devices file", "devices_file", devicesFile, "error", err)
			os.Exit(1)
		}
		// An explicit -interval flag always wins over the file's default.
		if fileInterval > 0 && !intervalSetOnCLI {
			interval = fileInterval
		}
		gatewayPrefix = fileGatewayPrefix
		commands = fileCommands
		excludeInterfacePrefixes = resolveExcludeInterfacePrefixes(fileExcludePrefixes)
		hubTopInterfacesConfigured = fileHubTopInterfaces
		deviceSpecsFromFile = specs
		haveDevicesFile = true
	} else {
		excludeInterfacePrefixes = resolveExcludeInterfacePrefixes(nil)
	}
	// spec and hubTopInterfaces are resolved once, here, from whatever the
	// --devices file set (if anything, nil otherwise — see
	// resolveHubTopInterfaces) — both the file-driven and interactive
	// onboarding paths below need them fully resolved before they run
	// auto-detection, since discovering a hub VRF's interfaces now also
	// ranks them by current utilization using spec's interface command.
	spec := resolveCollectionSpec(commands)
	hubTopInterfaces := resolveHubTopInterfaces(hubTopInterfacesConfigured)
	if haveDevicesFile {
		sessions = append(sessions, onboardDevicesFromSpecs(reader, deviceSpecsFromFile, deviceType, cache, registry, connectDevice, parsers, gatewayPrefix, excludeInterfacePrefixes, spec, hubTopInterfaces)...)
	}
	// Always fall through to interactive onboarding afterward: blank
	// hostname finishes immediately if the file already covered everything,
	// or lets the operator add ad hoc devices not listed in it. gatewayPrefix
	// (if the devices file set one) is offered as the default answer if the
	// operator opts into VRF auto-detection for one of these devices too.
	sessions = append(sessions, onboardDevices(reader, deviceType, cache, registry, connectDevice, parsers, gatewayPrefix, excludeInterfacePrefixes, spec, hubTopInterfaces)...)
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stderr, "no devices connected, exiting")
		return
	}

	statusOut := newTickStatusPrinter(&syncWriter{w: io.MultiWriter(os.Stdout, sessionLogFile)})
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
	fmt.Fprintln(os.Stderr, "all device sessions stopped, exiting")
	slog.Info("all device sessions stopped")
}

// sessionExecutor is the subset of *xrSSHClient that polling and onboarding
// need. Defining it as an interface (rather than depending on *xrSSHClient
// directly) lets tests exercise onboarding/polling/shutdown logic with a
// fake session instead of a real SSH connection.
type sessionExecutor interface {
	Execute(cmd string) (string, error)
	Close() error
}

// connectFunc abstracts connectDevice so onboarding's claim-after-success,
// no-claim-on-failure sequencing (see hostnameRegistry and connectDevice's
// no-retry docs) can be tested end-to-end without a real SSH connection.
type connectFunc func(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error)

// deviceSession holds one device's already-authenticated persistent SSH
// session plus the collection parameters gathered for it during onboarding.
// vrfs holds every VRF to monitor for this device: manually specified
// ones, auto-detected customer VRFs (see autoDetectCustomerVRFs), or both.
// coreInterfaces/customerInterfaces/hubInterfaces are kept as three separate
// lists (rather than one merged list) purely so the status line (status.go)
// can label each interface "core", the single monitored customer VRF (or
// "customer"), or "hub" by provenance — manually typed, auto-discovered
// customer-VRF, or sampled from a hub VRF (see autoDetectCustomerVRFs) —
// instead of losing that distinction the moment they're onboarded; all
// three are still polled together (see allInterfaces).
type deviceSession struct {
	hostname           string
	vrfs               []string
	coreInterfaces     []string
	customerInterfaces []string
	hubInterfaces      []string
	neighbors          []string
	client             sessionExecutor
}

// allInterfaces returns every interface to poll for this device — core,
// customer, and hub-sampled — deduped and sorted, since an operator could in
// principle type an interface manually that auto-detect also discovers.
func (s *deviceSession) allInterfaces() []string {
	all := append([]string{}, s.coreInterfaces...)
	all = append(all, s.customerInterfaces...)
	all = append(all, s.hubInterfaces...)
	return dedupeSorted(all)
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

// onboardDevices interactively prompts for each device to monitor. defaultGatewayPrefix
// (typically a --devices file's top-level customer_gateway_prefix, empty if none was
// loaded) is offered as the default answer when the operator opts into VRF
// auto-detection, so it only needs to be typed once per run rather than once per device.
func onboardDevices(reader *bufio.Reader, deviceType string, cache *credentialCache, registry *hostnameRegistry, connect connectFunc, parsers map[string]parserModule, defaultGatewayPrefix string, excludeInterfacePrefixes []string, spec collectionSpec, hubTopInterfaces int) []*deviceSession {
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

		var vrfs []string
		autoDetect, gatewayPrefix := promptAutoDetectVRF(reader, host, defaultGatewayPrefix)
		if !autoDetect {
			fmt.Fprintf(os.Stderr, "VRF name for route summary on %s (blank to skip): ", host)
			vrf, _ := reader.ReadString('\n')
			if vrf = strings.TrimSpace(vrf); vrf != "" {
				vrfs = []string{vrf}
			}
		}

		fmt.Fprintf(os.Stderr, "Core-facing Bundle-Ether interface(s) on %s, comma-separated (blank to skip): ", host)
		interfaceLine, _ := reader.ReadString('\n')
		coreInterfaces := dedupeSorted(splitCommaList(interfaceLine))

		fmt.Fprintf(os.Stderr, "BGP neighbor IP(s) on %s to snapshot routes for before/after the change, comma-separated (blank to skip): ", host)
		neighborLine, _ := reader.ReadString('\n')
		neighbors := splitCommaList(neighborLine)

		client, err := connect(reader, host, deviceType, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", host, err)
			continue
		}
		registry.claim(host)

		var customerInterfaces, hubInterfaces []string
		if autoDetect {
			vrfs, customerInterfaces, hubInterfaces = applyAutoDetectResult(client, gatewayPrefix, parsers, excludeInterfacePrefixes, spec, hubTopInterfaces, host, vrfs, os.Stderr)
		}

		fmt.Fprintf(os.Stderr, "connected to %s\n\n", host)
		slog.Info("device connected", "hostname", host, "vrfs", vrfs, "core_interfaces", coreInterfaces, "customer_interfaces", customerInterfaces, "hub_interfaces", hubInterfaces, "neighbors", neighbors)
		sessions = append(sessions, &deviceSession{hostname: host, vrfs: vrfs, coreInterfaces: coreInterfaces, customerInterfaces: customerInterfaces, hubInterfaces: hubInterfaces, neighbors: neighbors, client: client})
	}
	return sessions
}

// promptAutoDetectVRF asks whether to auto-detect this device's customer
// VRF(s) instead of typing a VRF name manually. When the operator opts in
// and defaultGatewayPrefix is empty (no --devices file supplied one), it
// also prompts for the gateway prefix that identifies a customer-facing
// default route on this fleet.
func promptAutoDetectVRF(reader *bufio.Reader, host, defaultGatewayPrefix string) (autoDetect bool, gatewayPrefix string) {
	fmt.Fprintf(os.Stderr, "Auto-detect customer VRF(s) via default-route gateway on %s? [y/N]: ", host)
	answer, _ := reader.ReadString('\n')
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return false, ""
	}
	if strings.TrimSpace(defaultGatewayPrefix) != "" {
		return true, strings.TrimSpace(defaultGatewayPrefix)
	}
	fmt.Fprintf(os.Stderr, "Customer-facing gateway prefix on %s (e.g. 10.99.99.): ", host)
	prefixLine, _ := reader.ReadString('\n')
	gatewayPrefix = strings.TrimSpace(prefixLine)
	if gatewayPrefix == "" {
		fmt.Fprintln(os.Stderr, "customer-facing gateway prefix is required for auto-detect; falling back to manual VRF entry")
		return false, ""
	}
	return true, gatewayPrefix
}

// credentialCache remembers the last successfully-used username/passcode so
// it can be offered for reuse on the next device within window — RSA
// passcodes stay valid for a short time (commonly ~60s, cached server-side
// by ISE), so the same code often authenticates a second device connected
// in quick succession. Reuse is always operator-confirmed, never silent,
// and window should be set with a safety margin under the real server-side
// cache duration.
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
		fmt.Fprintf(os.Stderr, "Reuse cached passcode for %s (~%s left in the ISE cache window)? [Y/n]: ", cache.username, remaining.Round(time.Second))
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
// first) and makes exactly one connection attempt. It deliberately does not
// retry on failure: RSA/ISE commonly locks the account after 3 consecutive
// bad attempts, so an easy inline "retry?" prompt is a real way to lock
// yourself out under pressure during a change window. A failed attempt
// invalidates the cache (a rejected passcode is never trustworthy to reuse)
// and returns the error immediately — trying again for this host requires a
// fresh, deliberate onboarding attempt.
func connectDevice(reader *bufio.Reader, host, deviceType string, cache *credentialCache) (sessionExecutor, error) {
	username, password, fresh, err := resolveCredentials(reader, cache)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	client, err := connectXRDevice(host, username, password, deviceType)
	if err != nil {
		if cache != nil {
			*cache = credentialCache{window: cache.window}
		}
		return nil, err
	}
	if cache != nil && fresh {
		*cache = credentialCache{username: username, password: password, capturedAt: time.Now(), window: cache.window}
	}
	return client, nil
}
