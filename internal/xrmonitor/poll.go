package xrmonitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

// CollectionSpec maps each data point to the IOS-XR command and parser
// module used to collect it, built from real IOS-XR command output.
type CollectionSpec struct {
	BGPCommand          string
	BGPParser           string
	RouteCommand        string // %s is replaced with the device's VRF name
	RouteParser         string
	DefaultRouteCommand string // %s is replaced with the device's VRF name
	DefaultRouteParser  string
	InterfaceCommand    string // %s is replaced with the interface name
	InterfaceParser     string
	// AuthzFailurePattern matches a TACACS/AAA command-authorization denial
	// in command output (see collectTick) — the session is still alive, but
	// the device rejected the command, which means the SSH session needs to
	// be restarted with fresh credentials rather than kept alive. See
	// defaultAuthzFailurePattern and CommandOverrides.AuthzFailurePattern.
	AuthzFailurePattern *regexp.Regexp
}

// defaultAuthzFailurePattern matches the confirmed IOS-XR rejection text
// ("Command authorization failed") plus the more general "authorization
// failed" phrasing TACACS/AAA command-authorization denials commonly use,
// case-insensitively.
var defaultAuthzFailurePattern = regexp.MustCompile(`(?i)authorization failed`)

// compileAuthzFailurePattern compiles pattern with a leading "(?i)" applied
// unconditionally, so an operator-provided authz_failure_pattern override
// matches case-insensitively just like defaultAuthzFailurePattern — without
// this, a documented override such as "authorization failed" would miss a
// device's actual "Command Authorization Failed" (mixed case) response. Used
// both here (to compile a real override) and by validateRegexPattern
// (devices.go), so a pattern that's valid at --devices-file load time is
// compiled the exact same way at collection time.
func compileAuthzFailurePattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}

var defaultSpec = CollectionSpec{
	BGPCommand:   "show bgp vpnv4 unicast summary",
	BGPParser:    "xr_bgp_vpnv4_summary",
	RouteCommand: "show route vrf %s summary",
	RouteParser:  "xr_route_vrf_summary",
	// DefaultRouteCommand separately tracks the default route's BGP next
	// hop (the originating PE, from the "<nexthop>, from <peer>" line under
	// "Routing Descriptor Blocks") for each monitored VRF — distinct from
	// RouteCommand's route *count* summary. Unlike Junos's "show route ...
	// extensive" (which repeats the next hop once per route reflector that
	// advertised the path), "show route vrf ... detail" already shows only
	// the installed/best path(s), so no route-reflector-count dedup
	// surprises are expected here — see summarizeDefaultRouteNextHops
	// (status.go), which still dedupes defensively for genuine ECMP.
	DefaultRouteCommand: "show route vrf %s 0.0.0.0/0 detail",
	DefaultRouteParser:  "xr_route_vrf_default_nexthop",
	InterfaceCommand:    `show int %s | inc "rate|Description:"`,
	InterfaceParser:     "xr_bundle_interface_stats",
	AuthzFailurePattern: defaultAuthzFailurePattern,
}

// ResolveCollectionSpec merges any non-empty overrides from a --devices
// file's top-level "commands:" section onto defaultSpec, so an operator can
// point this tool at a different show-command or parser (e.g. a code
// variant without "show bgp vpnv4 unicast summary", or one needing a
// "... detail" variant) by editing the devices file instead of patching Go
// source and rebuilding the static binary mid-engagement.
func ResolveCollectionSpec(overrides CommandOverrides) CollectionSpec {
	spec := defaultSpec
	if v := strings.TrimSpace(overrides.BGPCommand); v != "" {
		spec.BGPCommand = v
	}
	if v := strings.TrimSpace(overrides.BGPParser); v != "" {
		spec.BGPParser = v
	}
	if v := strings.TrimSpace(overrides.RouteCommand); v != "" {
		spec.RouteCommand = v
	}
	if v := strings.TrimSpace(overrides.RouteParser); v != "" {
		spec.RouteParser = v
	}
	if v := strings.TrimSpace(overrides.DefaultRouteCommand); v != "" {
		spec.DefaultRouteCommand = v
	}
	if v := strings.TrimSpace(overrides.DefaultRouteParser); v != "" {
		spec.DefaultRouteParser = v
	}
	if v := strings.TrimSpace(overrides.InterfaceCommand); v != "" {
		spec.InterfaceCommand = v
	}
	if v := strings.TrimSpace(overrides.InterfaceParser); v != "" {
		spec.InterfaceParser = v
	}
	if v := strings.TrimSpace(overrides.AuthzFailurePattern); v != "" {
		// Already validated as a compilable regex by ValidateDevicesDocument
		// in the real --devices-file load path; a compile failure here (e.g.
		// a caller that skipped validation) falls back to the default rather
		// than panicking or silently matching nothing.
		if compiled, err := compileAuthzFailurePattern(v); err == nil {
			spec.AuthzFailurePattern = compiled
		}
	}
	return spec
}

type tickResult struct {
	Timestamp            string                     `json:"timestamp"`
	Hostname             string                     `json:"hostname"`
	BGP                  json.RawMessage            `json:"bgp,omitempty"`
	Routes               map[string]json.RawMessage `json:"routes,omitempty"`
	DefaultRouteNextHops map[string]json.RawMessage `json:"default_route_next_hops,omitempty"`
	Interfaces           map[string]json.RawMessage `json:"interfaces,omitempty"`
	Errors               []string                   `json:"errors,omitempty"`
}

// PollDevice runs one collection tick immediately, then one per interval,
// against the device's already-open session, until ctx is cancelled or the
// session appears to have dropped (detected via the BGP command's Execute
// error, since BGP is collected on every tick and acts as a session
// liveness canary) and reauth is nil or fails to restart it. A TACACS
// command-authorization failure (session alive, but the device rejects
// commands — see collectTick's needsReauth) is treated differently: reauth,
// when non-nil, is used to close the stale session and open a fresh one
// with freshly-prompted credentials, and polling resumes on success.
func PollDevice(ctx context.Context, session *DeviceSession, interval time.Duration, outputDir string, parsers map[string]ParserModule, statusOut *TickStatusPrinter, snapshotOut io.Writer, runLabel string, spec CollectionSpec, captureRunningConfigEnabled bool, reauth *ReauthCoordinator) {
	defer func() {
		if err := session.client.Close(); err != nil {
			slog.Warn("error closing session", "hostname", session.hostname, "error", err)
		}
	}()

	outputPath := filepath.Join(outputDir, sanitizeFilename(session.hostname)+".jsonl")
	file, err := secureartifact.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		slog.Error("failed to open output file", "hostname", session.hostname, "path", outputPath, "error", err)
		return
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	tick := func() bool {
		result, sessionAlive, needsReauth := collectTick(session, parsers, spec)
		if needsReauth {
			sessionAlive = reauthenticate(ctx, session, reauth)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			slog.Error("failed to encode tick result", "hostname", session.hostname, "error", err)
			return sessionAlive
		}
		if _, err := writer.Write(append(encoded, '\n')); err != nil {
			slog.Error("failed to write tick result", "hostname", session.hostname, "error", err)
		}
		writer.Flush()
		statusOut.printTick(result, sessionAlive, session.coreInterfaces, session.hubInterfaces)
		if !sessionAlive {
			slog.Error("session appears to have dropped; stopping polling for this device", "hostname", session.hostname)
		}
		return sessionAlive
	}

	beforeCapturedAt := time.Now().UTC()
	beforeSnapshotOK := true
	if err := captureSnapshot(session, "before", outputDir, runLabel, beforeCapturedAt, parsers, snapshotOut); err != nil {
		slog.Error("failed to write before-change snapshot", "hostname", session.hostname, "error", err)
		beforeSnapshotOK = false
	}
	beforeConfigOK := true
	if captureRunningConfigEnabled {
		if err := CaptureRunningConfig(session, "before", outputDir, runLabel, beforeCapturedAt, snapshotOut); err != nil {
			slog.Error("failed to capture before-change running-config", "hostname", session.hostname, "error", err)
			beforeConfigOK = false
		}
	}

	if !tick() {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			afterCapturedAt := time.Now().UTC()
			afterSnapshotOK := true
			if err := captureSnapshot(session, "after", outputDir, runLabel, afterCapturedAt, parsers, snapshotOut); err != nil {
				slog.Error("failed to write after-change snapshot", "hostname", session.hostname, "error", err)
				afterSnapshotOK = false
			}
			afterConfigOK := true
			if captureRunningConfigEnabled {
				if err := CaptureRunningConfig(session, "after", outputDir, runLabel, afterCapturedAt, snapshotOut); err != nil {
					slog.Error("failed to capture after-change running-config", "hostname", session.hostname, "error", err)
					afterConfigOK = false
				}
			}
			printAutoDiffAfterChange(session, outputDir, runLabel, beforeCapturedAt, afterCapturedAt, captureRunningConfigEnabled, beforeSnapshotOK && afterSnapshotOK, beforeConfigOK && afterConfigOK, snapshotOut)
			return
		case <-ticker.C:
			if !tick() {
				return
			}
		}
	}
}

// collectTick runs the BGP, route, and interface commands for one device.
// It returns sessionAlive=false only when the BGP command itself failed to
// execute (a proxy for the SSH session having dropped); parser lookup/parse
// failures are recorded per-field and do not stop polling. needsReauth is
// true when any command's output matched spec.AuthzFailurePattern — the
// session is still alive (err == nil), but the device rejected the command,
// meaning TACACS/AAA command authorization has failed mid-session and the
// SSH session needs to be restarted with fresh credentials. The tick returns
// immediately on the first authorization-failure match rather than running
// the remaining commands against a session that's already been denied.
func collectTick(session *DeviceSession, parsers map[string]ParserModule, spec CollectionSpec) (result tickResult, sessionAlive bool, needsReauth bool) {
	result = tickResult{Timestamp: time.Now().UTC().Format(time.RFC3339), Hostname: session.hostname}

	bgpOutput, err := session.client.Execute(spec.BGPCommand)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("bgp: execute failed: %v", err))
		return result, false, false
	}
	if authorizationFailed(spec, bgpOutput) {
		result.Errors = append(result.Errors, "bgp: TACACS command authorization failed")
		return result, true, true
	}
	result.BGP = parseOrRaw(bgpOutput, spec.BGPParser, parsers, &result.Errors, "bgp")

	if len(session.vrfs) > 0 {
		result.Routes = map[string]json.RawMessage{}
		result.DefaultRouteNextHops = map[string]json.RawMessage{}
		for _, vrf := range session.vrfs {
			routeOutput, err := session.client.Execute(fmt.Sprintf(spec.RouteCommand, vrf))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("route vrf %s: execute failed: %v", vrf, err))
			} else if authorizationFailed(spec, routeOutput) {
				result.Errors = append(result.Errors, fmt.Sprintf("route vrf %s: TACACS command authorization failed", vrf))
				return result, true, true
			} else {
				result.Routes[vrf] = parseOrRaw(routeOutput, spec.RouteParser, parsers, &result.Errors, "route vrf "+vrf)
			}

			nextHopOutput, err := session.client.Execute(fmt.Sprintf(spec.DefaultRouteCommand, vrf))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("default route next hop vrf %s: execute failed: %v", vrf, err))
				continue
			}
			if authorizationFailed(spec, nextHopOutput) {
				result.Errors = append(result.Errors, fmt.Sprintf("default route next hop vrf %s: TACACS command authorization failed", vrf))
				return result, true, true
			}
			result.DefaultRouteNextHops[vrf] = parseOrRaw(nextHopOutput, spec.DefaultRouteParser, parsers, &result.Errors, "default route next hop vrf "+vrf)
		}
	}

	if interfaces := session.allInterfaces(); len(interfaces) > 0 {
		result.Interfaces = map[string]json.RawMessage{}
		for _, ifaceName := range interfaces {
			ifaceOutput, err := session.client.Execute(fmt.Sprintf(spec.InterfaceCommand, ifaceName))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("interface %s: execute failed: %v", ifaceName, err))
				continue
			}
			if authorizationFailed(spec, ifaceOutput) {
				result.Errors = append(result.Errors, fmt.Sprintf("interface %s: TACACS command authorization failed", ifaceName))
				return result, true, true
			}
			result.Interfaces[ifaceName] = parseOrRaw(ifaceOutput, spec.InterfaceParser, parsers, &result.Errors, "interface "+ifaceName)
		}
	}

	return result, true, false
}

// authorizationFailed reports whether output looks like a TACACS/AAA
// command-authorization denial rather than real command output (see
// CollectionSpec.AuthzFailurePattern). A nil pattern (only possible if a
// caller builds a CollectionSpec by hand instead of via ResolveCollectionSpec)
// never matches.
func authorizationFailed(spec CollectionSpec, output string) bool {
	return spec.AuthzFailurePattern != nil && spec.AuthzFailurePattern.MatchString(output)
}

func parseOrRaw(output, parserName string, parsers map[string]ParserModule, errs *[]string, label string) json.RawMessage {
	parsed, err := parseOutputWithModule(output, parserName, parsers)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s: %v", label, err))
		encoded, marshalErr := json.Marshal(map[string]string{"raw": output})
		if marshalErr != nil {
			return json.RawMessage("null")
		}
		return encoded
	}
	return json.RawMessage(parsed)
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", " ", "_")
	return replacer.Replace(strings.TrimSpace(name))
}
