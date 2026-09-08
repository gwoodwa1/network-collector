package junosmonitor

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
	"sort"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

// CollectionSpec maps each data point to the Junos command and parser
// module used to collect it, built from real Junos command output.
type CollectionSpec struct {
	BGPCommand          string
	BGPParser           string
	RouteCommand        string // %s is replaced with the device's routing table name (e.g. "CUSTOMER-A.inet.0")
	RouteParser         string
	DefaultRouteCommand string // %s is replaced with the device's routing table name
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

// defaultAuthzFailurePattern matches the general "authorization failed"
// phrasing TACACS/AAA command-authorization denials commonly use,
// case-insensitively (see internal/xrmonitor's identical default, confirmed
// against real IOS-XR rejection text — Junos fleets using per-command AAA
// authorization typically phrase it similarly).
var defaultAuthzFailurePattern = regexp.MustCompile(`(?i)authorization failed`)

// compileAuthzFailurePattern compiles pattern with a leading "(?i)" applied
// unconditionally, so an operator-provided authz_failure_pattern override
// matches case-insensitively just like defaultAuthzFailurePattern — without
// this, a documented override such as "authorization failed" would miss a
// device's actual mixed-case response. Used both here (to compile a real
// override) and by validateRegexPattern (devices.go), so a pattern that's
// valid at --devices-file load time is compiled the exact same way at
// collection time.
func compileAuthzFailurePattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}

// defaultSpec's RouteCommand/RouteParser deliberately take a full routing
// table name (e.g. "CUSTOMER-A.inet.0", or "inet.0" for the default/master
// instance) rather than a bare routing-instance name: Junos's "show route
// summary table" keyword wants the table, not the instance, and there is no
// universal instance-name-to-table-name mapping this tool could safely
// invent (a routing-instance can carry more than one address family/table).
// Requiring the operator to type the table name they actually want polled
// keeps this a plain, honest fmt.Sprintf substitution — see
// ResolveCollectionSpec/CommandOverrides for how a fleet with a different
// convention can override this without a rebuild.
//
// DefaultRouteCommand/DefaultRouteParser separately track the default
// route's BGP protocol next hop (the originating PE/RR, stable across
// underlay rerouting) for each monitored table — distinct from
// RouteCommand's route *count* summary. "0/0 exact" restricts the match to
// the default route itself, not any more-specific prefix; "extensive" is
// required for Junos to print the "Protocol next hop:" line at all.
var defaultSpec = CollectionSpec{
	BGPCommand:          "show bgp summary",
	BGPParser:           "junos_bgp_summary",
	RouteCommand:        "show route summary table %s",
	RouteParser:         "junos_route_table_summary",
	DefaultRouteCommand: `show route table %s 0/0 exact extensive | match "Protocol next hop:"`,
	DefaultRouteParser:  "junos_default_route_nexthop",
	// "extensive" plus the broad Input|Output filter covers both interface
	// statistics formats Junos produces: the compact
	// "Statistics Packets pps Bytes bps" table with "Input :"/"Output:"
	// rows (ae/physical units), and irb units' section-based output where
	// only the "Transit statistics" lines carry a trailing "N bps"/"N pps"
	// rate — the parser keys on that trailing rate, so the rate-less
	// Traffic/Local statistics lines the filter also lets through are
	// ignored rather than misparsed.
	InterfaceCommand:    `show interfaces %s extensive | match "Description:|Input|Output"`,
	InterfaceParser:     "junos_interface_stats",
	AuthzFailurePattern: defaultAuthzFailurePattern,
}

// ResolveCollectionSpec merges any non-empty overrides from a --devices
// file's top-level "commands:" section onto defaultSpec, so an operator can
// point this tool at a different show-command or parser by editing the
// devices file instead of patching Go source and rebuilding the static
// binary mid-engagement.
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
	Tables               map[string]json.RawMessage `json:"tables,omitempty"`
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
// with freshly-prompted credentials, and polling resumes on success. The
// NETCONF connection (session.netconfClient, if any) is never touched by
// reauth — it uses static credentials unrelated to the polled SSH session's
// TACACS command authorization (see DeviceSession's doc comment).
func PollDevice(ctx context.Context, session *DeviceSession, interval time.Duration, outputDir string, parsers map[string]ParserModule, statusOut *TickStatusPrinter, snapshotOut io.Writer, runLabel string, spec CollectionSpec, captureRunningConfigEnabled bool, reauth *ReauthCoordinator) {
	defer func() {
		if err := session.client.Close(); err != nil {
			slog.Warn("error closing session", "hostname", session.hostname, "error", err)
		}
		if session.netconfClient != nil {
			if err := session.netconfClient.Close(); err != nil {
				slog.Warn("error closing NETCONF session", "hostname", session.hostname, "error", err)
			}
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
		statusOut.printTick(result, sessionAlive)
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

	if len(session.tables) > 0 {
		result.Tables = map[string]json.RawMessage{}
		result.DefaultRouteNextHops = map[string]json.RawMessage{}
		for _, table := range session.tables {
			routeOutput, err := session.client.Execute(fmt.Sprintf(spec.RouteCommand, table))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("route table %s: execute failed: %v", table, err))
			} else if authorizationFailed(spec, routeOutput) {
				result.Errors = append(result.Errors, fmt.Sprintf("route table %s: TACACS command authorization failed", table))
				return result, true, true
			} else {
				result.Tables[table] = parseOrRaw(routeOutput, spec.RouteParser, parsers, &result.Errors, "route table "+table)
			}

			// Junos repeats "Protocol next hop: <ip>" once per route
			// reflector that advertised the path (a fleet with 3 RRs
			// commonly emits the same next hop 3 times over here) plus a
			// second, more detailed line per path — see
			// summarizeDefaultRouteNextHops (status.go), which dedupes
			// down to the distinct next-hop value(s) rather than reporting
			// a raw, RR-count-inflated total.
			nextHopOutput, err := session.client.Execute(fmt.Sprintf(spec.DefaultRouteCommand, table))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("default route next hop %s: execute failed: %v", table, err))
				continue
			}
			if authorizationFailed(spec, nextHopOutput) {
				result.Errors = append(result.Errors, fmt.Sprintf("default route next hop %s: TACACS command authorization failed", table))
				return result, true, true
			}
			result.DefaultRouteNextHops[table] = parseOrRaw(nextHopOutput, spec.DefaultRouteParser, parsers, &result.Errors, "default route next hop "+table)
		}
	}

	if len(session.interfaces) > 0 {
		result.Interfaces = map[string]json.RawMessage{}
		for _, ifaceName := range session.interfaces {
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

// dedupeSorted trims, drops empty entries from, deduplicates, and sorts
// values. Used everywhere a table/interface/neighbor list gets merged from
// more than one source (manually specified plus a legacy singular field),
// so the same target never ends up polled twice.
func dedupeSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
