package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

// collectionSpec maps each data point to the IOS-XR command and parser
// module used to collect it, built from real IOS-XR command output.
type collectionSpec struct {
	BGPCommand          string
	BGPParser           string
	RouteCommand        string // %s is replaced with the device's VRF name
	RouteParser         string
	DefaultRouteCommand string // %s is replaced with the device's VRF name
	DefaultRouteParser  string
	InterfaceCommand    string // %s is replaced with the interface name
	InterfaceParser     string
}

var defaultSpec = collectionSpec{
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
}

// resolveCollectionSpec merges any non-empty overrides from a --devices
// file's top-level "commands:" section onto defaultSpec, so an operator can
// point this tool at a different show-command or parser (e.g. a code
// variant without "show bgp vpnv4 unicast summary", or one needing a
// "... detail" variant) by editing the devices file instead of patching Go
// source and rebuilding the static binary mid-engagement.
func resolveCollectionSpec(overrides commandOverrides) collectionSpec {
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

// pollDevice runs one collection tick immediately, then one per interval,
// against the device's already-open session, until ctx is cancelled or the
// session appears to have dropped (detected via the BGP command's Execute
// error, since BGP is collected on every tick and acts as a session
// liveness canary). It never reconnects: a dropped session requires a fresh
// RSA passcode, which this loop cannot supply unattended.
func pollDevice(ctx context.Context, session *deviceSession, interval time.Duration, outputDir string, parsers map[string]parserModule, statusOut *tickStatusPrinter, snapshotOut io.Writer, runLabel string, spec collectionSpec, captureRunningConfigEnabled bool) {
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
		result, sessionAlive := collectTick(session, parsers, spec)
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
		if err := captureRunningConfig(session, "before", outputDir, runLabel, beforeCapturedAt, snapshotOut); err != nil {
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
				if err := captureRunningConfig(session, "after", outputDir, runLabel, afterCapturedAt, snapshotOut); err != nil {
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
// failures are recorded per-field and do not stop polling.
func collectTick(session *deviceSession, parsers map[string]parserModule, spec collectionSpec) (tickResult, bool) {
	result := tickResult{Timestamp: time.Now().UTC().Format(time.RFC3339), Hostname: session.hostname}

	bgpOutput, err := session.client.Execute(spec.BGPCommand)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("bgp: execute failed: %v", err))
		return result, false
	}
	result.BGP = parseOrRaw(bgpOutput, spec.BGPParser, parsers, &result.Errors, "bgp")

	if len(session.vrfs) > 0 {
		result.Routes = map[string]json.RawMessage{}
		result.DefaultRouteNextHops = map[string]json.RawMessage{}
		for _, vrf := range session.vrfs {
			routeOutput, err := session.client.Execute(fmt.Sprintf(spec.RouteCommand, vrf))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("route vrf %s: execute failed: %v", vrf, err))
			} else {
				result.Routes[vrf] = parseOrRaw(routeOutput, spec.RouteParser, parsers, &result.Errors, "route vrf "+vrf)
			}

			nextHopOutput, err := session.client.Execute(fmt.Sprintf(spec.DefaultRouteCommand, vrf))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("default route next hop vrf %s: execute failed: %v", vrf, err))
				continue
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
			result.Interfaces[ifaceName] = parseOrRaw(ifaceOutput, spec.InterfaceParser, parsers, &result.Errors, "interface "+ifaceName)
		}
	}

	return result, true
}

func parseOrRaw(output, parserName string, parsers map[string]parserModule, errs *[]string, label string) json.RawMessage {
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
