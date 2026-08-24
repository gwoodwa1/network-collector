package junosmonitor

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

// snapshotResult is the structured counterpart to the raw .txt snapshot:
// same commands, parsed via junos_route_table/junos_bgp_neighbor_routes so
// before/after prefix sets and next hops can be diffed programmatically
// instead of by eye. Fields fall back to raw text (via parseOrRaw, the same
// helper used for periodic ticks) if a parser isn't available.
type snapshotResult struct {
	Timestamp     string                      `json:"timestamp"`
	Hostname      string                      `json:"hostname"`
	Label         string                      `json:"label"`
	Tables        map[string]json.RawMessage  `json:"tables,omitempty"`
	Neighbors     map[string]neighborSnapshot `json:"neighbors,omitempty"`
	NetconfDetail *netconfSnapshotDetail      `json:"netconf_detail,omitempty"`
	Errors        []string                    `json:"errors,omitempty"`
}

type neighborSnapshot struct {
	Routes           json.RawMessage `json:"routes,omitempty"`
	AdvertisedRoutes json.RawMessage `json:"advertised_routes,omitempty"`
}

// netconfSnapshotDetail groups every section captureSnapshot adds when
// session.netconfClient is set (see -netconf-snapshot/netconf_snapshot) —
// kept as its own nested struct, rather than flat fields directly on
// snapshotResult, so it's visually obvious in both the Go struct and the
// written JSON which sections are NETCONF-only bonus data versus the
// SSH-sourced sections every device has always produced. Nil (and omitted
// from the JSON entirely) for a device that didn't opt into NETCONF
// snapshot capture, or whose NETCONF connection failed to dial at
// onboarding.
type netconfSnapshotDetail struct {
	// RouteInformation and RouteSummary are keyed by table, one entry per
	// session.tables, alongside the existing SSH-sourced Tables map.
	// RouteInformation (get-route-information) is the NETCONF counterpart
	// of Tables (SSH "show route table %s"); RouteSummary
	// (get-route-summary-information) is a new, coarser count-only
	// addition with no SSH equivalent.
	RouteInformation map[string]json.RawMessage `json:"route_information,omitempty"`
	RouteSummary     map[string]json.RawMessage `json:"route_summary,omitempty"`
	// Everything below is captured once per device per snapshot moment,
	// regardless of session.tables/session.neighbors — all of it is new
	// data this tool never captured before NETCONF snapshot support.
	BGPNeighborDetail      json.RawMessage `json:"bgp_neighbor_detail,omitempty"`
	ISISAdjacencies        json.RawMessage `json:"isis_adjacencies,omitempty"`
	LDPDatabase            json.RawMessage `json:"ldp_database,omitempty"`
	MPLSLSPInformation     json.RawMessage `json:"mpls_lsp_information,omitempty"`
	InterfaceInformation   json.RawMessage `json:"interface_information,omitempty"`
	SoftwareInformation    json.RawMessage `json:"software_information,omitempty"`
	RouteEngineInformation json.RawMessage `json:"route_engine_information,omitempty"`
	FPCInformation         json.RawMessage `json:"fpc_information,omitempty"`
	PICInformation         json.RawMessage `json:"pic_information,omitempty"`
	AlarmInformation       json.RawMessage `json:"alarm_information,omitempty"`
	CoreDumps              json.RawMessage `json:"core_dumps,omitempty"`
}

// captureSnapshot records the full route table for every monitored table
// and, per configured neighbor, the routes learned from and advertised to
// that neighbor — always over SSH (session.client), regardless of NETCONF
// opt-in. When session.netconfClient is set (see -netconf-snapshot), it
// additionally captures a much richer set of NETCONF-sourced sections (see
// netconfSnapshotDetail): a NETCONF counterpart of the route-table capture
// plus route summaries per table, and, once per device, BGP neighbor
// detail, ISIS/LDP/MPLS protocol state, interface state, and chassis/system
// health. It writes two files: a raw <base>.txt (verbatim command/RPC
// output, for a quick eyeball diff) and a structured <base>.json (for a
// programmatic before/after diff), where <base> is
// "[<runLabel>-]<hostname>-<capture-timestamp>-<label>" (see
// snapshotFilenameBase) — the timestamp keeps repeat runs against the same
// devices file from overwriting a previous change window's snapshots, and
// runLabel (typically the devices YAML file's basename, one dedicated file
// per change) keeps concurrent change windows' snapshots apart in a shared
// output directory. label is typically "before" or "after". A device with
// no tables, no neighbors, and no NETCONF connection produces no files. On
// success, a confirmation line is written to out (mirrored to session.log
// by the caller, not just the terminal, so the confirmation survives even
// if nobody is watching the terminal live).
func captureSnapshot(session *DeviceSession, label, outputDir, runLabel string, capturedAt time.Time, parsers map[string]ParserModule, out io.Writer) error {
	if len(session.tables) == 0 && len(session.neighbors) == 0 && session.netconfClient == nil {
		return nil
	}

	result := snapshotResult{
		Timestamp: capturedAt.Format(time.RFC3339),
		Hostname:  session.hostname,
		Label:     label,
	}
	var rawSections []string

	if len(session.tables) > 0 {
		result.Tables = map[string]json.RawMessage{}
	}
	for _, table := range session.tables {
		cmd := fmt.Sprintf("show route table %s", table)
		output, err := session.client.Execute(cmd)
		rawSections = append(rawSections, formatSnapshotSection(cmd, output, err))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("table %s: execute failed: %v", table, err))
		} else {
			result.Tables[table] = parseOrRaw(output, "junos_route_table", parsers, &result.Errors, "table "+table)
		}
	}

	if len(session.neighbors) > 0 {
		result.Neighbors = map[string]neighborSnapshot{}
	}
	for _, neighbor := range session.neighbors {
		var neighborResult neighborSnapshot

		routesCmd := fmt.Sprintf("show route receive-protocol bgp %s", neighbor)
		routesOutput, err := session.client.Execute(routesCmd)
		rawSections = append(rawSections, formatSnapshotSection(routesCmd, routesOutput, err))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("neighbor %s routes: execute failed: %v", neighbor, err))
		} else {
			neighborResult.Routes = parseOrRaw(routesOutput, "junos_bgp_neighbor_routes", parsers, &result.Errors, "neighbor "+neighbor+" routes")
		}

		advertisedCmd := fmt.Sprintf("show route advertising-protocol bgp %s", neighbor)
		advertisedOutput, err := session.client.Execute(advertisedCmd)
		rawSections = append(rawSections, formatSnapshotSection(advertisedCmd, advertisedOutput, err))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("neighbor %s advertised-routes: execute failed: %v", neighbor, err))
		} else {
			neighborResult.AdvertisedRoutes = parseOrRaw(advertisedOutput, "junos_bgp_neighbor_routes", parsers, &result.Errors, "neighbor "+neighbor+" advertised-routes")
		}

		result.Neighbors[neighbor] = neighborResult
	}

	if session.netconfClient != nil {
		detail := &netconfSnapshotDetail{}

		if len(session.tables) > 0 {
			detail.RouteInformation = map[string]json.RawMessage{}
			detail.RouteSummary = map[string]json.RawMessage{}
			for _, table := range session.tables {
				riRPC := fmt.Sprintf(routeInformationRPC, table)
				riOutput, err := session.netconfClient.Execute(riRPC)
				rawSections = append(rawSections, formatSnapshotSection(riRPC, riOutput, err))
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("netconf route information %s: execute failed: %v", table, err))
				} else {
					detail.RouteInformation[table] = decodeNetconfOrRaw(riOutput, decodeRouteInformationXML, &result.Errors, "netconf route information "+table)
				}

				rsRPC := fmt.Sprintf(routeSummaryInformationRPC, table)
				rsOutput, err := session.netconfClient.Execute(rsRPC)
				rawSections = append(rawSections, formatSnapshotSection(rsRPC, rsOutput, err))
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("netconf route summary %s: execute failed: %v", table, err))
				} else {
					detail.RouteSummary[table] = decodeNetconfOrRaw(rsOutput, decodeRouteSummaryXML, &result.Errors, "netconf route summary "+table)
				}
			}
		}

		// Every remaining section is device-wide (not table/neighbor
		// scoped), so it's captured exactly once per device regardless of
		// how many tables/neighbors are configured.
		captureNetconfSection := func(rpc string, decode func(string) (string, error), label string) json.RawMessage {
			output, err := session.netconfClient.Execute(rpc)
			rawSections = append(rawSections, formatSnapshotSection(rpc, output, err))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: execute failed: %v", label, err))
				return nil
			}
			return decodeNetconfOrRaw(output, decode, &result.Errors, label)
		}
		detail.BGPNeighborDetail = captureNetconfSection(bgpNeighborInformationRPC, decodeBGPNeighborDetailXML, "netconf bgp neighbor detail")
		detail.ISISAdjacencies = captureNetconfSection(isisAdjacencyInformationRPC, decodeISISAdjacenciesXML, "netconf isis adjacencies")
		detail.LDPDatabase = captureNetconfSection(ldpDatabaseInformationRPC, decodeLDPDatabaseXML, "netconf ldp database")
		detail.MPLSLSPInformation = captureNetconfSection(mplsLSPInformationRPC, decodeMPLSLSPInformationXML, "netconf mpls lsp information")
		detail.InterfaceInformation = captureNetconfSection(interfaceInformationRPC, decodeInterfaceInformationXML, "netconf interface information")
		detail.SoftwareInformation = captureNetconfSection(softwareInformationRPC, decodeSoftwareInformationXML, "netconf software information")
		detail.RouteEngineInformation = captureNetconfSection(routeEngineInformationRPC, decodeRouteEngineInformationXML, "netconf route engine information")
		detail.FPCInformation = captureNetconfSection(fpcInformationRPC, decodeFPCInformationXML, "netconf fpc information")
		detail.PICInformation = captureNetconfSection(picInformationRPC, decodePICInformationXML, "netconf pic information")
		detail.AlarmInformation = captureNetconfSection(alarmInformationRPC, decodeAlarmInformationXML, "netconf alarm information")
		detail.CoreDumps = captureNetconfSection(coreDumpsRPC, decodeCoreDumpsXML, "netconf core dumps")

		result.NetconfDetail = detail
	}

	base := snapshotFilenameBase(runLabel, session.hostname, label, capturedAt)

	textPath := filepath.Join(outputDir, base+".txt")
	header := fmt.Sprintf("# snapshot %s for %s captured %s\n\n", label, session.hostname, result.Timestamp)
	textContent := header + strings.Join(rawSections, "\n")
	if err := secureartifact.WriteFile(textPath, []byte(textContent)); err != nil {
		return fmt.Errorf("write raw snapshot: %w", err)
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode structured snapshot: %w", err)
	}
	jsonPath := filepath.Join(outputDir, base+".json")
	if err := secureartifact.WriteFile(jsonPath, encoded); err != nil {
		return fmt.Errorf("write structured snapshot: %w", err)
	}

	fmt.Fprintf(out, "%s-change snapshot captured for %s (%s, %s)\n", label, session.hostname, filepath.Base(textPath), filepath.Base(jsonPath))
	return nil
}

// snapshotFilenameBase builds the shared "<base>" (no extension) for a
// snapshot's .txt/.json pair: "[<runLabel>-]<hostname>-<timestamp>-<label>",
// e.g. "CRQXXX-pe-router-1-20260709-143022-before". runLabel is omitted
// entirely (along with its separator) when empty, e.g. for devices onboarded
// interactively without a --devices file.
func snapshotFilenameBase(runLabel, hostname, label string, capturedAt time.Time) string {
	var parts []string
	if trimmed := strings.TrimSpace(runLabel); trimmed != "" {
		parts = append(parts, sanitizeFilename(trimmed))
	}
	parts = append(parts, sanitizeFilename(hostname), capturedAt.Format("20060102-150405"), label)
	return strings.Join(parts, "-")
}

func formatSnapshotSection(cmd, output string, err error) string {
	if err != nil {
		return fmt.Sprintf("## %s\n(execute failed: %v)\n", cmd, err)
	}
	return fmt.Sprintf("## %s\n%s\n", cmd, output)
}
