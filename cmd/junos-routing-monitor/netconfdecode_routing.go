package main

// Decoders for the two "Routing tables" RPCs in networkflow's reference
// manifest (networkflow/config/commands_junos.yaml): get-route-information
// and get-route-summary-information. Response element names below are
// confirmed against networkflow/build/lib/networkflow/core/parsers/juniper/routing.py
// (a working reference implementation parsing real Junos NETCONF output),
// but the exact request-side RPC body and the response's wrapper-element
// nesting have not been observed against a real device from this repo —
// validate before relying on this operationally, matching this repo's
// existing caution for new TextFSM templates. parseXMLElement/find (see
// netconfxml.go) search by local element name at any depth specifically to
// stay resilient to that unconfirmed nesting.

// routeInformationRPC is get-route-information scoped to one routing table
// — the NETCONF counterpart of captureSnapshot's existing SSH route-table
// capture ("show route table %s", parser junos_route_table). Decoded shape
// matches junos_route_table exactly: NETWORK, PROTOCOL, NEXTHOP.
const routeInformationRPC = "<get-route-information><table>%s</table></get-route-information>"

// routeSummaryInformationRPC is get-route-summary-information scoped to one
// routing table — a new, coarser count-only addition (no SSH/TextFSM
// counterpart existed before this). Decoded shape: TABLE, DESTINATIONS,
// TOTAL_ROUTES, ACTIVE_ROUTES, HOLDDOWN, HIDDEN, matching
// junos_route_table_summary's tick-loop-only shape (see poll.go's
// defaultSpec.RouteParser) so this snapshot-only section reads the same way
// a tick's route-summary field would, even though the tick loop itself
// never uses NETCONF.
const routeSummaryInformationRPC = "<get-route-summary-information><table>%s</table></get-route-summary-information>"

// decodeRouteInformationXML parses a get-route-information <rpc-reply> into
// one record per (destination, next-hop) pair — a destination with more
// than one ECMP next hop produces one record per next hop, all sharing the
// same NETWORK/PROTOCOL, mirroring junos_route_table's Filldown behavior for
// the same multi-next-hop case over CLI text.
func decodeRouteInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, rt := range root.find("rt") {
		destination := rt.childText("rt-destination")
		entries := rt.find("rt-entry")
		if len(entries) == 0 {
			records = append(records, map[string]string{"NETWORK": destination})
			continue
		}
		for _, entry := range entries {
			protocol := entry.childText("protocol-name")
			nextHops := entry.find("nh")
			if len(nextHops) == 0 {
				records = append(records, map[string]string{"NETWORK": destination, "PROTOCOL": protocol})
				continue
			}
			for _, nh := range nextHops {
				nextHop := nh.childText("to")
				if nextHop == "" {
					nextHop = nh.childText("via")
				}
				records = append(records, map[string]string{"NETWORK": destination, "PROTOCOL": protocol, "NEXTHOP": nextHop})
			}
		}
	}
	return encodeRecords("routes", records)
}

// decodeRouteSummaryXML parses a get-route-summary-information <rpc-reply>
// into one record per route-table element — normally exactly one, since the
// RPC is scoped to a single table via <table>%s</table>.
func decodeRouteSummaryXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, table := range root.find("route-table") {
		records = append(records, map[string]string{
			"TABLE":         table.childText("table-name"),
			"DESTINATIONS":  table.childText("destination-count"),
			"TOTAL_ROUTES":  table.childText("total-route-count"),
			"ACTIVE_ROUTES": table.childText("active-route-count"),
			"HOLDDOWN":      table.childText("holddown-route-count"),
			"HIDDEN":        table.childText("hidden-route-count"),
		})
	}
	return encodeRecords("routes", records)
}
