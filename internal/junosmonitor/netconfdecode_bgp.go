package junosmonitor

import "strings"

// Decoder for get-bgp-neighbor-information, the "Routing protocols" BGP RPC
// in networkflow's reference manifest. This is new data junos-routing-monitor
// has never captured before (the tick loop's "show bgp summary" is a
// coarser, different data point), so its JSON shape is free to define — it
// follows this repo's existing ALL-CAPS field-name convention. Response
// element names are confirmed against
// networkflow/build/lib/networkflow/core/parsers/juniper/bgp.py (a working
// reference implementation), but the exact request-side RPC body and the
// response's wrapper-element nesting have not been observed against a real
// device from this repo — validate before relying on this operationally.

// bgpNeighborInformationRPC fetches every BGP peer's detail as a
// device-wide NETCONF snapshot section. This intentionally remains
// independent of session.neighbors, which only controls the existing
// SSH-sourced per-neighbor route and advertised-route captures.
const bgpNeighborInformationRPC = "<get-bgp-neighbor-information/>"

// decodeBGPNeighborDetailXML parses a get-bgp-neighbor-information
// <rpc-reply> into one record per bgp-peer. A peer with more than one
// bgp-rib (e.g. both unicast and labeled-unicast) has only its first/primary
// rib's prefix counts surfaced — which rib Junos lists first for a given
// peer is unconfirmed against real output, so this is a best-effort default
// to revisit once real output is available.
func decodeBGPNeighborDetailXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, peer := range root.find("bgp-peer") {
		record := map[string]string{
			"PEER_ADDRESS":  stripPortSuffix(peer.childText("peer-address")),
			"PEER_AS":       peer.childText("peer-as"),
			"LOCAL_ADDRESS": stripPortSuffix(peer.childText("local-address")),
			"LOCAL_AS":      peer.childText("local-as"),
			"DESCRIPTION":   peer.childText("description"),
			"PEER_TYPE":     peer.childText("peer-type"),
			"PEER_STATE":    peer.childText("peer-state"),
			"HOLDTIME":      peer.childText("holdtime"),
			"PREFERENCE":    peer.childText("preference"),
		}
		if ribs := peer.find("bgp-rib"); len(ribs) > 0 {
			rib := ribs[0]
			record["ACTIVE_PREFIX_COUNT"] = rib.childText("active-prefix-count")
			record["RECEIVED_PREFIX_COUNT"] = rib.childText("received-prefix-count")
			record["ACCEPTED_PREFIX_COUNT"] = rib.childText("accepted-prefix-count")
			record["SUPPRESSED_PREFIX_COUNT"] = rib.childText("suppressed-prefix-count")
			record["ADVERTISED_PREFIX_COUNT"] = rib.childText("advertised-prefix-count")
		}
		records = append(records, record)
	}
	return encodeRecords("bgp_neighbors", records)
}

// stripPortSuffix drops a trailing "+<port>" from a Junos peer/local
// address (e.g. "192.0.2.1+179" -> "192.0.2.1"), matching the reference
// implementation's address_str.split('+')[0].
func stripPortSuffix(address string) string {
	if idx := strings.IndexByte(address, '+'); idx >= 0 {
		return address[:idx]
	}
	return address
}
