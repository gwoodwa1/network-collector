package junosmonitor

// Decoders for the "Routing protocols" (ISIS) and "MPLS/LDP" RPCs in
// networkflow's reference manifest: get-isis-adjacency-information,
// get-ldp-database-information, get-mpls-lsp-information. All three are new
// data junos-routing-monitor has never captured before, so their JSON
// shapes are free to define — they follow this repo's existing ALL-CAPS
// field-name convention. Response element names are confirmed against
// networkflow/build/lib/networkflow/core/parsers/juniper/{isis,ldp,mpls}.py
// (a working reference implementation), but the exact request-side RPC
// bodies and the responses' wrapper-element nesting have not been observed
// against a real device from this repo — validate before relying on this
// operationally.

const isisAdjacencyInformationRPC = "<get-isis-adjacency-information/>"

const ldpDatabaseInformationRPC = "<get-ldp-database-information/>"

const mplsLSPInformationRPC = "<get-mpls-lsp-information/>"

// decodeISISAdjacenciesXML parses a get-isis-adjacency-information
// <rpc-reply> into one record per isis-adjacency.
func decodeISISAdjacenciesXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, adjacency := range root.find("isis-adjacency") {
		records = append(records, map[string]string{
			"INTERFACE_NAME": adjacency.childText("interface-name"),
			"SYSTEM_NAME":    adjacency.childText("system-name"),
			"LEVEL":          adjacency.childText("level"),
			"STATE":          adjacency.childText("adjacency-state"),
		})
	}
	return encodeRecords("isis_adjacencies", records)
}

// decodeLDPDatabaseXML parses a get-ldp-database-information <rpc-reply>
// into one record per ldp-binding, carrying its enclosing ldp-database's
// type and session ID along with it.
func decodeLDPDatabaseXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, database := range root.find("ldp-database") {
		databaseType := database.childText("ldp-database-type")
		sessionID := database.childText("ldp-session-id")
		bindings := database.find("ldp-binding")
		if len(bindings) == 0 {
			records = append(records, map[string]string{"KEY": sessionID, "DATABASE_TYPE": databaseType, "SESSION_ID": sessionID})
			continue
		}
		for _, binding := range bindings {
			prefix := binding.childText("ldp-prefix")
			records = append(records, map[string]string{
				"KEY":           sessionID + "|" + prefix,
				"DATABASE_TYPE": databaseType,
				"SESSION_ID":    sessionID,
				"LABEL":         binding.childText("ldp-label"),
				"PREFIX":        prefix,
			})
		}
	}
	return encodeRecords("ldp_bindings", records)
}

// decodeMPLSLSPInformationXML parses a get-mpls-lsp-information <rpc-reply>
// into one record per rsvp-session-data — this RPC (as used by the
// reference implementation) is itself a per-session-type count summary, not
// a per-LSP listing.
func decodeMPLSLSPInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, session := range root.find("rsvp-session-data") {
		records = append(records, map[string]string{
			"SESSION_TYPE":  session.childText("session-type"),
			"COUNT":         session.childText("count"),
			"DISPLAY_COUNT": session.childText("display-count"),
			"UP_COUNT":      session.childText("up-count"),
			"DOWN_COUNT":    session.childText("down-count"),
		})
	}
	return encodeRecords("mpls_lsp_sessions", records)
}
