package main

import "strings"

// Decoder for get-interface-information, the "Interfaces" RPC in
// networkflow's reference manifest. This is new data junos-routing-monitor's
// snapshot capture has never recorded before (the tick loop's interface
// stats are a different, traffic-rate-focused data point that stays
// SSH-only) — its JSON shape is free to define, following this repo's
// existing ALL-CAPS field-name convention. Response element names are
// confirmed against
// networkflow/build/lib/networkflow/core/parsers/juniper/interface.py (a
// working reference implementation), but the exact request-side RPC body
// and the response's wrapper-element nesting have not been observed against
// a real device from this repo — validate before relying on this
// operationally.

const interfaceInformationRPC = "<get-interface-information/>"

// decodeInterfaceInformationXML parses a get-interface-information
// <rpc-reply> into one record per physical interface, keyed on
// INTERFACE_NAME. Its logical interfaces and their addresses are summarized
// into one semicolon-joined LOGICAL_INTERFACES string field rather than a
// nested structure, matching every other decoder's flat map[string]string
// record shape (the same shape diffRecordsByKey and every TextFSM parser
// already produce).
func decodeInterfaceInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, iface := range root.find("physical-interface") {
		name := iface.childText("name")
		if name == "" {
			continue
		}
		records = append(records, map[string]string{
			"INTERFACE_NAME":     name,
			"ADMIN_STATUS":       iface.childText("admin-status"),
			"OPER_STATUS":        iface.childText("oper-status"),
			"DESCRIPTION":        iface.childText("description"),
			"MTU":                iface.childText("mtu"),
			"SPEED":              iface.childText("speed"),
			"LOGICAL_INTERFACES": summarizeLogicalInterfaces(iface),
		})
	}
	return encodeRecords("interfaces", records)
}

// summarizeLogicalInterfaces renders iface's logical-interface children as
// "<name>[<family>:<addr>,...]; ..." — e.g.
// "ae0.0[inet:192.0.2.1]; ae0.100[inet:192.0.2.5]" — so a changed IP or a
// disappeared logical unit is visible in a plain string diff without a
// nested JSON structure.
func summarizeLogicalInterfaces(iface *xmlElement) string {
	var units []string
	for _, logical := range iface.find("logical-interface") {
		name := logical.childText("name")
		if name == "" {
			continue
		}
		var addresses []string
		for _, family := range logical.find("address-family") {
			familyName := family.childText("address-family-name")
			for _, addr := range family.find("interface-address") {
				local := addr.childText("ifa-local")
				if local == "" {
					continue
				}
				if familyName != "" {
					addresses = append(addresses, familyName+":"+local)
				} else {
					addresses = append(addresses, local)
				}
			}
		}
		if len(addresses) > 0 {
			units = append(units, name+"["+strings.Join(addresses, ",")+"]")
		} else {
			units = append(units, name)
		}
	}
	return strings.Join(units, "; ")
}
