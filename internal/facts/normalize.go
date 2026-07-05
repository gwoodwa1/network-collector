package facts

import (
	"encoding/json"
	"fmt"
	"strings"
)

func Normalize(subset string, native json.RawMessage, transport string) (string, any, bool, []string, error) {
	root, ok := openConfigRoot[subset]
	if !ok {
		return "", nil, false, nil, fmt.Errorf("unsupported subset %q", subset)
	}
	var decoded any
	if err := json.Unmarshal(native, &decoded); err != nil {
		return "", nil, false, nil, err
	}
	if transport == "netconf" {
		return root, unwrapNETCONF(decoded, strings.TrimPrefix(root, "openconfig-")), true, nil, nil
	}
	records := findRecords(decoded)
	switch subset {
	case "system":
		r := first(records)
		return root, map[string]any{"state": compact(map[string]any{"hostname": field(r, "HOSTNAME"), "software-version": field(r, "VERSION")})}, false, unknownFields(records, "HOSTNAME", "VERSION"), nil
	case "platform":
		components := make([]any, 0, len(records))
		for _, r := range records {
			name := field(r, "NODE")
			components = append(components, map[string]any{"name": name, "state": compact(map[string]any{"name": name, "oper-status": operStatus(field(r, "STATE")), "description": field(r, "CONFIG_STATE")})})
		}
		return root, map[string]any{"component": components}, false, unknownFields(records, "NODE", "STATE", "CONFIG_STATE"), nil
	case "interfaces":
		interfaces := make([]any, 0, len(records))
		for _, r := range records {
			name := field(r, "INTERFACE")
			interfaces = append(interfaces, map[string]any{"name": name, "state": compact(map[string]any{"name": name, "admin-status": adminStatus(field(r, "STATUS")), "oper-status": upDown(firstNonEmpty(field(r, "PROTOCOL"), field(r, "STATUS"))), "description": field(r, "DESCRIPTION")})})
		}
		return root, map[string]any{"interface": interfaces}, false, unknownFields(records, "INTERFACE", "STATUS", "PROTOCOL", "DESCRIPTION"), nil
	case "lldp":
		byInterface := map[string][]any{}
		for _, r := range records {
			local := field(r, "LOCAL_INTERFACE")
			id := firstNonEmpty(field(r, "NEIGHBOR_ID"), field(r, "SYSTEM_NAME"), field(r, "PORT_ID"))
			neighbor := map[string]any{"id": id, "state": compact(map[string]any{"id": id, "system-name": field(r, "SYSTEM_NAME"), "chassis-id": field(r, "CHASSIS_ID"), "port-id": field(r, "PORT_ID"), "port-description": field(r, "PORT_DESCRIPTION")})}
			byInterface[local] = append(byInterface[local], neighbor)
		}
		interfaces := make([]any, 0, len(byInterface))
		for _, local := range sortedKeysAny(byInterface) {
			interfaces = append(interfaces, map[string]any{"name": local, "neighbors": map[string]any{"neighbor": byInterface[local]}})
		}
		return root, map[string]any{"interfaces": map[string]any{"interface": interfaces}}, false, unknownFields(records, "LOCAL_INTERFACE", "NEIGHBOR_ID", "SYSTEM_NAME", "CHASSIS_ID", "PORT_ID", "PORT_DESCRIPTION"), nil
	case "bgp":
		neighbors := make([]any, 0, len(records))
		for _, r := range records {
			address := field(r, "NEIGHBOR")
			neighbors = append(neighbors, map[string]any{"neighbor-address": address, "state": compact(map[string]any{"neighbor-address": address, "peer-as": number(field(r, "REMOTE_AS")), "session-state": bgpState(field(r, "STATE"))})})
		}
		return root, protocol("openconfig-policy-types:BGP", "BGP", map[string]any{"bgp": map[string]any{"neighbors": map[string]any{"neighbor": neighbors}}}), false, unknownFields(records, "NEIGHBOR", "REMOTE_AS", "STATE"), nil
	case "isis":
		adjacencies := make([]any, 0, len(records))
		for _, r := range records {
			id := field(r, "SYSTEM_ID")
			adjacencies = append(adjacencies, map[string]any{"system-id": id, "state": compact(map[string]any{"system-id": id, "adjacency-state": strings.ToUpper(field(r, "STATE")), "level": field(r, "LEVEL"), "hold-time": number(field(r, "HOLDTIME")), "neighbor-ip": field(r, "NEIGHBOR_IP")})})
		}
		isis := map[string]any{"isis": map[string]any{"interfaces": map[string]any{"interface": []any{map[string]any{"interface-id": "all", "levels": map[string]any{"level": []any{map[string]any{"level-number": 0, "adjacencies": map[string]any{"adjacency": adjacencies}}}}}}}}}
		return root, protocol("openconfig-policy-types:ISIS", "ISIS", isis), false, unknownFields(records, "SYSTEM_ID", "STATE", "LEVEL", "HOLDTIME", "NEIGHBOR_IP", "INTERFACE"), nil
	case "ldp":
		peers := make([]any, 0, len(records))
		for _, r := range records {
			id := field(r, "PEER_ID")
			peers = append(peers, map[string]any{"lsr-id": id, "state": compact(map[string]any{"lsr-id": id, "session-state": strings.ToUpper(field(r, "STATE")), "address": field(r, "ADDRESS")})})
		}
		return root, map[string]any{"network-instance": []any{map[string]any{"name": "default", "mpls": map[string]any{"signaling-protocols": map[string]any{"ldp": map[string]any{"neighbors": map[string]any{"neighbor": peers}}}}}}}, false, unknownFields(records, "PEER_ID", "STATE", "ADDRESS"), nil
	}
	return "", nil, false, nil, fmt.Errorf("unsupported subset %q", subset)
}

func findRecords(value any) []map[string]any {
	switch current := value.(type) {
	case []any:
		result := []map[string]any{}
		for _, item := range current {
			if record, ok := item.(map[string]any); ok {
				result = append(result, record)
			}
		}
		return result
	case map[string]any:
		for _, child := range current {
			if records := findRecords(child); len(records) > 0 {
				return records
			}
		}
		if len(current) > 0 {
			return []map[string]any{current}
		}
	}
	return nil
}

func first(records []map[string]any) map[string]any {
	if len(records) == 0 {
		return map[string]any{}
	}
	return records[0]
}
func field(record map[string]any, name string) string {
	for key, value := range record {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "unknown"
}
func compact(value map[string]any) map[string]any {
	for key, item := range value {
		if item == "" || item == nil {
			delete(value, key)
		}
	}
	return value
}
func number(value string) any {
	var n json.Number = json.Number(value)
	if _, err := n.Int64(); err == nil {
		return n
	}
	return value
}
func upDown(value string) string {
	if strings.EqualFold(value, "up") || strings.EqualFold(value, "connected") || strings.EqualFold(value, "active") {
		return "UP"
	}
	return "DOWN"
}
func adminStatus(value string) string {
	if strings.Contains(strings.ToLower(value), "admin") {
		return "DOWN"
	}
	return upDown(value)
}
func operStatus(value string) string {
	value = strings.ToUpper(strings.ReplaceAll(value, " ", "_"))
	if value == "IOS_XR_RUN" || value == "OPERATIONAL" || value == "OK" {
		return "ACTIVE"
	}
	return value
}
func bgpState(value string) string {
	if _, ok := number(value).(json.Number); ok {
		return "ESTABLISHED"
	}
	return strings.ToUpper(strings.ReplaceAll(value, "-", "_"))
}
func protocol(identifier, name string, body map[string]any) map[string]any {
	p := map[string]any{"identifier": identifier, "name": name}
	for k, v := range body {
		p[k] = v
	}
	return map[string]any{"network-instance": []any{
		map[string]any{"name": "default", "protocols": map[string]any{"protocol": []any{p}}},
	}}
}
func unknownFields(records []map[string]any, known ...string) []string {
	allowed := map[string]bool{}
	for _, key := range known {
		allowed[strings.ToUpper(key)] = true
	}
	unknown := map[string]bool{}
	for _, r := range records {
		for key := range r {
			if !allowed[strings.ToUpper(key)] {
				unknown[key] = true
			}
		}
	}
	keys := make([]string, 0, len(unknown))
	for key := range unknown {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return keys
}
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
func sortedKeysAny(value map[string][]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return keys
}
func unwrapNETCONF(value any, wanted string) any {
	if found, ok := findNETCONF(value, wanted); ok {
		return found
	}
	return value
}
func findNETCONF(value any, wanted string) (any, bool) {
	current, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	for key, child := range current {
		lower := strings.ToLower(key)
		if strings.Contains(wanted, lower) || strings.Contains(lower, strings.TrimSuffix(wanted, "s")) {
			return child, true
		}
		if found, ok := findNETCONF(child, wanted); ok {
			return found, true
		}
	}
	return nil, false
}
