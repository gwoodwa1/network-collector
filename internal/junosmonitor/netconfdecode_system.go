package junosmonitor

// Decoders for the "System software", "System health", and "Chassis" RPCs
// in networkflow's reference manifest: get-software-information,
// get-route-engine-information, get-fpc-information, get-pic-information,
// get-alarm-information, and the core-dumps CLI-passthrough. All are new
// data junos-routing-monitor has never captured before, so their JSON
// shapes are free to define — they follow this repo's existing ALL-CAPS
// field-name convention. Response element names are confirmed against
// networkflow/build/lib/networkflow/core/parsers/juniper/system.py (a
// working reference implementation), but the exact request-side RPC bodies
// and the responses' wrapper-element nesting have not been observed against
// a real device from this repo — validate before relying on this
// operationally.
//
// Every section here is stored and diffed as a keyed-record list (via
// diffRecordsByKey in snapshotdiff.go), including the two the plan
// originally described as "scalar" (software and route-engine information):
// a one-record list keyed on a stable field (HOST_NAME, SLOT) reuses the
// exact same diff mechanism as every other section instead of a bespoke
// scalar-comparison path, for one fewer thing to maintain. A composite key
// (e.g. FPC slot + PIC slot) is precomputed into a synthetic "KEY" field at
// decode time, rather than teaching diffRecordsByKey about composite keys.

const softwareInformationRPC = "<get-software-information/>"

const routeEngineInformationRPC = "<get-route-engine-information/>"

const fpcInformationRPC = "<get-fpc-information><detail/></get-fpc-information>"

const picInformationRPC = "<get-pic-information/>"

const alarmInformationRPC = "<get-alarm-information/>"

// coreDumpsRPC has no native get-*-information RPC (confirmed by
// networkflow/config/commands_junos.yaml, which lists it as a CLI command
// rather than an rpc) — Junos's CLI-passthrough RPC wraps the command text
// itself instead. This is a structurally different request shape from every
// other RPC in this file; treat it as higher-risk until confirmed against
// real hardware.
const coreDumpsRPC = `<command format="xml">show system core-dumps routing-engine both</command>`

// decodeSoftwareInformationXML parses a get-software-information
// <rpc-reply> into a single record (there is exactly one Junos version per
// device).
func decodeSoftwareInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	record := map[string]string{
		"HOST_NAME":     firstText(root, "host-name"),
		"PRODUCT_MODEL": firstText(root, "product-model"),
		"PRODUCT_NAME":  firstText(root, "product-name"),
		"JUNOS_VERSION": firstText(root, "junos-version"),
	}
	return encodeRecords("software", []map[string]string{record})
}

// decodeRouteEngineInformationXML parses a get-route-engine-information
// <rpc-reply> into one record per route-engine (two, on a dual-RE chassis).
func decodeRouteEngineInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, re := range root.find("route-engine") {
		records = append(records, map[string]string{
			"SLOT":                      re.childText("slot"),
			"MASTERSHIP_STATE":          re.childText("mastership-state"),
			"MASTERSHIP_PRIORITY":       re.childText("mastership-priority"),
			"STATUS":                    re.childText("status"),
			"MODEL":                     re.childText("model"),
			"MEMORY_DRAM_SIZE":          re.childText("memory-dram-size"),
			"MEMORY_INSTALLED_SIZE":     re.childText("memory-installed-size"),
			"MEMORY_BUFFER_UTILIZATION": re.childText("memory-buffer-utilization"),
			"CPU_USER":                  re.childText("cpu-user"),
			"CPU_BACKGROUND":            re.childText("cpu-background"),
			"CPU_SYSTEM":                re.childText("cpu-system"),
			"CPU_INTERRUPT":             re.childText("cpu-interrupt"),
			"CPU_IDLE":                  re.childText("cpu-idle"),
			"LOAD_AVERAGE_ONE":          re.childText("load-average-one"),
			"LOAD_AVERAGE_FIVE":         re.childText("load-average-five"),
			"LOAD_AVERAGE_FIFTEEN":      re.childText("load-average-fifteen"),
		})
	}
	return encodeRecords("route_engines", records)
}

// decodeFPCInformationXML parses a get-fpc-information <rpc-reply> into one
// record per fpc slot.
func decodeFPCInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, fpc := range root.find("fpc") {
		records = append(records, map[string]string{
			"SLOT":                 fpc.childText("slot"),
			"STATE":                fpc.childText("state"),
			"TEMPERATURE":          fpc.childText("temperature"),
			"MEMORY_DRAM_SIZE":     fpc.childText("memory-dram-size"),
			"MEMORY_RLDRAM_SIZE":   fpc.childText("memory-rldram-size"),
			"MEMORY_DDR_DRAM_SIZE": fpc.childText("memory-ddr-dram-size"),
		})
	}
	return encodeRecords("fpc_information", records)
}

// decodePICInformationXML parses a get-pic-information <rpc-reply> into one
// record per pic, carrying its enclosing fpc's slot/state/description along
// with it. KEY is a synthetic "<fpc-slot>/<pic-slot>" composite, since
// neither field alone is unique across the chassis.
func decodePICInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, fpc := range root.find("fpc") {
		fpcSlot := fpc.childText("slot")
		for _, pic := range fpc.find("pic") {
			picSlot := pic.childText("pic-slot")
			records = append(records, map[string]string{
				"KEY":             fpcSlot + "/" + picSlot,
				"FPC_SLOT":        fpcSlot,
				"FPC_STATE":       fpc.childText("state"),
				"FPC_DESCRIPTION": fpc.childText("description"),
				"PIC_SLOT":        picSlot,
				"PIC_STATE":       pic.childText("pic-state"),
				"PIC_TYPE":        pic.childText("pic-type"),
			})
		}
	}
	return encodeRecords("pic_information", records)
}

// decodeAlarmInformationXML parses a get-alarm-information <rpc-reply> into
// one record per alarm-detail. KEY is a synthetic
// "<class>|<description>" composite, since Junos alarms have no persistent
// ID of their own.
func decodeAlarmInformationXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, alarm := range root.find("alarm-detail") {
		class := alarm.childText("alarm-class")
		description := alarm.childText("alarm-description")
		records = append(records, map[string]string{
			"KEY":               class + "|" + description,
			"ALARM_CLASS":       class,
			"ALARM_DESCRIPTION": description,
			"ALARM_TIME":        alarm.childText("alarm-time"),
			"ALARM_TYPE":        alarm.childText("alarm-type"),
		})
	}
	return encodeRecords("alarms", records)
}

// decodeCoreDumpsXML parses the core-dumps CLI-passthrough <rpc-reply> into
// one record per dump file, carrying its enclosing routing engine's name
// along with it. KEY is a synthetic "<re-name>|<file-name>" composite, since
// the same core-dump filename can independently exist on both routing
// engines.
func decodeCoreDumpsXML(rpcReply string) (string, error) {
	root, err := parseXMLElement(rpcReply)
	if err != nil {
		return "", err
	}

	var records []map[string]string
	for _, item := range root.find("multi-routing-engine-item") {
		reName := item.childText("re-name")
		for _, file := range item.find("file-information") {
			fileName := file.childText("file-name")
			records = append(records, map[string]string{
				"KEY":              reName + "|" + fileName,
				"RE_NAME":          reName,
				"FILE_NAME":        fileName,
				"FILE_PERMISSIONS": file.childText("file-permissions"),
				"FILE_OWNER":       file.childText("file-owner"),
				"FILE_GROUP":       file.childText("file-group"),
				"FILE_LINKS":       file.childText("file-links"),
				"FILE_SIZE":        file.childText("file-size"),
				"FILE_DATE":        file.childText("file-date"),
			})
		}
	}
	return encodeRecords("core_dumps", records)
}

// firstText returns the trimmed text of the first descendant of e (at any
// depth) named name — used by decodeSoftwareInformationXML, whose fields
// sit directly under the RPC's top-level wrapper with unconfirmed exact
// nesting, the same way find/childText handle every other decoder in this
// file.
func firstText(e *xmlElement, name string) string {
	matches := e.find(name)
	if len(matches) == 0 {
		return ""
	}
	return matches[0].text()
}
