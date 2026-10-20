package junosmonitor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
	"github.com/gwoodwa1/network-collector/internal/safeyaml"
	"gopkg.in/yaml.v3"
)

// flexibleStringList decodes a YAML field that's conventionally singular
// (one scalar value) but accepts a list too, for a field like vrf: where
// real --devices files have been observed writing vrf: [A, B] — treating
// the singular key as "one or more" rather than strictly "exactly one."
// Without this, that exact shape fails with a hard "cannot unmarshal !!seq
// into string" parse error instead of being accepted.
type flexibleStringList []string

func (f *flexibleStringList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*f = flexibleStringList{s}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return fmt.Errorf("expected a string or a list of strings: %w", err)
	}
	*f = flexibleStringList(list)
	return nil
}

// DeviceSpec is one entry from an optional --devices YAML file. It only
// covers the static per-device fields gathered during interactive
// onboarding (hostname/table(s)/interfaces/neighbors) — credentials are
// deliberately never part of this file, since a one-time passcode must
// always be typed interactively per device.
type DeviceSpec struct {
	Hostname string `yaml:"hostname"`
	// Table is a single-table legacy alias for Tables, kept for files
	// written with only one routing table in mind; both may be set, and
	// their values are merged.
	Table  string   `yaml:"table"`
	Tables []string `yaml:"tables"`
	// VRF/VRFs are accepted purely as aliases for Table/Tables, merged into
	// the exact same list. This repo's own cisco_iosxr devices use vrf:/
	// vrfs: for the equivalent field (internal/xrmonitor/devices.go), and a
	// --devices file's cisco_iosxr and juniper_junos sections sit side by
	// side in the same combined routing-monitor YAML — so reaching for
	// vrf: while writing the juniper_junos section is a natural mistake to
	// make, not a typo worth punishing. Plain yaml.Unmarshal silently drops
	// unrecognized keys rather than erroring, so without this alias a
	// device written with vrf: onboards looking fine (hostname/interfaces/
	// neighbors all populate) while Tables stays silently empty — no VRF
	// routing table, including the default-route (0/0) one, is ever
	// polled, and nothing surfaces that failure. VRF and VRFs are both
	// flexibleStringList, not string/[]string respectively, because either
	// key's "obvious" shape can turn out to be the other in practice —
	// vrf: [A, B] (a list under the singular key) is the real-world case
	// that motivated this, and vrfs: A.inet.0 (a scalar under the plural
	// key, e.g. after trimming a list down to one entry) is just as
	// plausible a thing for an operator to write by hand. A plain
	// string/[]string field would reject either mismatch with a YAML type
	// error instead of accepting it.
	VRF        flexibleStringList `yaml:"vrf"`
	VRFs       flexibleStringList `yaml:"vrfs"`
	Interfaces []string           `yaml:"interfaces"`
	Neighbors  []string           `yaml:"neighbors"`
	// NetconfSnapshot overrides the fleet-wide default (see
	// DevicesDocument.NetconfSnapshot / -netconf-snapshot) for this one
	// device — e.g. one device that doesn't support NETCONF can opt back
	// out while the rest of the fleet uses it. nil means "use the fleet
	// default", not "false" — see ResolveNetconfSnapshot.
	NetconfSnapshot *bool `yaml:"netconf_snapshot"`
}

// resolvedNetconfSnapshot returns whether NETCONF snapshot capture is
// enabled for this device: its own override when set, otherwise
// fleetDefault (see ResolveNetconfSnapshot for the nil-vs-explicit-false
// distinction).
func (spec DeviceSpec) resolvedNetconfSnapshot(fleetDefault bool) bool {
	return ResolveNetconfSnapshot(spec.NetconfSnapshot, fleetDefault)
}

// ResolveNetconfSnapshot falls back to fallback when configured is unset
// (nil). configured == nil is "unset", not "false" — a plain bool can't
// represent that distinction on its own, mirroring the nil-vs-explicit-zero
// convention xr-routing-monitor/discover.go's resolveHubTopInterfaces
// already uses for hub_top_interfaces. Shared by both resolution steps this
// tool needs: DevicesDocument.NetconfSnapshot vs. the -netconf-snapshot CLI
// default (main.go), and DeviceSpec.NetconfSnapshot vs. that resolved
// fleet-wide default (resolvedNetconfSnapshot above).
func ResolveNetconfSnapshot(configured *bool, fallback bool) bool {
	if configured == nil {
		return fallback
	}
	return *configured
}

// tables returns spec's Table, Tables, VRF, and VRFs fields merged into one
// deduplicated, sorted list — blank entries (a stray "" in a tables: list)
// are dropped rather than turning into a malformed "show route summary
// table " command.
func (spec DeviceSpec) tables() []string {
	all := append([]string{spec.Table}, spec.Tables...)
	all = append(all, []string(spec.VRF)...)
	all = append(all, spec.VRFs...)
	return dedupeSorted(all)
}

// rawTables is spec's Table/Tables/VRF/VRFs fields concatenated in that
// fixed order, exactly as written — unlike tables(), it is neither
// deduplicated nor sorted. tables() alphabetically sorts its result, which
// is fine for every other use (building commands, status-line display,
// where declaration order is irrelevant) but would silently scramble
// tableInterfaces' position-for-position pairing against Interfaces for
// any file whose VRFs aren't already in alphabetical order.
func (spec DeviceSpec) rawTables() []string {
	var all []string
	if spec.Table != "" {
		all = append(all, spec.Table)
	}
	all = append(all, spec.Tables...)
	all = append(all, []string(spec.VRF)...)
	all = append(all, spec.VRFs...)
	return all
}

// tableInterfaces returns a positional table-to-interface association —
// table[i] paired with Interfaces[i] — when spec's (raw, as-written) table
// list and its Interfaces list are the same non-zero length. This is an
// explicit, opt-in convention for the common case of a device with exactly
// one interface per VRF (e.g. RI-FEM-200034.inet.0 carried over irb.341,
// RI-WFA-200036.inet.0 over ae72.360) — the --devices schema has no other
// way to express that relationship. Returns nil when the counts differ or
// either list is empty, meaning "no known association," never "associated
// with nothing": callers (see Tick.TableInterfaces) must fall back to
// treating every one of the device's interfaces as possibly relevant
// rather than treating a nil map as "relevant to none of them." A blank
// entry anywhere in either list voids the whole association for this
// device rather than silently skipping just that one pair, since a blank
// is a sign the positional assumption itself may not hold. A table name
// that's repeated with a different interface each time (e.g.
// tables: [A, A] with interfaces: [irb.100, ae0.200]) is the same kind of
// problem: there's no way to tell which pairing is the real one, and
// keeping just the last-seen one would silently lose A's first interface
// from every chart it should have appeared on — so that voids the whole
// association too, not just the conflicting entry. A table repeated with
// the *same* interface each time isn't a conflict and doesn't void
// anything.
func (spec DeviceSpec) tableInterfaces() map[string]string {
	tables := spec.rawTables()
	if len(tables) == 0 || len(tables) != len(spec.Interfaces) {
		return nil
	}
	out := make(map[string]string, len(tables))
	for i, table := range tables {
		table = strings.TrimSpace(table)
		iface := strings.TrimSpace(spec.Interfaces[i])
		if table == "" || iface == "" {
			return nil
		}
		if existing, dup := out[table]; dup && existing != iface {
			return nil
		}
		out[table] = iface
	}
	return out
}

// CommandOverrides lets a --devices file replace the default show-commands
// and parser modules this tool polls (see defaultSpec in poll.go), so an
// operator whose fleet needs a different command can edit a config file
// instead of patching Go source and rebuilding the static binary
// mid-engagement. Every field is optional; only non-empty ones override
// defaultSpec (see ResolveCollectionSpec).
type CommandOverrides struct {
	BGPCommand          string `yaml:"bgp_command"`
	BGPParser           string `yaml:"bgp_parser"`
	RouteCommand        string `yaml:"route_command"`
	RouteParser         string `yaml:"route_parser"`
	DefaultRouteCommand string `yaml:"default_route_command"`
	DefaultRouteParser  string `yaml:"default_route_parser"`
	InterfaceCommand    string `yaml:"interface_command"`
	InterfaceParser     string `yaml:"interface_parser"`
	// AuthzFailurePattern overrides the default regex (see
	// defaultAuthzFailurePattern in poll.go) used to detect a TACACS/AAA
	// command-authorization denial in command output, so a fleet whose AAA
	// server phrases the rejection differently can match it without a
	// rebuild. Case-insensitive regex syntax; blank keeps the built-in
	// default.
	AuthzFailurePattern string `yaml:"authz_failure_pattern"`
}

type DevicesDocument struct {
	TACACSTimeoutReminder []int `yaml:"tacacs_timeout_reminder"`
	// Interval sets the default polling interval for this run, e.g. "30s".
	// The -interval CLI flag takes precedence when passed explicitly; this
	// exists so the interval can be checked into the same file as the
	// device list instead of retyped on the command line every time.
	Interval string           `yaml:"interval"`
	Commands CommandOverrides `yaml:"commands"`
	// NetconfSnapshot sets the fleet-wide default for whether the
	// before/after snapshot capture also dials NETCONF (see
	// DeviceSession.netconfClient); the -netconf-snapshot CLI flag takes
	// precedence when passed explicitly, mirroring Interval's precedence
	// against -interval. nil means "not set in this file" — see
	// ResolveNetconfSnapshot.
	NetconfSnapshot *bool        `yaml:"netconf_snapshot"`
	Devices         []DeviceSpec `yaml:"devices"`
}

func countStringPlaceholders(format string) (count int, ok bool) {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		if i+1 >= len(format) {
			return 0, false
		}
		switch format[i+1] {
		case '%':
			i++
		case 's':
			count++
			i++
		default:
			return 0, false
		}
	}
	return count, true
}

func validateCommandTemplate(path, field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if count, ok := countStringPlaceholders(value); !ok || count != 1 {
		return fmt.Errorf("%s: commands.%s must contain exactly one %%s placeholder", path, field)
	}
	return nil
}

// validateRegexPattern checks that value (if non-empty) compiles as a Go
// regex, so a typo'd authz_failure_pattern fails fast at startup rather than
// silently never matching mid-run.
func validateRegexPattern(path, field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	// Compiled the same way ResolveCollectionSpec compiles it for real
	// (see compileAuthzFailurePattern in poll.go), so a pattern that's
	// rejected or accepted here behaves identically at collection time.
	if _, err := compileAuthzFailurePattern(value); err != nil {
		return fmt.Errorf("%s: commands.%s is not a valid regex: %w", path, field, err)
	}
	return nil
}

// LoadDeviceSpecs reads an optional --devices YAML file, e.g.:
//
//	interval: 30s
//
//	devices:
//	  - hostname: pe-router-1
//	    tables: [CUSTOMER-A.inet.0]
//	    interfaces: [ae0, ae1]
//	    neighbors: [198.51.100.101]
//	  - hostname: pe-router-2
//	    tables: [inet.0]
//	    interfaces: [ae10]
//
// The returned duration is zero when the file has no top-level interval
// set, signaling the caller should fall back to its own default. The
// returned netconfSnapshotDefault is nil when the file has no top-level
// netconf_snapshot set, signaling the caller should fall back to the
// -netconf-snapshot CLI flag's own value (see ResolveNetconfSnapshot).
// ValidateDevicesDocument checks that doc (already YAML-decoded, from path
// purely for error messages) is internally consistent: every device has a
// hostname, command overrides have exactly one %s placeholder, and Interval
// (if set) parses to a positive duration. Errors are collected across every
// device rather than returning on the first hit, so a file with more than
// one problem reports both in one pass instead of masking the second until
// the first is fixed and the file is reloaded. Extracted from
// LoadDeviceSpecs so cmd/routing-monitor's combined-YAML loader can run the
// exact same checks against a DevicesDocument nested under its own
// juniper_junos: section, without duplicating this logic.
func ValidateDevicesDocument(path string, doc DevicesDocument) (time.Duration, error) {
	var errs []error
	for i, spec := range doc.Devices {
		if strings.TrimSpace(spec.Hostname) == "" {
			errs = append(errs, fmt.Errorf("%s: device at index %d is missing hostname", path, i))
		}
	}
	if err := validateCommandTemplate(path, "route_command", doc.Commands.RouteCommand); err != nil {
		errs = append(errs, err)
	}
	if err := validateCommandTemplate(path, "default_route_command", doc.Commands.DefaultRouteCommand); err != nil {
		errs = append(errs, err)
	}
	if err := validateCommandTemplate(path, "interface_command", doc.Commands.InterfaceCommand); err != nil {
		errs = append(errs, err)
	}
	if err := validateRegexPattern(path, "authz_failure_pattern", doc.Commands.AuthzFailurePattern); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return 0, err
	}
	var interval time.Duration
	if raw := strings.TrimSpace(doc.Interval); raw != "" {
		var err error
		interval, err = time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("%s: invalid interval %q: %w", path, raw, err)
		}
		if interval <= 0 {
			return 0, fmt.Errorf("%s: interval %q must be positive", path, raw)
		}
	}
	return interval, nil
}

func LoadDeviceSpecs(path string) (specs []DeviceSpec, interval time.Duration, commands CommandOverrides, netconfSnapshotDefault *bool, err error) {
	b, err := safeyaml.ReadFile(path)
	if err != nil {
		return nil, 0, CommandOverrides{}, nil, err
	}
	var doc DevicesDocument
	if err := safeyaml.Unmarshal(b, &doc); err != nil {
		return nil, 0, CommandOverrides{}, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	interval, err = ValidateDevicesDocument(path, doc)
	if err != nil {
		return nil, 0, CommandOverrides{}, nil, err
	}
	return doc.Devices, interval, doc.Commands, doc.NetconfSnapshot, nil
}

// OnboardDevicesFromSpecs connects to each device from a --devices file in
// order, prompting for credentials only (all other fields come from the
// spec). A connection failure — after any operator-confirmed retries inside
// ConnectDevice — is reported and does not stop the remaining devices in
// the file from being tried. A
// hostname already claimed in registry (e.g. duplicated within the file, or
// present more than once for any other reason) is skipped without
// attempting to connect again. netconfSnapshotDefault is the fleet-wide
// default (already resolved from -netconf-snapshot / DevicesDocument); each
// spec's own resolvedNetconfSnapshot overrides it per device.
func OnboardDevicesFromSpecs(reader *bufio.Reader, specs []DeviceSpec, deviceType string, netconfSnapshotDefault bool, cache *monitorsetup.CredentialCache, registry *monitorsetup.HostnameRegistry, connect connectFunc) []*DeviceSession {
	var sessions []*DeviceSession
	hostnames := make([]string, len(specs))
	for i, spec := range specs {
		hostnames[i] = spec.Hostname
	}
	checklist := monitorsetup.NewDeviceChecklist(hostnames)
	checklist.Print(os.Stderr)
	for i, spec := range specs {
		if exists, existing := registry.Has(spec.Hostname); exists {
			fmt.Fprintf(os.Stderr, "already connected to %s (as %q), skipping duplicate\n\n", spec.Hostname, existing)
			checklist.SetAt(i, monitorsetup.ChecklistSkipped, "duplicate of "+existing)
			checklist.Print(os.Stderr)
			continue
		}
		fmt.Fprintf(os.Stderr, "Connecting to %s (tables=%v interfaces=%v neighbors=%v)\n", spec.Hostname, spec.tables(), spec.Interfaces, spec.Neighbors)
		netconfSnapshot := spec.resolvedNetconfSnapshot(netconfSnapshotDefault)
		client, netconfClient, err := connect(reader, spec.Hostname, deviceType, netconfSnapshot, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", spec.Hostname, err)
			checklist.SetAt(i, monitorsetup.ChecklistFailed, err.Error())
			checklist.Print(os.Stderr)
			continue
		}
		registry.Claim(spec.Hostname)

		fmt.Fprintf(os.Stderr, "connected to %s\n\n", spec.Hostname)
		checklist.SetAt(i, monitorsetup.ChecklistConnected, "")
		checklist.Print(os.Stderr)
		sessions = append(sessions, &DeviceSession{
			hostname:        spec.Hostname,
			tables:          spec.tables(),
			interfaces:      dedupeSorted(spec.Interfaces),
			tableInterfaces: spec.tableInterfaces(),
			neighbors:       dedupeSorted(spec.Neighbors),
			client:          client,
			netconfClient:   netconfClient,
		})
	}
	return sessions
}
