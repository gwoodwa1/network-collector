package junosmonitor

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
)

// sessionExecutor is the subset of *ssh.Client that polling and onboarding
// need. Defining it as an interface (rather than depending on *ssh.Client
// directly) lets tests exercise onboarding/polling/shutdown logic with a
// fake session instead of a real SSH connection.
type sessionExecutor interface {
	Execute(cmd string) (string, error)
	Close() error
}

// connectFunc abstracts ConnectDevice so onboarding's claim-after-success,
// no-claim-on-failure sequencing (see monitorsetup.HostnameRegistry and
// ConnectDevice's retry docs) can be tested end-to-end without a real SSH
// connection. netconfSnapshot requests a second, NETCONF connection
// alongside the always-required SSH one (see ConnectDevice); netconfClient
// is nil when netconfSnapshot was false, or when the NETCONF dial itself
// failed (a warning is logged, but that alone never fails the device's
// onboarding — see ConnectDevice).
type connectFunc func(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *monitorsetup.CredentialCache) (client sessionExecutor, netconfClient sessionExecutor, err error)

// DeviceSession holds one device's already-authenticated persistent SSH
// session plus the collection parameters gathered for it during onboarding.
// tables holds every routing table to monitor for this device (e.g.
// "CUSTOMER-A.inet.0", "inet.0"); interfaces holds every interface to poll.
// There is no auto-detection here (unlike cmd/xr-routing-monitor's VRF
// auto-detect) — everything is exactly what the operator typed or listed in
// a --devices file.
//
// netconfClient is an optional second, NETCONF connection dialed alongside
// client (SSH) at onboarding, used only by captureSnapshot's NETCONF-sourced
// sections (see snapshot.go) — nil when NETCONF snapshot capture wasn't
// opted in for this device, or when the NETCONF dial failed. The periodic
// tick loop (poll.go) never touches it; it only ever uses client.
type DeviceSession struct {
	hostname      string
	tables        []string
	interfaces    []string
	neighbors     []string
	client        sessionExecutor
	netconfClient sessionExecutor
}

func splitCommaList(line string) []string {
	var values []string
	for _, value := range strings.Split(line, ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

// OnboardDevices interactively prompts for each device to monitor.
// netconfSnapshot is the fleet-wide default (-netconf-snapshot /
// DevicesDocument.NetconfSnapshot, already resolved by the caller) applied
// to every device onboarded this way — interactive onboarding has no
// per-device override prompt for it, unlike tables/interfaces/neighbors; an
// operator who needs a per-device override should describe that device in a
// --devices file instead.
func OnboardDevices(reader *bufio.Reader, deviceType string, netconfSnapshot bool, cache *monitorsetup.CredentialCache, registry *monitorsetup.HostnameRegistry, connect connectFunc) []*DeviceSession {
	var sessions []*DeviceSession
	for {
		fmt.Fprintf(os.Stderr, "Router hostname/IP (blank to finish onboarding): ")
		host, _ := reader.ReadString('\n')
		host = strings.TrimSpace(host)
		if host == "" {
			break
		}
		if exists, existing := registry.Has(host); exists {
			fmt.Fprintf(os.Stderr, "already connected to %s (as %q), skipping duplicate\n\n", host, existing)
			continue
		}

		fmt.Fprintf(os.Stderr, "Routing table(s) for route-summary polling on %s, comma-separated (e.g. CUSTOMER-A.inet.0; blank to skip): ", host)
		tableLine, _ := reader.ReadString('\n')
		tables := dedupeSorted(splitCommaList(tableLine))

		fmt.Fprintf(os.Stderr, "Interface(s) on %s, comma-separated (blank to skip): ", host)
		interfaceLine, _ := reader.ReadString('\n')
		interfaces := dedupeSorted(splitCommaList(interfaceLine))

		fmt.Fprintf(os.Stderr, "BGP neighbor IP(s) on %s to snapshot routes for before/after the change, comma-separated (blank to skip): ", host)
		neighborLine, _ := reader.ReadString('\n')
		neighbors := dedupeSorted(splitCommaList(neighborLine))

		client, netconfClient, err := connect(reader, host, deviceType, netconfSnapshot, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", host, err)
			continue
		}
		registry.Claim(host)

		fmt.Fprintf(os.Stderr, "connected to %s\n\n", host)
		slog.Info("device connected", "hostname", host, "tables", tables, "interfaces", interfaces, "neighbors", neighbors)
		sessions = append(sessions, &DeviceSession{hostname: host, tables: tables, interfaces: interfaces, neighbors: neighbors, client: client, netconfClient: netconfClient})
	}
	return sessions
}

// ConnectDevice prompts for credentials (offering passcode reuse via cache
// first), attempts an SSH connection, and — on failure — asks the operator
// whether to retry with a fresh prompt before giving up (see
// promptRetryConnection). This question is asked again after every failed
// attempt, so confirming it repeatedly does let the operator retry more
// than once — it is deliberately not an automatic retry (nothing loops
// without a human confirming each time), but it is also not capped at a
// single retry. A one-time-passcode backend commonly locks the account
// after a handful of consecutive bad attempts, so repeatedly confirming
// this prompt against a genuinely rejected passcode is a real way to lock
// yourself out under pressure during a change window — the explicit,
// default-"no" confirmation exists to recover a client-side mistake — e.g.
// typing the passcode into the username prompt, or a transient/fixable
// failure like an untrusted host key — without losing this device's
// already-gathered onboarding context (tables, interfaces, neighbors) and
// having to restart onboarding for it from scratch, not to make repeatedly
// retrying a genuinely rejected passcode any safer. Decline it once you
// suspect the credential itself, not just the prompt, was wrong. Each
// failed SSH attempt still invalidates the cache (a rejected passcode is
// never trustworthy to reuse) before the retry question is asked.
//
// When netconfSnapshot is true, a second connection is dialed immediately
// after a successful SSH connect via ConnectJunosNetconfDevice, using the
// exact same username/password that just authenticated the SSH session —
// no additional prompt, and safe for a one-time passcode specifically
// because it's reused within the same moment it was accepted, not later
// (see ConnectJunosNetconfDevice's doc comment). Unlike the SSH connection,
// a failed NETCONF dial does not fail the device's onboarding: it's an
// opt-in, additive capability, so a warning is logged and the device
// proceeds with netconfClient == nil — its snapshot capture falls back to
// SSH-only sections for that one device (see captureSnapshot).
func ConnectDevice(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *monitorsetup.CredentialCache) (client sessionExecutor, netconfClient sessionExecutor, err error) {
	return connectWithRetry(reader, host, deviceType, netconfSnapshot, cache, ConnectJunosDevice, ConnectJunosNetconfDevice)
}

// connectWithRetry implements ConnectDevice's credential-prompt / connect /
// retry-prompt / optional-NETCONF-dial loop against dial and dialNetconf,
// so it can be exercised in tests without a real SSH connection —
// ConnectDevice wires in the real ConnectJunosDevice/ConnectJunosNetconfDevice.
func connectWithRetry(reader *bufio.Reader, host, deviceType string, netconfSnapshot bool, cache *monitorsetup.CredentialCache, dial func(host, username, password, deviceType string) (sessionExecutor, error), dialNetconf func(host, username, password string) (sessionExecutor, error)) (client sessionExecutor, netconfClient sessionExecutor, err error) {
	for {
		username, password, fresh, err := monitorsetup.ResolveCredentials(reader, cache)
		if err != nil {
			return nil, nil, fmt.Errorf("read credentials: %w", err)
		}
		client, err = dial(host, username, password, deviceType)
		if err != nil {
			cache.RecordFailure()
			if promptRetryConnection(reader, host, err) {
				continue
			}
			return nil, nil, err
		}
		if fresh {
			cache.RecordSuccess(username, password)
		}
		if netconfSnapshot {
			nc, ncErr := dialNetconf(host, username, password)
			if ncErr != nil {
				slog.Warn("failed to establish NETCONF connection for snapshot capture; falling back to SSH-only snapshots for this device", "hostname", host, "error", ncErr)
			} else {
				netconfClient = nc
			}
		}
		return client, netconfClient, nil
	}
}

// promptRetryConnection reports a failed connection attempt and asks the
// operator whether to retry — called again after each subsequent failed
// attempt, so it can be confirmed more than once in a row (see
// ConnectDevice's doc comment for why this is a per-attempt human decision
// rather than an automatic loop). Defaults to "no" so holding Enter under
// pressure never triggers a retry.
func promptRetryConnection(reader *bufio.Reader, host string, connectErr error) bool {
	fmt.Fprintf(os.Stderr, "connection to %s failed: %v\nRetry credentials for %s? [y/N]: ", host, connectErr, host)
	answer, _ := reader.ReadString('\n')
	trimmed := strings.TrimSpace(answer)
	return strings.EqualFold(trimmed, "y") || strings.EqualFold(trimmed, "yes")
}
