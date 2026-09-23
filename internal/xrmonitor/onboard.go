package xrmonitor

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
)

// sessionExecutor is the subset of *xrSSHClient that polling and onboarding
// need. Defining it as an interface (rather than depending on *xrSSHClient
// directly) lets tests exercise onboarding/polling/shutdown logic with a
// fake session instead of a real SSH connection.
type sessionExecutor interface {
	Execute(cmd string) (string, error)
	Close() error
}

// connectFunc abstracts ConnectDevice so onboarding's claim-after-success,
// no-claim-on-failure sequencing (see monitorsetup.HostnameRegistry and
// ConnectDevice's retry docs) can be tested end-to-end without a real SSH
// connection.
type connectFunc func(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error)

// DeviceSession holds one device's already-authenticated persistent SSH
// session plus the collection parameters gathered for it during onboarding.
// vrfs holds every VRF to monitor for this device: manually specified
// ones, auto-detected customer VRFs (see AutoDetectCustomerVRFs), or both.
// coreInterfaces/customerInterfaces/hubInterfaces are kept as three separate
// lists (rather than one merged list) purely so the status line (status.go)
// can label each interface "core", the single monitored customer VRF (or
// "customer"), or "hub" by provenance — manually typed, auto-discovered
// customer-VRF, or sampled from a hub VRF (see AutoDetectCustomerVRFs) —
// instead of losing that distinction the moment they're onboarded; all
// three are still polled together (see allInterfaces).
type DeviceSession struct {
	hostname           string
	vrfs               []string
	coreInterfaces     []string
	customerInterfaces []string
	hubInterfaces      []string
	neighbors          []string
	client             sessionExecutor
}

// allInterfaces returns every interface to poll for this device — core,
// customer, and hub-sampled — deduped and sorted, since an operator could in
// principle type an interface manually that auto-detect also discovers.
func (s *DeviceSession) allInterfaces() []string {
	all := append([]string{}, s.coreInterfaces...)
	all = append(all, s.customerInterfaces...)
	all = append(all, s.hubInterfaces...)
	return dedupeSorted(all)
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

// OnboardDevices interactively prompts for each device to monitor. defaultGatewayPrefix
// (typically a --devices file's top-level customer_gateway_prefix, empty if none was
// loaded) is offered as the default answer when the operator opts into VRF
// auto-detection, so it only needs to be typed once per run rather than once per device.
func OnboardDevices(reader *bufio.Reader, deviceType string, cache *monitorsetup.CredentialCache, registry *monitorsetup.HostnameRegistry, connect connectFunc, parsers map[string]ParserModule, defaultGatewayPrefix string, excludeInterfacePrefixes []string, spec CollectionSpec, hubTopInterfaces int) []*DeviceSession {
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

		var vrfs []string
		autoDetect, gatewayPrefix := promptAutoDetectVRF(reader, host, defaultGatewayPrefix)
		if !autoDetect {
			fmt.Fprintf(os.Stderr, "VRF name for route summary on %s (blank to skip): ", host)
			vrf, _ := reader.ReadString('\n')
			if vrf = strings.TrimSpace(vrf); vrf != "" {
				vrfs = []string{vrf}
			}
		}

		fmt.Fprintf(os.Stderr, "Core-facing Bundle-Ether interface(s) on %s, comma-separated (blank to skip): ", host)
		interfaceLine, _ := reader.ReadString('\n')
		coreInterfaces := dedupeSorted(splitCommaList(interfaceLine))

		fmt.Fprintf(os.Stderr, "BGP neighbor IP(s) on %s to snapshot routes for before/after the change, comma-separated (blank to skip): ", host)
		neighborLine, _ := reader.ReadString('\n')
		neighbors := splitCommaList(neighborLine)

		client, err := connect(reader, host, deviceType, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n\n", host, err)
			continue
		}
		registry.Claim(host)

		var customerInterfaces, hubInterfaces []string
		if autoDetect {
			vrfs, customerInterfaces, hubInterfaces = ApplyAutoDetectResult(client, gatewayPrefix, parsers, excludeInterfacePrefixes, spec, hubTopInterfaces, host, vrfs, os.Stderr)
		}

		fmt.Fprintf(os.Stderr, "connected to %s\n\n", host)
		slog.Info("device connected", "hostname", host, "vrfs", vrfs, "core_interfaces", coreInterfaces, "customer_interfaces", customerInterfaces, "hub_interfaces", hubInterfaces, "neighbors", neighbors)
		sessions = append(sessions, &DeviceSession{hostname: host, vrfs: vrfs, coreInterfaces: coreInterfaces, customerInterfaces: customerInterfaces, hubInterfaces: hubInterfaces, neighbors: neighbors, client: client})
	}
	return sessions
}

// promptAutoDetectVRF asks whether to auto-detect this device's customer
// VRF(s) instead of typing a VRF name manually. When the operator opts in
// and defaultGatewayPrefix is empty (no --devices file supplied one), it
// also prompts for the gateway prefix that identifies a customer-facing
// default route on this fleet.
func promptAutoDetectVRF(reader *bufio.Reader, host, defaultGatewayPrefix string) (autoDetect bool, gatewayPrefix string) {
	fmt.Fprintf(os.Stderr, "Auto-detect customer VRF(s) via default-route gateway on %s? [y/N]: ", host)
	answer, _ := reader.ReadString('\n')
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return false, ""
	}
	if strings.TrimSpace(defaultGatewayPrefix) != "" {
		return true, strings.TrimSpace(defaultGatewayPrefix)
	}
	fmt.Fprintf(os.Stderr, "Customer-facing gateway prefix on %s (e.g. 192.0.2.): ", host)
	prefixLine, _ := reader.ReadString('\n')
	gatewayPrefix = strings.TrimSpace(prefixLine)
	if gatewayPrefix == "" {
		fmt.Fprintln(os.Stderr, "customer-facing gateway prefix is required for auto-detect; falling back to manual VRF entry")
		return false, ""
	}
	return true, gatewayPrefix
}

// ConnectDevice prompts for credentials (offering passcode reuse via cache
// first), attempts a connection, and — on failure — asks the operator
// whether to retry with a fresh prompt before giving up (see
// promptRetryConnection). This question is asked again after every failed
// attempt, so confirming it repeatedly does let the operator retry more
// than once — it is deliberately not an automatic retry (nothing loops
// without a human confirming each time), but it is also not capped at a
// single retry. RSA/ISE commonly locks the account after 3 consecutive bad
// attempts, so repeatedly confirming this prompt against a genuinely
// rejected passcode is a real way to lock yourself out under pressure
// during a change window — the explicit, default-"no" confirmation exists
// to recover a client-side mistake — e.g. typing the passcode into the
// username prompt, or a transient/fixable failure like an untrusted host
// key — without losing this device's already-gathered onboarding context
// (VRF, interfaces, neighbors) and having to restart onboarding for it from
// scratch, not to make repeatedly retrying a genuinely rejected passcode
// any safer. Decline it once you suspect the credential itself, not just
// the prompt, was wrong. Each failed attempt still invalidates the cache (a
// rejected passcode is never trustworthy to reuse) before the retry
// question is asked.
func ConnectDevice(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache) (sessionExecutor, error) {
	return connectWithRetry(reader, host, deviceType, cache, ConnectXRDevice)
}

// connectWithRetry implements ConnectDevice's credential-prompt / connect /
// retry-prompt loop against dial, so it can be exercised in tests without a
// real SSH connection — ConnectDevice wires in the real ConnectXRDevice.
func connectWithRetry(reader *bufio.Reader, host, deviceType string, cache *monitorsetup.CredentialCache, dial func(host, username, password, deviceType string) (sessionExecutor, error)) (sessionExecutor, error) {
	var retryUsername string
	for {
		username, password, fresh, err := monitorsetup.ResolveCredentials(reader, cache, retryUsername)
		if err != nil {
			return nil, fmt.Errorf("read credentials: %w", err)
		}
		retryUsername = username
		client, err := dialRetryingHostKeyMismatch(reader, host, username, password, deviceType, dial)
		if err != nil {
			if hostkey.ClassifyConnectError(host, err) != nil {
				// Still a host-key mismatch: the operator declined to
				// refresh it inside dialRetryingHostKeyMismatch. That was
				// never a credential problem (see that function's doc
				// comment), so — unlike every other failure below — this
				// must not invalidate the cache or offer the unrelated
				// "Retry credentials?" prompt.
				return nil, err
			}
			cache.RecordFailure()
			if promptRetryConnection(reader, host, err) {
				continue
			}
			return nil, err
		}
		if fresh {
			cache.RecordSuccess(username, password)
		}
		return client, nil
	}
}

// dialRetryingHostKeyMismatch calls dial, and — only when it fails
// specifically because of a genuine SSH host-key mismatch (see
// hostkey.ClassifyConnectError) — offers PromptHostKeyMismatch's
// high-friction refresh flow. A mismatch happens during the transport
// handshake, before authentication, so it says nothing about the
// username/password just entered: on a confirmed refresh, dial is retried
// right here with those exact same credentials, never by looping back to
// connectWithRetry's credential prompt (which would needlessly re-prompt).
// A non-mismatch failure is returned as-is, to be handled by
// connectWithRetry's normal RecordFailure/promptRetryConnection path. A
// declined mismatch is also returned as-is, but connectWithRetry
// re-classifies it and must route it away from that same credential path —
// see the check there — since it's still not a credential problem either.
func dialRetryingHostKeyMismatch(reader *bufio.Reader, host, username, password, deviceType string, dial func(host, username, password, deviceType string) (sessionExecutor, error)) (sessionExecutor, error) {
	for {
		client, err := dial(host, username, password, deviceType)
		if err == nil {
			return client, nil
		}
		mismatch := hostkey.ClassifyConnectError(host, err)
		if mismatch == nil {
			return nil, err
		}
		if !monitorsetup.PromptHostKeyMismatch(reader, mismatch, hostkey.FetchPresentedKey) {
			return nil, err
		}
		// known_hosts was just rewritten; retry with the same credentials.
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
