package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
	"github.com/scrapli/scrapligo/driver/network"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
	"github.com/scrapli/scrapligo/util"
)

const maxSSHResponseBytes = 64 * 1024 * 1024

type Client struct {
	driverName      string
	host            string
	platform        *platform.Platform
	network         sshSession
	channelLog      io.Writer
	socketTimeout   time.Duration
	opsTimeout      time.Duration
	port            int
	securityProfile string
	hostKeyPolicy   string
	knownHostsFile  string
	selectedProfile string
	passwordPattern *regexp.Regexp
	connectProfile  func(host, username, password, driverName, profile, hostKeyPolicy string) error
}

type sshSession interface {
	SendInput(string) ([]byte, error)
	Close() error
}

type scrapligoSSHSession struct {
	driver *network.Driver
}

func (s *scrapligoSSHSession) SendInput(command string) ([]byte, error) {
	return s.driver.Channel.SendInput(command)
}

func (s *scrapligoSSHSession) Close() error {
	return s.driver.Close()
}

// Option is a type-safe option for configuring Client
type Option func(*Client)

func NewClient(opts ...Option) *Client {
	c := &Client{
		channelLog:      io.Discard,
		socketTimeout:   45 * time.Second,
		opsTimeout:      90 * time.Second,
		securityProfile: "modern",
		hostKeyPolicy:   "known_hosts",
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

func WithSecurityProfile(profile string) Option {
	return func(c *Client) {
		if c != nil {
			c.securityProfile = strings.ToLower(strings.TrimSpace(profile))
		}
	}
}

func WithHostKeyPolicy(policy, knownHostsFile string) Option {
	return func(c *Client) {
		if c == nil {
			return
		}
		c.hostKeyPolicy = strings.ToLower(strings.TrimSpace(policy))
		c.knownHostsFile = strings.TrimSpace(knownHostsFile)
	}
}

func normalizeSecurityProfile(profile string) (string, error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return "modern", nil
	}
	switch profile {
	case "compatibility", "auto", "modern", "legacy":
		return profile, nil
	}
	return "", fmt.Errorf("unsupported SSH security profile %q", profile)
}

func normalizeHostKeyPolicy(policy string) (string, error) {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		return "known_hosts", nil
	}
	switch policy {
	case "insecure", "known_hosts", "pinned":
		return policy, nil
	}
	return "", fmt.Errorf("unsupported SSH host key policy %q", policy)
}

func isAlgorithmNegotiationError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	markers := []string{"no common algorithm", "no common algo", "no matching key exchange", "no matching cipher", "unable to negotiate", "no common key exchange", "no common cipher"}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (c *Client) SelectedSecurityProfile() string {
	if c == nil {
		return ""
	}
	return c.selectedProfile
}

func WithChannelLog(writer io.Writer) Option {
	return func(c *Client) {
		if c == nil {
			return
		}
		if writer != nil {
			c.channelLog = writer
		}
	}
}

func WithConnectionTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if c == nil {
			return
		}
		if timeout > 0 {
			c.socketTimeout = timeout
		}
	}
}

// WithPort overrides the SSH port scrapligo's transport connects to
// (default: 22). Only needed for a non-standard port — e.g. a test SSH
// server bound to an ephemeral port, since the real endpoints this client
// normally connects to are always on their fleet's standard port.
func WithPort(port int) Option {
	return func(c *Client) {
		if c == nil {
			return
		}
		if port > 0 {
			c.port = port
		}
	}
}

func WithOperationTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if c == nil {
			return
		}
		if timeout > 0 {
			c.opsTimeout = timeout
		}
	}
}

// WithPasswordPattern overrides scrapligo's default password-prompt regex
// (which only matches literal "password:"). Some fleets challenge with a
// different prompt entirely — e.g. RSA SecurID's "Enter PASSCODE:" — and
// without this option, a connection against them just hangs until the
// operation timeout instead of ever sending the passcode.
func WithPasswordPattern(pattern *regexp.Regexp) Option {
	return func(c *Client) {
		if c == nil {
			return
		}
		c.passwordPattern = pattern
	}
}

func validateNonEmpty(value, name string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

func (c *Client) Connect(host, username, password, driverName string) error {
	if c == nil {
		return errors.New("ssh client is nil")
	}

	if err := validateNonEmpty(host, "host"); err != nil {
		return err
	}
	if err := validateNonEmpty(username, "username"); err != nil {
		return err
	}
	if err := validateNonEmpty(password, "password"); err != nil {
		return err
	}
	if err := validateNonEmpty(driverName, "driverName"); err != nil {
		return err
	}

	trimmedDriverName := strings.TrimSpace(driverName)
	trimmedHost := strings.TrimSpace(host)
	profile, err := normalizeSecurityProfile(c.securityProfile)
	if err != nil {
		return err
	}
	policy, err := normalizeHostKeyPolicy(c.hostKeyPolicy)
	if err != nil {
		return err
	}
	if policy == "insecure" {
		slog.Warn("SSH host-key verification is disabled; use only for explicitly approved lab devices", "host", trimmedHost)
	}

	if profile == "auto" {
		connect := c.connectWithProfile
		if c.connectProfile != nil {
			connect = c.connectProfile
		}
		err = connect(trimmedHost, username, password, trimmedDriverName, "modern", policy)
		if err == nil {
			return nil
		}
		if !isAlgorithmNegotiationError(err) {
			return err
		}
		slog.Warn("modern SSH negotiation failed; retrying with legacy compatibility algorithms", "host", trimmedHost, "error", err)
		if c.channelLog != nil {
			_, _ = fmt.Fprintf(c.channelLog, "WARNING: modern SSH negotiation failed for %s; retrying legacy compatibility profile\n", trimmedHost)
		}
		return connect(trimmedHost, username, password, trimmedDriverName, "legacy", policy)
	}
	if c.connectProfile != nil {
		return c.connectProfile(trimmedHost, username, password, trimmedDriverName, profile, policy)
	}
	return c.connectWithProfile(trimmedHost, username, password, trimmedDriverName, profile, policy)
}

// closeAfterFailedOpen calls driver.Close(), recovering the panic scrapligo
// raises when it already closed the channel internally as part of its own
// Open() failure cleanup. scrapligo's self-cleanup on a failed Open() is
// inconsistent: if the transport itself fails to open (host unreachable,
// dial timeout), nothing is closed internally and driver.Close() here is
// required to avoid leaking the connection; but if the transport opens and a
// later step fails (in-channel auth, PTY/shell setup — e.g. a VTY session
// limit), scrapligo's own defer already closed the channel, and calling
// Close() again double-closes Channel.Errs and panics. There's no way to
// tell from here which case occurred, so this attempts the close and
// recovers if scrapligo already did it — logging whatever was recovered so
// an unrelated future panic in Close() doesn't vanish silently.
func closeAfterFailedOpen(driver *network.Driver) {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("recovered panic while closing driver after failed open (expected if scrapligo already closed its channel)", "recovered", r)
		}
	}()
	_ = driver.Close()
}

// maxCaptureBytes bounds how much connect-setup output
// channelDiagnosticCapture retains while active. It only ever needs to hold
// a short diagnostic line (see recoverRacedChannelDiagnostic) — this is
// generous headroom for that, not a tight fit — but without a bound, a
// device with an unusually large pre-auth banner/MOTD, or one that simply
// floods output before authentication, could otherwise grow this without
// limit during the setup window even though growth after setup (stop()) is
// already capped at zero.
const maxCaptureBytes = 64 * 1024

// channelDiagnosticCapture mirrors every byte scrapligo's channel reader
// logs during a single connect attempt, independent of whatever destination
// the caller configured via WithChannelLog (which may be io.Discard). It
// exists to recover a specific scrapligo race, documented on
// connectWithProfile's diagnostic-recovery step below: the channel log
// write happens synchronously as each chunk is read, strictly before that
// chunk could ever be lost to the race, so this capture is a reliable
// independent source of truth even when scrapligo's own returned error text
// isn't.
//
// The io.Writer wiring it's installed under (options.WithChannelLog) stays
// attached to the driver's channel for the life of the whole SSH session,
// not just the connect attempt — scrapligo has no "log this only during
// Open()" mode. Without stop(), every command response for a long-running
// monitor session would keep accumulating in here forever, an unbounded
// buffer for the process's entire lifetime. stop() is called once Open()
// returns (success or failure) and makes every write after that a no-op, so
// growth stops there while the caller's own channel log — wired in
// alongside this one via io.MultiWriter, never through it — keeps receiving
// output for as long as the session lasts, exactly as before. Safe for
// concurrent use: scrapligo's channel reader writes from its own goroutine,
// which can still be mid-write when connectWithProfile calls stop() the
// moment Open() returns.
type channelDiagnosticCapture struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	active bool
}

func newChannelDiagnosticCapture() *channelDiagnosticCapture {
	return &channelDiagnosticCapture{active: true}
}

func (c *channelDiagnosticCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active {
		c.buf.Write(p)
		if excess := c.buf.Len() - maxCaptureBytes; excess > 0 {
			// Rebuild into a fresh buffer holding only the most recent
			// maxCaptureBytes, rather than trimming c.buf in place: the
			// diagnostic this capture exists to recover is always the last
			// thing written before the connection dies (see
			// recoverRacedChannelDiagnostic), so keeping the tail preserves
			// it even behind an oversized banner/MOTD, where keeping the
			// head would risk losing exactly the part that matters. A
			// rebuild is also what actually keeps Cap() bounded, not just
			// Len(): bytes.Buffer's own growth strategy doesn't shrink its
			// backing array back down after trimming from the front
			// (Buffer.Next), so that alone would still leave the array
			// sized to whatever the largest single write happened to be —
			// a multiple of maxCaptureBytes, not maxCaptureBytes itself.
			tail := append([]byte(nil), c.buf.Bytes()[excess:]...)
			c.buf = bytes.Buffer{}
			c.buf.Write(tail)
		}
	}
	return len(p), nil
}

// stop detaches the capture: every write after this becomes a no-op, and
// whatever was already buffered is released. Assigning a zero-value Buffer
// (rather than calling Reset, which only zeroes length and keeps the
// existing backing array allocated) drops the reference to that array so
// its memory — up to maxCaptureBytes, for the life of a session that could
// otherwise run for days — is actually reclaimable instead of sitting
// pinned, unused, for as long as the driver this capture is wired into
// stays open. Idempotent.
func (c *channelDiagnosticCapture) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
	c.buf = bytes.Buffer{}
}

func (c *channelDiagnosticCapture) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

func (c *Client) connectWithProfile(host, username, password, driverName, profile, hostKeyPolicy string) error {
	callerChannelLog := c.channelLog
	if callerChannelLog == nil {
		callerChannelLog = io.Discard
	}
	capture := newChannelDiagnosticCapture()
	defer capture.stop()

	platformOptions := []util.Option{
		options.WithAuthUsername(username),
		options.WithAuthPassword(password),
		options.WithTimeoutSocket(c.socketTimeout),
		options.WithTimeoutOps(c.opsTimeout),
		options.WithChannelLog(io.MultiWriter(callerChannelLog, capture)),
	}
	if c.passwordPattern != nil {
		platformOptions = append(platformOptions, options.WithPasswordPattern(c.passwordPattern))
	}
	if c.port > 0 {
		platformOptions = append(platformOptions, options.WithPort(c.port))
	}
	hostPolicy, err := hostkey.New(hostKeyPolicy, c.knownHostsFile)
	if err != nil {
		return err
	}
	platformOptions, err = hostPolicy.Apply(platformOptions)
	if err != nil {
		return err
	}
	if profile == "compatibility" || profile == "legacy" {
		platformOptions = append(platformOptions,
			options.WithStandardTransportExtraKexs([]string{"diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"}),
			options.WithStandardTransportExtraCiphers([]string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"}),
		)
	}

	platformConfig, err := platform.NewPlatform(
		driverName,
		host,
		// Keep scrapligo's process logger disabled; expected reload disconnects
		// are handled by the collector and channel output is still logged below.
		platformOptions...,
	)
	if err != nil {
		return fmt.Errorf("failed to create platform: %w", err)
	}

	driver, err := platformConfig.GetNetworkDriver()
	if err != nil {
		return fmt.Errorf("failed to get network driver: %w", err)
	}

	if err := driver.Open(); err != nil {
		closeAfterFailedOpen(driver)
		return fmt.Errorf("failed to open driver: %w", recoverRacedChannelDiagnostic(err, capture.bytes()))
	}

	c.driverName = driverName
	c.host = host
	c.platform = platformConfig
	c.network = &scrapligoSSHSession{driver: driver}
	c.selectedProfile = profile
	return nil
}

// recoverRacedChannelDiagnostic works around a race in scrapligo v1.4.1's
// channel reader (channel/read.go's Read/ReadAll): both check whether the
// read loop has already exited (readDone closed, e.g. because the real ssh
// subprocess exited right after printing its final diagnostic line and its
// pty closed) *before* draining whatever is still sitting in the queue from
// that same final read — so a message like "Host key verification failed."
// can be enqueued and logged, and then never handed to scrapligo's own
// sshMessageHandler, which instead returns a bare, textless
// util.ErrConnectionError. Downstream classification (see
// pkg/drivers/hostkey.ClassifyConnectError) depends on that text to tell a
// genuine host-key mismatch apart from an unrelated connection failure, so
// losing it silently sends every raced mismatch down the generic
// credential-retry path instead of the mismatch-confirmation flow.
//
// captured is the same bytes scrapligo's channel logger wrote, captured
// synchronously as each chunk was read — strictly before the specific
// iteration that can close readDone and trigger the race above — so it
// still has the diagnostic even when err's own text has lost it. This only
// ever *adds* text recovered verbatim from that capture; it never invents a
// diagnosis err doesn't already carry independent evidence for elsewhere,
// so a genuinely unrelated connection error (timeout, refused, no route)
// is never reclassified as a host-key failure.
func recoverRacedChannelDiagnostic(err error, captured []byte) error {
	if err == nil {
		return nil
	}
	const marker = "host key verification failed"
	if strings.Contains(strings.ToLower(err.Error()), marker) {
		return err // scrapligo's own error already carries the diagnostic
	}
	if !strings.Contains(strings.ToLower(string(captured)), marker) {
		return err // nothing to recover
	}
	return fmt.Errorf("%w: host key verification failed (recovered from channel output after a race dropped it from the driver error)", err)
}

func (c *Client) Execute(cmd string) (string, error) {
	if c == nil {
		return "", errors.New("ssh client is nil")
	}
	if c.network == nil {
		return "", errors.New("ssh client is not connected")
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", errors.New("command is required")
	}

	output, err := c.network.SendInput(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to send input command: %w", err)
	}
	if len(output) > maxSSHResponseBytes {
		return "", fmt.Errorf("SSH response exceeds the %d-byte limit", maxSSHResponseBytes)
	}

	return string(output), nil
}

func (c *Client) Close() error {
	if c == nil || c.network == nil {
		return nil
	}

	session := c.network
	c.network = nil
	c.platform = nil
	err := closeSSHSession(session)
	if err != nil {
		return fmt.Errorf("failed to close network driver: %w", err)
	}
	return nil
}

func closeSSHSession(session sshSession) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic while closing SSH session: %v", recovered)
		}
	}()
	return session.Close()
}
