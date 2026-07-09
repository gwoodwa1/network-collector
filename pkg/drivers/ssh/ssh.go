package ssh

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/scrapli/scrapligo/driver/network"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
	"github.com/scrapli/scrapligo/util"
)

type Client struct {
	driverName      string
	host            string
	platform        *platform.Platform
	network         *network.Driver
	channelLog      io.Writer
	socketTimeout   time.Duration
	opsTimeout      time.Duration
	securityProfile string
	hostKeyPolicy   string
	knownHostsFile  string
	selectedProfile string
	passwordPattern *regexp.Regexp
	connectProfile  func(host, username, password, driverName, profile, hostKeyPolicy string) error
}

// Option is a type-safe option for configuring Client
type Option func(*Client)

func NewClient(opts ...Option) *Client {
	c := &Client{
		channelLog:      os.Stdout,
		socketTimeout:   45 * time.Second,
		opsTimeout:      90 * time.Second,
		securityProfile: "compatibility",
		hostKeyPolicy:   "insecure",
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
		return "compatibility", nil
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
		return "insecure", nil
	}
	switch policy {
	case "insecure", "known_hosts":
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

func (c *Client) connectWithProfile(host, username, password, driverName, profile, hostKeyPolicy string) error {
	platformOptions := []util.Option{
		options.WithAuthUsername(username),
		options.WithAuthPassword(password),
		options.WithTimeoutSocket(c.socketTimeout),
		options.WithTimeoutOps(c.opsTimeout),
		options.WithChannelLog(c.channelLog),
	}
	if c.passwordPattern != nil {
		platformOptions = append(platformOptions, options.WithPasswordPattern(c.passwordPattern))
	}
	if hostKeyPolicy == "insecure" {
		platformOptions = append(platformOptions, options.WithAuthNoStrictKey())
	} else if c.knownHostsFile != "" {
		platformOptions = append(platformOptions, options.WithSSHKnownHostsFile(c.knownHostsFile))
	} else {
		platformOptions = append(platformOptions, options.WithSSHKnownHostsFileSystem())
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
		return fmt.Errorf("failed to open driver: %w", err)
	}

	c.driverName = driverName
	c.host = host
	c.platform = platformConfig
	c.network = driver
	c.selectedProfile = profile
	return nil
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

	output, err := c.network.Channel.SendInput(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to send input command: %w", err)
	}

	return string(output), nil
}

func (c *Client) Close() error {
	if c == nil || c.network == nil {
		return nil
	}

	if err := c.network.Close(); err != nil {
		return fmt.Errorf("failed to close network driver: %w", err)
	}

	c.network = nil
	c.platform = nil
	return nil
}
