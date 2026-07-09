package main

import (
	"fmt"
	"regexp"
	"time"

	"github.com/scrapli/scrapligo/driver/network"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
)

// passcodePromptPattern matches this fleet's RSA SecurID challenge prompt
// ("Enter PASSCODE:"). scrapligo's built-in default password pattern only
// matches literal "password:" and never matches "passcode" — with that
// default, every connection attempt against these devices would just hang
// until the operation timeout instead of ever sending the passcode. It also
// still matches plain "password:" prompts, in case a device or profile ever
// falls back to that instead.
var passcodePromptPattern = regexp.MustCompile(`(?im)(password|passcode):\s?$`)

// xrSSHClient is a minimal, isolated scrapligo wrapper — deliberately not
// pkg/drivers/ssh.Client. That type's fields are all unexported, so there is
// no way to override its password-prompt regex from outside the ssh
// package, and the regex mismatch above means the shared client cannot
// authenticate against this fleet as configured. This wrapper exists solely
// to set that one option; everything else (timeouts, insecure host key
// handling) matches ssh.Client's own defaults.
type xrSSHClient struct {
	driver *network.Driver
}

// connectXRDevice opens exactly one SSH session. Channel logging is left
// disabled (unlike pkg/drivers/ssh.Client, which defaults it to stdout) so
// raw device output never mixes into this tool's status-line stream; the
// scrapligo channel logger only ever captures data received from the
// device, never what this process sends, so this is about output
// cleanliness, not credential exposure either way.
func connectXRDevice(host, username, password, deviceType string) (*xrSSHClient, error) {
	platformConfig, err := platform.NewPlatform(
		deviceType,
		host,
		options.WithAuthUsername(username),
		options.WithAuthPassword(password),
		options.WithAuthNoStrictKey(),
		options.WithTimeoutSocket(45*time.Second),
		options.WithTimeoutOps(90*time.Second),
		options.WithPasswordPattern(passcodePromptPattern),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform: %w", err)
	}

	driver, err := platformConfig.GetNetworkDriver()
	if err != nil {
		return nil, fmt.Errorf("failed to get network driver: %w", err)
	}

	if err := driver.Open(); err != nil {
		// scrapligo's self-cleanup on a failed Open() is inconsistent: if the
		// transport itself fails to open (host unreachable, dial timeout),
		// nothing is closed internally and driver.Close() is required to
		// avoid leaking the connection. But if the transport opens
		// successfully and a later step fails (in-channel auth, PTY/shell
		// setup — e.g. hitting a VTY session limit), scrapligo's own defer
		// (channel.Channel.Open) already closes the channel, and calling
		// Close() again double-closes Channel.Errs and panics. There's no
		// way to tell from here which case occurred, so attempt the close
		// and recover if scrapligo already did it.
		closeAfterFailedOpen(driver)
		return nil, fmt.Errorf("failed to open driver: %w", err)
	}

	return &xrSSHClient{driver: driver}, nil
}

// closeAfterFailedOpen calls driver.Close(), swallowing the panic scrapligo
// raises if it already closed the channel internally as part of its own
// Open() failure cleanup (see the comment in connectXRDevice). This makes
// close-after-failed-open safe regardless of which of scrapligo's two
// inconsistent self-cleanup behaviors applies.
func closeAfterFailedOpen(driver *network.Driver) {
	defer func() {
		_ = recover()
	}()
	_ = driver.Close()
}

func (c *xrSSHClient) Execute(cmd string) (string, error) {
	output, err := c.driver.Channel.SendInput(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to send input command: %w", err)
	}
	return string(output), nil
}

func (c *xrSSHClient) Close() error {
	if c == nil || c.driver == nil {
		return nil
	}
	return c.driver.Close()
}
