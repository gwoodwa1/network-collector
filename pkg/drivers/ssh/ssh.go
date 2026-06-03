package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/scrapli/scrapligo/driver/network"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
)

type Client struct {
	driverName    string
	host          string
	platform      *platform.Platform
	network       *network.Driver
	channelLog    io.Writer
	socketTimeout time.Duration
	opsTimeout    time.Duration
}

// Option is a type-safe option for configuring Client
type Option func(*Client)

func NewClient(opts ...Option) *Client {
	c := &Client{
		channelLog:    os.Stdout,
		socketTimeout: 45 * time.Second,
		opsTimeout:    90 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
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

	platformConfig, err := platform.NewPlatform(
		trimmedDriverName,
		trimmedHost,
		options.WithAuthNoStrictKey(),
		options.WithAuthUsername(username),
		options.WithAuthPassword(password),
		options.WithStandardTransportExtraKexs([]string{
			"diffie-hellman-group14-sha1",
			"diffie-hellman-group-exchange-sha1",
			"diffie-hellman-group1-sha1",
		}),
		options.WithStandardTransportExtraCiphers([]string{
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
			"aes128-cbc", "aes192-cbc", "aes256-cbc",
			"3des-cbc",
		}),
		options.WithTimeoutSocket(c.socketTimeout),
		options.WithTimeoutOps(c.opsTimeout),
		// Keep scrapligo's process logger disabled; expected reload disconnects
		// are handled by the collector and channel output is still logged below.
		options.WithChannelLog(c.channelLog),
	)
	if err != nil {
		return fmt.Errorf("failed to create platform: %w", err)
	}

	driver, err := platformConfig.GetNetworkDriver()
	if err != nil {
		return fmt.Errorf("failed to get network driver: %w", err)
	}

	if err := driver.Open(); err != nil {
		return fmt.Errorf("failed to open driver: %w", err)
	}

	c.driverName = trimmedDriverName
	c.host = trimmedHost
	c.platform = platformConfig
	c.network = driver
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
