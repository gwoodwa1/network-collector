package netconf

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers"
	"github.com/scrapli/scrapligo/driver/netconf"
	"github.com/scrapli/scrapligo/driver/opoptions"
	scraplioptions "github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/util"
)

type Option = drivers.Option

type ScrapligoNETCONF struct {
	host          string
	network       *netconf.Driver
	socketTimeout time.Duration
	opsTimeout    time.Duration
}

func WithNetconfTimeouts(socketTimeout, opsTimeout time.Duration) Option {
	return func(d interface{}) {
		if socketTimeout <= 0 && opsTimeout <= 0 {
			return
		}
		if device, ok := d.(*ScrapligoNETCONF); ok {
			if socketTimeout > 0 {
				device.socketTimeout = socketTimeout
			}
			if opsTimeout > 0 {
				device.opsTimeout = opsTimeout
			}
		}
	}
}

func (n *ScrapligoNETCONF) Connect(host, username, password string, opts ...Option) error {
	if n == nil {
		return errors.New("NETCONF client is nil")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}

	n.host = strings.TrimSpace(host)

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(n)
	}

	options := []util.Option{
		scraplioptions.WithAuthNoStrictKey(),
		scraplioptions.WithAuthUsername(username),
		scraplioptions.WithAuthPassword(password),
		scraplioptions.WithPort(830),
	}
	if n.socketTimeout > 0 {
		options = append(options, scraplioptions.WithTimeoutSocket(n.socketTimeout))
	}
	if n.opsTimeout > 0 {
		options = append(options, scraplioptions.WithTimeoutOps(n.opsTimeout))
	}

	d, err := netconf.NewDriver(n.host, options...)
	if err != nil {
		return fmt.Errorf("failed to create NETCONF driver: %w", err)
	}

	if err := d.Open(); err != nil {
		return fmt.Errorf("failed to open NETCONF driver: %w", err)
	}

	n.network = d
	return nil
}

func (n *ScrapligoNETCONF) Execute(cmd string) (string, error) {
	if n == nil {
		return "", errors.New("NETCONF client is nil")
	}
	if n.network == nil {
		return "", errors.New("NETCONF client is not connected")
	}
	if strings.TrimSpace(cmd) == "" {
		return "", errors.New("rpc payload is required")
	}

	r, err := n.network.RPC(opoptions.WithFilter(cmd))
	if err != nil {
		return "", fmt.Errorf("failed to execute NETCONF RPC: %w", err)
	}

	if r.Failed != nil {
		return "", fmt.Errorf("NETCONF response indicates failure: %+v", r.Failed)
	}

	return r.Result, nil
}

func (n *ScrapligoNETCONF) Close() error {
	if n == nil || n.network == nil {
		return nil
	}
	if err := n.network.Close(); err != nil {
		return fmt.Errorf("failed to close NETCONF client: %w", err)
	}
	return nil
}
