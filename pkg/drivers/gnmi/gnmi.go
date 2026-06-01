package gnmi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/api/path"
	"github.com/openconfig/gnmic/pkg/api/target"
	"github.com/openconfig/gnmic/pkg/api/types"
	"github.com/openconfig/gnmic/pkg/formatters"
)

type Option = drivers.Option

type GNMIClient struct {
	target  *target.Target
	timeout time.Duration
	drivers.TLSConfig
}

func WithSkipTLS() Option {
	return func(d interface{}) {
		if device, ok := d.(*GNMIClient); ok {
			device.TLSConfig.SkipVerify = true
			device.TLSConfig.Insecure = true
		}
	}
}

func WithGNMITimeout(timeout time.Duration) Option {
	return WithRequestTimeout(timeout)
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(d interface{}) {
		if timeout <= 0 {
			return
		}
		if device, ok := d.(*GNMIClient); ok {
			device.timeout = timeout
		}
	}
}

func (g *GNMIClient) Connect(address, username, password string, opts ...Option) error {
	if g == nil {
		return errors.New("GNMI client is nil")
	}
	if strings.TrimSpace(address) == "" {
		return errors.New("address is required")
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(g)
	}

	if g.timeout <= 0 {
		g.timeout = 30 * time.Second
	}

	tc := &types.TargetConfig{
		Address:    address,
		Username:   &username,
		Password:   &password,
		Insecure:   &g.TLSConfig.Insecure,
		SkipVerify: &g.TLSConfig.SkipVerify,
		Timeout:    g.timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	gnmiTarget := target.NewTarget(tc)
	if err := gnmiTarget.CreateGNMIClient(ctx); err != nil {
		return fmt.Errorf("failed to create gNMI client: %w", err)
	}

	g.target = gnmiTarget
	return nil
}

func (g *GNMIClient) Execute(gnmiPath string) (string, error) {
	if g == nil {
		return "", errors.New("GNMI client is nil")
	}
	if g.target == nil {
		return "", errors.New("GNMI client is not connected")
	}
	pathString := strings.TrimSpace(gnmiPath)
	if pathString == "" {
		return "", errors.New("gNMI path is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	parsedPath, err := path.ParsePath(pathString)
	if err != nil {
		return "", fmt.Errorf("failed to parse path: %w", err)
	}

	rsp, err := g.target.Get(ctx, &gnmi.GetRequest{Path: []*gnmi.Path{parsedPath}})
	if err != nil {
		return "", fmt.Errorf("gNMI get request failed: %w", err)
	}

	options := &formatters.MarshalOptions{Multiline: true, Indent: " "}
	jsonOutput, err := options.Marshal(rsp, nil)
	if err != nil {
		return "", fmt.Errorf("failed to marshal gNMI response: %w", err)
	}

	return string(jsonOutput), nil
}

func (g *GNMIClient) Close() error {
	if g == nil || g.target == nil {
		return nil
	}
	if err := g.target.Close(); err != nil {
		return fmt.Errorf("failed to close gNMI client: %w", err)
	}
	return nil
}
