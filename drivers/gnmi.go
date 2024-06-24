package drivers

import (
	"context"
	"time"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/formatters"
	"github.com/openconfig/gnmic/pkg/api/target"
	"github.com/openconfig/gnmic/pkg/api/types"
	"github.com/openconfig/gnmic/pkg/api/path"
)

type GNMIClient struct {
	target    *target.Target
	TLSConfig TLSConfig
}

func (g *GNMIClient) Connect(address, username, password string, opts ...Option) error {
	for _, opt := range opts {
		opt(g)
	}
	tc := &types.TargetConfig{
		Address:    address,
		Username:   &username,
		Password:   &password,
		Insecure:   &g.TLSConfig.Insecure,
		SkipVerify: &g.TLSConfig.SkipVerify,
		Timeout:    30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gnmiTarget := target.NewTarget(tc)

	err := gnmiTarget.CreateGNMIClient(ctx)
	if err != nil {
		return err
	}

	g.target = gnmiTarget
	return nil
}

func (g *GNMIClient) Execute(gnmiPath string) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parsedPath, err := path.ParsePath(gnmiPath)
	if err != nil {
		return "", err
	}

	rsp, err := g.target.Get(ctx, &gnmi.GetRequest{
		Path: []*gnmi.Path{parsedPath},
	})

	if err != nil {
		return "", err
	}
	options := &formatters.MarshalOptions{Multiline: true, Indent: " ", }
	jsonOutput, err := options.Marshal(rsp, nil)
	if err != nil {
		return "", err
	}
	return string(jsonOutput), nil
}

func (g *GNMIClient) Close() error {
	return g.target.Close()
}
