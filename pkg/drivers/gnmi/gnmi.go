package gnmi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/api/path"
	"github.com/openconfig/gnmic/pkg/api/target"
	"github.com/openconfig/gnmic/pkg/api/types"
	"github.com/openconfig/gnmic/pkg/formatters"
)

type Subscription struct {
	Paths          []string
	Mode           string
	StreamMode     string
	SampleInterval time.Duration
	Duration       time.Duration
	MaxUpdates     int
}

// Option is a type-safe option for configuring GNMIClient
type Option func(*GNMIClient)

type GNMIClient struct {
	target  *target.Target
	timeout time.Duration
	drivers.TLSConfig
}

func WithSkipTLS() Option {
	return func(g *GNMIClient) {
		if g != nil {
			g.TLSConfig.SkipVerify = true
			g.TLSConfig.Insecure = true
		}
	}
}

func WithGNMITimeout(timeout time.Duration) Option {
	return WithRequestTimeout(timeout)
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(g *GNMIClient) {
		if g != nil && timeout > 0 {
			g.timeout = timeout
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

func (g *GNMIClient) Subscribe(ctx context.Context, config Subscription) (string, error) {
	if g == nil || g.target == nil {
		return "", errors.New("GNMI client is not connected")
	}
	if len(config.Paths) == 0 {
		return "", errors.New("at least one gNMI subscription path is required")
	}
	mode := strings.ToLower(strings.TrimSpace(config.Mode))
	if mode == "" {
		mode = "once"
	}
	if mode != "once" && mode != "stream" {
		return "", fmt.Errorf("subscription mode must be once or stream")
	}
	if mode == "stream" && config.Duration <= 0 && config.MaxUpdates <= 0 {
		return "", errors.New("stream subscriptions require duration or max_updates")
	}
	streamMode := strings.ToLower(strings.TrimSpace(config.StreamMode))
	if streamMode == "" {
		streamMode = "target_defined"
	}
	var subscriptionMode gnmi.SubscriptionMode
	switch streamMode {
	case "target_defined":
		subscriptionMode = gnmi.SubscriptionMode_TARGET_DEFINED
	case "on_change":
		subscriptionMode = gnmi.SubscriptionMode_ON_CHANGE
	case "sample":
		subscriptionMode = gnmi.SubscriptionMode_SAMPLE
		if config.SampleInterval <= 0 {
			return "", errors.New("sample subscriptions require sample_interval")
		}
	default:
		return "", fmt.Errorf("stream mode must be target_defined, on_change, or sample")
	}
	subscriptions := make([]*gnmi.Subscription, 0, len(config.Paths))
	for _, value := range config.Paths {
		parsed, err := path.ParsePath(strings.TrimSpace(value))
		if err != nil {
			return "", fmt.Errorf("failed to parse subscription path %q: %w", value, err)
		}
		subscriptions = append(subscriptions, &gnmi.Subscription{Path: parsed, Mode: subscriptionMode, SampleInterval: uint64(config.SampleInterval)})
	}
	listMode := gnmi.SubscriptionList_ONCE
	if mode == "stream" {
		listMode = gnmi.SubscriptionList_STREAM
	}
	request := &gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Subscribe{Subscribe: &gnmi.SubscriptionList{Mode: listMode, Subscription: subscriptions}}}
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := config.Duration
	if deadline <= 0 {
		deadline = g.timeout
	}
	if _, exists := ctx.Deadline(); !exists && deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}
	var responses <-chan *gnmi.SubscribeResponse
	var failures <-chan error
	if mode == "once" {
		responses, failures = g.target.SubscribeOnceChan(ctx, request)
	} else {
		responses, failures = g.target.SubscribeStreamChan(ctx, request, "network-collector")
	}
	encoded := make([]json.RawMessage, 0)
	updates := 0
	options := &formatters.MarshalOptions{Multiline: false}
	for {
		select {
		case response, ok := <-responses:
			if !ok {
				return marshalSubscriptionResponses(encoded)
			}
			if response == nil {
				continue
			}
			body, err := options.Marshal(response, nil)
			if err != nil {
				return "", fmt.Errorf("failed to marshal gNMI subscription response: %w", err)
			}
			encoded = append(encoded, json.RawMessage(body))
			if response.GetUpdate() != nil {
				updates++
			}
			if response.GetSyncResponse() && mode == "once" {
				return marshalSubscriptionResponses(encoded)
			}
			if config.MaxUpdates > 0 && updates >= config.MaxUpdates {
				return marshalSubscriptionResponses(encoded)
			}
		case err, ok := <-failures:
			if !ok || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return marshalSubscriptionResponses(encoded)
			}
			return "", fmt.Errorf("gNMI subscribe request failed: %w", err)
		case <-ctx.Done():
			return marshalSubscriptionResponses(encoded)
		}
	}
}

func marshalSubscriptionResponses(responses []json.RawMessage) (string, error) {
	body, err := json.MarshalIndent(responses, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
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
