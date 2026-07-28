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
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/gnmic/pkg/api/path"
	"github.com/openconfig/gnmic/pkg/api/target"
	"github.com/openconfig/gnmic/pkg/api/types"
	"github.com/openconfig/gnmic/pkg/formatters"
	"google.golang.org/grpc"
)

type Subscription struct {
	Paths            []string
	Mode             string
	StreamMode       string
	SampleInterval   time.Duration
	Duration         time.Duration
	MaxUpdates       int
	MaxResponseBytes int
	MaxResponseCount int
}

const (
	MaxSubscriptionDuration            = time.Hour
	MaxSubscriptionUpdates             = 100_000
	MaxGRPCReceiveMessageBytes         = 10 * 1024 * 1024
	MaxSubscriptionReceiveMessageBytes = 1024 * 1024
	MaxGetResponseJSONBytes            = 10 * 1024 * 1024
	MaxSubscriptionResponseBytes       = 10 * 1024 * 1024
	MaxSingleResponseJSONBytes         = 1024 * 1024
	MaxSubscriptionResponses           = 100_000
	DefaultSubscriptionResponses       = 10_000
)

type Event struct {
	Type      string      `json:"type"`
	Path      string      `json:"path"`
	Value     interface{} `json:"value,omitempty"`
	Timestamp int64       `json:"timestamp"`
	Initial   bool        `json:"initial"`
}

type EventHandler func(Event) error

// subscriptionBoundedGNMIClient preserves gnmic's target behavior while
// applying a tighter receive boundary only to streaming Subscribe RPCs.
// Unary Get responses retain the larger connection-level limit.
type subscriptionBoundedGNMIClient struct {
	gnmi.GNMIClient
}

func (c *subscriptionBoundedGNMIClient) Subscribe(
	ctx context.Context,
	opts ...grpc.CallOption,
) (gnmi.GNMI_SubscribeClient, error) {
	boundedOptions := append([]grpc.CallOption(nil), opts...)
	boundedOptions = append(
		boundedOptions,
		grpc.MaxCallRecvMsgSize(MaxSubscriptionReceiveMessageBytes),
	)
	return c.GNMIClient.Subscribe(ctx, boundedOptions...)
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
			g.TLSConfig.Insecure = true
		}
	}
}

func WithInsecure(insecure bool) Option {
	return func(g *GNMIClient) {
		if g != nil {
			g.TLSConfig.Insecure = insecure
		}
	}
}

func WithSkipVerify(skipVerify bool) Option {
	return func(g *GNMIClient) {
		if g != nil {
			g.TLSConfig.SkipVerify = skipVerify
		}
	}
}

func WithTLSCredentials(caFile, certFile, keyFile, serverName string) Option {
	return func(g *GNMIClient) {
		if g == nil {
			return
		}
		g.TLSConfig.CAFile = strings.TrimSpace(caFile)
		g.TLSConfig.CertFile = strings.TrimSpace(certFile)
		g.TLSConfig.KeyFile = strings.TrimSpace(keyFile)
		g.TLSConfig.ServerName = strings.TrimSpace(serverName)
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
		Address:       address,
		Username:      &username,
		Password:      &password,
		Insecure:      &g.TLSConfig.Insecure,
		SkipVerify:    &g.TLSConfig.SkipVerify,
		Timeout:       g.timeout,
		TLSServerName: g.TLSConfig.ServerName,
	}
	if g.TLSConfig.CAFile != "" {
		tc.TLSCA = &g.TLSConfig.CAFile
	}
	if g.TLSConfig.CertFile != "" {
		tc.TLSCert = &g.TLSConfig.CertFile
	}
	if g.TLSConfig.KeyFile != "" {
		tc.TLSKey = &g.TLSConfig.KeyFile
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	gnmiTarget := target.NewTarget(tc)
	if err := gnmiTarget.CreateGNMIClient(
		ctx,
		// This is the pre-unmarshal boundary for unary RPCs. Subscribe calls
		// receive the tighter per-call boundary installed below.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxGRPCReceiveMessageBytes)),
	); err != nil {
		return fmt.Errorf("failed to create gNMI client: %w", err)
	}
	gnmiTarget.Client = &subscriptionBoundedGNMIClient{GNMIClient: gnmiTarget.Client}

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
	if len(jsonOutput) > MaxGetResponseJSONBytes {
		return "", fmt.Errorf("gNMI get JSON response exceeds the %d-byte post-decode limit", MaxGetResponseJSONBytes)
	}

	return string(jsonOutput), nil
}

func (g *GNMIClient) Subscribe(ctx context.Context, config Subscription) (string, error) {
	return g.SubscribeEvents(ctx, config, nil)
}

func (g *GNMIClient) SubscribeEvents(ctx context.Context, config Subscription, handler EventHandler) (string, error) {
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
	if config.Duration < 0 || config.Duration > MaxSubscriptionDuration {
		return "", fmt.Errorf("subscription duration must be between 1s and %s", MaxSubscriptionDuration)
	}
	if config.MaxUpdates < 0 || config.MaxUpdates > MaxSubscriptionUpdates {
		return "", fmt.Errorf("subscription max_updates must be between 1 and %d", MaxSubscriptionUpdates)
	}
	maxResponseBytes := config.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = MaxSubscriptionResponseBytes
	}
	if maxResponseBytes < 0 || maxResponseBytes > MaxSubscriptionResponseBytes {
		return "", fmt.Errorf("subscription max_response_bytes must be between 1 and %d", MaxSubscriptionResponseBytes)
	}
	maxResponseCount := config.MaxResponseCount
	if maxResponseCount == 0 {
		maxResponseCount = DefaultSubscriptionResponses
	}
	if maxResponseCount < 0 || maxResponseCount > MaxSubscriptionResponses {
		return "", fmt.Errorf("subscription max_response_count must be between 1 and %d", MaxSubscriptionResponses)
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
	if config.SampleInterval < 0 {
		return "", errors.New("sample_interval must not be negative")
	}
	subscriptions := make([]*gnmi.Subscription, 0, len(config.Paths))
	for _, value := range config.Paths {
		parsed, err := path.ParsePath(strings.TrimSpace(value))
		if err != nil {
			return "", fmt.Errorf("failed to parse subscription path %q: %w", value, err)
		}
		// #nosec G115 -- negative durations are rejected above.
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
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	deadline := config.Duration
	if deadline <= 0 {
		deadline = g.timeout
	}
	if _, exists := streamCtx.Deadline(); !exists && deadline > 0 {
		var timeoutCancel context.CancelFunc
		streamCtx, timeoutCancel = context.WithTimeout(streamCtx, deadline)
		defer timeoutCancel()
	}
	var responses <-chan *gnmi.SubscribeResponse
	var failures <-chan error
	if mode == "once" {
		responses, failures = g.target.SubscribeOnceChan(streamCtx, request)
	} else {
		responses, failures = g.target.SubscribeStreamChan(streamCtx, request, "network-collector")
	}
	encoded := make([]json.RawMessage, 0)
	responseBytes := 0
	updates := 0
	options := &formatters.MarshalOptions{Multiline: false}
	synced := false
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
			if len(body) > MaxSingleResponseJSONBytes {
				return "", fmt.Errorf("gNMI subscription JSON response exceeds the %d-byte post-decode per-response limit", MaxSingleResponseJSONBytes)
			}
			if len(encoded) >= maxResponseCount {
				return "", fmt.Errorf("gNMI subscription exceeded the %d-response limit", maxResponseCount)
			}
			if len(body) > maxResponseBytes-responseBytes {
				return "", fmt.Errorf("gNMI subscription exceeded the %d-byte aggregate response limit", maxResponseBytes)
			}
			encoded = append(encoded, json.RawMessage(body))
			responseBytes += len(body)
			if notification := response.GetUpdate(); notification != nil {
				updates++
				if handler != nil {
					if err := handleNotification(notification, !synced, handler); err != nil {
						return "", err
					}
				}
			}
			if response.GetSyncResponse() {
				synced = true
				if mode == "once" {
					return marshalSubscriptionResponses(encoded)
				}
			}
			if config.MaxUpdates > 0 && updates >= config.MaxUpdates {
				return marshalSubscriptionResponses(encoded)
			}
		case err, ok := <-failures:
			if !ok || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return marshalSubscriptionResponses(encoded)
			}
			return "", fmt.Errorf("gNMI subscribe request failed: %w", err)
		case <-streamCtx.Done():
			return marshalSubscriptionResponses(encoded)
		}
	}
}

func handleNotification(notification *gnmi.Notification, initial bool, handler EventHandler) error {
	for _, update := range notification.GetUpdate() {
		scalar, err := value.ToScalar(update.GetVal())
		if err != nil {
			return fmt.Errorf("failed to decode gNMI value: %w", err)
		}
		event := Event{
			Type: "update", Path: notificationPath(notification.GetPrefix(), update.GetPath()),
			Value: scalar, Timestamp: notification.GetTimestamp(), Initial: initial,
		}
		if err := handler(event); err != nil {
			return fmt.Errorf("gNMI event handler failed for %s: %w", event.Path, err)
		}
	}
	for _, deleted := range notification.GetDelete() {
		event := Event{
			Type: "delete", Path: notificationPath(notification.GetPrefix(), deleted),
			Timestamp: notification.GetTimestamp(), Initial: initial,
		}
		if err := handler(event); err != nil {
			return fmt.Errorf("gNMI event handler failed for %s: %w", event.Path, err)
		}
	}
	return nil
}

func notificationPath(prefix, leaf *gnmi.Path) string {
	combined := &gnmi.Path{Elem: path.PathElems(prefix, leaf)}
	if leaf.GetOrigin() != "" {
		combined.Origin = leaf.GetOrigin()
	} else {
		combined.Origin = prefix.GetOrigin()
	}
	result := path.GnmiPathToXPath(combined, false)
	if combined.GetOrigin() == "" && result != "" {
		return "/" + result
	}
	return result
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
