package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

type lifecycleEvent = orchestrator.Event
type eventSink = orchestrator.EventSink

type eventDispatcher struct {
	runID string
	sinks []eventSink
}

func (d *eventDispatcher) emit(event lifecycleEvent) {
	if d == nil {
		return
	}
	event.RunID = d.runID
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	for _, sink := range d.sinks {
		if err := sink.Handle(context.Background(), event); err != nil {
			slog.Warn("lifecycle event sink failed", "event", event.Type, "error", err)
		}
	}
}

func (d *eventDispatcher) close() {
	if d == nil {
		return
	}
	for _, sink := range d.sinks {
		if err := sink.Close(); err != nil {
			slog.Warn("error closing lifecycle event sink", "error", err)
		}
	}
}

func newJSONLEventSink(path string) (eventSink, error) {
	return orchestrator.NewJSONLSink(path)
}

func newNetworkEventSink(config EventSinkConfig) (eventSink, error) {
	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	var sink eventSink
	var err error
	switch strings.ToLower(strings.TrimSpace(config.Type)) {
	case "webhook":
		secret := ""
		if name := strings.TrimSpace(config.HMACSecretEnv); name != "" {
			secret, _ = os.LookupEnv(name)
			if secret == "" {
				return nil, fmt.Errorf("webhook HMAC secret environment variable %q is empty", name)
			}
		}
		allowedHosts := splitAllowedHosts(os.Getenv("NETWORK_COLLECTOR_WEBHOOK_ALLOWED_HOSTS"))
		if len(allowedHosts) == 0 {
			return nil, fmt.Errorf("webhook sinks require deployment environment NETWORK_COLLECTOR_WEBHOOK_ALLOWED_HOSTS")
		}
		sink, err = orchestrator.NewWebhookSinkWithPolicy(
			config.URL, config.Headers, secret, timeout,
			orchestrator.WebhookPolicy{AllowedHosts: allowedHosts},
		)
	case "syslog":
		sink, err = orchestrator.NewSyslogSink(config.Network, config.Address, config.AppName, timeout)
	default:
		return nil, fmt.Errorf("unsupported event sink type %q", config.Type)
	}
	if err != nil {
		return nil, err
	}
	return orchestrator.NewAsyncSink(sink, config.QueueSize, func(err error) {
		slog.Warn("asynchronous lifecycle event delivery failed", "type", config.Type, "error", err)
	})
}

func splitAllowedHosts(value string) []string {
	var hosts []string
	for _, host := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if trimmed := strings.TrimSpace(host); trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}
	return hosts
}
