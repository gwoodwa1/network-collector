// Package monitoring provides shared health, bounded history and alerting for
// the XR, Junos and mixed-fleet monitor front ends.
package monitoring

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
	"gopkg.in/yaml.v3"
)

type reminderKey struct{}

// WithTACACSTimeoutReminders installs a validated, monotonic reminder
// schedule. Each reminder causes the polling goroutine to warn the operator
// and deliberately refresh the RSA-authenticated SSH session before TACACS
// command authorisation expires.
func WithTACACSTimeoutReminders(ctx context.Context, seconds []int) (context.Context, error) {
	reminders := make([]time.Duration, 0, len(seconds))
	previous := 0
	for _, second := range seconds {
		if second <= previous || second > 86400 {
			return nil, errors.New("tacacs_timeout_reminder values must be strictly increasing seconds between 1 and 86400")
		}
		previous = second
		reminders = append(reminders, time.Duration(second)*time.Second)
	}
	return context.WithValue(ctx, reminderKey{}, reminders), nil
}

func TACACSTimeoutReminders(ctx context.Context) []time.Duration {
	reminders, _ := ctx.Value(reminderKey{}).([]time.Duration)
	return append([]time.Duration(nil), reminders...)
}

type Config struct {
	RotateBytes   int64       `yaml:"rotate_bytes"`
	RetentionDays int         `yaml:"retention_days"`
	Alerts        AlertConfig `yaml:"alerts"`
	Webhook       struct {
		URL                  string   `yaml:"url"`
		AllowedHosts         []string `yaml:"allowed_hosts"`
		AllowPrivateNetworks bool     `yaml:"allow_private_networks"`
		HMACSecretEnv        string   `yaml:"hmac_secret_env"`
	} `yaml:"webhook"`
	Syslog struct {
		Network string `yaml:"network"`
		Address string `yaml:"address"`
	} `yaml:"syslog"`
}

type AlertConfig struct {
	Enabled             bool    `yaml:"enabled"`
	ConsecutiveSamples  int     `yaml:"consecutive_samples"`
	CooldownSeconds     int     `yaml:"cooldown_seconds"`
	RouteDropPercent    float64 `yaml:"route_drop_percent"`
	TrafficShiftPercent float64 `yaml:"traffic_shift_percent"`
	TrafficMinimumBPS   float64 `yaml:"traffic_minimum_bps"`
	InterfaceErrorDelta float64 `yaml:"interface_error_delta"`
}

func RegisterFlags(flags *flag.FlagSet) *string {
	return flags.String("monitor-config", "", "optional YAML configuring history rotation/retention and live alerts")
}

func LoadConfig(path string) (Config, error) {
	c := Config{RotateBytes: 32 << 20, Alerts: AlertConfig{
		ConsecutiveSamples: 2, CooldownSeconds: 300, RouteDropPercent: 20,
		TrafficShiftPercent: 50, TrafficMinimumBPS: 1000000, InterfaceErrorDelta: 1,
	}}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil {
			return c, err
		}
		if len(data) > 1<<20 {
			return c, errors.New("monitor config exceeds 1 MiB")
		}
		d := yaml.NewDecoder(bytes.NewReader(data))
		d.KnownFields(true)
		if err := d.Decode(&c); err != nil {
			return c, fmt.Errorf("monitor config: %w", err)
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return c, errors.New("monitor config must contain exactly one YAML document")
		}
	}
	if c.RotateBytes < 1024 || c.RotateBytes > 1<<30 || c.RetentionDays < 0 || c.RetentionDays > 36500 {
		return c, errors.New("rotate_bytes must be 1024..1073741824; retention_days must be 0..36500 (0 disables deletion)")
	}
	a := c.Alerts
	if a.ConsecutiveSamples < 1 || a.ConsecutiveSamples > 10000 || a.CooldownSeconds < 1 || a.CooldownSeconds > 86400 ||
		!finite(a.RouteDropPercent) || a.RouteDropPercent <= 0 || a.RouteDropPercent > 100 ||
		!finite(a.TrafficShiftPercent) || a.TrafficShiftPercent <= 0 ||
		!finite(a.TrafficMinimumBPS) || a.TrafficMinimumBPS < 1 ||
		!finite(a.InterfaceErrorDelta) || a.InterfaceErrorDelta < 1 {
		return c, errors.New("invalid alert thresholds, persistence, or cooldown")
	}
	return c, nil
}

func (c Config) sinks() ([]orchestrator.EventSink, error) {
	var sinks []orchestrator.EventSink
	if c.Webhook.URL != "" {
		secret := ""
		if c.Webhook.HMACSecretEnv != "" {
			secret = os.Getenv(c.Webhook.HMACSecretEnv)
			if secret == "" {
				return nil, errors.New("webhook HMAC secret environment variable is empty")
			}
		}
		s, err := orchestrator.NewWebhookSinkWithPolicy(c.Webhook.URL, nil, secret, 5*time.Second,
			orchestrator.WebhookPolicy{AllowedHosts: c.Webhook.AllowedHosts, AllowPrivateNetworks: c.Webhook.AllowPrivateNetworks})
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, s)
	}
	if c.Syslog.Address != "" {
		network := c.Syslog.Network
		if network == "" {
			network = "tls"
		}
		s, err := orchestrator.NewSyslogSink(network, c.Syslog.Address, "routing-monitor", 5*time.Second)
		if err != nil {
			for _, s := range sinks {
				_ = s.Close()
			}
			return nil, err
		}
		sinks = append(sinks, s)
	}
	return sinks, nil
}

type contextKey struct{}

func WithRuntime(ctx context.Context, runtime *Runtime) context.Context {
	return context.WithValue(ctx, contextKey{}, runtime)
}
