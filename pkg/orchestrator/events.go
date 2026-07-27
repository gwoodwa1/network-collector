package orchestrator

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	RunID     string                 `json:"run_id,omitempty"`
	Hostname  string                 `json:"hostname,omitempty"`
	IP        string                 `json:"ip,omitempty"`
	Step      string                 `json:"step,omitempty"`
	Failed    *bool                  `json:"failed,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

type EventSink interface {
	Handle(context.Context, Event) error
	Close() error
}

type AsyncSink struct {
	sink      EventSink
	queue     chan Event
	done      chan struct{}
	onError   func(error)
	closeOnce sync.Once
	mu        sync.RWMutex
	closed    bool
	closeErr  error
}

func NewAsyncSink(sink EventSink, queueSize int, onError func(error)) (*AsyncSink, error) {
	if sink == nil {
		return nil, errors.New("event sink is required")
	}
	if queueSize <= 0 {
		queueSize = 256
	}
	s := &AsyncSink{sink: sink, queue: make(chan Event, queueSize), done: make(chan struct{}), onError: onError}
	go func() {
		defer close(s.done)
		for event := range s.queue {
			if err := s.sink.Handle(context.Background(), event); err != nil && s.onError != nil {
				s.onError(err)
			}
		}
	}()
	return s, nil
}

func (s *AsyncSink) Handle(ctx context.Context, event Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("event sink is closed")
	}
	select {
	case s.queue <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("event sink queue is full")
	}
}

func (s *AsyncSink) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
		<-s.done
		s.closeErr = s.sink.Close()
	})
	return s.closeErr
}

type WebhookSink struct {
	url        string
	headers    map[string]string
	hmacSecret []byte
	client     *http.Client
}

type WebhookPolicy struct {
	AllowedHosts         []string
	AllowPrivateNetworks bool
}

func NewWebhookSink(url string, headers map[string]string, hmacSecret string, timeout time.Duration) (*WebhookSink, error) {
	parsed, err := urlpkgParse(url)
	if err != nil {
		return nil, err
	}
	return NewWebhookSinkWithPolicy(url, headers, hmacSecret, timeout, WebhookPolicy{AllowedHosts: []string{parsed.Hostname()}})
}

func NewWebhookSinkWithPolicy(rawURL string, headers map[string]string, hmacSecret string, timeout time.Duration, policy WebhookPolicy) (*WebhookSink, error) {
	parsed, err := urlpkgParse(rawURL)
	if err != nil {
		return nil, err
	}
	if !hostAllowed(parsed.Hostname(), policy.AllowedHosts) {
		return nil, fmt.Errorf("webhook host %q is not in the deployment allowlist", parsed.Hostname())
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && !policy.AllowPrivateNetworks && isPrivateDestination(ip) {
		return nil, fmt.Errorf("webhook destination %q is a private or local address", parsed.Hostname())
	}
	if len(policy.AllowedHosts) == 0 {
		return nil, errors.New("webhook destination allowlist is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: secureWebhookDialer(policy.AllowPrivateNetworks),
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("webhook redirects are disabled")
		},
	}
	return &WebhookSink{url: rawURL, headers: headers, hmacSecret: []byte(hmacSecret), client: client}, nil
}

func urlpkgParse(rawURL string) (*url.URL, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("webhook URL is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("webhook URL must be an absolute HTTPS URL without user information")
	}
	return parsed, nil
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), host) {
			return true
		}
	}
	return false
}

func isPrivateDestination(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func secureWebhookDialer(allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, resolved := range addresses {
			if !allowPrivate && isPrivateDestination(resolved.IP) {
				return nil, fmt.Errorf("webhook host %q resolved to private or local address %s", host, resolved.IP)
			}
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("webhook host %q resolved to no addresses", host)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
	}
}

func (s *WebhookSink) Handle(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range s.headers {
		req.Header.Set(key, value)
	}
	if len(s.hmacSecret) > 0 {
		mac := hmac.New(sha256.New, s.hmacSecret)
		_, _ = mac.Write(body)
		req.Header.Set("X-Network-Collector-Signature", "sha256="+fmt.Sprintf("%x", mac.Sum(nil)))
	}
	response, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.CopyN(io.Discard, response.Body, 4096)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", response.Status)
	}
	return nil
}

func (s *WebhookSink) Close() error { return nil }

type SyslogSink struct {
	network, address, appName string
	timeout                   time.Duration
}

func NewSyslogSink(network, address, appName string, timeout time.Duration) (*SyslogSink, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" && network != "tls" {
		return nil, fmt.Errorf("syslog network must be udp, tcp, or tls")
	}
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("syslog address is required")
	}
	if strings.TrimSpace(appName) == "" {
		appName = "network-collector"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &SyslogSink{network: network, address: address, appName: appName, timeout: timeout}, nil
}

func (s *SyslogSink) Handle(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: s.timeout}
	var conn net.Conn
	if s.network == "tls" {
		host, _, splitErr := net.SplitHostPort(s.address)
		if splitErr != nil {
			return splitErr
		}
		conn, err = (&tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		}).DialContext(ctx, "tcp", s.address)
	} else {
		conn, err = dialer.DialContext(ctx, s.network, s.address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(s.timeout))
	message := fmt.Sprintf("<14>1 %s - %s - - - %s", time.Now().UTC().Format(time.RFC3339), s.appName, body)
	if s.network == "tcp" || s.network == "tls" {
		message = fmt.Sprintf("%d %s", len(message), message)
	} else {
		message += "\n"
	}
	_, err = io.WriteString(conn, message)
	return err
}

func (s *SyslogSink) Close() error { return nil }

type JSONLSink struct {
	mu     sync.Mutex
	writer io.WriteCloser
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create event output directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("secure event output directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open event output: %w", err)
	}
	return &JSONLSink{writer: file}, nil
}

func (s *JSONLSink) Handle(_ context.Context, event Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.writer.Write(append(encoded, '\n'))
	return err
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Close()
}

type DeviceOutcome struct {
	Hostname string        `json:"hostname"`
	IP       string        `json:"ip,omitempty"`
	Failed   bool          `json:"failed"`
	Duration time.Duration `json:"duration_ns,omitempty"`
}
