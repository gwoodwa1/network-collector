package orchestrator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookSink(t *testing.T) {
	var received string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		received = string(body)
		mac := hmac.New(sha256.New, []byte("secret"))
		_, _ = mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if request.Header.Get("X-Network-Collector-Signature") != want {
			t.Errorf("bad signature")
		}
		if request.Header.Get("X-Test") != "yes" {
			t.Errorf("missing custom header")
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sink, err := NewWebhookSinkWithPolicy(
		server.URL, map[string]string{"X-Test": "yes"}, "secret", time.Second,
		WebhookPolicy{AllowedHosts: []string{"127.0.0.1"}, AllowPrivateNetworks: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	sink.client = server.Client()
	if err := sink.Handle(context.Background(), Event{Type: "run.started"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(received, `"type":"run.started"`) {
		t.Fatalf("unexpected body: %s", received)
	}
}

func TestWebhookSinkRequiresHTTPSAndAllowlistedPublicDestination(t *testing.T) {
	if _, err := NewWebhookSink("http://events.example.test/hook", nil, "", time.Second); err == nil {
		t.Fatal("accepted plaintext webhook URL")
	}
	if _, err := NewWebhookSinkWithPolicy(
		"https://127.0.0.1/hook", nil, "", time.Second,
		WebhookPolicy{AllowedHosts: []string{"127.0.0.1"}},
	); err == nil {
		t.Fatal("accepted private destination without explicit policy")
	}
	if _, err := NewWebhookSinkWithPolicy(
		"https://events.example.test/hook", nil, "", time.Second,
		WebhookPolicy{AllowedHosts: []string{"other.example.test"}},
	); err == nil {
		t.Fatal("accepted destination outside allowlist")
	}
}

func TestWebhookSinkDoesNotInheritEnvironmentProxy(t *testing.T) {
	const unreachableProxy = "http://127.0.0.1:1"
	t.Setenv("HTTPS_PROXY", unreachableProxy)
	t.Setenv("HTTP_PROXY", unreachableProxy)
	t.Setenv("ALL_PROXY", unreachableProxy)
	t.Setenv("NO_PROXY", "unrelated.example.test")

	var received bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		received = true
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink, err := NewWebhookSinkWithPolicy(
		server.URL, nil, "", time.Second,
		WebhookPolicy{AllowedHosts: []string{"127.0.0.1"}, AllowPrivateNetworks: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := sink.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", sink.client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("hardened webhook transport inherited proxy configuration")
	}
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if err := sink.Handle(context.Background(), Event{Type: "run.started"}); err != nil {
		t.Fatalf("direct webhook delivery failed with ambient proxies set: %v", err)
	}
	if !received {
		t.Fatal("webhook request did not reach the direct destination")
	}
}

func TestSecureWebhookDialerPinsAndVerifiesConnectedPeer(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "203.0.113.10:443" {
			t.Fatalf("dialer did not pin the verified IP literal: %s", address)
		}
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return client, nil
	}
	_, err := secureWebhookDialerWith(false, lookup, dial)(
		context.Background(), "tcp", "events.example.test:443",
	)
	if err == nil || !strings.Contains(err.Error(), "does not match verified address") {
		t.Fatalf("connected peer mismatch was not rejected: %v", err)
	}
}

func TestWebhookSinkRefusesRedirectAtFinalHTTPClient(t *testing.T) {
	var redirectReached atomic.Bool
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		redirectReached.Store(true)
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer redirectTarget.Close()

	var sourceReached atomic.Bool
	redirectSource := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sourceReached.Store(true)
		http.Redirect(writer, request, redirectTarget.URL, http.StatusFound)
	}))
	defer redirectSource.Close()

	sink, err := NewWebhookSinkWithPolicy(
		redirectSource.URL, nil, "", time.Second,
		WebhookPolicy{AllowedHosts: []string{"127.0.0.1"}, AllowPrivateNetworks: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	transport := sink.client.Transport.(*http.Transport)
	transport.TLSClientConfig = redirectSource.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	err = sink.Handle(context.Background(), Event{Type: "run.started"})
	if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect was not rejected by the final HTTP client: %v", err)
	}
	if !sourceReached.Load() {
		t.Fatal("redirect source was not reached")
	}
	if redirectReached.Load() {
		t.Fatal("redirect destination received a request")
	}
}

func TestSecureWebhookDialerRejectsMixedPublicAndPrivateDNSAnswersBeforeDial(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("127.0.0.1")},
		}, nil
	}
	var dialed atomic.Bool
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, nil
	}
	_, err := secureWebhookDialerWith(false, lookup, dial)(
		context.Background(), "tcp", "events.example.test:443",
	)
	if err == nil || !strings.Contains(err.Error(), "private or local address") {
		t.Fatalf("mixed DNS answer set was accepted: %v", err)
	}
	if dialed.Load() {
		t.Fatal("dial occurred before the complete DNS answer set was validated")
	}
}

func TestWebhookHostAndIPAddressNormalization(t *testing.T) {
	if !hostAllowed("EXAMPLE.COM.", []string{"example.com"}) {
		t.Fatal("equivalent case and trailing-dot hostname was not allowlisted")
	}
	if hostAllowed("example.com.evil", []string{"example.com"}) {
		t.Fatal("hostname suffix escaped the exact allowlist")
	}
	if !isPrivateDestination(net.ParseIP("::ffff:127.0.0.1")) {
		t.Fatal("IPv4-mapped IPv6 loopback was not classified as private")
	}
	if isPrivateDestination(net.ParseIP("::ffff:203.0.113.10")) {
		t.Fatal("IPv4-mapped public documentation address was classified as private")
	}
}

func TestSyslogSinkUDP(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sink, err := NewSyslogSink("udp", listener.LocalAddr().String(), "collector-test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Handle(context.Background(), Event{Type: "device.completed"}); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 2048)
	count, _, err := listener.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message := string(buffer[:count])
	if !strings.Contains(message, "collector-test") || !strings.Contains(message, `"type":"device.completed"`) {
		t.Fatalf("unexpected syslog message: %s", message)
	}
}
