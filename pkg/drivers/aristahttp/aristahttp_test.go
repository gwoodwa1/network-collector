package aristahttp

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tlsServerHost(server *httptest.Server) string { return strings.TrimPrefix(server.URL, "https://") }

func TestExecuteAgainstTLSServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/command-api" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			t.Errorf("unexpected basic auth %q/%q ok=%v", username, password, ok)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("invalid request JSON: %v", err)
		}
		params := payload["params"].(map[string]interface{})
		commands := params["cmds"].([]interface{})
		if len(commands) != 2 || commands[0] != "show version" || commands[1] != "show clock" {
			t.Errorf("unexpected commands: %+v", commands)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","result":[{"version":"test"}],"id":"EapiExplorer-1"}`)
	}))
	defer server.Close()

	strict := &AristaHTTP{}
	if err := strict.Connect(tlsServerHost(server), "admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Execute("show version"); err == nil {
		t.Fatal("self-signed TLS unexpectedly succeeded without WithSkipTLS")
	}

	client := &AristaHTTP{}
	if err := client.Connect(tlsServerHost(server), "admin", "secret", WithSkipTLSVerification()); err != nil {
		t.Fatal(err)
	}
	output, err := client.Execute("show version, show clock")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, `"version":"test"`) {
		t.Fatalf("unexpected response: %s", output)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteReportsHTTPStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "device unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := &AristaHTTP{}
	if err := client.Connect(tlsServerHost(server), "admin", "secret", WithSkipTLSVerification()); err != nil {
		t.Fatal(err)
	}
	_, err := client.Execute("show version")
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "device unavailable") {
		t.Fatalf("unexpected status error: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	client := &AristaHTTP{}
	if err := client.Connect("", "user", "pass"); err == nil {
		t.Fatal("empty host accepted")
	}
	if _, err := client.Execute("show version"); err == nil {
		t.Fatal("execute before connect accepted")
	}
}

func TestDefaultsAndResponseLimit(t *testing.T) {
	client := &AristaHTTP{}
	if err := client.Connect("router.example", "user", "pass"); err != nil {
		t.Fatal(err)
	}
	if client.session.Timeout != 30*time.Second {
		t.Fatalf("unexpected default timeout: %s", client.session.Timeout)
	}
	transport := client.session.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version is not TLS 1.2: %#x", transport.TLSClientConfig.MinVersion)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBytes+1))
	}))
	defer server.Close()
	limited := &AristaHTTP{}
	if err := limited.Connect(tlsServerHost(server), "user", "pass", WithSkipTLSVerification()); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Execute("show version"); err == nil ||
		!strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversized response was not rejected: %v", err)
	}
}
