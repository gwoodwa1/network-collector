package restconf

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExecuteAgainstTLSServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/restconf/data/openconfig-interfaces:interfaces" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			t.Errorf("unexpected basic auth %q/%q ok=%v", username, password, ok)
		}
		if r.Header.Get("Accept") != "application/yang-data+json" {
			t.Errorf("unexpected accept header %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/yang-data+json")
		_, _ = io.WriteString(w, `{"openconfig-interfaces:interfaces":{"interface":[]}}`)
	}))
	defer server.Close()

	strict := &RESTCONFClient{}
	if err := strict.Connect(server.URL, "admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Execute(http.MethodGet, "/restconf/data/openconfig-interfaces:interfaces"); err == nil {
		t.Fatal("self-signed TLS unexpectedly succeeded without WithSkipTLS")
	}

	client := &RESTCONFClient{}
	if err := client.Connect(server.URL+"/", "admin", "secret", WithSkipTLSVerification()); err != nil {
		t.Fatal(err)
	}
	output, err := client.Execute(http.MethodGet, "/restconf/data/openconfig-interfaces:interfaces")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, `"openconfig-interfaces:interfaces"`) {
		t.Fatalf("unexpected response: %s", output)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteReportsStatusAndInvalidJSON(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "status", status: http.StatusUnauthorized, body: "denied", want: "401 Unauthorized"},
		{name: "invalid-json", status: http.StatusOK, body: "not-json", want: "failed to unmarshal RESTCONF JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := &RESTCONFClient{}
			if err := client.Connect(server.URL, "admin", "secret", WithSkipTLSVerification()); err != nil {
				t.Fatal(err)
			}
			_, err := client.Execute(http.MethodGet, "restconf/data/test")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidationErrors(t *testing.T) {
	client := &RESTCONFClient{}
	if err := client.Connect("", "user", "pass"); err == nil {
		t.Fatal("empty base URL accepted")
	}
	if _, err := client.Execute(http.MethodGet, "data/test"); err == nil {
		t.Fatal("execute before connect accepted")
	}
	if err := client.Connect("http://router.example/restconf", "user", "pass"); err == nil {
		t.Fatal("plaintext RESTCONF accepted without explicit lab option")
	}
	if err := client.Connect("router.example/restconf", "user", "pass"); err == nil {
		t.Fatal("relative RESTCONF URL accepted")
	}
}

func TestDefaultsAndResponseLimit(t *testing.T) {
	client := &RESTCONFClient{}
	if err := client.Connect("https://router.example/restconf", "user", "pass"); err != nil {
		t.Fatal(err)
	}
	if client.client.Timeout != 30*time.Second {
		t.Fatalf("unexpected default timeout: %s", client.client.Timeout)
	}
	transport := client.client.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version is not TLS 1.2: %#x", transport.TLSClientConfig.MinVersion)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBytes+1))
	}))
	defer server.Close()
	limited := &RESTCONFClient{}
	if err := limited.Connect(server.URL, "user", "pass", WithSkipTLSVerification()); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Execute(http.MethodGet, "restconf/data"); err == nil ||
		!strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversized response was not rejected: %v", err)
	}
}
