package credentials

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHashicorpProviderUsesProfileAndKVV2Response(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "vault")
	script := `#!/bin/sh
set -eu
case "$*" in
  *"-mount=network devices/datacenter")
    printf '%s\n' '{"data":{"data":{"login":"vault-user","secret":"vault-pass"}}}'
    ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(helper, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(ProviderConfig{
		Type: "hashicorp",
		Hashicorp: HashicorpConfig{
			Address: "https://vault.example:8200",
			Mount:   "network", PathPrefix: "devices", UsernameField: "login",
			PasswordField: "secret", Binary: helper,
		},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Resolve(context.Background(), Target{Hostname: "core-01", Profile: "datacenter"})
	if err != nil || got.Username != "vault-user" || got.Password != "vault-pass" {
		t.Fatalf("unexpected credentials=%#v error=%v", got, err)
	}
}

func TestOnePasswordProviderUsesProfileItem(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "op")
	script := `#!/bin/sh
set -eu
case "$2" in
  "op://Network Automation/collector-datacenter/login") printf '%s\n' 'op-user' ;;
  "op://Network Automation/collector-datacenter/secret") printf '%s\n' 'op-pass' ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(helper, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(ProviderConfig{
		Type: "1password",
		OnePassword: OnePasswordConfig{
			Vault: "Network Automation", ItemPrefix: "collector-",
			UsernameField: "login", PasswordField: "secret", Binary: helper,
		},
		TimeoutSeconds: 5,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Resolve(context.Background(), Target{Hostname: "core-01", Profile: "datacenter"})
	if err != nil || got.Username != "op-user" || got.Password != "op-pass" {
		t.Fatalf("unexpected credentials=%#v error=%v", got, err)
	}
}

func TestCyberArkProviderBuildsExactCCPQuery(t *testing.T) {
	var receivedQuery string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected request: method=%s accept=%q", request.Method, request.Header.Get("Accept"))
		}
		if request.URL.Query().Get("AppID") != "NetworkCollector" || request.URL.Query().Get("QueryFormat") != "Exact" || request.URL.Query().Get("Reason") != "change window" {
			t.Errorf("unexpected query values: %v", request.URL.Query())
		}
		receivedQuery = request.URL.Query().Get("Query")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"UserName":"cyberark-user","Content":"cyberark-pass"}`)),
			Header:     make(http.Header),
		}, nil
	})}
	provider := &CyberArkProvider{
		Config: CyberArkConfig{
			URL: "https://ccp.example/AIMWebService/api/Accounts", AppID: "NetworkCollector", Safe: "Network-Automation",
			ObjectPrefix: "collector-", Folder: "Root", Reason: "change window",
		},
		Client: client,
	}
	got, err := provider.Resolve(context.Background(), Target{Hostname: "core-01", Profile: "datacenter"})
	if err != nil || got.Username != "cyberark-user" || got.Password != "cyberark-pass" {
		t.Fatalf("unexpected credentials=%#v error=%v", got, err)
	}
	if receivedQuery != "Safe=Network-Automation;Object=collector-datacenter;Folder=Root" {
		t.Fatalf("unexpected CCP query %q", receivedQuery)
	}
}

func TestEnterpriseProviderEnvironmentFallbackAndYAMLPrecedence(t *testing.T) {
	t.Setenv("VAULT_ADDR", "https://environment-vault.example:8200")
	t.Setenv("VAULT_KV_MOUNT", "environment-mount")
	t.Setenv("VAULT_KV_PREFIX", "environment-prefix")
	provider, err := newHashicorpProvider(HashicorpConfig{
		Mount: "yaml-mount", PathPrefix: "yaml-prefix",
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Config.Mount != "yaml-mount" || provider.Config.PathPrefix != "yaml-prefix" {
		t.Fatalf("YAML values did not take precedence: %#v", provider.Config)
	}

	t.Setenv("OP_VAULT", "Environment Vault")
	onePassword, err := newOnePasswordProvider(OnePasswordConfig{}, 5*time.Second)
	if err != nil || onePassword.Config.Vault != "Environment Vault" {
		t.Fatalf("1Password environment fallback failed: provider=%#v error=%v", onePassword, err)
	}
}

func TestCyberArkProviderRequiresHTTPSAndCertificatePair(t *testing.T) {
	base := CyberArkConfig{URL: "http://ccp.example/AIMWebService/api/Accounts", AppID: "app", Safe: "safe"}
	if _, err := newCyberArkProvider(base, time.Second); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
	base.URL = "https://ccp.example/AIMWebService/api/Accounts"
	base.CertFile = "client.pem"
	if _, err := newCyberArkProvider(base, time.Second); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("expected certificate pair validation error, got %v", err)
	}
	base.CertFile = ""
	base.Safe = "safe;Object=other"
	if _, err := newCyberArkProvider(base, time.Second); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("expected exact-query safety error, got %v", err)
	}
}

func TestHashicorpProviderRequiresHTTPSAddress(t *testing.T) {
	_, err := newHashicorpProvider(HashicorpConfig{
		Address: "http://vault.example:8200", Mount: "network", PathPrefix: "devices",
	}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS address validation error, got %v", err)
	}
}

func TestCredentialSelectorRejectsPathAndQueryInjection(t *testing.T) {
	for _, profile := range []string{"../admin", `group\admin`, "name;Safe=other", "item?query"} {
		if _, err := credentialSelector(Target{Hostname: "core-01", Profile: profile}); err == nil {
			t.Fatalf("accepted unsafe credential selector %q", profile)
		}
	}
}
