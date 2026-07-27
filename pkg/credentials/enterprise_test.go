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

func secureTestExecutable(t *testing.T, name, script string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "admin-bin")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(directory, 0755)
	})
	return path
}

func TestHashicorpProviderUsesProfileAndKVV2Response(t *testing.T) {
	script := `#!/bin/sh
set -eu
case "$*" in
  *"-mount=network devices/datacenter")
    printf '%s\n' '{"data":{"data":{"login":"vault-user","secret":"vault-pass"}}}'
    ;;
  *) exit 2 ;;
esac
`
	helper := secureTestExecutable(t, "vault", script)
	t.Setenv("NETWORK_COLLECTOR_VAULT_BINARY", helper)
	provider, err := NewProvider(ProviderConfig{
		Type: "hashicorp",
		Hashicorp: HashicorpConfig{
			Address: "https://vault.example:8200",
			Mount:   "network", PathPrefix: "devices", UsernameField: "login",
			PasswordField: "secret",
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
	script := `#!/bin/sh
set -eu
case "$2" in
  "op://Network Automation/collector-datacenter/login") printf '%s\n' 'op-user' ;;
  "op://Network Automation/collector-datacenter/secret") printf '%s\n' 'op-pass' ;;
  *) exit 2 ;;
esac
`
	helper := secureTestExecutable(t, "op", script)
	t.Setenv("NETWORK_COLLECTOR_ONEPASSWORD_BINARY", helper)
	provider, err := NewProvider(ProviderConfig{
		Type: "1password",
		OnePassword: OnePasswordConfig{
			Vault: "Network Automation", ItemPrefix: "collector-",
			UsernameField: "login", PasswordField: "secret",
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

func TestEnterpriseProvidersRejectWorkbookBinarySelection(t *testing.T) {
	_, err := NewProvider(ProviderConfig{
		Type: "hashicorp",
		Hashicorp: HashicorpConfig{
			Mount: "network", PathPrefix: "devices", RemovedBinary: "/bin/sh",
		},
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "administrator-controlled") {
		t.Fatalf("HashiCorp binary selection was not rejected: %v", err)
	}
	_, err = NewProvider(ProviderConfig{
		Type:        "1password",
		OnePassword: OnePasswordConfig{Vault: "Network Automation", RemovedBinary: "/bin/sh"},
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "administrator-controlled") {
		t.Fatalf("1Password binary selection was not rejected: %v", err)
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
	t.Setenv("NETWORK_COLLECTOR_VAULT_BINARY", secureTestExecutable(t, "vault", "#!/bin/sh\nexit 0\n"))
	t.Setenv("NETWORK_COLLECTOR_ONEPASSWORD_BINARY", secureTestExecutable(t, "op", "#!/bin/sh\nexit 0\n"))
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

func TestEnterpriseProvidersRequireSecureAbsoluteRuntimeBinaries(t *testing.T) {
	t.Setenv("NETWORK_COLLECTOR_VAULT_BINARY", "vault")
	_, err := newHashicorpProvider(HashicorpConfig{Mount: "network", PathPrefix: "devices"}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("relative Vault executable accepted: %v", err)
	}

	directory := t.TempDir()
	insecure := filepath.Join(directory, "vault")
	if err := os.WriteFile(insecure, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETWORK_COLLECTOR_VAULT_BINARY", insecure)
	_, err = newHashicorpProvider(HashicorpConfig{Mount: "network", PathPrefix: "devices"}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "parent directory is writable") {
		t.Fatalf("collector-writable executable directory accepted: %v", err)
	}

	target := secureTestExecutable(t, "vault-real", "#!/bin/sh\nexit 0\n")
	link := filepath.Join(t.TempDir(), "vault-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETWORK_COLLECTOR_VAULT_BINARY", link)
	_, err = newHashicorpProvider(HashicorpConfig{Mount: "network", PathPrefix: "devices"}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink Vault executable accepted: %v", err)
	}
}

func TestMinimalEnvironmentDoesNotInheritUnrelatedSecrets(t *testing.T) {
	t.Setenv("PATH", "/approved/bin")
	t.Setenv("HOME", "/approved/home")
	t.Setenv("NET_PASSWORD", "must-not-be-inherited")
	t.Setenv("CI_TOKEN", "must-not-be-inherited")
	t.Setenv("VAULT_TOKEN", "vault-token")

	got := strings.Join(minimalEnvironment(
		[]string{"PATH", "HOME", "VAULT_TOKEN"},
		map[string]string{"VAULT_ADDR": "https://vault.example"},
	), "\n")
	for _, expected := range []string{"PATH=/approved/bin", "HOME=/approved/home", "VAULT_TOKEN=vault-token", "VAULT_ADDR=https://vault.example"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("expected %q in minimal environment: %s", expected, got)
		}
	}
	for _, forbidden := range []string{"NET_PASSWORD", "CI_TOKEN", "must-not-be-inherited"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("minimal environment leaked %q: %s", forbidden, got)
		}
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

func TestCyberArkProviderRefusesAllRedirects(t *testing.T) {
	provider, err := newCyberArkProvider(CyberArkConfig{
		URL:   "https://ccp.example/AIMWebService/api/Accounts",
		AppID: "app", Safe: "safe",
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{
		"https://ccp.example/other",
		"https://other.example/credential",
		"http://ccp.example/insecure",
		"https://127.0.0.1/credential",
		"https://169.254.169.254/credential",
	} {
		request, requestErr := http.NewRequest(http.MethodGet, destination, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if redirectErr := provider.Client.CheckRedirect(request, nil); redirectErr != http.ErrUseLastResponse {
			t.Fatalf("redirect to %s was not refused: %v", destination, redirectErr)
		}
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
