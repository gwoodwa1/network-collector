package credentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

type HashicorpProvider struct {
	Config  HashicorpConfig
	Timeout time.Duration
}

func newHashicorpProvider(config HashicorpConfig, timeout time.Duration) (*HashicorpProvider, error) {
	config.Address = configuredValue(config.Address, "VAULT_ADDR")
	config.Namespace = configuredValue(config.Namespace, "VAULT_NAMESPACE")
	config.Mount = configuredValue(config.Mount, "VAULT_KV_MOUNT")
	config.PathPrefix = configuredValue(config.PathPrefix, "VAULT_KV_PREFIX")
	config.UsernameField = defaultValue(config.UsernameField, "username")
	config.PasswordField = defaultValue(config.PasswordField, "password")
	config.CAFile = configuredValue(config.CAFile, "VAULT_CACERT")
	config.CertFile = configuredValue(config.CertFile, "VAULT_CLIENT_CERT")
	config.KeyFile = configuredValue(config.KeyFile, "VAULT_CLIENT_KEY")
	if config.RemovedBinary != nil {
		return nil, fmt.Errorf("hashicorp.binary is unsupported: executable selection is fixed to the approved vault CLI")
	}
	if config.Mount == "" {
		return nil, fmt.Errorf("hashicorp.mount or VAULT_KV_MOUNT is required")
	}
	if config.PathPrefix == "" {
		return nil, fmt.Errorf("hashicorp.path_prefix or VAULT_KV_PREFIX is required")
	}
	if config.Address != "" {
		address, err := url.Parse(config.Address)
		if err != nil || address.Scheme != "https" || address.Host == "" {
			return nil, fmt.Errorf("hashicorp.address must be an absolute HTTPS URL")
		}
	}
	if (config.CertFile == "") != (config.KeyFile == "") {
		return nil, fmt.Errorf("hashicorp.cert_file and hashicorp.key_file must be configured together")
	}
	return &HashicorpProvider{Config: config, Timeout: timeout}, nil
}

func (provider *HashicorpProvider) Resolve(ctx context.Context, target Target) (Credentials, error) {
	selector, err := credentialSelector(target)
	if err != nil {
		return Credentials{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, provider.Timeout)
	defer cancel()
	secretPath := cleanSecretPath(provider.Config.PathPrefix, selector)
	vaultBinary, err := exec.LookPath("vault")
	if err != nil {
		return Credentials{}, fmt.Errorf("approved vault CLI was not found in PATH: %w", err)
	}
	command := exec.CommandContext(
		ctx, vaultBinary, "kv", "get", "-format=json",
		"-mount="+provider.Config.Mount, secretPath,
	)
	command.Env = minimalEnvironment(
		[]string{"PATH", "HOME", "LANG", "LC_ALL", "VAULT_TOKEN", "VAULT_AGENT_ADDR"},
		map[string]string{
			"VAULT_ADDR":        provider.Config.Address,
			"VAULT_NAMESPACE":   provider.Config.Namespace,
			"VAULT_CACERT":      provider.Config.CAFile,
			"VAULT_CLIENT_CERT": provider.Config.CertFile,
			"VAULT_CLIENT_KEY":  provider.Config.KeyFile,
		},
	)
	output, err := command.Output()
	if err != nil {
		return Credentials{}, fmt.Errorf("HashiCorp Vault credential lookup failed: %w", err)
	}
	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return Credentials{}, fmt.Errorf("decode HashiCorp Vault response: %w", err)
	}
	data := response.Data
	if nested, ok := data["data"].(map[string]interface{}); ok {
		data = nested
	}
	return validate(Credentials{
		Username: stringField(data, provider.Config.UsernameField),
		Password: stringField(data, provider.Config.PasswordField),
	}, target)
}

type OnePasswordProvider struct {
	Config  OnePasswordConfig
	Timeout time.Duration
}

func newOnePasswordProvider(config OnePasswordConfig, timeout time.Duration) (*OnePasswordProvider, error) {
	config.Account = configuredValue(config.Account, "OP_ACCOUNT")
	config.Vault = configuredValue(config.Vault, "OP_VAULT")
	config.ItemPrefix = configuredValue(config.ItemPrefix, "OP_ITEM_PREFIX")
	config.UsernameField = defaultValue(config.UsernameField, "username")
	config.PasswordField = defaultValue(config.PasswordField, "password")
	if config.RemovedBinary != nil {
		return nil, fmt.Errorf("onepassword.binary is unsupported: executable selection is fixed to the approved op CLI")
	}
	if config.Vault == "" {
		return nil, fmt.Errorf("onepassword.vault or OP_VAULT is required")
	}
	return &OnePasswordProvider{Config: config, Timeout: timeout}, nil
}

func (provider *OnePasswordProvider) Resolve(ctx context.Context, target Target) (Credentials, error) {
	selector, err := credentialSelector(target)
	if err != nil {
		return Credentials{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, provider.Timeout)
	defer cancel()
	item := provider.Config.ItemPrefix + selector
	opBinary, err := exec.LookPath("op")
	if err != nil {
		return Credentials{}, fmt.Errorf("approved 1Password CLI was not found in PATH: %w", err)
	}
	read := func(field string) (string, error) {
		reference := fmt.Sprintf("op://%s/%s/%s", provider.Config.Vault, item, field)
		command := exec.CommandContext(ctx, opBinary, "read", reference)
		command.Env = minimalEnvironment(
			[]string{"PATH", "HOME", "LANG", "LC_ALL", "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN"},
			map[string]string{"OP_ACCOUNT": provider.Config.Account},
		)
		output, commandErr := command.Output()
		if commandErr != nil {
			return "", commandErr
		}
		return strings.TrimRight(string(output), "\r\n"), nil
	}
	username, err := read(provider.Config.UsernameField)
	if err != nil {
		return Credentials{}, fmt.Errorf("1Password username lookup failed: %w", err)
	}
	password, err := read(provider.Config.PasswordField)
	if err != nil {
		return Credentials{}, fmt.Errorf("1Password password lookup failed: %w", err)
	}
	return validate(Credentials{Username: username, Password: password}, target)
}

type CyberArkProvider struct {
	Config CyberArkConfig
	Client *http.Client
}

func newCyberArkProvider(config CyberArkConfig, timeout time.Duration) (*CyberArkProvider, error) {
	config.URL = configuredValue(config.URL, "CYBERARK_CCP_URL")
	config.AppID = configuredValue(config.AppID, "CYBERARK_APP_ID")
	config.Safe = configuredValue(config.Safe, "CYBERARK_SAFE")
	config.ObjectPrefix = configuredValue(config.ObjectPrefix, "CYBERARK_OBJECT_PREFIX")
	config.Folder = configuredValue(config.Folder, "CYBERARK_FOLDER")
	config.Reason = configuredValue(config.Reason, "CYBERARK_REASON")
	config.CAFile = configuredValue(config.CAFile, "CYBERARK_CA_FILE")
	config.CertFile = configuredValue(config.CertFile, "CYBERARK_CLIENT_CERT")
	config.KeyFile = configuredValue(config.KeyFile, "CYBERARK_CLIENT_KEY")
	if config.URL == "" || config.AppID == "" || config.Safe == "" {
		return nil, fmt.Errorf("cyberark.url, cyberark.app_id, and cyberark.safe are required (or their CYBERARK_* environment variables)")
	}
	parsed, err := url.Parse(config.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("cyberark.url must be an absolute HTTPS URL")
	}
	if (config.CertFile == "") != (config.KeyFile == "") {
		return nil, fmt.Errorf("cyberark.cert_file and cyberark.key_file must be configured together")
	}
	for field, value := range map[string]string{
		"safe": config.Safe, "object_prefix": config.ObjectPrefix, "folder": config.Folder,
	} {
		if strings.Contains(value, ";") || containsControl(value) {
			return nil, fmt.Errorf("cyberark.%s contains characters that are unsafe in an exact CCP query", field)
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CAFile != "" {
		pem, readErr := os.ReadFile(config.CAFile)
		if readErr != nil {
			return nil, fmt.Errorf("read CyberArk CA file: %w", readErr)
		}
		roots, rootErr := x509.SystemCertPool()
		if rootErr != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CyberArk CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if config.CertFile != "" {
		certificate, loadErr := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if loadErr != nil {
			return nil, fmt.Errorf("load CyberArk client certificate: %w", loadErr)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return &CyberArkProvider{
		Config: config,
		Client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: tlsConfig,
			},
			CheckRedirect: func(request *http.Request, previous []*http.Request) error {
				if request.URL.Scheme != "https" {
					return fmt.Errorf("CyberArk CCP refused non-HTTPS redirect")
				}
				if len(previous) >= 10 {
					return fmt.Errorf("CyberArk CCP stopped after 10 redirects")
				}
				return nil
			},
		},
	}, nil
}

func (provider *CyberArkProvider) Resolve(ctx context.Context, target Target) (Credentials, error) {
	selector, err := credentialSelector(target)
	if err != nil {
		return Credentials{}, err
	}
	endpoint, err := url.Parse(provider.Config.URL)
	if err != nil {
		return Credentials{}, err
	}
	queryParts := []string{"Safe=" + provider.Config.Safe, "Object=" + provider.Config.ObjectPrefix + selector}
	if provider.Config.Folder != "" {
		queryParts = append(queryParts, "Folder="+provider.Config.Folder)
	}
	query := endpoint.Query()
	query.Set("AppID", provider.Config.AppID)
	query.Set("Query", strings.Join(queryParts, ";"))
	query.Set("QueryFormat", "Exact")
	if provider.Config.Reason != "" {
		query.Set("Reason", provider.Config.Reason)
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Credentials{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := provider.Client.Do(request)
	if err != nil {
		return Credentials{}, fmt.Errorf("CyberArk CCP credential lookup failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Credentials{}, fmt.Errorf("CyberArk CCP credential lookup returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Credentials{}, fmt.Errorf("read CyberArk CCP response: %w", err)
	}
	var secret struct {
		Username string `json:"UserName"`
		Password string `json:"Content"`
	}
	if err := json.Unmarshal(content, &secret); err != nil {
		return Credentials{}, fmt.Errorf("decode CyberArk CCP response: %w", err)
	}
	return validate(Credentials{Username: secret.Username, Password: secret.Password}, target)
}

func credentialSelector(target Target) (string, error) {
	selector := strings.TrimSpace(target.Profile)
	if selector == "" {
		selector = strings.TrimSpace(target.Hostname)
	}
	if selector == "" {
		return "", fmt.Errorf("credential target requires a profile or hostname")
	}
	if strings.ContainsAny(selector, `/\;?#`) || containsControl(selector) {
		return "", fmt.Errorf("credential profile or hostname %q contains unsupported selector characters", selector)
	}
	return selector, nil
}

func configuredValue(configured, environment string) string {
	if value := strings.TrimSpace(configured); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(environment))
}

func defaultValue(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func stringField(values map[string]interface{}, name string) string {
	value, _ := values[name].(string)
	return value
}

func minimalEnvironment(allowed []string, overrides map[string]string) []string {
	values := make(map[string]string, len(allowed)+len(overrides))
	order := make([]string, 0, len(allowed)+len(overrides))
	for _, key := range allowed {
		if value := os.Getenv(key); value != "" {
			order = append(order, key)
			values[key] = value
		}
	}
	for key, value := range overrides {
		if value == "" {
			continue
		}
		if _, exists := values[key]; !exists {
			order = append(order, key)
		}
		values[key] = value
	}
	result := make([]string, 0, len(order))
	for _, key := range order {
		result = append(result, key+"="+values[key])
	}
	return result
}

func cleanSecretPath(prefix, selector string) string {
	return strings.Trim(prefix, "/") + "/" + selector
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
