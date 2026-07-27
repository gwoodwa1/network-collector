package credentials

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Credentials struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}
type Target struct{ Hostname, IP, Profile string }
type Provider interface {
	Resolve(context.Context, Target) (Credentials, error)
}
type ProviderConfig struct {
	Type, File     string
	TimeoutSeconds int
	Hashicorp      HashicorpConfig
	OnePassword    OnePasswordConfig
	CyberArk       CyberArkConfig
}
type HashicorpConfig struct {
	Address       string      `mapstructure:"address" yaml:"address"`
	Namespace     string      `mapstructure:"namespace" yaml:"namespace"`
	Mount         string      `mapstructure:"mount" yaml:"mount"`
	PathPrefix    string      `mapstructure:"path_prefix" yaml:"path_prefix"`
	UsernameField string      `mapstructure:"username_field" yaml:"username_field"`
	PasswordField string      `mapstructure:"password_field" yaml:"password_field"`
	CAFile        string      `mapstructure:"ca_file" yaml:"ca_file"`
	CertFile      string      `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile       string      `mapstructure:"key_file" yaml:"key_file"`
	RemovedBinary interface{} `mapstructure:"binary" yaml:"binary"`
}
type OnePasswordConfig struct {
	Account       string      `mapstructure:"account" yaml:"account"`
	Vault         string      `mapstructure:"vault" yaml:"vault"`
	ItemPrefix    string      `mapstructure:"item_prefix" yaml:"item_prefix"`
	UsernameField string      `mapstructure:"username_field" yaml:"username_field"`
	PasswordField string      `mapstructure:"password_field" yaml:"password_field"`
	RemovedBinary interface{} `mapstructure:"binary" yaml:"binary"`
}
type CyberArkConfig struct {
	URL          string `mapstructure:"url" yaml:"url"`
	AppID        string `mapstructure:"app_id" yaml:"app_id"`
	Safe         string `mapstructure:"safe" yaml:"safe"`
	ObjectPrefix string `mapstructure:"object_prefix" yaml:"object_prefix"`
	Folder       string `mapstructure:"folder" yaml:"folder"`
	Reason       string `mapstructure:"reason" yaml:"reason"`
	CAFile       string `mapstructure:"ca_file" yaml:"ca_file"`
	CertFile     string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile      string `mapstructure:"key_file" yaml:"key_file"`
}

func NewProvider(config ProviderConfig, input io.Reader, output io.Writer) (Provider, error) {
	if err := validateProviderTimeout(config.TimeoutSeconds); err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(config.Type)) {
	case "", "env", "environment":
		return EnvironmentProvider{}, nil
	case "interactive", "prompt":
		return InteractiveProvider{Input: input, Output: output}, nil
	case "file":
		return NewFileProvider(config.File)
	case "command", "exec":
		return nil, fmt.Errorf("credential command provider is unsupported: workbook-controlled process execution has been removed")
	case "hashicorp", "vault", "hashicorp-vault":
		return newHashicorpProvider(config.Hashicorp, providerTimeout(config.TimeoutSeconds))
	case "1password", "onepassword", "op":
		return newOnePasswordProvider(config.OnePassword, providerTimeout(config.TimeoutSeconds))
	case "cyberark", "cyberark-ccp", "ccp":
		return newCyberArkProvider(config.CyberArk, providerTimeout(config.TimeoutSeconds))
	default:
		return nil, fmt.Errorf("unsupported credential provider %q", config.Type)
	}
}

func providerTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func validateProviderTimeout(seconds int) error {
	if seconds < 0 || seconds > 300 {
		return fmt.Errorf("credential provider timeout_seconds must be between 1 and 300")
	}
	return nil
}

type EnvironmentProvider struct{}

func (EnvironmentProvider) Resolve(_ context.Context, target Target) (Credentials, error) {
	return validate(Credentials{Username: strings.TrimSpace(os.Getenv("NET_USER")), Password: strings.TrimSpace(os.Getenv("NET_PASSWORD"))}, target)
}

type InteractiveProvider struct {
	Input  io.Reader
	Output io.Writer
}

func (p InteractiveProvider) Resolve(_ context.Context, target Target) (Credentials, error) {
	u, pw, err := ResolveCredentials(true, p.Input, p.Output)
	if err != nil {
		return Credentials{}, err
	}
	return validate(Credentials{Username: u, Password: pw}, target)
}

type credentialFile struct {
	Default  Credentials            `yaml:"default"`
	Profiles map[string]Credentials `yaml:"profiles"`
}
type FileProvider struct{ data credentialFile }

func NewFileProvider(path string) (*FileProvider, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("credential file path cannot be empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat credential file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential file %q permissions must not allow group or other access", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	var data credentialFile
	if err := yaml.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("decode credential file: %w", err)
	}
	return &FileProvider{data: data}, nil
}
func (p *FileProvider) Resolve(_ context.Context, target Target) (Credentials, error) {
	c := p.data.Default
	if profile := strings.TrimSpace(target.Profile); profile != "" {
		var ok bool
		c, ok = p.data.Profiles[profile]
		if !ok {
			return Credentials{}, fmt.Errorf("credential profile %q not found for %s", profile, target.Hostname)
		}
	}
	return validate(c, target)
}

func validate(c Credentials, target Target) (Credentials, error) {
	c.Username = strings.TrimSpace(c.Username)
	if c.Username == "" || c.Password == "" {
		return Credentials{}, fmt.Errorf("credential provider returned empty username or password for %s", target.Hostname)
	}
	return c, nil
}
