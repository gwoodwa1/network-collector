package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	Command        []string
	TimeoutSeconds int
}

func NewProvider(config ProviderConfig, input io.Reader, output io.Writer) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(config.Type)) {
	case "", "env", "environment":
		return EnvironmentProvider{}, nil
	case "interactive", "prompt":
		return InteractiveProvider{Input: input, Output: output}, nil
	case "file":
		return NewFileProvider(config.File)
	case "command", "exec":
		if len(config.Command) == 0 || strings.TrimSpace(config.Command[0]) == "" {
			return nil, fmt.Errorf("credential command cannot be empty")
		}
		timeout := 30 * time.Second
		if config.TimeoutSeconds != 0 {
			if config.TimeoutSeconds < 1 || config.TimeoutSeconds > 300 {
				return nil, fmt.Errorf("credential command timeout_seconds must be between 1 and 300")
			}
			timeout = time.Duration(config.TimeoutSeconds) * time.Second
		}
		return CommandProvider{Command: append([]string(nil), config.Command...), Timeout: timeout}, nil
	default:
		return nil, fmt.Errorf("unsupported credential provider %q", config.Type)
	}
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

type CommandProvider struct {
	Command []string
	Timeout time.Duration
}

func (p CommandProvider) Resolve(ctx context.Context, target Target) (Credentials, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Command[0], p.Command[1:]...)
	cmd.Env = append(os.Environ(), "NET_TARGET_HOSTNAME="+target.Hostname, "NET_TARGET_IP="+target.IP, "NET_CREDENTIAL_PROFILE="+target.Profile)
	output, err := cmd.Output()
	if err != nil {
		return Credentials{}, fmt.Errorf("credential command failed: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(output, &c); err != nil {
		return Credentials{}, fmt.Errorf("credential command returned invalid JSON: %w", err)
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
