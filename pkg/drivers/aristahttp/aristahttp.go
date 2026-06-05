package aristahttp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers"
)

// Option is a type-safe option for configuring AristaHTTP
type Option func(*AristaHTTP)

type AristaHTTP struct {
	host           string
	username       string
	password       string
	session        *http.Client
	requestTimeout time.Duration
	drivers.TLSConfig
}

func WithSkipTLS() Option {
	return func(a *AristaHTTP) {
		if a != nil {
			a.TLSConfig.SkipVerify = true
		}
	}
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(a *AristaHTTP) {
		if a != nil && timeout > 0 {
			a.requestTimeout = timeout
		}
	}
}

func (a *AristaHTTP) Connect(ip string, username string, password string, opts ...Option) error {
	if a == nil {
		return errors.New("AristaHTTP client is nil")
	}
	if strings.TrimSpace(ip) == "" {
		return errors.New("ip is required")
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}

	a.host = strings.TrimSpace(ip)
	a.username = username
	a.password = password
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(a)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: a.TLSConfig.SkipVerify},
	}

	a.session = &http.Client{
		Transport: transport,
		Timeout:   a.requestTimeout,
	}

	return nil
}

func (a *AristaHTTP) Execute(cmd string) (string, error) {
	if a == nil {
		return "", errors.New("AristaHTTP client is nil")
	}
	if a.session == nil {
		return "", errors.New("AristaHTTP client is not connected")
	}
	if strings.TrimSpace(cmd) == "" {
		return "", errors.New("command is required")
	}

	cmds := []string{strings.TrimSpace(cmd)}
	if strings.Contains(cmd, ",") {
		cmds = strings.Split(cmd, ",")
		for i := range cmds {
			cmds[i] = strings.TrimSpace(cmds[i])
		}
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "runCmds",
		"params": map[string]interface{}{
			"version": 1,
			"cmds":    cmds,
			"format":  "json",
		},
		"id": "EapiExplorer-1",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/command-api", a.host), bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(a.username, a.password)

	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

func (a *AristaHTTP) Close() error {
	if a == nil || a.session == nil || a.session.Transport == nil {
		return nil
	}

	transport, ok := a.session.Transport.(*http.Transport)
	if !ok || transport == nil {
		return nil
	}

	transport.CloseIdleConnections()
	return nil
}
