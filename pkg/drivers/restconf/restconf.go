package restconf

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers"
)

// Option is a type-safe option for configuring RESTCONFClient
type Option func(*RESTCONFClient)

type RESTCONFClient struct {
	BaseURL        string
	Username       string
	Password       string
	TLSConfig      drivers.TLSConfig
	requestTimeout time.Duration
	client         *http.Client
}

func WithSkipTLS() Option {
	return func(r *RESTCONFClient) {
		if r != nil {
			r.TLSConfig.SkipVerify = true
			r.TLSConfig.Insecure = true
		}
	}
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(r *RESTCONFClient) {
		if r != nil && timeout > 0 {
			r.requestTimeout = timeout
		}
	}
}

func (r *RESTCONFClient) Connect(baseURL, username, password string, opts ...Option) error {
	if r == nil {
		return errors.New("RESTCONF client is nil")
	}
	if strings.TrimSpace(baseURL) == "" {
		return errors.New("baseURL is required")
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}

	r.BaseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	r.Username = username
	r.Password = password

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(r)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: r.TLSConfig.SkipVerify},
	}
	r.client = &http.Client{
		Transport: transport,
		Timeout:   r.requestTimeout,
	}
	return nil
}

func (r *RESTCONFClient) Execute(method, endpoint string) (string, error) {
	if r == nil {
		return "", errors.New("RESTCONF client is nil")
	}
	if r.client == nil {
		return "", errors.New("RESTCONF client is not connected")
	}
	method = strings.TrimSpace(method)
	endpoint = strings.TrimSpace(endpoint)
	if method == "" {
		return "", errors.New("method is required")
	}
	if endpoint == "" {
		return "", errors.New("endpoint is required")
	}

	fullURL, err := url.Parse(fmt.Sprintf("%s/%s", r.BaseURL, strings.TrimLeft(endpoint, "/")))
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	req, err := http.NewRequest(method, fullURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(r.Username, r.Password)
	req.Header.Add("Accept", "application/yang-data+json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status %s: %s", resp.Status, string(body))
	}

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w; body=%s", err, string(body))
	}

	output, err := json.MarshalIndent(jsonResponse, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(output), nil
}

func (r *RESTCONFClient) Close() error {
	return nil
}
