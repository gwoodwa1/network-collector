package drivers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type RESTCONFClient struct {
	BaseURL   string
	Username  string
	Password  string
	TLSConfig TLSConfig
	client    *http.Client
}

func (r *RESTCONFClient) Connect(baseURL, username, password string, opts ...Option) error {
	r.BaseURL = baseURL
	r.Username = username
	r.Password = password

	for _, opt := range opts {
		opt(r)
	}

	// Create an HTTP client with optional TLS skipping
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: r.TLSConfig.SkipVerify},
	}
	r.client = &http.Client{Transport: transport}
	return nil
}

func (r *RESTCONFClient) Execute(method, endpoint string) (string, error) {
	fullURL, err := url.Parse(fmt.Sprintf("%s/%s", r.BaseURL, endpoint))
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

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	output, err := json.MarshalIndent(jsonResponse, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(output), nil
}

func (r *RESTCONFClient) Close() error {
	// No resources to close for HTTP client
	return nil
}
