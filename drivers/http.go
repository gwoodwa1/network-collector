package drivers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type AristaHTTP struct {
	host      string
	username  string
	password  string
	session   *http.Client
	TLSConfig // Add this field to keep track of the skipTLS option
}

// Connect now accepts functional options as its last parameter
func (a *AristaHTTP) Connect(ip string, username string, password string, opts ...Option) error {
	// Apply the functional options
	a.host = ip
	a.username = username
	a.password = password
	for _, opt := range opts {
		opt(a)
	}

	// Create a custom transport based on the skipTLS option
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: a.TLSConfig.SkipVerify, // set by option
		},
	}

	// Use the custom transport in the HTTP client
	a.session = &http.Client{Transport: tr}

	return nil
}

func (a *AristaHTTP) Execute(cmd string) (string, error) {
	// Split the command string into individual commands
	var cmds []string
	if strings.Contains(cmd, ",") {
		cmds = strings.Split(cmd, ",")
		for i := range cmds {
			cmds[i] = strings.TrimSpace(cmds[i])
		}
	} else {
		cmds = []string{strings.TrimSpace(cmd)}
	}

	// Construct the eAPI request payload
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

	// Serialize the payload to JSON
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/command-api", a.host), bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(a.username, a.password)

	// Send the request
	resp, err := a.session.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("Error closing HTTP connection: %v", err)
		}
	}()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", errors.New(string(body))
	}

	return string(body), nil
}

// Close closes any idle connections maintained
// by the HTTP client transport
func (a *AristaHTTP) Close() error {

	// Check session and transport pointers are not nil
	if a.session != nil && a.session.Transport != nil {

		// Type assert the transport to the concrete *http.Transport type
		transport := a.session.Transport.(*http.Transport)

		// Call CloseIdleConnections() to close any idle connections
		transport.CloseIdleConnections()
	}

	return nil

}
