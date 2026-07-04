package restconf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if err := client.Connect(server.URL+"/", "admin", "secret", WithSkipTLS()); err != nil {
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
		{name: "invalid-json", status: http.StatusOK, body: "not-json", want: "failed to unmarshal JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := &RESTCONFClient{}
			if err := client.Connect(server.URL, "admin", "secret", WithSkipTLS()); err != nil {
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
}
