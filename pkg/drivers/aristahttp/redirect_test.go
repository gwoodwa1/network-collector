package aristahttp

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRedirectsNeverReachAnotherRequest(t *testing.T) {
	var requests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer destination.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL, status)
			}))
			defer server.Close()
			client := &AristaHTTP{}
			if err := client.Connect(strings.TrimPrefix(server.URL, "https://"), "test-user", "synthetic-password"); err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client.session.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
			if _, err := client.Execute("show version"); err == nil {
				t.Fatal("redirect accepted")
			}
			if requests.Load() != 0 {
				t.Fatal("redirect reached destination")
			}
		})
	}
}
