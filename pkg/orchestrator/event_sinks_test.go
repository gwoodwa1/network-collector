package orchestrator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookSink(t *testing.T) {
	var received string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		received = string(body)
		mac := hmac.New(sha256.New, []byte("secret"))
		_, _ = mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if request.Header.Get("X-Network-Collector-Signature") != want {
			t.Errorf("bad signature")
		}
		if request.Header.Get("X-Test") != "yes" {
			t.Errorf("missing custom header")
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sink, err := NewWebhookSink(server.URL, map[string]string{"X-Test": "yes"}, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Handle(context.Background(), Event{Type: "run.started"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(received, `"type":"run.started"`) {
		t.Fatalf("unexpected body: %s", received)
	}
}

func TestSyslogSinkUDP(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sink, err := NewSyslogSink("udp", listener.LocalAddr().String(), "collector-test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Handle(context.Background(), Event{Type: "device.completed"}); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 2048)
	count, _, err := listener.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message := string(buffer[:count])
	if !strings.Contains(message, "collector-test") || !strings.Contains(message, `"type":"device.completed"`) {
		t.Fatalf("unexpected syslog message: %s", message)
	}
}
