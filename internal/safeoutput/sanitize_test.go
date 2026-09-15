package safeoutput

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStructuredAndVendorSecretRedaction(t *testing.T) {
	inputs := []string{
		`{"password":"SYNTHETIC_CANARY with spaces","nested":[{"api_key":"SYNTHETIC_CANARY"}],"count":9007199254740993}`,
		`device returned {"password":"SYNTHETIC_CANARY"}`,
		`encrypted-password "SYNTHETIC_CANARY with spaces";`,
		`key-string 7 SYNTHETIC_CANARY`,
		`authentication-key SYNTHETIC_CANARY`,
	}
	for _, input := range inputs {
		var output bytes.Buffer
		if _, err := NewWriter(&output).Write([]byte(input)); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "SYNTHETIC_CANARY") {
			t.Fatalf("secret reached output: %q", output.String())
		}
		if json.Valid([]byte(input)) && (!json.Valid(output.Bytes()) || !strings.Contains(output.String(), "9007199254740993")) {
			t.Fatal("structured redaction damaged JSON or numeric precision")
		}
	}
}

func TestSanitizeRedactsSecretsAndNeutralisesTerminalControls(t *testing.T) {
	input := "password=NC_SECRET_CANARY\x1b]2;hostile-title\x07\n" +
		"Authorization: Bearer FOURTH_CANARY\n" +
		"<token>SECOND_CANARY</token>\n" +
		"-----BEGIN PRIVATE KEY-----\nTHIRD_CANARY\n-----END PRIVATE KEY-----"
	got := Sanitize(input)
	for _, secret := range []string{"NC_SECRET_CANARY", "SECOND_CANARY", "THIRD_CANARY", "FOURTH_CANARY"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sanitised output retained %q: %q", secret, got)
		}
	}
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\a') {
		t.Fatalf("sanitised output retained a terminal control: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("sanitised output did not retain a redaction marker: %q", got)
	}
}

func TestWriterReportsOriginalLengthAfterRemovingControls(t *testing.T) {
	var destination bytes.Buffer
	writer := NewWriter(&destination)
	input := []byte("password=WRITER_CANARY\x1b]2;title\x07\n")
	written, err := writer.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(input) {
		t.Fatalf("Write reported %d bytes, want original length %d", written, len(input))
	}
	if strings.Contains(destination.String(), "WRITER_CANARY") ||
		strings.ContainsRune(destination.String(), '\x1b') ||
		strings.ContainsRune(destination.String(), '\a') {
		t.Fatalf("writer forwarded unsafe output: %q", destination.String())
	}
}
