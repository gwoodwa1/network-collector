package main

import (
	"strings"
	"testing"
)

func TestParseXMLElementFindsNestedElementsAtAnyDepth(t *testing.T) {
	doc := `<rpc-reply><a><b><c>value</c></b></a></rpc-reply>`
	root, err := parseXMLElement(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if root.Name != "rpc-reply" {
		t.Fatalf("expected root rpc-reply, got %q", root.Name)
	}
	matches := root.find("c")
	if len(matches) != 1 || matches[0].text() != "value" {
		t.Fatalf("expected to find one <c>value</c> at any depth, got %+v", matches)
	}
}

func TestParseXMLElementInvalidXML(t *testing.T) {
	if _, err := parseXMLElement("not xml at all <unclosed"); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

func TestChildTextReturnsEmptyForMissingChild(t *testing.T) {
	root, err := parseXMLElement(`<rpc-reply><a>x</a></rpc-reply>`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := root.childText("missing"); got != "" {
		t.Fatalf("expected empty string for a missing child, got %q", got)
	}
}

func TestEncodeRecordsMatchesTextFSMConvention(t *testing.T) {
	encoded, err := encodeRecords("routes", []map[string]string{{"NETWORK": "192.0.2.0/24"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(encoded, `"routes"`) || !strings.Contains(encoded, `"NETWORK":"192.0.2.0/24"`) {
		t.Fatalf("unexpected encoded shape: %s", encoded)
	}
}

func TestDecodeNetconfOrRawFallsBackOnDecodeError(t *testing.T) {
	var errs []string
	raw := decodeNetconfOrRaw("<rpc-reply><broken", func(string) (string, error) {
		return "", errParseFailure
	}, &errs, "test section")
	if !strings.Contains(string(raw), `"raw"`) {
		t.Fatalf("expected a {\"raw\": ...} fallback, got %s", raw)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "test section") {
		t.Fatalf("expected the decode error to be recorded against the label, got %v", errs)
	}
}

func TestDecodeNetconfOrRawReturnsDecodedValueOnSuccess(t *testing.T) {
	var errs []string
	raw := decodeNetconfOrRaw("<rpc-reply/>", func(string) (string, error) {
		return `{"routes":[]}`, nil
	}, &errs, "test section")
	if string(raw) != `{"routes":[]}` {
		t.Fatalf("expected the decoded value to pass through unchanged, got %s", raw)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors recorded on success, got %v", errs)
	}
}

var errParseFailure = &staticError{"parse failed"}

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }
