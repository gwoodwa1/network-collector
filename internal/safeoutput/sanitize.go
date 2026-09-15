// Package safeoutput removes terminal controls and common credential forms
// from text before it reaches human-readable logs or reports.
package safeoutput

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(password|passwd|encrypted-password|secret|community|token|authentication-key|auth-key|md5-key|key-string)\b(\s+(?:[0579]\s+)?|\s*[:=]\s*)("(?:\\.|[^"\\])*"|'[^']*'|[^\s,;]+)`),
	regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)\b(\s*:\s*)(?:basic|bearer)\s+([^\s,;]+)`),
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?is)<(?:password|secret|community|token)(?:\s[^>]*)?>.*?</(?:password|secret|community|token)>`),
}

// Quoted fields also occur inside diagnostic prose, outside a JSON document.
var quotedSecret = regexp.MustCompile(`(?i)("(?:password|passwd|secret|community|token|access[_-]token|refresh[_-]token|api[_-]key|client[_-]secret|private[_-]key)"\s*:\s*)("(?:\\.|[^"\\])*"|[^\s,}]+)`)

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch key {
	case "password", "passwd", "encryptedpassword", "secret", "community", "token", "accesstoken", "refreshtoken", "apikey", "clientsecret", "privatekey", "authorization", "proxyauthorization", "authenticationkey", "authkey", "md5key", "keystring":
		return true
	}
	return false
}

func redactDocument(value interface{}) interface{} {
	switch node := value.(type) {
	case map[string]interface{}:
		for key, child := range node {
			if sensitiveKey(key) {
				node[key] = "[REDACTED]"
			} else {
				node[key] = redactDocument(child)
			}
		}
	case []interface{}:
		for i, child := range node {
			node[i] = redactDocument(child)
		}
	case string:
		return redactText(node)
	}
	return value
}

func redactText(value string) string {
	value = quotedSecret.ReplaceAllString(value, `${1}"[REDACTED]"`)
	for _, pattern := range sensitivePatterns {
		value = pattern.ReplaceAllString(value, "$1$2[REDACTED]")
	}
	return value
}

// Sanitize neutralises terminal escape/control sequences and redacts common
// credential representations while retaining enough surrounding text for
// diagnosis.
func Sanitize(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 && (r < 0x7f || r > 0x9f) {
			return r
		}
		return -1
	}, value)
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		var document interface{}
		if decoder.Decode(&document) == nil {
			var extra interface{}
			if decoder.Decode(&extra) == io.EOF {
				if encoded, err := json.Marshal(redactDocument(document)); err == nil {
					return string(encoded)
				}
			}
		}
	}
	return redactText(value)
}

type sanitizingWriter struct {
	destination io.Writer
}

// NewWriter returns a writer that applies Sanitize to each complete write
// before forwarding it. It is intended for line-oriented human output, where
// fmt, slog, and similar callers emit one complete record per write.
func NewWriter(destination io.Writer) io.Writer {
	return &sanitizingWriter{destination: destination}
}

func (writer *sanitizingWriter) Write(content []byte) (int, error) {
	sanitized := []byte(Sanitize(string(content)))
	written, err := writer.destination.Write(sanitized)
	if err != nil {
		return 0, err
	}
	if written != len(sanitized) {
		return 0, io.ErrShortWrite
	}
	return len(content), nil
}
