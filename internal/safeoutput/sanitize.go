// Package safeoutput removes terminal controls and common credential forms
// from text before it reaches human-readable logs or reports.
package safeoutput

import (
	"io"
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(password|passwd|secret|community|token)\b(\s+(?:[0579]\s+)?|\s*[:=]\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)\b(\s*:\s*)(?:basic|bearer)\s+([^\s,;]+)`),
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?is)<(?:password|secret|community|token)(?:\s[^>]*)?>.*?</(?:password|secret|community|token)>`),
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
	for _, pattern := range sensitivePatterns {
		value = pattern.ReplaceAllString(value, "$1$2[REDACTED]")
	}
	return value
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
