package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/term"
)

var rsaPasscodePromptPattern = regexp.MustCompile(`(?im)(password|passcode):\s?$`)

// rsaTokenAuth serializes human-in-the-loop prompts. The passcode entered at
// startup is deliberately cached by main for all initial device connections;
// this prompt is only used after code intentionally tears down a live session.
type rsaTokenAuth struct {
	mu       sync.Mutex
	username string
	input    *os.File
	output   io.Writer
}

func newRSATokenAuth(username string, input *os.File, output io.Writer) *rsaTokenAuth {
	return &rsaTokenAuth{username: username, input: input, output: output}
}

func (a *rsaTokenAuth) prompt() (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintf(a.output, "SSH session closed; enter a fresh RSA passcode for %s: ", a.username)
	if term.IsTerminal(int(a.input.Fd())) {
		value, err := term.ReadPassword(int(a.input.Fd()))
		fmt.Fprintln(a.output, "********")
		if err != nil {
			return "", "", fmt.Errorf("read RSA passcode: %w", err)
		}
		return a.username, string(value), nil
	}
	value, err := bufio.NewReader(a.input).ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("read RSA passcode: %w", err)
	}
	return a.username, strings.TrimRight(value, "\r\n"), nil
}
