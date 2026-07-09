package credentials

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

const passwordMask = "********"

// ResolveCredentials returns username/password using environment variables by default,
// or prompts interactively when requested.
func ResolveCredentials(promptForCreds bool, input io.Reader, output io.Writer) (string, string, error) {
	return resolveCredentials(promptForCreds, input, nil, output)
}

// ResolveCredentialsWithTerminal behaves like ResolveCredentials, but lets the
// caller supply the *os.File to check/read from for terminal echo-suppressed
// password entry (term.IsTerminal/term.ReadPassword need a real file
// descriptor), separately from input, the io.Reader used for buffered line
// reads. This is for callers that keep one long-lived *bufio.Reader across
// many sequential prompts sharing the same underlying terminal: passing that
// *bufio.Reader as input to ResolveCredentials would never satisfy its
// internal input.(*os.File) check, silently disabling password masking even
// at a real interactive terminal.
func ResolveCredentialsWithTerminal(promptForCreds bool, input io.Reader, terminal *os.File, output io.Writer) (string, string, error) {
	return resolveCredentials(promptForCreds, input, terminal, output)
}

func resolveCredentials(promptForCreds bool, input io.Reader, terminal *os.File, output io.Writer) (string, string, error) {
	username := strings.TrimSpace(os.Getenv("NET_USER"))
	password := strings.TrimSpace(os.Getenv("NET_PASSWORD"))

	if !promptForCreds {
		return username, password, nil
	}

	if input == nil {
		input = os.Stdin
	}
	if output == nil {
		output = os.Stderr
	}

	// Explicit interactive input overrides credentials inherited from the
	// environment. This makes the flag useful when switching accounts.
	username = ""
	password = ""

	terminalFile := terminal
	if terminalFile == nil {
		terminalFile, _ = input.(*os.File)
	}
	terminalInput := terminalFile != nil && term.IsTerminal(int(terminalFile.Fd()))
	if terminalInput {
		fmt.Fprint(output, "Username: ")
		if _, err := fmt.Fscanln(terminalFile, &username); err != nil {
			return "", "", fmt.Errorf("read username: %w", err)
		}

		fmt.Fprint(output, "Password: ")
		passwordBytes, err := term.ReadPassword(int(terminalFile.Fd()))
		if err != nil {
			fmt.Fprintln(output)
			return "", "", fmt.Errorf("read password: %w", err)
		}
		fmt.Fprintln(output, passwordMask)
		password = string(passwordBytes)
	} else {
		reader := bufio.NewReader(input)
		fmt.Fprint(output, "Username: ")
		var err error
		username, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("read username: %w", err)
		}
		if err == io.EOF && username == "" {
			return "", "", fmt.Errorf("read username: %w", io.EOF)
		}

		fmt.Fprint(output, "Password: ")
		password, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("read password: %w", err)
		}
		if err == io.EOF && password == "" {
			return "", "", fmt.Errorf("read password: %w", io.EOF)
		}
		fmt.Fprintln(output, passwordMask)
	}

	return strings.TrimSpace(username), strings.TrimRight(password, "\r\n"), nil
}
