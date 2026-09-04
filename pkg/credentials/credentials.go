package credentials

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ResolveCredentials returns username/password using environment variables by default,
// or prompts interactively when requested.
func ResolveCredentials(promptForCreds bool, input io.Reader, output io.Writer) (string, string, error) {
	return resolveCredentials(promptForCreds, input, nil, output, "")
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
//
// defaultUsername, when non-empty, is offered at the username prompt as
// "Username [defaultUsername]: " — pressing Enter keeps it. Callers polling
// several devices in one run use this so the operator only has to retype a
// fresh one-time passcode per device, not the username too.
func ResolveCredentialsWithTerminal(promptForCreds bool, input io.Reader, terminal *os.File, output io.Writer, defaultUsername string) (string, string, error) {
	return resolveCredentials(promptForCreds, input, terminal, output, defaultUsername)
}

func resolveCredentials(promptForCreds bool, input io.Reader, terminal *os.File, output io.Writer, defaultUsername string) (string, string, error) {
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

	usernamePrompt := "Username: "
	if defaultUsername != "" {
		usernamePrompt = fmt.Sprintf("Username [%s]: ", defaultUsername)
	}

	terminalFile := terminal
	if terminalFile == nil {
		terminalFile, _ = input.(*os.File)
	}
	// #nosec G115 -- os.File.Fd is an operating-system file descriptor and
	// x/term requires that descriptor as int.
	terminalInput := terminalFile != nil && term.IsTerminal(int(terminalFile.Fd()))
	if terminalInput {
		fmt.Fprint(output, usernamePrompt)
		line, err := readLineFromFile(terminalFile)
		if err != nil {
			return "", "", fmt.Errorf("read username: %w", err)
		}
		username = strings.TrimSpace(line)
		if username == "" {
			if defaultUsername == "" {
				return "", "", fmt.Errorf("read username: %w", io.EOF)
			}
			username = defaultUsername
		}

		fmt.Fprint(output, "Password (input hidden): ")
		// #nosec G115 -- see the descriptor conversion rationale above.
		passwordBytes, err := term.ReadPassword(int(terminalFile.Fd()))
		if err != nil {
			fmt.Fprintln(output)
			return "", "", fmt.Errorf("read password: %w", err)
		}
		fmt.Fprintln(output)
		password = string(passwordBytes)
	} else {
		reader := bufio.NewReader(input)
		fmt.Fprint(output, usernamePrompt)
		var err error
		username, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("read username: %w", err)
		}
		username = strings.TrimSpace(username)
		if username == "" {
			if err == io.EOF && defaultUsername == "" {
				return "", "", fmt.Errorf("read username: %w", io.EOF)
			}
			username = defaultUsername
		}

		fmt.Fprint(output, "Password (input hidden): ")
		password, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("read password: %w", err)
		}
		if err == io.EOF && password == "" {
			return "", "", fmt.Errorf("read password: %w", io.EOF)
		}
	}

	return strings.TrimSpace(username), strings.TrimRight(password, "\r\n"), nil
}

// readLineFromFile reads a single newline-terminated line directly from f,
// one byte at a time. It deliberately avoids wrapping f in a bufio.Reader:
// the caller immediately follows this with a raw term.ReadPassword on the
// same file descriptor, and a bufio.Reader could read ahead past the
// username's newline and swallow bytes the password read still needs.
func readLineFromFile(f *os.File) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := f.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return string(line), err
		}
	}
	return strings.TrimRight(string(line), "\r"), nil
}
