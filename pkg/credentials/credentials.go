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

	inputFile, terminalInput := input.(*os.File)
	terminalInput = terminalInput && term.IsTerminal(int(inputFile.Fd()))
	if terminalInput {
		fmt.Fprint(output, "Username: ")
		if _, err := fmt.Fscanln(inputFile, &username); err != nil {
			return "", "", fmt.Errorf("read username: %w", err)
		}

		fmt.Fprint(output, "Password: ")
		passwordBytes, err := term.ReadPassword(int(inputFile.Fd()))
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
