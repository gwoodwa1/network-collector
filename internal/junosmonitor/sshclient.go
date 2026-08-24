package junosmonitor

import (
	"io"
	"regexp"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

// passcodePromptPattern matches a one-time-passcode challenge prompt (e.g.
// RSA SecurID's "Enter PASSCODE:"). scrapligo's built-in default password
// pattern only matches literal "password:" and never matches "passcode" —
// with that default, a connection attempt against a passcode-challenging
// device would just hang until the operation timeout instead of ever
// sending the passcode. It also still matches plain "password:" prompts, in
// case a device or profile ever falls back to that instead.
var passcodePromptPattern = regexp.MustCompile(`(?im)(password|passcode):\s?$`)

// ConnectJunosDevice opens exactly one SSH session via the shared
// pkg/drivers/ssh.Client, overriding only the password-prompt pattern (to
// also match a one-time-passcode challenge) and channel log (left disabled,
// unlike ssh.Client's stdout default, so raw device output never mixes into
// this tool's status-line stream — the scrapligo channel logger only ever
// captures data received from the device, never what this process sends, so
// this is about output cleanliness, not credential exposure either way).
// Everything else (timeouts, insecure host key handling) uses ssh.Client's
// own defaults. deviceType is normally "juniper_junos" (scrapligo's bundled
// Junos platform), overridable via --type.
func ConnectJunosDevice(host, username, password, deviceType string) (sessionExecutor, error) {
	client := ssh.NewClient(
		ssh.WithPasswordPattern(passcodePromptPattern),
		ssh.WithChannelLog(io.Discard),
	)
	if err := client.Connect(host, username, password, deviceType); err != nil {
		return nil, err
	}
	return client, nil
}

// sessionExecutor (main.go) is satisfied directly by *ssh.Client's
// Execute/Close methods, so a fake can still stand in for it in tests
// without a real SSH connection.
var _ sessionExecutor = (*ssh.Client)(nil)
