package monitorsetup

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
	"golang.org/x/crypto/ssh"
)

// hostKeyFetchTimeout bounds how long PromptHostKeyMismatch waits for the
// independent key-fetch dial (fetchKey) to respond.
const hostKeyFetchTimeout = 10 * time.Second

// PromptHostKeyMismatch handles a genuine SSH host-key mismatch (see
// hostkey.ClassifyConnectError) with its own explicit, high-friction
// confirmation flow — deliberately never folded into the routine "Retry
// credentials?" prompt (promptRetryConnection in xrmonitor/junosmonitor),
// because this has nothing to do with credentials: the device's SSH host
// key no longer matches what's saved in known_hosts, which can mean the
// device was reimaged/replaced, or it can mean an active MITM. Silently
// offering this as a routine "retry, y/N" would make the tool a MITM's best
// friend, so:
//   - it requires typing the literal word REPLACE, not just "y", to even
//     look at the currently presented key
//   - it fetches that key independently (fetchKey — hostkey.FetchPresentedKey
//     in production, injected here so tests never need a real network dial)
//     rather than trusting anything about the original failed connection
//   - it shows both the old and newly fetched fingerprints and asks a
//     second, separate y/N before writing anything to disk
//
// Returns true only once known_hosts has actually been rewritten, telling
// the caller it's safe to immediately retry the connection with the same
// credentials: a host-key mismatch happens during the transport handshake,
// before authentication, so the credentials were never actually tested, and
// the caller must not invalidate or re-prompt for them because of this.
func PromptHostKeyMismatch(reader *bufio.Reader, mismatch *hostkey.Mismatch, fetchKey func(host string, timeout time.Duration) (ssh.PublicKey, error)) bool {
	fmt.Fprintf(os.Stderr, "\n*** SSH HOST KEY MISMATCH for %s ***\n", mismatch.Host)
	fmt.Fprintf(os.Stderr, "The key saved in %s no longer matches what %s just presented.\n", mismatch.File, mismatch.Host)
	fmt.Fprintln(os.Stderr, "This can mean the device was reimaged or replaced — or it can mean someone is intercepting this connection. Verify the device's real key out-of-band (console, vendor docs, change record) before continuing.")
	for _, old := range mismatch.OldKeys {
		fmt.Fprintf(os.Stderr, "  saved key:     %s\n", hostkey.Fingerprint(old))
	}
	fmt.Fprint(os.Stderr, "Type REPLACE to fetch the key it's presenting right now and compare, or press Enter to abort: ")
	answer, err := reader.ReadString('\n')
	// A read error (including EOF) means this confirmation was never
	// cleanly given — never treat a truncated/interrupted read as REPLACE,
	// however its partial content happens to compare.
	if err != nil || strings.TrimSpace(answer) != "REPLACE" {
		fmt.Fprintln(os.Stderr, "not refreshing the host key; skipping this device.")
		return false
	}

	presented, err := fetchKey(mismatch.Host, hostKeyFetchTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch the currently presented key: %v\n", err)
		return false
	}
	fmt.Fprintf(os.Stderr, "  presented key: %s\n", hostkey.Fingerprint(presented))
	fmt.Fprintf(os.Stderr, "Trust this key and update %s? [y/N]: ", mismatch.File)
	answer, err = reader.ReadString('\n')
	trimmed := strings.ToLower(strings.TrimSpace(answer))
	if err != nil || (trimmed != "y" && trimmed != "yes") {
		fmt.Fprintln(os.Stderr, "not updating known_hosts; skipping this device.")
		return false
	}

	if err := hostkey.ReplaceEntry(mismatch, presented); err != nil {
		fmt.Fprintf(os.Stderr, "failed to update %s: %v\n", mismatch.File, err)
		return false
	}
	fmt.Fprintf(os.Stderr, "updated %s; retrying %s...\n", mismatch.File, mismatch.Host)
	return true
}
