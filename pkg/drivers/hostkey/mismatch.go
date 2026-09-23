package hostkey

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	scrapliutil "github.com/scrapli/scrapligo/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Mismatch describes a genuine SSH host-key mismatch: the device presented a
// key that does not match what's saved in known_hosts, as opposed to simply
// being unknown (no saved entry at all — an expected, low-stakes case on a
// first-ever connection, which ClassifyConnectError deliberately does not
// report as a Mismatch). A mismatch can mean the device was reimaged or
// replaced, or it can mean an active MITM — the caller is expected to make
// refreshing it a deliberate, high-friction operator decision, never
// automatic.
type Mismatch struct {
	// Host is exactly what the caller was trying to connect to (whatever
	// string it passed to the dial attempt that failed), used only for
	// display and for building the replacement known_hosts entry.
	Host string
	// File is the known_hosts file containing the stale entries.
	File string
	// StaleLines are the 1-indexed line numbers in File that no longer
	// match what the device presents, descending order (so callers can
	// delete them in place without earlier deletions shifting later line
	// numbers).
	StaleLines []int
	// OldKeys are the previously-trusted keys being replaced, one per
	// StaleLines entry in the same order, for display alongside the newly
	// fetched key so an operator can compare fingerprints.
	OldKeys []ssh.PublicKey
}

// KnownHostsFilesResolver locates every known_hosts file the real OS ssh
// subprocess actually consults for a connection, in the order it checks
// them. scrapligo's "system" transport (this repo's default, and the only
// one xrmonitor/junosmonitor ever use) resolves a single file via
// options.WithSSHKnownHostsFileSystem() and passes it as
// "-o UserKnownHostsFile=<that file>" — but that only overrides the *user*
// known_hosts directive. It never touches GlobalKnownHostsFile, so ssh's
// own default global files (/etc/ssh/ssh_known_hosts,
// /etc/ssh/ssh_known_hosts2 — confirmed locally via `ssh -G`) stay active
// and are checked in addition to the resolved user file. A stale entry that
// exists only in a global file must still be detected as a mismatch, not
// missed because only the user file was inspected. Exported so tests can
// point it at throwaway fixtures; production code must never reassign it.
var KnownHostsFilesResolver = resolveKnownHostsFiles

func resolveKnownHostsFiles() ([]string, error) {
	var files []string
	seen := make(map[string]bool)
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		if _, err := os.Stat(path); err != nil {
			return
		}
		seen[path] = true
		files = append(files, path)
	}

	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".ssh", "known_hosts"))
	}
	add("/etc/ssh/ssh_known_hosts")
	add("/etc/ssh/ssh_known_hosts2")

	if len(files) == 0 {
		return nil, fmt.Errorf("no known_hosts file found (checked ~/.ssh/known_hosts, /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2)")
	}
	return files, nil
}

// ClassifyConnectError inspects a failed connection's error for a real SSH
// host-key mismatch. The connect path in this repo always uses scrapligo's
// default "system" transport, which shells out to the real OS ssh binary —
// host-key verification is done entirely by that OpenSSH client, so a
// failure never surfaces as a *knownhosts.KeyError (that type is only ever
// constructed by scrapligo's alternate, unused "standard"/native-Go-crypto
// transport). Instead it surfaces as a plain wrapped error whose text
// contains "host key verification failed" — which by itself can't
// distinguish an unknown host from a genuine mismatch, since OpenSSH prints
// that same final line for both. So this independently re-derives the
// distinction by reading the real known_hosts files (via
// KnownHostsFilesResolver, every file the real ssh subprocess actually
// consults — user and global) and checking whether any line in any of them
// currently binds host to a key: zero bound entries anywhere means the host
// was never trusted in the first place (an unknown host, not a mismatch —
// left to the caller's normal failure handling), one or more bound entries
// in a single file means a mismatch, built from the first file (in
// resolver-order: user file, then global files) that has any.
func ClassifyConnectError(host string, err error) *Mismatch {
	if !looksLikeHostKeyVerificationFailure(err) {
		return nil
	}

	files, ferr := KnownHostsFilesResolver()
	if ferr != nil {
		return nil // can't independently verify; fall through to generic handling
	}

	for _, file := range files {
		lines, keys, ferr := findBoundEntries(file, host)
		if ferr != nil || len(lines) == 0 {
			continue
		}
		m := &Mismatch{Host: host, File: file, StaleLines: lines, OldKeys: keys}
		// Descending order so ReplaceEntry can delete by line number
		// without earlier deletions shifting the position of later ones.
		sort.Sort(sort.Reverse(byStaleLine(*m)))
		return m
	}
	return nil
}

// looksLikeHostKeyVerificationFailure reports whether err is the specific
// scrapligo error produced when the OS ssh subprocess prints "Host key
// verification failed." — checking both errors.Is (scrapliutil.ErrConnectionError
// also covers unrelated failures like timeouts or no-route-to-host, so the
// substring check is required too) and a case-insensitive substring match,
// tolerant of this repo's actual double-wrap chain
// ("failed to open driver: %w" wrapping scrapligo's own wrap).
func looksLikeHostKeyVerificationFailure(err error) bool {
	return errors.Is(err, scrapliutil.ErrConnectionError) &&
		strings.Contains(strings.ToLower(err.Error()), "host key verification failed")
}

// findBoundEntries scans file for every line currently bound to host,
// regardless of what key it holds — reusing lineBindsHostToKey by testing
// each line against its own parsed key. Deliberately does not duplicate
// ReplaceEntry's marker/wildcard/shared-host safety checks: a bound
// wildcard or @cert-authority line still correctly signals "an entry
// currently claims to trust this host" (reported as a genuine mismatch),
// and ReplaceEntry's existing, unchanged revalidation will still correctly
// refuse to auto-rewrite that specific line, forcing a manual edit.
func findBoundEntries(file, host string) (lines []int, keys []ssh.PublicKey, err error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	for i, raw := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		_, _, key, _, _, perr := ssh.ParseKnownHosts([]byte(raw + "\n"))
		if perr != nil {
			continue // comment/malformed — not a candidate entry
		}
		bound, berr := lineBindsHostToKey(raw, host, key)
		if berr != nil || !bound {
			continue
		}
		lines = append(lines, i+1)
		keys = append(keys, key)
	}
	return lines, keys, nil
}

type byStaleLine Mismatch

func (b byStaleLine) Len() int { return len(b.StaleLines) }
func (b byStaleLine) Swap(i, j int) {
	b.StaleLines[i], b.StaleLines[j] = b.StaleLines[j], b.StaleLines[i]
	b.OldKeys[i], b.OldKeys[j] = b.OldKeys[j], b.OldKeys[i]
}
func (b byStaleLine) Less(i, j int) bool {
	return b.StaleLines[i] < b.StaleLines[j]
}

// Fingerprint formats key the same way OpenSSH's own tooling does
// (SHA256:base64...), so an operator can compare it against an
// out-of-band record (console output, vendor documentation, a change
// ticket) rather than trusting this tool's word for it.
func Fingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// FetchPresentedKey independently dials host purely to capture the SSH host
// key it currently presents — the same technique ssh-keyscan uses. It never
// authenticates and never leaves a usable session open: the moment the key
// is captured, the handshake is deliberately failed and the connection is
// torn down. This is always a second, distinct connection from whatever
// attempt originally failed with a mismatch, never a reuse of it.
//
// timeout bounds the whole operation — TCP connect and the SSH handshake
// that follows — via an explicit conn deadline, not ssh.ClientConfig.Timeout
// (which only covers TCP establishment: a server that accepts a connection
// but withholds its SSH version banner would otherwise stall this
// indefinitely past timeout).
func FetchPresentedKey(host string, timeout time.Duration) (ssh.PublicKey, error) {
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "22")
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("fetch presented host key: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("fetch presented host key: %w", err)
	}

	var captured ssh.PublicKey
	errStop := errors.New("host key captured")
	cfg := &ssh.ClientConfig{
		User: "network-collector-hostkey-fetch",
		Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			// Deliberately abort the handshake right after capturing the
			// key — this call must never complete a real authenticated
			// session.
			return errStop
		},
	}

	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if captured != nil {
		return captured, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetch presented host key: %w", err)
	}
	return nil, fmt.Errorf("fetch presented host key: no key was presented")
}

// ReplaceEntry rewrites m.File: removes m.StaleLines (already in descending
// order — see ClassifyConnectError) and appends a fresh entry binding
// m.Host to newKey. The file is rewritten atomically (temp file + rename in
// the same directory) so a crash or concurrent read never observes a
// half-written known_hosts file, and the original file's permissions are
// preserved on the replacement.
//
// Before touching anything, every stale line is revalidated against the
// file's *current* content: m.StaleLines/m.OldKeys were captured back when
// the original connection failed, and everything since then — the operator
// typing REPLACE, the independent key fetch, the final y/N — is real wall
// time during which something else could have edited known_hosts. Deleting
// by a now-stale line number could silently remove an unrelated, still-valid
// entry that happens to now sit at that position — including one that
// merely happens to hold the *same key* for a *different* host, which a
// key-only comparison would miss. Each stale line must still parse as a
// plain (no @cert-authority/@revoked marker) entry naming exactly one
// literal host (no comma-separated sharing, no wildcard/pattern like
// "*.example" that could match more than m.Host) and must still, per the
// real knownhosts matcher (lineBindsHostToKey — this also correctly
// handles a hashed host field, which can't be compared as a plain string),
// bind m.Host to exactly the key recorded in m.OldKeys for that line — or
// the whole call is aborted with no write at all. Any of these cases needs
// a manual edit, not an automatic one.
func ReplaceEntry(m *Mismatch, newKey ssh.PublicKey) error {
	info, err := os.Stat(m.File)
	if err != nil {
		return fmt.Errorf("stat %s: %w", m.File, err)
	}
	original, err := os.ReadFile(m.File)
	if err != nil {
		return fmt.Errorf("read %s: %w", m.File, err)
	}

	lines := strings.Split(string(original), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // original ended in a trailing newline; Split's final "" isn't a real line
	}

	oldByLine := make(map[int]ssh.PublicKey, len(m.StaleLines))
	for i, line := range m.StaleLines {
		oldByLine[line] = m.OldKeys[i]
	}
	for _, lineNum := range m.StaleLines {
		if lineNum < 1 || lineNum > len(lines) {
			return fmt.Errorf("known_hosts changed since this mismatch was detected: line %d no longer exists in %s — start over from the current mismatch prompt", lineNum, m.File)
		}
		raw := lines[lineNum-1]
		marker, hosts, _, _, _, parseErr := ssh.ParseKnownHosts([]byte(raw + "\n"))
		if parseErr != nil {
			return fmt.Errorf("known_hosts changed since this mismatch was detected: line %d in %s no longer parses as the expected entry (%v) — start over from the current mismatch prompt", lineNum, m.File, parseErr)
		}
		if marker != "" {
			return fmt.Errorf("refusing to replace line %d in %s automatically: it has a %q marker, not a plain trusted-key entry — edit it manually", lineNum, m.File, marker)
		}
		if len(hosts) != 1 {
			return fmt.Errorf("refusing to replace line %d in %s automatically: it's shared by multiple hosts (%v), not just %s — replacing it would drop trust for the others; edit it manually", lineNum, m.File, hosts, m.Host)
		}
		if isWildcardHostPattern(hosts[0]) {
			return fmt.Errorf("refusing to replace line %d in %s automatically: its host field (%q) is a wildcard/pattern that could match more than just %s — replacing it could drop trust for other hosts matching the same pattern; edit it manually", lineNum, m.File, hosts[0], m.Host)
		}
		bound, err := lineBindsHostToKey(raw, m.Host, oldByLine[lineNum])
		if err != nil {
			return fmt.Errorf("known_hosts changed since this mismatch was detected: could not revalidate line %d in %s (%w) — start over from the current mismatch prompt", lineNum, m.File, err)
		}
		if !bound {
			return fmt.Errorf("known_hosts changed since this mismatch was detected: line %d in %s no longer binds %s to the key this refresh was about to replace — start over from the current mismatch prompt", lineNum, m.File, m.Host)
		}
	}

	stale := make(map[int]bool, len(m.StaleLines))
	for _, line := range m.StaleLines {
		stale[line] = true
	}
	kept := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		if !stale[i+1] { // known_hosts / KnownKey.Line is 1-indexed
			kept = append(kept, line)
		}
	}
	kept = append(kept, knownhosts.Line([]string{knownhosts.Normalize(m.Host)}, newKey))

	dir := filepath.Dir(m.File)
	tmp, err := os.CreateTemp(dir, ".known_hosts-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file next to %s: %w", m.File, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	content := strings.Join(kept, "\n") + "\n"
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, m.File); err != nil {
		return fmt.Errorf("replace %s: %w", m.File, err)
	}
	return nil
}

// isWildcardHostPattern reports whether a known_hosts host field is a
// pattern that could match more than one literal host — "*" or "?"
// wildcards, or "!"-prefixed negation, per the HOST PATTERNS section of the
// sshd(8) manual page — rather than one specific host. A hashed field
// (the "|1|salt|hash" form) is never a pattern: hashing only ever applies
// to one literal, already-known hostname.
func isWildcardHostPattern(host string) bool {
	if strings.HasPrefix(host, "|1|") {
		return false
	}
	return strings.ContainsAny(host, "*?") || strings.HasPrefix(host, "!")
}

// lineBindsHostToKey reports whether raw, taken alone as a one-line
// known_hosts file, binds host to exactly key — reusing the real
// knownhosts host-matching logic (via a synthetic single-entry file)
// instead of comparing the parsed host field as a plain string, which
// would silently accept two different failure modes: a hashed host field
// (an opaque "|1|salt|hash" token that never equals any plaintext
// hostname, hashed or not, by direct comparison) and an entry for an
// unrelated host that merely happens to hold the same key bytes as the one
// being replaced. If host doesn't match raw's pattern at all, or matches
// but under a different key, this returns false, not an error — both are
// legitimate "the file changed since this mismatch was detected" outcomes
// for the caller to report, not exceptional processing failures.
func lineBindsHostToKey(raw, host string, key ssh.PublicKey) (bool, error) {
	if key == nil {
		return false, nil
	}

	tmp, err := os.CreateTemp("", "known_hosts-verify-*")
	if err != nil {
		return false, fmt.Errorf("create temp verification file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(raw + "\n"); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write temp verification file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp verification file: %w", err)
	}

	callback, err := knownhosts.New(tmpPath)
	if err != nil {
		return false, fmt.Errorf("parse line for verification: %w", err)
	}

	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "22")
	}
	// address (first arg) takes precedence over remote whenever non-empty —
	// see knownhosts' own check() — so this placeholder just needs to be a
	// syntactically valid host:port for that function's own internal
	// SplitHostPort call to succeed; it's never actually used to match.
	placeholderRemote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}

	return callback(addr, placeholderRemote, key) == nil, nil
}
