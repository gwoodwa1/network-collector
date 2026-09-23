package monitorsetup

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/credentials"
)

// CredentialCache remembers the last successfully-used username/passcode so
// it can be offered for reuse on the next device within Window — a
// one-time passcode (RSA SecurID or similar) stays valid for a short time
// (commonly cached server-side by the auth backend), so the same code often
// authenticates a second device connected in quick succession. For a
// mixed-fleet run (cmd/routing-monitor), one shared cache means a passcode
// just entered for a Cisco IOS-XR device can be offered for reuse on the
// very next Juniper Junos device too. Reuse is always operator-confirmed,
// never silent, and Window should be set with a safety margin under the
// real server-side cache duration.
type CredentialCache struct {
	username   string
	password   string
	capturedAt time.Time
	Window     time.Duration

	// lastUsername is the username from the most recent successful
	// connection, offered as the default at every later prompt in the run —
	// see ResolveCredentials. Only RecordSuccess sets it, deliberately: it
	// must reflect a username that actually authenticated, not merely
	// whatever was typed. Earlier this eagerly captured whatever was just
	// typed regardless of outcome, which meant a passcode fat-fingered into
	// the username field (a real fat-finger case: typing a fresh RSA code
	// where the prompt still expected the username) got offered as the
	// default on every subsequent device too, cascading one mistake across
	// the rest of the run instead of confining it to the device it happened
	// on. Unlike username/password above, it survives RecordFailure: a
	// rejected or expired one-time passcode says nothing about whether the
	// previously-successful username is now wrong, so there's no reason to
	// make the operator retype it too.
	lastUsername string
}

// NewCredentialCache returns a cache with no captured credentials yet,
// offering reuse for window after each successful capture (0 disables
// reuse entirely).
func NewCredentialCache(window time.Duration) *CredentialCache {
	return &CredentialCache{Window: window}
}

func (c *CredentialCache) valid() bool {
	return c != nil && !c.capturedAt.IsZero() && c.Window > 0 && time.Since(c.capturedAt) < c.Window
}

// ResolveCredentials returns a username/password, offering reuse of a still
// valid cached passcode first. fresh reports whether a new prompt happened
// (as opposed to reuse), which the caller uses to decide whether to update
// the cache's capture time — reuse never extends the original window.
//
// retryUsername, when non-empty, is offered as the username prompt's default
// instead of the cache's own cross-device default (see knownUsername) —
// callers retrying the same device after a failed attempt (see
// xrmonitor/junosmonitor's connectWithRetry) pass the username from that
// immediately-preceding attempt, since it reflects this specific device's
// most recent attempt, not merely the last device that fully succeeded. It's
// still just a default: pressing Enter keeps it, typing a different
// username overrides it, exactly like the cache's own default.
func ResolveCredentials(reader *bufio.Reader, cache *CredentialCache, retryUsername string) (username, password string, fresh bool, err error) {
	if cache.valid() {
		remaining := cache.Window - time.Since(cache.capturedAt)
		fmt.Fprintf(os.Stderr, "Reuse cached passcode for %s (~%s left in the cache window)? [y/N]: ", cache.username, remaining.Round(time.Second))
		answer, readErr := reader.ReadString('\n')
		if readErr != nil {
			cache.RecordFailure()
			return "", "", false, fmt.Errorf("read passcode reuse consent: %w", readErr)
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			if cache.valid() {
				return cache.username, cache.password, false, nil
			}
			fmt.Fprintln(os.Stderr, "Cached passcode expired while awaiting consent; enter a fresh passcode.")
		case "", "n", "no":
		default:
			cache.RecordFailure()
			return "", "", false, fmt.Errorf("passcode reuse requires yes or no")
		}
		cache.RecordFailure()
	}
	defaultUsername := retryUsername
	if defaultUsername == "" {
		defaultUsername = cache.knownUsername()
	}
	username, password, err = credentials.ResolveCredentialsWithTerminal(true, reader, os.Stdin, os.Stderr, defaultUsername)
	return username, password, true, err
}

// knownUsername returns the username to offer as the prompt's default, or
// "" on a nil cache or before any device has ever been successfully
// authenticated against in this run.
func (c *CredentialCache) knownUsername() string {
	if c == nil {
		return ""
	}
	return c.lastUsername
}

// RecordFailure invalidates the cache after a failed connection attempt (a
// rejected passcode is never trustworthy to reuse), preserving Window and
// lastUsername — see the lastUsername field comment.
func (c *CredentialCache) RecordFailure() {
	if c == nil {
		return
	}
	*c = CredentialCache{Window: c.Window, lastUsername: c.lastUsername}
}

// RecordSuccess updates the cache with a freshly-entered, successfully-used
// credential. Called only when fresh (from ResolveCredentials) is true —
// reuse of an already-cached credential must never reset the capture time,
// or reuse could be extended indefinitely past the real server-side window.
func (c *CredentialCache) RecordSuccess(username, password string) {
	if c == nil {
		return
	}
	*c = CredentialCache{username: username, password: password, capturedAt: time.Now(), Window: c.Window, lastUsername: username}
}
