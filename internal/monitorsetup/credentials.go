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
func ResolveCredentials(reader *bufio.Reader, cache *CredentialCache) (username, password string, fresh bool, err error) {
	if cache.valid() {
		remaining := cache.Window - time.Since(cache.capturedAt)
		fmt.Fprintf(os.Stderr, "Reuse cached passcode for %s (~%s left in the cache window)? [Y/n]: ", cache.username, remaining.Round(time.Second))
		answer, _ := reader.ReadString('\n')
		declined := strings.EqualFold(strings.TrimSpace(answer), "n") || strings.EqualFold(strings.TrimSpace(answer), "no")
		if !declined {
			return cache.username, cache.password, false, nil
		}
	}
	username, password, err = credentials.ResolveCredentialsWithTerminal(true, reader, os.Stdin, os.Stderr)
	return username, password, true, err
}

// RecordFailure invalidates the cache after a failed connection attempt (a
// rejected passcode is never trustworthy to reuse), preserving Window.
func (c *CredentialCache) RecordFailure() {
	if c == nil {
		return
	}
	*c = CredentialCache{Window: c.Window}
}

// RecordSuccess updates the cache with a freshly-entered, successfully-used
// credential. Called only when fresh (from ResolveCredentials) is true —
// reuse of an already-cached credential must never reset the capture time,
// or reuse could be extended indefinitely past the real server-side window.
func (c *CredentialCache) RecordSuccess(username, password string) {
	if c == nil {
		return
	}
	*c = CredentialCache{username: username, password: password, capturedAt: time.Now(), Window: c.Window}
}
