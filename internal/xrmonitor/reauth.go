package xrmonitor

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/gwoodwa1/network-collector/internal/monitorsetup"
)

// ReauthCoordinator re-establishes a device's SSH session with freshly
// prompted credentials after collectTick detects a TACACS command-
// authorization failure mid-session (the transport is fine, but the device
// is rejecting commands, so the session needs to be closed and reopened).
//
// sem is a size-1 buffered channel used as a cancellable mutex (see
// Reconnect), not a *sync.Mutex, specifically so a reconnect still queued
// waiting for its turn can be abandoned the moment ctx is cancelled
// (Ctrl+C), rather than leaving PollDevice's goroutine, and therefore
// main's wg.Wait(), hung on human input that may never come. A reconnect
// that has already started prompting is different: Reconnect itself can
// still return early on cancellation, but sem stays held by that in-flight
// attempt until its underlying connect call actually finishes — see
// Reconnect — so a queued reconnect can never start a second, concurrent
// prompt against the same reader/cache while an abandoned one might still
// be running. It's a channel rather than a pointer so cmd/routing-monitor
// can pass the same one to both this coordinator and internal/junosmonitor's:
// both platforms' device goroutines share one os.Stdin reader once
// concurrent polling starts, and without a shared semaphore a reconnect
// prompt from an XR device and one from a Junos device could interleave on
// the same terminal.
type ReauthCoordinator struct {
	sem        chan struct{}
	reader     *bufio.Reader
	cache      *monitorsetup.CredentialCache
	connect    connectFunc
	deviceType string
}

// NewReauthCoordinator builds a coordinator that reconnects via connect
// (normally ConnectDevice), reusing the same reader/cache/deviceType every
// device was onboarded with. sem must be a channel with capacity 1
// (typically make(chan struct{}, 1)), shared with any other
// ReauthCoordinator (of this or another platform's package) that prompts on
// the same terminal.
func NewReauthCoordinator(sem chan struct{}, reader *bufio.Reader, cache *monitorsetup.CredentialCache, connect connectFunc, deviceType string) *ReauthCoordinator {
	return &ReauthCoordinator{sem: sem, reader: reader, cache: cache, connect: connect, deviceType: deviceType}
}

// Reconnect opens a fresh SSH session for hostname, reusing ConnectDevice's
// existing credential-prompt flow (cached-passcode reuse offer, username
// defaulted to the last one entered, exactly one connection attempt with no
// retry — see ConnectDevice's doc comment; a reauth path must not loop, for
// the same RSA/ISE lockout reason ConnectDevice itself never retries).
//
// It acquires sem for the whole prompt-and-connect sequence so a concurrent
// reconnect from another device's polling goroutine can never interleave
// its prompt with this one on the shared terminal — but, unlike a plain
// Lock(), waiting for sem is cancellable via ctx: if the run is shutting
// down (Ctrl+C) while this device is queued behind another device's prompt,
// Reconnect returns ctx.Err() immediately instead of blocking shutdown on
// human input.
//
// Once sem is held, cancellation no longer releases it: the actual
// r.connect call runs in its own goroutine that keeps sem until connect
// truly returns (however long that takes — even indefinitely, if it's
// genuinely stuck on stdin), and Reconnect itself may return ctx.Err() well
// before that goroutine finishes. This is deliberate — sem exists to keep
// every access to the shared reader/cache serialized, and releasing it the
// moment Reconnect is abandoned would let a queued reconnect start a second,
// concurrent prompt/connect against that same reader/cache while the first
// one might still be running. If the abandoned goroutine eventually
// produces a connected client with no one left to claim it, Reconnect
// closes it in the background instead of leaking the SSH session.
func (r *ReauthCoordinator) Reconnect(ctx context.Context, hostname string) (sessionExecutor, error) {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// The select above can choose the acquire branch even when ctx is
	// already done (when both cases are ready, Go picks between them
	// pseudo-randomly) — recheck before actually prompting, so a reconnect
	// whose context died while queued never starts a fresh credential
	// prompt during shutdown.
	select {
	case <-ctx.Done():
		<-r.sem
		return nil, ctx.Err()
	default:
	}

	fmt.Fprintf(os.Stderr, "\nTACACS command-authorization failure detected on %s; SSH session must be restarted.\n", hostname)

	type connectResult struct {
		client sessionExecutor
		err    error
	}
	resultCh := make(chan connectResult, 1)
	go func() {
		defer func() { <-r.sem }()
		client, err := r.connect(r.reader, hostname, r.deviceType, r.cache)
		resultCh <- connectResult{client, err}
	}()

	select {
	case res := <-resultCh:
		return res.client, res.err
	case <-ctx.Done():
		// This call is abandoning the attempt, but the goroutine above (and
		// its hold on sem) keeps running until connect actually returns. If
		// it eventually succeeds, no caller is left to use that session —
		// drain the result here and close any client it produced rather
		// than leaking the connection.
		go func() {
			if res := <-resultCh; res.client != nil {
				if closeErr := res.client.Close(); closeErr != nil {
					slog.Warn("error closing an SSH session that connected after its TACACS reauth attempt was already cancelled", "hostname", hostname, "error", closeErr)
				}
			}
		}()
		return nil, ctx.Err()
	}
}

// reauthenticate closes session's stale client and swaps in a freshly
// reconnected one via reauth, returning whether the session is alive
// afterward (mirroring collectTick's sessionAlive semantics). A nil reauth
// (no coordinator configured), a failed reconnect, or ctx being cancelled
// while the reconnect was pending all report the session as dead, stopping
// polling for this device only — the same graceful-degradation behavior
// PollDevice already has for a hard connection failure.
func reauthenticate(ctx context.Context, session *DeviceSession, reauth *ReauthCoordinator) bool {
	if reauth == nil {
		slog.Error("no reauth coordinator configured; stopping polling for this device", "hostname", session.hostname)
		return false
	}
	newClient, err := reauth.Reconnect(ctx, session.hostname)
	if err != nil {
		if ctx.Err() != nil {
			slog.Warn("shutting down while a TACACS reauthentication prompt was pending; stopping polling for this device", "hostname", session.hostname)
		} else {
			slog.Error("failed to restart SSH session after TACACS authorization failure; stopping polling for this device", "hostname", session.hostname, "error", err)
		}
		return false
	}
	if err := session.client.Close(); err != nil {
		slog.Warn("error closing stale session after reauth", "hostname", session.hostname, "error", err)
	}
	session.client = newClient
	fmt.Fprintf(os.Stderr, "reconnected to %s\n\n", session.hostname)
	slog.Info("SSH session restarted after TACACS authorization failure", "hostname", session.hostname)
	return true
}
