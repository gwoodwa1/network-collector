package junosmonitor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
	"github.com/pmezard/go-difflib/difflib"
)

// CaptureRunningConfig captures "show configuration" as a single raw text
// file named "<base>-running-config.txt", where <base> is the same
// "[<runLabel>-]<hostname>-<capture-timestamp>-<label>" (see
// snapshotFilenameBase) captureSnapshot uses — a separate file, but sharing
// captureSnapshot's naming convention and capturedAt so a before/after
// config pair for one hostname is identifiable alongside, without being
// mixed into, that same moment's route/BGP snapshot pair. Opt-in via
// --capture-running-config (see main.go): a full config is a heavier
// capture (one extra SSH round trip, a potentially large file) that not
// every change window needs. On success, a confirmation line is written to
// out, matching captureSnapshot's confirmation style.
func CaptureRunningConfig(session *DeviceSession, label, outputDir, runLabel string, capturedAt time.Time, out io.Writer) error {
	const cmd = "show configuration"
	output, err := session.client.Execute(cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}

	base := snapshotFilenameBase(runLabel, session.hostname, label, capturedAt)
	path := filepath.Join(outputDir, base+"-running-config.txt")
	header := fmt.Sprintf("# %s running-config for %s captured %s\n\n", label, session.hostname, capturedAt.Format(time.RFC3339))
	if err := secureartifact.WriteFile(path, []byte(header+output)); err != nil {
		return fmt.Errorf("write running-config: %w", err)
	}

	fmt.Fprintf(out, "%s-change running-config captured for %s (%s)\n", label, session.hostname, filepath.Base(path))
	return nil
}

// stripCaptureHeader removes the "# <label> running-config for <hostname>
// captured <timestamp>\n\n" header CaptureRunningConfig writes ahead of the
// actual config body, so RunConfigDiff compares only the device's real
// output. Without this, the before/after capture timestamps (and "before"
// vs "after" label) differ on every single run, so an otherwise byte-for-
// byte identical config would always report a spurious diff. Only strips a
// recognized "# ..." header followed by a blank line; content that doesn't
// start with "# " (e.g. a config with no header at all) is returned
// unchanged.
func stripCaptureHeader(content string) string {
	if !strings.HasPrefix(content, "# ") {
		return content
	}
	if idx := strings.Index(content, "\n\n"); idx != -1 {
		return content[idx+2:]
	}
	return content
}

// RunConfigDiff loads two captured running-config text files (see
// CaptureRunningConfig) and prints a unified line diff to out — config text
// is not meaningfully reducible to a by-key comparison the way route tables
// are (see snapshotdiff.go), so this is an ordinary ordered line diff via
// go-difflib. Only called from printAutoDiffAfterChange right after the
// after-change capture; there is no standalone CLI flag for it, unlike
// -diff-before/-diff-after for route snapshots — the automatic diff on
// Ctrl+C is the only workflow this needs.
func RunConfigDiff(beforePath, afterPath string, out io.Writer) error {
	beforeContent, err := os.ReadFile(beforePath)
	if err != nil {
		return fmt.Errorf("load before running-config: %w", err)
	}
	afterContent, err := os.ReadFile(afterPath)
	if err != nil {
		return fmt.Errorf("load after running-config: %w", err)
	}

	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(stripCaptureHeader(string(beforeContent))),
		B:        difflib.SplitLines(stripCaptureHeader(string(afterContent))),
		FromFile: filepath.Base(beforePath),
		ToFile:   filepath.Base(afterPath),
		Context:  3,
	}
	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return fmt.Errorf("compute running-config diff: %w", err)
	}

	if strings.TrimSpace(text) == "" {
		fmt.Fprintln(out, "running-config diff: no changes")
		return nil
	}
	fmt.Fprintln(out, "running-config diff:")
	fmt.Fprint(out, text)
	if !strings.HasSuffix(text, "\n") {
		fmt.Fprintln(out)
	}
	return nil
}
