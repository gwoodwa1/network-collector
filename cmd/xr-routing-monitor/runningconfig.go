package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pmezard/go-difflib/difflib"
)

// captureRunningConfig captures "show running-config" as a single raw text
// file named "<base>-running-config.txt", where <base> is the same
// "[<runLabel>-]<hostname>-<capture-timestamp>-<label>" (see
// snapshotFilenameBase) captureSnapshot uses — a separate file, but sharing
// captureSnapshot's naming convention and capturedAt so a before/after
// config pair for one hostname is identifiable alongside, without being
// mixed into, that same moment's BGP snapshot pair. Opt-in via
// --capture-running-config (see main.go): a full running-config is a
// heavier capture (one extra SSH round trip, a potentially large file) that
// not every change window needs. On success, a confirmation line is
// written to out, matching captureSnapshot's confirmation style.
func captureRunningConfig(session *deviceSession, label, outputDir, runLabel string, capturedAt time.Time, out io.Writer) error {
	const cmd = "show running-config"
	output, err := session.client.Execute(cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}

	base := snapshotFilenameBase(runLabel, session.hostname, label, capturedAt)
	path := filepath.Join(outputDir, base+"-running-config.txt")
	header := fmt.Sprintf("# %s running-config for %s captured %s\n\n", label, session.hostname, capturedAt.Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(header+output), 0o644); err != nil {
		return fmt.Errorf("write running-config: %w", err)
	}

	fmt.Fprintf(out, "%s-change running-config captured for %s (%s)\n", label, session.hostname, filepath.Base(path))
	return nil
}

// runConfigDiff loads two captured running-config text files (see
// captureRunningConfig) and prints a unified line diff to out — unlike the
// route-level snapshot diff (see snapshotdiff.go), config text is not
// meaningfully reducible to a by-key comparison, so this is an ordinary
// ordered line diff (via go-difflib, already an indirect dependency of this
// module through testify). Used by main's -diff-before-config/
// -diff-after-config flags, entirely offline.
func runConfigDiff(beforePath, afterPath string, out io.Writer) error {
	beforeContent, err := os.ReadFile(beforePath)
	if err != nil {
		return fmt.Errorf("load before running-config: %w", err)
	}
	afterContent, err := os.ReadFile(afterPath)
	if err != nil {
		return fmt.Errorf("load after running-config: %w", err)
	}

	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(beforeContent)),
		B:        difflib.SplitLines(string(afterContent)),
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
