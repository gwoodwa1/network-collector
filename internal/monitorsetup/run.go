package monitorsetup

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/safeoutput"
	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

// Run holds everything SetupRun prepares: the resolved output directory and
// change-window label, the open session log, and the writers that mirror
// terminal output to it. Callers still build their own platform-specific
// tick-status printer around StatusBaseWriter (each platform's status line
// format differs) — SetupRun only owns the parts that are identical across
// every caller.
type Run struct {
	OutputDir        string
	RunLabel         string
	StartedAt        time.Time
	SessionLogFile   *os.File
	HumanOutput      io.Writer // safeoutput-sanitized io.MultiWriter(os.Stderr, SessionLogFile); also installed as slog's default handler writer
	SnapshotOut      *SyncWriter
	StatusBaseWriter io.Writer // safeoutput-sanitized io.MultiWriter(os.Stdout, SessionLogFile); wrap in a platform's own tick-status printer
}

// SetupRun resolves the shared output-folder/session-log/writer setup every
// routing-monitor tool needs, identically: RunLabel is devicesFile's
// basename without extension (empty when onboarding is purely interactive),
// OutputDir is outputDirFlag/<RunLabel>, or outputDirFlag/<timestamp>-<pid>
// when RunLabel is empty (the PID guards against two such processes
// launched within the same second landing on an identical folder name).
// Re-running against the *same* devicesFile deliberately reuses the same
// folder every time — it's named for the change, not the run — so per-file
// timestamps inside it are what keep repeat runs from overwriting each
// other. It also installs the returned HumanOutput as slog's default
// handler writer, matching every caller's existing behavior.
func SetupRun(outputDirFlag, devicesFile string, startedAt time.Time) (*Run, error) {
	var runLabel string
	if trimmed := strings.TrimSpace(devicesFile); trimmed != "" {
		base := filepath.Base(trimmed)
		runLabel = strings.TrimSuffix(base, filepath.Ext(base))
	}

	changeDirName := runLabel
	if changeDirName == "" {
		changeDirName = fmt.Sprintf("%s-%d", startedAt.Format("20060102-150405"), os.Getpid())
	}
	outputDir := filepath.Join(outputDirFlag, changeDirName)
	if err := secureartifact.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	var sessionLogNameParts []string
	if runLabel != "" {
		sessionLogNameParts = append(sessionLogNameParts, runLabel)
	}
	sessionLogNameParts = append(sessionLogNameParts, startedAt.Format("20060102-150405"), "session.log")
	sessionLogPath := filepath.Join(outputDir, strings.Join(sessionLogNameParts, "-"))
	sessionLogFile, err := secureartifact.OpenFile(sessionLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return nil, fmt.Errorf("failed to open session log %s: %w", sessionLogPath, err)
	}

	humanOutput := safeoutput.NewWriter(io.MultiWriter(os.Stderr, sessionLogFile))
	slog.SetDefault(slog.New(slog.NewTextHandler(humanOutput, nil)))

	return &Run{
		OutputDir:        outputDir,
		RunLabel:         runLabel,
		StartedAt:        startedAt,
		SessionLogFile:   sessionLogFile,
		HumanOutput:      humanOutput,
		SnapshotOut:      NewSyncWriter(humanOutput),
		StatusBaseWriter: safeoutput.NewWriter(io.MultiWriter(os.Stdout, sessionLogFile)),
	}, nil
}
