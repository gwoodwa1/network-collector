package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
	ansiBold  = "\x1b[1m"
	ansiReset = "\x1b[0m"
)

func prettyColourEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	// #nosec G115 -- os.File.Fd is an operating-system file descriptor and
	// x/term requires that descriptor as int.
	return ok && term.IsTerminal(int(f.Fd()))
}

func colour(text, code string, enabled bool) string {
	if !enabled {
		return text
	}
	return code + text + ansiReset
}

func renderPrettyResults(results []deviceRunResult, runFailed bool, duration time.Duration, colours bool) string {
	ordered := append([]deviceRunResult(nil), results...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })

	rows := make([][]string, 0, len(ordered))
	for _, result := range ordered {
		passed, failed, errors := 0, 0, 0
		for _, item := range result.aggregated {
			switch strings.ToLower(item.Result.Status) {
			case "pass":
				passed++
			case "fail":
				failed++
			case "error":
				errors++
			}
		}
		status := colour("✓ PASS", ansiGreen, colours)
		if result.failed {
			status = colour("✗ FAIL", ansiRed+ansiBold, colours)
		}
		rows = append(rows, []string{
			result.hostname, result.ip, status,
			fmt.Sprint(passed), fmt.Sprint(failed), fmt.Sprint(errors),
			fmt.Sprint(len(result.artifacts)), formatPrettyDuration(result.duration),
		})
	}

	headings := []string{"DEVICE", "ADDRESS", "STATUS", "PASS", "FAIL", "ERROR", "FILES", "DURATION"}
	widths := make([]int, len(headings))
	for i, heading := range headings {
		widths[i] = len(heading)
	}
	for _, row := range rows {
		for i, cell := range row {
			plain := stripANSI(cell)
			if len(plain) > widths[i] {
				widths[i] = len(plain)
			}
		}
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(colour("Network collection results", ansiBold, colours))
	b.WriteString("\n\n")
	writePrettyRow(&b, headings, widths)
	for i, width := range widths {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(strings.Repeat("─", width))
	}
	b.WriteByte('\n')
	for _, row := range rows {
		writePrettyRow(&b, row, widths)
	}

	overall := colour("✓ Run passed", ansiGreen+ansiBold, colours)
	if runFailed {
		overall = colour("✗ Run failed", ansiRed+ansiBold, colours)
	}
	fmt.Fprintf(&b, "\n%s  •  %d device(s)  •  %s\n", overall, len(ordered), formatPrettyDuration(duration))
	return b.String()
}

func writePrettyRow(b *strings.Builder, cells []string, widths []int) {
	for i, cell := range cells {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(cell)
		b.WriteString(strings.Repeat(" ", widths[i]-len(stripANSI(cell))))
	}
	b.WriteByte('\n')
}

func formatPrettyDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func stripANSI(s string) string {
	for _, code := range []string{ansiGreen, ansiRed, ansiBold, ansiReset} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}
