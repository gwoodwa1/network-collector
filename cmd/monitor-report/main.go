// Command monitor-report renders (or re-renders) the professional HTML
// interface report from an existing routing-monitor / xr-routing-monitor /
// junos-routing-monitor output folder, without touching whatever process is
// still writing into it.
//
// internal/monitorreport only ever reads *.jsonl tick files from the folder
// and writes the report file via an atomic write-then-rename
// (internal/secureartifact.WriteFile), so this is safe to run — repeatedly,
// from a second terminal or a watch loop — against a folder a live monitor
// process is still appending ticks into. It never signals, locks, or
// otherwise interferes with that process; it just plots whatever ticks have
// landed so far.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/monitorreport"
	"github.com/gwoodwa1/network-collector/internal/reporting"
)

// version is replaced by GoReleaser at build time.
var version = "dev"

func main() {
	var outputDir string
	var sinceFlag string
	var reportOutput, reportTitle, changeReference string
	var logoFolder, headerLogo, footerLogo string
	var showVersion bool
	flag.StringVar(&outputDir, "output-dir", "", "required: an existing run's output folder to read *.jsonl tick files from (e.g. artifacts/<devices-file-basename>)")
	flag.StringVar(&sinceFlag, "since", "", "RFC3339 timestamp; only plot ticks at or after this time. Default: every tick ever recorded in output-dir, which includes prior runs against the same --devices file since its .jsonl files are never truncated on re-run")
	flag.StringVar(&reportOutput, "report-output", "interface-traffic.html", "HTML report filename, written into output-dir")
	flag.StringVar(&reportTitle, "report-title", "Change Monitoring Report", "report title")
	flag.StringVar(&changeReference, "change-reference", "", "change/ticket reference shown in the report")
	flag.StringVar(&logoFolder, "logo-folder", "", "directory containing optional PNG report branding")
	flag.StringVar(&headerLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&footerLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Printf("monitor-report %s\n", version)
		return
	}
	if strings.TrimSpace(outputDir) == "" {
		fmt.Fprintln(os.Stderr, "-output-dir is required (an existing run's output folder)")
		os.Exit(1)
	}
	if err := reporting.ValidateBranding(reporting.Config{
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo,
	}); err != nil {
		slog.Error("invalid report branding", "error", err)
		os.Exit(1)
	}

	var since time.Time
	if trimmed := strings.TrimSpace(sinceFlag); trimmed != "" {
		parsed, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -since %q: %v (expected RFC3339, e.g. 2026-09-02T09:00:00Z)\n", trimmed, err)
			os.Exit(1)
		}
		since = parsed
	}

	reportPath, err := monitorreport.GenerateProfessionalInterfaceReport(outputDir, since, monitorreport.ProfessionalReportConfig{
		Output: reportOutput, Title: reportTitle, ChangeReference: changeReference,
		LogoFolder: logoFolder, HeaderLogo: headerLogo, FooterLogo: footerLogo, CompletedAt: time.Now(),
	})
	if err != nil {
		slog.Error("failed to write report", "output_dir", outputDir, "error", err)
		os.Exit(1)
	}
	if reportPath == "" {
		fmt.Fprintf(os.Stderr, "no interface samples found yet in %s\n", outputDir)
		return
	}
	fmt.Println(reportPath)
}
