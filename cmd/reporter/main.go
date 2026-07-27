package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/gwoodwa1/network-collector/internal/reporting"
)

func main() {
	var config reporting.Config
	var format, pdfOutput, pdfBrowser string
	flag.StringVar(&config.RunDir, "run-dir", "", "network-collector run directory")
	flag.StringVar(&config.SummaryFile, "summary", "results.json", "summary JSON filename or path")
	flag.StringVar(&config.EventsFile, "events", "events.jsonl", "lifecycle JSONL filename or path")
	flag.StringVar(&config.Output, "output", "change-report.html", "output HTML filename or path")
	flag.StringVar(&config.Title, "title", "", "report title (defaults to playbook name)")
	flag.StringVar(&config.ChangeReference, "change-reference", "", "change or ticket reference")
	flag.StringVar(&config.LogoFolder, "logo-folder", "", "directory containing optional PNG branding")
	flag.StringVar(&config.HeaderLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&config.FooterLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.StringVar(&format, "format", "html", "output format: html, pdf, or both")
	flag.StringVar(&pdfOutput, "pdf-output", "", "PDF output filename or path")
	flag.StringVar(&pdfBrowser, "pdf-browser", "", "Chrome/Chromium executable for PDF output")
	flag.Parse()

	format = strings.ToLower(strings.TrimSpace(format))
	if format != "html" && format != "pdf" && format != "both" {
		log.Fatal("-format must be html, pdf, or both")
	}
	path, err := reporting.Generate(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(path)
	if format == "pdf" || format == "both" {
		if strings.TrimSpace(pdfOutput) == "" {
			pdfOutput = strings.TrimSuffix(path, filepath.Ext(path)) + ".pdf"
		}
		pdfPath, pdfErr := reporting.RenderPDF(path, pdfOutput, pdfBrowser)
		if pdfErr != nil {
			log.Fatal(pdfErr)
		}
		fmt.Println(pdfPath)
	}
}
