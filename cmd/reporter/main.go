package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/gwoodwa1/network-collector/internal/reporting"
)

func main() {
	var config reporting.Config
	flag.StringVar(&config.RunDir, "run-dir", "", "network-collector run directory")
	flag.StringVar(&config.SummaryFile, "summary", "results.json", "summary JSON filename or path")
	flag.StringVar(&config.EventsFile, "events", "events.jsonl", "lifecycle JSONL filename or path")
	flag.StringVar(&config.Output, "output", "change-report.html", "output HTML filename or path")
	flag.StringVar(&config.Title, "title", "", "report title (defaults to playbook name)")
	flag.StringVar(&config.ChangeReference, "change-reference", "", "change or ticket reference")
	flag.StringVar(&config.LogoFolder, "logo-folder", "", "directory containing optional PNG branding")
	flag.StringVar(&config.HeaderLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&config.FooterLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.Parse()

	path, err := reporting.Generate(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(path)
}
