package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/gwoodwa1/network-collector/internal/reporting"
)

func main() {
	var config reporting.Config
	var validateTemplate bool
	flag.StringVar(&config.RunDir, "run-dir", "", "network-collector run directory")
	flag.StringVar(&config.SummaryFile, "summary", "results.json", "summary JSON filename or path")
	flag.StringVar(&config.EventsFile, "events", "events.jsonl", "lifecycle JSONL filename or path")
	flag.StringVar(&config.Output, "output", "change-report.html", "output HTML filename or path")
	flag.StringVar(&config.Template, "template", "", "report template: professional or compact (default professional)")
	flag.BoolVar(&validateTemplate, "validate-template", false, "validate the selected report template without reading a run bundle")
	flag.StringVar(&config.Title, "title", "", "report title (defaults to playbook name)")
	flag.StringVar(&config.ChangeReference, "change-reference", "", "change or ticket reference")
	flag.StringVar(&config.LogoFolder, "logo-folder", "", "directory containing optional PNG branding")
	flag.StringVar(&config.HeaderLogo, "header-logo", "", "PNG filename inside logo-folder (default: header.png when present)")
	flag.StringVar(&config.FooterLogo, "footer-logo", "", "PNG filename inside logo-folder (default: footer.png when present)")
	flag.Parse()

	if validateTemplate {
		if err := reporting.ValidateTemplate(config); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("report template valid (model %s)\n", reporting.ReportModelVersion)
		return
	}
	path, err := reporting.Generate(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(path)
}
