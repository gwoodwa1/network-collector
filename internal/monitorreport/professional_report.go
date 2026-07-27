package monitorreport

import (
	"time"

	"github.com/gwoodwa1/network-collector/internal/reporting"
)

type ProfessionalReportConfig struct {
	Output          string
	Title           string
	ChangeReference string
	LogoFolder      string
	HeaderLogo      string
	FooterLogo      string
	CompletedAt     time.Time
}

func GenerateProfessionalInterfaceReport(outputDir string, since time.Time, config ProfessionalReportConfig) (string, error) {
	series, events, err := collectInterfaceSeries(outputDir, since)
	if err != nil || len(series) == 0 {
		return "", err
	}
	reportSeries := make([]reporting.MonitorSeries, 0, len(series))
	for _, item := range series {
		points := make([]reporting.MonitorPoint, 0, len(item.Points))
		for _, point := range item.Points {
			points = append(points, reporting.MonitorPoint{
				Timestamp: point.Timestamp, InputBPS: point.InputBPS, OutputBPS: point.OutputBPS,
			})
		}
		reportSeries = append(reportSeries, reporting.MonitorSeries{
			Hostname: item.Hostname, Interface: item.Interface, Points: points,
		})
	}
	reportEvents := make([]reporting.MonitorEvent, 0, len(events))
	for _, event := range events {
		reportEvents = append(reportEvents, reporting.MonitorEvent{
			Timestamp: event.Timestamp, Hostname: event.Hostname, Table: event.Table, From: event.From, To: event.To,
		})
	}
	return reporting.GenerateMonitorReport(reporting.MonitorConfig{
		OutputDir: outputDir, Output: config.Output, Title: config.Title,
		ChangeReference: config.ChangeReference, StartedAt: since, CompletedAt: config.CompletedAt,
		LogoFolder: config.LogoFolder, HeaderLogo: config.HeaderLogo, FooterLogo: config.FooterLogo,
	}, reportSeries, reportEvents)
}
