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
	// The report's "Window" card is completed-minus-started: when since is
	// the zero time.Time (callers that want "every tick on disk" rather than
	// a specific run's start, e.g. cmd/monitor-report with no -since given),
	// using since directly here would render an absurd ~292-year duration.
	// The earliest sample actually collected is a sane stand-in for that case
	// only — real callers (every monitor's own main.go) always pass their
	// actual process start time, which must never be overridden here even
	// when the first sample landed a little later (onboarding/poll delay).
	startedAt := since
	if since.IsZero() {
		if earliest, ok := earliestPointTime(series); ok {
			startedAt = earliest
		}
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
		ChangeReference: config.ChangeReference, StartedAt: startedAt, CompletedAt: config.CompletedAt,
		LogoFolder: config.LogoFolder, HeaderLogo: config.HeaderLogo, FooterLogo: config.FooterLogo,
	}, reportSeries, reportEvents)
}

// earliestPointTime returns the earliest sample timestamp across every
// series' first point (each series' Points are already chronological, so
// its own first point is its earliest).
func earliestPointTime(series []reportSeries) (time.Time, bool) {
	var earliest time.Time
	found := false
	for _, s := range series {
		if len(s.Points) == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339, s.Points[0].Timestamp)
		if err != nil {
			continue
		}
		if !found || t.Before(earliest) {
			earliest = t
			found = true
		}
	}
	return earliest, found
}
