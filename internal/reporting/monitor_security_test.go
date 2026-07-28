package reporting

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestMonitorReportEscapesHostileOutputAndRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	hostile := `</script><script>alert(1)</script>`
	secret := "token=NC_MONITOR_SECRET_CANARY"
	now := time.Now().UTC()
	path, err := GenerateMonitorReport(MonitorConfig{
		OutputDir: dir, Title: hostile, StartedAt: now, CompletedAt: now.Add(time.Second),
	}, []MonitorSeries{{
		Hostname: hostile, Interface: secret,
		Points: []MonitorPoint{{Timestamp: now.Format(time.RFC3339), InputBPS: 1, OutputBPS: 2}},
	}}, []MonitorEvent{{
		Timestamp: now.Format(time.RFC3339), Hostname: hostile, Table: secret, From: hostile, To: secret,
	}})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(content)
	if strings.Contains(html, hostile) {
		t.Fatal("hostile monitoring output escaped its HTML or script-data context")
	}
	if strings.Contains(html, "NC_MONITOR_SECRET_CANARY") {
		t.Fatal("known secret form reached the monitoring report")
	}
	if !strings.Contains(html, "[REDACTED]") {
		t.Fatal("monitoring report did not retain a redaction marker")
	}
}
