package monitorreport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type tickLine struct {
	Timestamp  string                     `json:"timestamp"`
	Hostname   string                     `json:"hostname"`
	Interfaces map[string]json.RawMessage `json:"interfaces"`
}

// FirstInterfaceStat decodes one interface's {"stats": [...]} result — the
// shape every InterfaceParser produces via parseOrRaw in both
// cmd/xr-routing-monitor and cmd/junos-routing-monitor — and returns its
// first record, or ok=false if the JSON doesn't decode or has no records.
// Exported so both tools' status-line renderers (firstInterfaceStat in each
// status.go) and this package's report generator decode the exact same
// shape from one definition, rather than three independent copies that
// could silently drift apart if a tool's parser output ever changes.
func FirstInterfaceStat(raw json.RawMessage) (map[string]string, bool) {
	var decoded struct {
		Stats []map[string]string `json:"stats"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.Stats) == 0 {
		return nil, false
	}
	return decoded.Stats[0], true
}

type reportPoint struct {
	Timestamp string  `json:"timestamp"`
	InputBPS  float64 `json:"input_bps"`
	OutputBPS float64 `json:"output_bps"`
}

type reportSeries struct {
	Hostname  string        `json:"hostname"`
	Interface string        `json:"interface"`
	Points    []reportPoint `json:"points"`
}

// GenerateInterfaceReport reads monitor JSONL tick files from outputDir and
// writes a self-contained HTML graph of per-interface input/output rates,
// plotting only samples at or after since. Passing the run's own start time
// as since keeps the report scoped to the change window that just ran: the
// per-device .jsonl files this reads are deliberately never truncated
// on re-runs against the same --devices file (see both tools' READMEs), so
// without this filter a report generated after the Nth run against the same
// file would plot the full N-run accumulated history on one time axis,
// diluting the run that just happened. It returns an empty path when no
// parseable interface samples at or after since were found.
func GenerateInterfaceReport(outputDir string, since time.Time) (string, error) {
	series, err := collectInterfaceSeries(outputDir, since)
	if err != nil {
		return "", err
	}
	if len(series) == 0 {
		return "", nil
	}

	data, err := json.Marshal(series)
	if err != nil {
		return "", fmt.Errorf("encode report data: %w", err)
	}

	path := filepath.Join(outputDir, "interface-traffic.html")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", fmt.Errorf("open report: %w", err)
	}
	defer file.Close()

	if err := interfaceReportTemplate.Execute(file, map[string]any{
		"Data": template.JS(data),
	}); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}

func collectInterfaceSeries(outputDir string, since time.Time) ([]reportSeries, error) {
	paths, err := filepath.Glob(filepath.Join(outputDir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	byKey := map[string]*reportSeries{}
	for _, path := range paths {
		if err := collectInterfaceSeriesFromFile(path, since, byKey); err != nil {
			return nil, err
		}
	}

	series := make([]reportSeries, 0, len(byKey))
	for _, s := range byKey {
		series = append(series, *s)
	}
	sort.Slice(series, func(i, j int) bool {
		if series[i].Hostname != series[j].Hostname {
			return series[i].Hostname < series[j].Hostname
		}
		return series[i].Interface < series[j].Interface
	})
	return series, nil
}

func collectInterfaceSeriesFromFile(path string, since time.Time, byKey map[string]*reportSeries) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var tick tickLine
		if err := json.Unmarshal([]byte(line), &tick); err != nil {
			// A single malformed line (realistically only possible from an
			// abnormal event — the writer in poll.go always flushes one
			// complete JSON object per line — e.g. a process killed
			// mid-write) must not discard every other, perfectly valid tick
			// in this file, let alone every other device's file in the same
			// run. Skip it and keep going.
			slog.Warn("skipping malformed tick line in report input", "path", path, "line", lineNo, "error", err)
			continue
		}
		if tick.Timestamp == "" || tick.Hostname == "" || len(tick.Interfaces) == 0 {
			continue
		}
		capturedAt, err := time.Parse(time.RFC3339, tick.Timestamp)
		if err != nil || capturedAt.Before(since) {
			continue
		}
		for name, raw := range tick.Interfaces {
			in, out, ok := decodeInterfaceRates(raw)
			if !ok {
				continue
			}
			key := tick.Hostname + "\x00" + name
			s := byKey[key]
			if s == nil {
				s = &reportSeries{Hostname: tick.Hostname, Interface: name}
				byKey[key] = s
			}
			s.Points = append(s.Points, reportPoint{
				Timestamp: tick.Timestamp,
				InputBPS:  in,
				OutputBPS: out,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func decodeInterfaceRates(raw json.RawMessage) (float64, float64, bool) {
	stat, ok := FirstInterfaceStat(raw)
	if !ok {
		return 0, 0, false
	}
	in, inOK := parseRate(stat["INPUT_RATE_BPS"])
	out, outOK := parseRate(stat["OUTPUT_RATE_BPS"])
	if !inOK || !outOK {
		return 0, 0, false
	}
	return in, out, true
}

func parseRate(raw string) (float64, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// interfaceReportTemplate's embedded <script> (polyline/renderChart/
// formatRate below) runs client-side in the browser and has no test
// coverage: this repo is otherwise pure Go with no JS toolchain, and this
// package's own tests can only assert on the emitted HTML/JSON, not
// execute or verify the chart-rendering math itself. A bug in the axis
// scaling or rate formatting would only surface by opening the generated
// report. Accepted trade-off rather than introducing a JS test runner for
// one embedded script.
var interfaceReportTemplate = template.Must(template.New("interface-report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Interface Traffic Report</title>
<style>
body { margin: 0; font-family: Arial, sans-serif; color: #17202a; background: #f6f8fa; }
header { padding: 20px 24px 12px; background: #ffffff; border-bottom: 1px solid #d8dee4; }
h1 { margin: 0; font-size: 24px; }
main { padding: 20px 24px 32px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 16px; }
.chart { background: #ffffff; border: 1px solid #d8dee4; border-radius: 8px; padding: 14px; }
.chart h2 { margin: 0 0 10px; font-size: 15px; font-weight: 700; }
svg { width: 100%; height: 260px; overflow: visible; }
.axis { stroke: #8792a2; stroke-width: 1; }
.gridline { stroke: #e6ebf0; stroke-width: 1; }
.input { fill: none; stroke: #0969da; stroke-width: 2; }
.output { fill: none; stroke: #d1242f; stroke-width: 2; }
.label { fill: #57606a; font-size: 11px; }
.legend { display: flex; gap: 14px; color: #57606a; font-size: 12px; margin-top: 8px; }
.swatch { display: inline-block; width: 18px; height: 3px; margin-right: 6px; vertical-align: middle; }
.swatch.input { background: #0969da; }
.swatch.output { background: #d1242f; }
@media (max-width: 560px) { main { padding: 14px; } .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header><h1>Interface Traffic Report</h1></header>
<main><div id="charts" class="grid"></div></main>
<script>
const series = {{.Data}};

function formatRate(value) {
  if (value >= 1e9) return (value / 1e9).toFixed(1) + " Gbps";
  if (value >= 1e6) return (value / 1e6).toFixed(1) + " Mbps";
  if (value >= 1e3) return (value / 1e3).toFixed(1) + " Kbps";
  return value.toFixed(0) + " bps";
}

function polyline(points, key, minTime, maxTime, maxRate, width, height, pad) {
  const span = Math.max(1, maxTime - minTime);
  const ceiling = Math.max(1, maxRate);
  return points.map(p => {
    const t = new Date(p.timestamp).getTime();
    const x = pad.left + ((t - minTime) / span) * (width - pad.left - pad.right);
    const y = pad.top + (1 - (p[key] / ceiling)) * (height - pad.top - pad.bottom);
    return x.toFixed(1) + "," + y.toFixed(1);
  }).join(" ");
}

function renderChart(item) {
  const width = 640;
  const height = 260;
  const pad = { left: 58, right: 16, top: 18, bottom: 34 };
  const times = item.points.map(p => new Date(p.timestamp).getTime());
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const maxRate = Math.max(...item.points.flatMap(p => [p.input_bps, p.output_bps]));
  const title = item.hostname + " / " + item.interface;
  const input = polyline(item.points, "input_bps", minTime, maxTime, maxRate, width, height, pad);
  const output = polyline(item.points, "output_bps", minTime, maxTime, maxRate, width, height, pad);
  const yMid = pad.top + (height - pad.top - pad.bottom) / 2;
  const x0 = pad.left;
  const x1 = width - pad.right;
  const y0 = height - pad.bottom;

  const card = document.createElement("section");
  card.className = "chart";
  card.innerHTML = ` + "`" + `
    <h2></h2>
    <svg viewBox="0 0 ${width} ${height}" role="img">
      <line class="gridline" x1="${x0}" y1="${pad.top}" x2="${x1}" y2="${pad.top}"></line>
      <line class="gridline" x1="${x0}" y1="${yMid}" x2="${x1}" y2="${yMid}"></line>
      <line class="axis" x1="${x0}" y1="${pad.top}" x2="${x0}" y2="${y0}"></line>
      <line class="axis" x1="${x0}" y1="${y0}" x2="${x1}" y2="${y0}"></line>
      <text class="label" x="4" y="${pad.top + 4}">${formatRate(maxRate)}</text>
      <text class="label" x="4" y="${yMid + 4}">${formatRate(maxRate / 2)}</text>
      <text class="label" x="${x0}" y="${height - 10}">${new Date(minTime).toLocaleTimeString()}</text>
      <text class="label" text-anchor="end" x="${x1}" y="${height - 10}">${new Date(maxTime).toLocaleTimeString()}</text>
      <polyline class="input" points="${input}"></polyline>
      <polyline class="output" points="${output}"></polyline>
    </svg>
    <div class="legend">
      <span><span class="swatch input"></span>Input</span>
      <span><span class="swatch output"></span>Output</span>
    </div>
  ` + "`" + `;
  card.querySelector("h2").textContent = title;
  card.querySelector("svg").setAttribute("aria-label", title);
  return card;
}

const root = document.getElementById("charts");
for (const item of series) {
  if (item.points.length > 0) root.appendChild(renderChart(item));
}
</script>
</body>
</html>
`))
