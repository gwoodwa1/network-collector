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

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

type tickLine struct {
	Timestamp            string                     `json:"timestamp"`
	Hostname             string                     `json:"hostname"`
	Interfaces           map[string]json.RawMessage `json:"interfaces"`
	DefaultRouteNextHops map[string]json.RawMessage `json:"default_route_next_hops"`
}

// reportEvent marks the tick at which a monitored table's/VRF's
// default-route next hop changed — during a change window that repoints an
// internet-facing VRF at a different peering router, this is the moment
// the migration actually took effect, and it's drawn as a labeled vertical
// marker on that device's traffic charts so the rate change around it can
// be read in context.
type reportEvent struct {
	Timestamp string `json:"timestamp"`
	Hostname  string `json:"hostname"`
	Table     string `json:"table"`
	From      string `json:"from"`
	To        string `json:"to"`
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
	series, events, err := collectInterfaceSeries(outputDir, since)
	if err != nil {
		return "", err
	}
	if len(series) == 0 {
		return "", nil
	}

	data, err := json.Marshal(map[string]any{"series": series, "events": events})
	if err != nil {
		return "", fmt.Errorf("encode report data: %w", err)
	}

	path := filepath.Join(outputDir, "interface-traffic.html")
	file, err := secureartifact.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
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

func collectInterfaceSeries(outputDir string, since time.Time) ([]reportSeries, []reportEvent, error) {
	paths, err := filepath.Glob(filepath.Join(outputDir, "*.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)

	byKey := map[string]*reportSeries{}
	// lastNextHops tracks the previous tick's deduped next-hop signature per
	// hostname+table so a change between consecutive ticks becomes a
	// reportEvent. Ticks within one file are chronological (the .jsonl is
	// append-only), and each hostname's ticks live in that hostname's own
	// file, so a per-key last-seen value is enough.
	lastNextHops := map[string]string{}
	events := []reportEvent{}
	for _, path := range paths {
		if err := collectInterfaceSeriesFromFile(path, since, byKey, lastNextHops, &events); err != nil {
			return nil, nil, err
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
	return series, events, nil
}

func collectInterfaceSeriesFromFile(path string, since time.Time, byKey map[string]*reportSeries, lastNextHops map[string]string, events *[]reportEvent) error {
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
		collectNextHopEvents(tick, lastNextHops, events)
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

// collectNextHopEvents compares one tick's per-table default-route next-hop
// signatures against the previous tick's and appends a reportEvent for each
// change. Undecodable/raw-fallback data is treated as unknown: it neither
// produces an event nor clobbers the baseline, so a single tick with a
// parse hiccup can't fabricate a "changed and changed back" pair.
func collectNextHopEvents(tick tickLine, lastNextHops map[string]string, events *[]reportEvent) {
	if len(tick.DefaultRouteNextHops) == 0 {
		return
	}
	names := make([]string, 0, len(tick.DefaultRouteNextHops))
	for name := range tick.DefaultRouteNextHops {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sig, ok := nextHopSignature(tick.DefaultRouteNextHops[name])
		if !ok {
			continue
		}
		key := tick.Hostname + "\x00" + name
		prev, seen := lastNextHops[key]
		lastNextHops[key] = sig
		if !seen || prev == sig {
			continue
		}
		*events = append(*events, reportEvent{
			Timestamp: tick.Timestamp,
			Hostname:  tick.Hostname,
			Table:     name,
			From:      displayNextHopSignature(prev),
			To:        displayNextHopSignature(sig),
		})
	}
}

// nextHopSignature reduces one table's {"next_hops": [...]} raw JSON to the
// comma-joined distinct next-hop values (same dedup both tools' status
// lines apply — Junos repeats the value once per route reflector). ok=false
// means the data is a raw fallback or undecodable, i.e. unknown rather than
// "no next hop"; a decoded-but-empty list returns ("", true), which
// displayNextHopSignature renders as "none".
func nextHopSignature(raw json.RawMessage) (string, bool) {
	var decoded struct {
		NextHops []map[string]string `json:"next_hops"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.NextHops == nil {
		return "", false
	}
	seen := map[string]bool{}
	var unique []string
	for _, record := range decoded.NextHops {
		nh := strings.TrimSpace(record["NEXTHOP"])
		if nh == "" || seen[nh] {
			continue
		}
		seen[nh] = true
		unique = append(unique, nh)
	}
	sort.Strings(unique)
	return strings.Join(unique, ","), true
}

func displayNextHopSignature(sig string) string {
	if sig == "" {
		return "none"
	}
	return sig
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
.event { stroke: #9a6700; stroke-width: 2; stroke-dasharray: 4 3; }
.event-label { fill: #9a6700; font-weight: 600; }
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
const payload = {{.Data}};
const series = payload.series || [];
const events = payload.events || [];

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

// minuteTicks returns minute-aligned timestamps between minTime and
// maxTime for the x-axis time scale. The step starts at one minute and
// coarsens (2, 5, 10, ... minutes) just enough to keep at most ~24
// gridlines, so a short window gets true per-minute lines while a
// multi-hour window stays readable.
function minuteTicks(minTime, maxTime) {
  const minute = 60000;
  const spanMinutes = Math.max(1, (maxTime - minTime) / minute);
  const steps = [1, 2, 5, 10, 15, 30, 60, 120, 240];
  const step = steps.find(s => spanMinutes / s <= 24) || 480;
  const ticks = [];
  for (let t = Math.ceil(minTime / (step * minute)) * step * minute; t <= maxTime; t += step * minute) {
    ticks.push(t);
  }
  return ticks;
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

  const ticks = minuteTicks(minTime, maxTime);
  const span = Math.max(1, maxTime - minTime);
  const labelEvery = Math.max(1, Math.ceil(ticks.length / 8));
  const tickMarkup = ticks.map(function (t, i) {
    const x = pad.left + ((t - minTime) / span) * (width - pad.left - pad.right);
    let m = '<line class="gridline" x1="' + x.toFixed(1) + '" y1="' + pad.top + '" x2="' + x.toFixed(1) + '" y2="' + y0 + '"></line>';
    if (i % labelEvery === 0 && x > x0 + 40 && x < x1 - 40) {
      const label = new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      m += '<text class="label" text-anchor="middle" x="' + x.toFixed(1) + '" y="' + (height - 10) + '">' + label + '</text>';
    }
    return m;
  }).join("");

  const hostEvents = events.filter(function (e) {
    if (e.hostname !== item.hostname) return false;
    const t = new Date(e.timestamp).getTime();
    return t >= minTime && t <= maxTime;
  });
  const eventMarkup = hostEvents.map(function (e, i) {
    const t = new Date(e.timestamp).getTime();
    const x = pad.left + ((t - minTime) / span) * (width - pad.left - pad.right);
    const onRight = x > (x0 + x1) / 2;
    const y = pad.top + 12 + (i % 3) * 12;
    return '<line class="event" x1="' + x.toFixed(1) + '" y1="' + pad.top + '" x2="' + x.toFixed(1) + '" y2="' + y0 + '"></line>' +
      '<text class="label event-label" text-anchor="' + (onRight ? "end" : "start") + '" x="' + (onRight ? x - 4 : x + 4).toFixed(1) + '" y="' + y + '"></text>';
  }).join("");

  const card = document.createElement("section");
  card.className = "chart";
  card.innerHTML = ` + "`" + `
    <h2></h2>
    <svg viewBox="0 0 ${width} ${height}" role="img">
      <line class="gridline" x1="${x0}" y1="${pad.top}" x2="${x1}" y2="${pad.top}"></line>
      <line class="gridline" x1="${x0}" y1="${yMid}" x2="${x1}" y2="${yMid}"></line>
      ${tickMarkup}
      <line class="axis" x1="${x0}" y1="${pad.top}" x2="${x0}" y2="${y0}"></line>
      <line class="axis" x1="${x0}" y1="${y0}" x2="${x1}" y2="${y0}"></line>
      <text class="label" x="4" y="${pad.top + 4}">${formatRate(maxRate)}</text>
      <text class="label" x="4" y="${yMid + 4}">${formatRate(maxRate / 2)}</text>
      <text class="label" x="${x0}" y="${height - 10}">${new Date(minTime).toLocaleTimeString()}</text>
      <text class="label" text-anchor="end" x="${x1}" y="${height - 10}">${new Date(maxTime).toLocaleTimeString()}</text>
      <polyline class="input" points="${input}"></polyline>
      <polyline class="output" points="${output}"></polyline>
      ${eventMarkup}
    </svg>
    <div class="legend">
      <span><span class="swatch input"></span>Input</span>
      <span><span class="swatch output"></span>Output</span>
      <span><span class="swatch" style="background:#9a6700"></span>Next-hop change</span>
    </div>
  ` + "`" + `;
  card.querySelector("h2").textContent = title;
  card.querySelector("svg").setAttribute("aria-label", title);
  // Event label text comes from parsed device output, so it's assigned via
  // textContent (never string-built into innerHTML) to keep any markup in a
  // device-supplied value inert.
  const eventLabels = card.querySelectorAll(".event-label");
  hostEvents.forEach(function (e, i) {
    eventLabels[i].textContent = e.table.split(".")[0] + " 0/0 → " + e.to;
  });
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
