package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/internal/safeoutput"
	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

type MonitorConfig struct {
	OutputDir       string
	Output          string
	Title           string
	ChangeReference string
	StartedAt       time.Time
	CompletedAt     time.Time
	LogoFolder      string
	HeaderLogo      string
	FooterLogo      string
}

type MonitorPoint struct {
	Timestamp string  `json:"timestamp"`
	InputBPS  float64 `json:"input_bps"`
	OutputBPS float64 `json:"output_bps"`
}

type MonitorSeries struct {
	Hostname  string         `json:"hostname"`
	Interface string         `json:"interface"`
	Points    []MonitorPoint `json:"points"`
}

type MonitorEvent struct {
	Timestamp string `json:"timestamp"`
	Hostname  string `json:"hostname"`
	Table     string `json:"table"`
	From      string `json:"from"`
	To        string `json:"to"`
}

type monitorView struct {
	Title           string
	OutputFolder    string
	ChangeReference string
	StartedAt       time.Time
	CompletedAt     time.Time
	Duration        time.Duration
	DeviceCount     int
	InterfaceCount  int
	SampleCount     int
	EventCount      int
	HeaderLogo      template.URL
	FooterLogo      template.URL
	Data            template.JS
	Events          []MonitorEvent
	GeneratedAt     time.Time
}

func GenerateMonitorReport(config MonitorConfig, series []MonitorSeries, events []MonitorEvent) (string, error) {
	if len(series) == 0 {
		return "", nil
	}
	outputDir := strings.TrimSpace(config.OutputDir)
	if outputDir == "" {
		return "", fmt.Errorf("monitor report output directory is required")
	}
	output := strings.TrimSpace(config.Output)
	if output == "" {
		output = "monitoring-change-report.html"
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(outputDir, output)
	}
	header, err := loadLogo(config.LogoFolder, config.HeaderLogo, "header.png")
	if err != nil {
		return "", err
	}
	footer, err := loadLogo(config.LogoFolder, config.FooterLogo, "footer.png")
	if err != nil {
		return "", err
	}
	safeSeries := append([]MonitorSeries(nil), series...)
	for index := range safeSeries {
		safeSeries[index].Hostname = safeoutput.Sanitize(safeSeries[index].Hostname)
		safeSeries[index].Interface = safeoutput.Sanitize(safeSeries[index].Interface)
	}
	safeEvents := append([]MonitorEvent(nil), events...)
	for index := range safeEvents {
		safeEvents[index].Hostname = safeoutput.Sanitize(safeEvents[index].Hostname)
		safeEvents[index].Table = safeoutput.Sanitize(safeEvents[index].Table)
		safeEvents[index].From = safeoutput.Sanitize(safeEvents[index].From)
		safeEvents[index].To = safeoutput.Sanitize(safeEvents[index].To)
	}
	payload, err := json.Marshal(map[string]interface{}{"series": safeSeries, "events": safeEvents})
	if err != nil {
		return "", err
	}
	devices := map[string]bool{}
	samples := 0
	for _, item := range safeSeries {
		devices[item.Hostname] = true
		samples += len(item.Points)
	}
	title := strings.TrimSpace(config.Title)
	if title == "" {
		title = "IOS XR Change Monitoring Report"
	}
	completed := config.CompletedAt
	if completed.IsZero() {
		completed = time.Now()
	}
	outputFolder := safeoutput.Sanitize(filepath.Base(strings.TrimRight(outputDir, "/")))
	view := monitorView{
		Title: safeoutput.Sanitize(title), OutputFolder: outputFolder,
		ChangeReference: safeoutput.Sanitize(strings.TrimSpace(config.ChangeReference)),
		StartedAt:       config.StartedAt, CompletedAt: completed, Duration: completed.Sub(config.StartedAt),
		DeviceCount: len(devices), InterfaceCount: len(series), SampleCount: samples, EventCount: len(events),
		HeaderLogo: header, FooterLogo: footer, Data: template.JS(payload), Events: safeEvents,
		GeneratedAt: time.Now().UTC(),
	}
	sort.Slice(view.Events, func(i, j int) bool { return view.Events[i].Timestamp < view.Events[j].Timestamp })
	var rendered bytes.Buffer
	if err := monitorTemplate.Execute(&rendered, view); err != nil {
		return "", err
	}
	if err := secureartifact.EnsureDir(filepath.Dir(output)); err != nil {
		return "", err
	}
	if err := secureartifact.WriteFile(output, rendered.Bytes()); err != nil {
		return "", err
	}
	return output, nil
}

var monitorTemplate = template.Must(template.New("monitor-professional").Funcs(template.FuncMap{
	"timefmt": formatTime,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title>
<style>
:root{--ink:#10233f;--muted:#607086;--paper:#fff;--canvas:#eef3f8;--line:#dce5ee;--brand:#0b5cad;--brand2:#10a7a1;--input:#0b68c4;--output:#df5060;--event:#c77a0a}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.hero{position:relative;overflow:hidden;padding:38px 48px 62px;color:#fff;background:linear-gradient(125deg,#092a50 0%,#0b5cad 58%,#10a7a1 130%)}.hero:after{content:"";position:absolute;right:-90px;top:-150px;width:430px;height:430px;border:70px solid rgba(255,255,255,.08);border-radius:50%}
.hero-row,.footer-row{display:flex;align-items:center;justify-content:space-between;gap:28px;position:relative;z-index:1}.logo{max-width:220px;max-height:70px;object-fit:contain}.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;opacity:.8;font-weight:700}.hero h1{font-size:34px;line-height:1.15;margin:12px 0 8px}.hero p{margin:0;opacity:.86}
.shell{max-width:1320px;margin:-34px auto 44px;padding:0 28px;position:relative;z-index:2}.cards{display:grid;grid-template-columns:repeat(5,minmax(150px,1fr));gap:14px}.card,.panel,.chart{background:#fff;border:1px solid rgba(16,35,63,.08);border-radius:14px;box-shadow:0 8px 28px rgba(22,47,78,.08)}.card{padding:18px;border-top:4px solid var(--brand2)}.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}.card .value{font-size:27px;font-weight:760;margin-top:6px}
.panel{padding:22px;margin-top:18px}.panel h2{font-size:18px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 16px;font-size:13px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(480px,1fr));gap:18px;margin-top:18px}.chart{padding:18px}.chart h2{margin:0 0 2px;font-size:15px}.chart .range{color:var(--muted);font-size:12px;margin-bottom:8px}svg{width:100%;height:280px;overflow:visible}.axis{stroke:#8792a2}.gridline{stroke:#e6ebf0}.input-line{fill:none;stroke:var(--input);stroke-width:2.4}.output-line{fill:none;stroke:var(--output);stroke-width:2.4}.event-line{stroke:var(--event);stroke-width:2;stroke-dasharray:4 3}.label-svg{fill:#57606a;font-size:11px}.legend{display:flex;flex-wrap:wrap;gap:8px 16px;color:var(--muted);font-size:12px;margin-top:8px}.swatch{display:inline-block;width:18px;height:3px;margin-right:6px;vertical-align:middle}#combinedChart svg{height:380px}#combinedLegend span{cursor:pointer;user-select:none;padding:2px 5px;border-radius:5px}#combinedLegend span:hover{background:#eef3f8}#combinedLegend span.off{opacity:.35;text-decoration:line-through}.event-table{width:100%;border-collapse:collapse}.event-table th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;padding:9px;border-bottom:1px solid var(--line)}.event-table td{padding:10px 9px;border-bottom:1px solid #edf1f5}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.filterbar{display:flex;align-items:center;gap:10px 18px;padding:16px 22px;flex-wrap:wrap}.filterbar>label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:700}.devicechecks{display:flex;flex-wrap:wrap;gap:6px 16px}.devicechecks label{display:inline-flex;align-items:center;gap:5px;font-size:13px;color:var(--ink);cursor:pointer;text-transform:none;letter-spacing:normal;font-weight:400}.filterlinks{margin-left:auto;font-size:12px;white-space:nowrap}.filterlinks a{color:var(--brand);text-decoration:none;cursor:pointer}.filterlinks a:hover{text-decoration:underline}
footer{background:#0c203a;color:#dbe7f5;padding:24px 48px}.footer-note{font-size:12px;opacity:.74}.footer-logo{max-width:180px;max-height:52px;object-fit:contain}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.hero{padding:30px 24px 56px}.shell{padding:0 16px}}@media print{body{background:#fff}.hero,footer{print-color-adjust:exact;-webkit-print-color-adjust:exact}.panel,.card,.chart{box-shadow:none;break-inside:avoid}.shell{max-width:none;margin:-25px 0 0}}
</style></head><body>
<header class="hero"><div class="hero-row"><div><div class="eyebrow">Continuous change assurance</div><h1>{{.Title}}</h1><p>{{if .OutputFolder}}{{.OutputFolder}} · {{end}}IOS XR routing and interface monitoring{{if .ChangeReference}} · {{.ChangeReference}}{{end}}</p></div>{{if .HeaderLogo}}<img class="logo" src="{{.HeaderLogo}}" alt="Company logo">{{end}}</div></header>
<main class="shell"><section class="cards"><div class="card"><div class="label">Devices</div><div class="value">{{.DeviceCount}}</div></div><div class="card"><div class="label">Interfaces</div><div class="value">{{.InterfaceCount}}</div></div><div class="card"><div class="label">Samples</div><div class="value">{{.SampleCount}}</div></div><div class="card"><div class="label">Route transitions</div><div class="value">{{.EventCount}}</div></div><div class="card"><div class="label">Window</div><div class="value">{{.Duration.Round 1000000000}}</div></div></section>
<section class="panel"><h2>All interfaces (combined)</h2><p class="sub">Every interface normalized to a percentage of its own peak output rate and drawn on one shared time axis, so a shift on one device can be lined up against events on another. Switch to a single device below for absolute rates.</p><div id="combinedChart"></div><div class="legend" id="combinedLegend"></div></section>
<section class="panel filterbar"><label>Devices</label><div class="devicechecks" id="deviceChecks"></div><span class="filterlinks"><a href="#" id="devicesAll">All</a> · <a href="#" id="devicesNone">None</a></span></section>
<section class="grid" id="charts"></section>
<section class="panel"><h2>Default-route transitions</h2><p class="sub">Detected next-hop changes are also marked on each affected device chart.</p>{{if .Events}}<table class="event-table"><thead><tr><th>Time</th><th>Device</th><th>VRF/table</th><th>Previous</th><th>New</th></tr></thead><tbody>{{range .Events}}<tr data-host="{{.Hostname}}"><td>{{.Timestamp}}</td><td>{{.Hostname}}</td><td class="mono">{{.Table}}</td><td class="mono">{{.From}}</td><td class="mono">{{.To}}</td></tr>{{end}}</tbody></table>{{else}}<div class="sub">No default-route next-hop transitions were observed.</div>{{end}}</section></main>
<footer><div class="footer-row"><div><strong>Generated by Network Collector Reporter</strong><div class="footer-note">{{timefmt .GeneratedAt}} · {{timefmt .StartedAt}} to {{timefmt .CompletedAt}}</div></div>{{if .FooterLogo}}<img class="footer-logo" src="{{.FooterLogo}}" alt="Company logo">{{end}}</div></footer>
<script>
const payload={{.Data}},series=payload.series||[],events=payload.events||[];
function rate(v){if(v>=1e9)return(v/1e9).toFixed(1)+" Gbps";if(v>=1e6)return(v/1e6).toFixed(1)+" Mbps";if(v>=1e3)return(v/1e3).toFixed(1)+" Kbps";return v.toFixed(0)+" bps"}
function points(ps,key,a,b,max,w,h,p){const span=Math.max(1,b-a),ceil=Math.max(1,max);return ps.map(x=>{const t=new Date(x.timestamp).getTime(),xx=p.l+((t-a)/span)*(w-p.l-p.r),yy=p.t+(1-x[key]/ceil)*(h-p.t-p.b);return xx.toFixed(1)+","+yy.toFixed(1)}).join(" ")}
function ticks(a,b){const m=60000,s=Math.max(1,(b-a)/m),steps=[1,2,5,10,15,30,60,120,240],step=steps.find(x=>s/x<=20)||480,out=[];for(let t=Math.ceil(a/(step*m))*step*m;t<=b;t+=step*m)out.push(t);return out}
function chart(item){const w=680,h=280,p={l:62,r:18,t:20,b:38},ts=item.points.map(x=>new Date(x.timestamp).getTime()),a=Math.min(...ts),b=Math.max(...ts),max=Math.max(...item.points.flatMap(x=>[x.input_bps,x.output_bps])),x0=p.l,x1=w-p.r,y0=h-p.b,span=Math.max(1,b-a);const grid=ticks(a,b).map((t,i,all)=>{const x=p.l+((t-a)/span)*(w-p.l-p.r),label=i%Math.max(1,Math.ceil(all.length/7))===0?'<text class="label-svg" text-anchor="middle" x="'+x.toFixed(1)+'" y="'+(h-11)+'">'+new Date(t).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})+"</text>":"";return'<line class="gridline" x1="'+x+'" y1="'+p.t+'" x2="'+x+'" y2="'+y0+'"></line>'+label}).join("");const hostEvents=events.filter(e=>e.hostname===item.hostname&&new Date(e.timestamp).getTime()>=a&&new Date(e.timestamp).getTime()<=b),marks=hostEvents.map(e=>{const x=p.l+((new Date(e.timestamp).getTime()-a)/span)*(w-p.l-p.r);return'<line class="event-line" x1="'+x+'" y1="'+p.t+'" x2="'+x+'" y2="'+y0+'"></line>'}).join("");const el=document.createElement("article");el.className="chart";el.dataset.host=item.hostname;el.innerHTML='<h2></h2><div class="range"></div><svg viewBox="0 0 '+w+" "+h+'" role="img"><line class="gridline" x1="'+x0+'" y1="'+p.t+'" x2="'+x1+'" y2="'+p.t+'"></line><line class="gridline" x1="'+x0+'" y1="'+(p.t+(y0-p.t)/2)+'" x2="'+x1+'" y2="'+(p.t+(y0-p.t)/2)+'"></line>'+grid+'<line class="axis" x1="'+x0+'" y1="'+p.t+'" x2="'+x0+'" y2="'+y0+'"></line><line class="axis" x1="'+x0+'" y1="'+y0+'" x2="'+x1+'" y2="'+y0+'"></line><text class="label-svg" x="3" y="'+(p.t+4)+'">'+rate(max)+'</text><text class="label-svg" x="3" y="'+(p.t+(y0-p.t)/2+4)+'">'+rate(max/2)+'</text><polyline class="input-line" points="'+points(item.points,"input_bps",a,b,max,w,h,p)+'"></polyline><polyline class="output-line" points="'+points(item.points,"output_bps",a,b,max,w,h,p)+'"></polyline>'+marks+'</svg><div class="legend"><span><i class="swatch" style="background:var(--input)"></i>Input</span><span><i class="swatch" style="background:var(--output)"></i>Output</span><span><i class="swatch" style="background:var(--event)"></i>Next-hop change</span></div>';const title=item.hostname+" / "+item.interface;el.querySelector("h2").textContent=title;el.querySelector(".range").textContent=new Date(a).toLocaleString()+" — "+new Date(b).toLocaleString();el.querySelector("svg").setAttribute("aria-label",title);return el}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
const palette=["#0b68c4","#df5060","#10a7a1","#c77a0a","#7b4fd1","#2e9e4f","#d1428f","#4f7bd1","#a35b2b","#4fae9e","#c94f4f","#5c8f2e"];
const hosts=[...new Set(series.map(s=>s.hostname))].sort();
let combinedHosts=[],selectedHosts=new Set(hosts),manualOff=new Set();
function combinedVisible(idx){return selectedHosts.has(combinedHosts[idx])&&!manualOff.has(idx)}
function applyCombinedVisibility(){document.querySelectorAll('#combinedChart polyline[data-idx]').forEach(pl=>{pl.style.display=combinedVisible(Number(pl.dataset.idx))?"":"none"});document.querySelectorAll('#combinedLegend span[data-idx]').forEach(sp=>{sp.classList.toggle("off",!combinedVisible(Number(sp.dataset.idx)))})}
function combinedChart(){const items=series.filter(s=>s.points.length),wrap=document.getElementById("combinedChart");if(!items.length){wrap.textContent="No samples to plot.";return}const allTs=items.flatMap(s=>s.points.map(x=>new Date(x.timestamp).getTime())),a=Math.min(...allTs),b=Math.max(...allTs),span=Math.max(1,b-a),w=1200,h=380,p={l:52,r:18,t:20,b:38},x0=p.l,x1=w-p.r,y0=h-p.b;const grid=ticks(a,b).map((t,i,all)=>{const x=p.l+((t-a)/span)*(w-p.l-p.r),label=i%Math.max(1,Math.ceil(all.length/9))===0?'<text class="label-svg" text-anchor="middle" x="'+x.toFixed(1)+'" y="'+(h-11)+'">'+new Date(t).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})+"</text>":"";return'<line class="gridline" x1="'+x+'" y1="'+p.t+'" x2="'+x+'" y2="'+y0+'"></line>'+label}).join(""),marks=events.filter(e=>{const t=new Date(e.timestamp).getTime();return t>=a&&t<=b}).map(e=>{const x=p.l+((new Date(e.timestamp).getTime()-a)/span)*(w-p.l-p.r);return'<line class="event-line" x1="'+x+'" y1="'+p.t+'" x2="'+x+'" y2="'+y0+'"></line>'}).join("");let lines="",legend="";items.forEach((item,i)=>{combinedHosts[i]=item.hostname;const color=palette[i%palette.length],max=Math.max(...item.points.map(x=>x.output_bps),1),pts=item.points.map(x=>{const t=new Date(x.timestamp).getTime(),xx=p.l+((t-a)/span)*(w-p.l-p.r),norm=max>0?x.output_bps/max:0,yy=p.t+(1-norm)*(y0-p.t);return xx.toFixed(1)+","+yy.toFixed(1)}).join(" ");lines+='<polyline data-idx="'+i+'" points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="2"></polyline>';legend+='<span data-idx="'+i+'"><i class="swatch" style="background:'+color+'"></i>'+esc(item.hostname)+" / "+esc(item.interface)+"</span>"});wrap.innerHTML='<svg viewBox="0 0 '+w+" "+h+'" role="img" aria-label="All interfaces, normalized"><line class="gridline" x1="'+x0+'" y1="'+p.t+'" x2="'+x1+'" y2="'+p.t+'"></line>'+grid+'<line class="axis" x1="'+x0+'" y1="'+p.t+'" x2="'+x0+'" y2="'+y0+'"></line><line class="axis" x1="'+x0+'" y1="'+y0+'" x2="'+x1+'" y2="'+y0+'"></line><text class="label-svg" x="3" y="'+(p.t+4)+'">100%</text><text class="label-svg" x="3" y="'+(y0+4)+'">0%</text>'+marks+lines+"</svg>";const legendEl=document.getElementById("combinedLegend");legendEl.innerHTML=legend;legendEl.querySelectorAll("span").forEach(sp=>{sp.addEventListener("click",()=>{const idx=Number(sp.dataset.idx);if(manualOff.has(idx))manualOff.delete(idx);else manualOff.add(idx);applyCombinedVisibility()})});applyCombinedVisibility()}
combinedChart();
const root=document.getElementById("charts");for(const item of series)if(item.points.length)root.appendChild(chart(item));
const deviceChecksEl=document.getElementById("deviceChecks");
function applyDeviceFilter(){for(const el of root.children)el.style.display=selectedHosts.has(el.dataset.host)?"":"none";for(const tr of document.querySelectorAll(".event-table tbody tr"))tr.style.display=selectedHosts.has(tr.dataset.host)?"":"none";applyCombinedVisibility()}
for(const h of hosts){const lab=document.createElement("label"),cb=document.createElement("input");cb.type="checkbox";cb.checked=true;cb.dataset.host=h;cb.addEventListener("change",()=>{if(cb.checked)selectedHosts.add(h);else selectedHosts.delete(h);applyDeviceFilter()});lab.appendChild(cb);lab.appendChild(document.createTextNode(" "+h));deviceChecksEl.appendChild(lab)}
document.getElementById("devicesAll").addEventListener("click",e=>{e.preventDefault();selectedHosts=new Set(hosts);deviceChecksEl.querySelectorAll("input").forEach(cb=>cb.checked=true);applyDeviceFilter()});
document.getElementById("devicesNone").addEventListener("click",e=>{e.preventDefault();selectedHosts=new Set();deviceChecksEl.querySelectorAll("input").forEach(cb=>cb.checked=false);applyDeviceFilter()});
</script></body></html>`))
