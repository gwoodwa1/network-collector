package reporting

import (
	"fmt"
	"html/template"
	"strings"
)

const ReportModelVersion = "v1"

func ValidateTemplate(config Config) error {
	_, err := resolveReportTemplate(config)
	return err
}

func resolveReportTemplate(config Config) (*template.Template, error) {
	name := strings.ToLower(strings.TrimSpace(config.Template))
	if name == "" {
		name = "professional"
	}
	switch name {
	case "professional":
		return professionalTemplate, nil
	case "compact":
		return compactTemplate, nil
	default:
		return nil, fmt.Errorf("report template must be professional or compact")
	}
}

var compactTemplate = template.Must(template.New("compact").Funcs(template.FuncMap{
	"timefmt": formatTime,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--ink:#14243a;--muted:#66758a;--line:#dce4ed;--success:#13795b;--warning:#a86509;--danger:#b83245;--paper:#fff;--canvas:#f3f6f9}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:#102d50;color:#fff;padding:26px 34px}.header-row,.footer-row{display:flex;align-items:center;justify-content:space-between;gap:20px}.logo{max-width:180px;max-height:55px;object-fit:contain}
h1{font-size:25px;margin:4px 0}.meta{color:var(--muted);font-size:12px}.header-meta{color:#d7e4f3}.shell{max-width:980px;margin:24px auto;padding:0 20px}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.card,section{background:var(--paper);border:1px solid var(--line);border-radius:10px}.card{padding:14px}.label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.value{font-size:21px;font-weight:750;margin-top:3px}
section{padding:18px;margin-top:14px}h2{font-size:16px;margin:0 0 10px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #edf1f5}th{color:var(--muted);font-size:11px;text-transform:uppercase}
.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:700;background:#e9eef4}.success{color:var(--success)}.warning{color:var(--warning)}.danger{color:var(--danger)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.notice{padding:9px 11px;background:#fff6e7;border-left:3px solid var(--warning);margin-top:8px}
footer{margin-top:24px;background:#102d50;color:#d7e4f3;padding:18px 34px}.footer-logo{max-width:150px;max-height:42px;object-fit:contain}
@media(max-width:700px){.summary{grid-template-columns:repeat(2,1fr)}.header-row,.footer-row{align-items:flex-start;flex-direction:column}}@media print{body{background:#fff}.card,section{break-inside:avoid}.shell{max-width:none}}
</style>
</head>
<body>
<header><div class="header-row"><div><div class="header-meta">Network change summary · model {{.SchemaVersion}}</div><h1>{{.Title}}</h1><div class="header-meta">{{.Playbook}} · {{.RunID}}{{if .ChangeReference}} · {{.ChangeReference}}{{end}}</div></div>{{if .HeaderLogo}}<img class="logo" src="{{.HeaderLogo}}" alt="Company logo">{{end}}</div></header>
<main class="shell">
<div class="summary">
<div class="card"><div class="label">Outcome</div><div class="value {{.StatusClass}}">{{.Status}}</div></div>
<div class="card"><div class="label">Devices</div><div class="value">{{.DevicePassed}} / {{.DeviceCount}}</div></div>
<div class="card"><div class="label">Validations</div><div class="value">{{.ValidationPassed}} / {{.ValidationCount}}</div></div>
<div class="card"><div class="label">Duration</div><div class="value">{{.Duration}}</div></div>
</div>
<section><h2>Run</h2><table><tr><th>Started</th><td>{{timefmt .StartedAt}}</td><th>Completed</th><td>{{timefmt .CompletedAt}}</td></tr><tr><th>Failed/errors</th><td>{{.ValidationFailed}} / {{.ValidationErrors}}</td><th>Recovered</th><td>{{.ValidationRecovered}}</td></tr></table></section>
<section><h2>Device outcomes</h2>{{if .Devices}}<table><thead><tr><th>Device</th><th>Address</th><th>Status</th></tr></thead><tbody>{{range .Devices}}<tr><td>{{.Hostname}}</td><td class="mono">{{.IP}}</td><td><span class="badge {{if .Failed}}danger{{else}}success{{end}}">{{.Status}}</span></td></tr>{{end}}</tbody></table>{{else}}<div class="meta">No device outcomes recorded.</div>{{end}}</section>
{{if .Changes}}<section><h2>Changes</h2><table><thead><tr><th>Device</th><th>Step</th><th>Resource</th><th>Action</th><th>Rollback</th></tr></thead><tbody>{{range .Changes}}<tr><td>{{.Hostname}}</td><td>{{.Step}}</td><td>{{.Resource}}</td><td><span class="badge {{.StatusClass}}">{{.Action}}</span></td><td>{{.RollbackStatus}}</td></tr>{{end}}</tbody></table></section>{{end}}
{{if .FailedValidations}}<section><h2>Exceptions and recovery</h2><table><thead><tr><th>Device</th><th>Status</th><th>Check</th><th>Message</th></tr></thead><tbody>{{range .FailedValidations}}<tr><td>{{.Hostname}}</td><td class="{{.StatusClass}}">{{if .Recovered}}Recovered{{else}}{{.Status}}{{end}}</td><td class="mono">{{.Check}}</td><td>{{.Message}}</td></tr>{{end}}</tbody></table></section>{{end}}
{{if .Warnings}}<section><h2>Warnings</h2>{{range .Warnings}}<div class="notice">{{.}}</div>{{end}}</section>{{end}}
</main>
<footer><div class="footer-row"><div><strong>Generated by Network Collector Reporter</strong><div>Self-contained compact evidence summary · {{timefmt .GeneratedAt}}</div></div>{{if .FooterLogo}}<img class="footer-logo" src="{{.FooterLogo}}" alt="Company logo">{{end}}</div></footer>
</body></html>`))
