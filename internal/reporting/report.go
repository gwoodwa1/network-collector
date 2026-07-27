package reporting

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxLogoBytes = 2 * 1024 * 1024

type Config struct {
	RunDir          string
	SummaryFile     string
	EventsFile      string
	Output          string
	Template        string
	Title           string
	ChangeReference string
	LogoFolder      string
	HeaderLogo      string
	FooterLogo      string
}

type Model struct {
	SchemaVersion       string
	Title               string
	ChangeReference     string
	RunID               string
	Playbook            string
	StartedAt           time.Time
	CompletedAt         time.Time
	Duration            time.Duration
	Failed              bool
	Status              string
	StatusClass         string
	DeviceCount         int
	DevicePassed        int
	DeviceFailed        int
	ValidationCount     int
	ValidationPassed    int
	ValidationFailed    int
	ValidationErrors    int
	ValidationRecovered int
	Devices             []Device
	FailedValidations   []Validation
	Changes             []Change
	Triggers            []Trigger
	Timeline            []TimelineEvent
	Artifacts           []Artifact
	Warnings            []string
	HeaderLogo          template.URL
	FooterLogo          template.URL
	GeneratedAt         time.Time
}

type Device struct {
	Hostname string
	IP       string
	Failed   bool
	Status   string
	Duration string
}

type Validation struct {
	Hostname    string
	Status      string
	StatusClass string
	Recovered   bool
	Check       string
	Condition   string
	Expected    string
	Value       string
	Message     string
	Timestamp   string
}

type Change struct {
	Hostname       string
	Step           string
	Resource       string
	Platform       string
	Action         string
	StatusClass    string
	Changed        bool
	Current        string
	Desired        string
	Commands       []string
	RollbackStatus string
	Evidence       string
}

type Trigger struct {
	Timestamp string
	Hostname  string
	Step      string
	Path      string
	Value     string
	Metric    string
	Threshold string
}

type TimelineEvent struct {
	Timestamp string
	Hostname  string
	Step      string
	Type      string
	Summary   string
	Class     string
}

type Artifact struct {
	Hostname string
	Step     string
	Kind     string
	Path     string
}

type summaryDocument struct {
	RunID       string              `json:"run_id"`
	Playbook    string              `json:"playbook"`
	StartedAt   time.Time           `json:"started_at"`
	CompletedAt time.Time           `json:"completed_at"`
	Failed      bool                `json:"failed"`
	Validations []summaryValidation `json:"validations"`
	Artifacts   []summaryArtifact   `json:"artifacts"`
	Devices     []summaryDevice     `json:"devices"`
}

type summaryDevice struct {
	Hostname string        `json:"hostname"`
	IP       string        `json:"ip"`
	Failed   bool          `json:"failed"`
	Duration time.Duration `json:"duration"`
}

type summaryValidation struct {
	Hostname  string           `json:"hostname"`
	Recovered bool             `json:"recovered"`
	Result    validationResult `json:"result"`
}

type validationResult struct {
	Pass          bool        `json:"pass"`
	Status        string      `json:"status"`
	PatternOrPath string      `json:"pattern_or_path"`
	Value         interface{} `json:"value"`
	Expected      interface{} `json:"expected"`
	Condition     string      `json:"condition"`
	Message       string      `json:"message"`
	Err           string      `json:"err"`
	Timestamp     time.Time   `json:"timestamp"`
}

type summaryArtifact struct {
	Hostname string `json:"hostname"`
	Step     string `json:"step"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
}

type eventDocument struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Hostname  string                 `json:"hostname"`
	Step      string                 `json:"step"`
	Failed    *bool                  `json:"failed"`
	Data      map[string]interface{} `json:"data"`
}

func Generate(config Config) (string, error) {
	model, err := BuildModel(config)
	if err != nil {
		return "", err
	}
	return Render(config, model)
}

func ValidateBranding(config Config) error {
	if _, err := loadLogo(config.LogoFolder, config.HeaderLogo, "header.png"); err != nil {
		return err
	}
	if _, err := loadLogo(config.LogoFolder, config.FooterLogo, "footer.png"); err != nil {
		return err
	}
	return nil
}

func BuildModel(config Config) (Model, error) {
	runDir, err := filepath.Abs(strings.TrimSpace(config.RunDir))
	if err != nil || strings.TrimSpace(config.RunDir) == "" {
		return Model{}, fmt.Errorf("run directory is required")
	}
	summaryPath := resolveInputPath(runDir, config.SummaryFile, "results.json")
	content, err := os.ReadFile(summaryPath)
	if err != nil {
		return Model{}, fmt.Errorf("read summary %q: %w", summaryPath, err)
	}
	var summary summaryDocument
	if err := json.Unmarshal(content, &summary); err != nil {
		return Model{}, fmt.Errorf("decode summary %q: %w", summaryPath, err)
	}
	model := Model{
		SchemaVersion: ReportModelVersion,
		Title:         strings.TrimSpace(config.Title), ChangeReference: strings.TrimSpace(config.ChangeReference),
		RunID: summary.RunID, Playbook: summary.Playbook, StartedAt: summary.StartedAt,
		CompletedAt: summary.CompletedAt, Failed: summary.Failed, GeneratedAt: time.Now().UTC(),
	}
	if model.Title == "" {
		model.Title = summary.Playbook
	}
	if model.Title == "" {
		model.Title = "Network Change Report"
	}
	model.Duration = summary.CompletedAt.Sub(summary.StartedAt)
	if summary.Failed {
		model.Status, model.StatusClass = "Failed", "danger"
	} else {
		model.Status, model.StatusClass = "Successful", "success"
	}
	for _, device := range summary.Devices {
		view := Device{Hostname: device.Hostname, IP: device.IP, Failed: device.Failed, Duration: device.Duration.Round(time.Millisecond).String()}
		if device.Failed {
			view.Status = "Failed"
			model.DeviceFailed++
		} else {
			view.Status = "Successful"
			model.DevicePassed++
		}
		model.Devices = append(model.Devices, view)
	}
	model.DeviceCount = len(model.Devices)
	for _, item := range summary.Validations {
		model.ValidationCount++
		switch strings.ToLower(item.Result.Status) {
		case "pass":
			model.ValidationPassed++
		case "error":
			model.ValidationErrors++
		default:
			model.ValidationFailed++
		}
		if item.Recovered {
			model.ValidationRecovered++
		}
		if item.Result.Pass && !item.Recovered {
			continue
		}
		message := strings.TrimSpace(item.Result.Message)
		if message == "" {
			message = strings.TrimSpace(item.Result.Err)
		}
		model.FailedValidations = append(model.FailedValidations, Validation{
			Hostname: item.Hostname, Status: titleStatus(item.Result.Status), StatusClass: validationClass(item.Result.Status, item.Recovered),
			Recovered: item.Recovered, Check: item.Result.PatternOrPath, Condition: item.Result.Condition,
			Expected: displayValue(item.Result.Expected), Value: displayValue(item.Result.Value), Message: message,
			Timestamp: formatTime(item.Result.Timestamp),
		})
	}
	for _, artifact := range summary.Artifacts {
		model.Artifacts = append(model.Artifacts, Artifact{
			Hostname: artifact.Hostname, Step: artifact.Step, Kind: artifact.Kind, Path: relativeDisplayPath(runDir, artifact.Path),
		})
		if change, ok, warning := extractChange(runDir, artifact); ok {
			model.Changes = append(model.Changes, change)
		} else if warning != "" {
			model.Warnings = append(model.Warnings, warning)
		}
	}
	eventsPath := resolveInputPath(runDir, config.EventsFile, "events.jsonl")
	if events, warnings, eventErr := readEvents(eventsPath); eventErr == nil {
		model.Warnings = append(model.Warnings, warnings...)
		for _, event := range events {
			addEvent(&model, event)
		}
	} else if os.IsNotExist(eventErr) && strings.TrimSpace(config.EventsFile) != "" {
		model.Warnings = append(model.Warnings, fmt.Sprintf("Lifecycle event file was not found: %s", eventsPath))
	} else if !os.IsNotExist(eventErr) {
		model.Warnings = append(model.Warnings, eventErr.Error())
	}
	sort.Slice(model.Timeline, func(i, j int) bool { return model.Timeline[i].Timestamp < model.Timeline[j].Timestamp })
	if len(model.Timeline) > 80 {
		model.Timeline = model.Timeline[len(model.Timeline)-80:]
		model.Warnings = append(model.Warnings, "Timeline limited to the 80 most recent relevant events.")
	}
	header, err := loadLogo(config.LogoFolder, config.HeaderLogo, "header.png")
	if err != nil {
		return Model{}, err
	}
	footer, err := loadLogo(config.LogoFolder, config.FooterLogo, "footer.png")
	if err != nil {
		return Model{}, err
	}
	model.HeaderLogo, model.FooterLogo = header, footer
	return model, nil
}

func Render(config Config, model Model) (string, error) {
	runDir, err := filepath.Abs(strings.TrimSpace(config.RunDir))
	if err != nil {
		return "", err
	}
	output := strings.TrimSpace(config.Output)
	if output == "" {
		output = "change-report.html"
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(runDir, output)
	}
	reportTemplate, err := resolveReportTemplate(config)
	if err != nil {
		return "", err
	}
	if model.SchemaVersion == "" {
		model.SchemaVersion = ReportModelVersion
	}
	var rendered bytes.Buffer
	if err := reportTemplate.Execute(&rendered, model); err != nil {
		return "", fmt.Errorf("render report: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(filepath.Dir(output), ".report-*")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(rendered.Bytes()); err != nil {
		_ = temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tempName, output); err != nil {
		return "", err
	}
	return output, nil
}

func extractChange(runDir string, artifact summaryArtifact) (Change, bool, string) {
	path, ok := safeArtifactPath(runDir, artifact.Path)
	if !ok {
		return Change{}, false, fmt.Sprintf("Skipped artifact outside run directory: %s", artifact.Path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Change{}, false, ""
	}
	var raw struct {
		Resource       string          `json:"resource"`
		Platform       string          `json:"platform"`
		Changed        bool            `json:"changed"`
		Action         string          `json:"action"`
		Current        json.RawMessage `json:"current"`
		Desired        json.RawMessage `json:"desired"`
		Commands       []string        `json:"commands"`
		RollbackStatus string          `json:"rollback_status"`
	}
	if json.Unmarshal(content, &raw) != nil || strings.TrimSpace(raw.Resource) == "" {
		return Change{}, false, ""
	}
	action := strings.TrimSpace(raw.Action)
	if action == "" {
		if raw.Changed {
			action = "changed"
		} else {
			action = "none"
		}
	}
	return Change{
		Hostname: artifact.Hostname, Step: artifact.Step, Resource: raw.Resource, Platform: raw.Platform,
		Action: action, StatusClass: actionClass(action), Changed: raw.Changed,
		Current: compactJSON(raw.Current), Desired: compactJSON(raw.Desired), Commands: raw.Commands,
		RollbackStatus: raw.RollbackStatus, Evidence: relativeDisplayPath(runDir, artifact.Path),
	}, true, ""
}

func readEvents(path string) ([]eventDocument, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	var events []eventDocument
	var warnings []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var event eventDocument
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			warnings = append(warnings, fmt.Sprintf("Skipped malformed event at line %d.", line))
			continue
		}
		events = append(events, event)
	}
	return events, warnings, scanner.Err()
}

func addEvent(model *Model, event eventDocument) {
	switch event.Type {
	case "gnmi.triggered":
		model.Triggers = append(model.Triggers, Trigger{
			Timestamp: formatTime(event.Timestamp), Hostname: event.Hostname, Step: event.Step,
			Path: displayValue(event.Data["path"]), Value: displayValue(event.Data["value"]),
			Metric: displayValue(event.Data["metric_value"]), Threshold: displayValue(event.Data["threshold_value"]),
		})
	case "run.started", "run.completed", "device.started", "device.completed", "step.failed":
	default:
		return
	}
	summary := event.Type
	if event.Type == "device.completed" && event.Failed != nil {
		summary = "Device completed successfully"
		if *event.Failed {
			summary = "Device completed with failures"
		}
	}
	if event.Type == "gnmi.triggered" {
		summary = "gNMI guard triggered for " + displayValue(event.Data["path"])
	}
	class := "neutral"
	if event.Failed != nil && *event.Failed || event.Type == "step.failed" {
		class = "danger"
	} else if event.Type == "run.completed" || event.Type == "device.completed" {
		class = "success"
	}
	model.Timeline = append(model.Timeline, TimelineEvent{
		Timestamp: formatTime(event.Timestamp), Hostname: event.Hostname, Step: event.Step,
		Type: event.Type, Summary: summary, Class: class,
	})
}

func loadLogo(folder, configured, fallback string) (template.URL, error) {
	folder = strings.TrimSpace(folder)
	name := strings.TrimSpace(configured)
	explicit := name != ""
	if name == "" {
		name = fallback
	}
	if folder == "" {
		if explicit {
			return "", fmt.Errorf("logo_folder is required when %s is configured", name)
		}
		return "", nil
	}
	if filepath.IsAbs(name) || filepath.Base(name) != name || strings.ToLower(filepath.Ext(name)) != ".png" {
		return "", fmt.Errorf("logo %q must be a PNG filename inside logo_folder", name)
	}
	path := filepath.Join(folder, name)
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) && !explicit {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read logo %q: %w", path, err)
	}
	if len(content) > maxLogoBytes {
		return "", fmt.Errorf("logo %q exceeds %d bytes", path, maxLogoBytes)
	}
	if len(content) < 8 || !bytes.Equal(content[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return "", fmt.Errorf("logo %q is not a valid PNG file", path)
	}
	imageConfig, err := png.DecodeConfig(bytes.NewReader(content))
	if err != nil || imageConfig.Width < 1 || imageConfig.Height < 1 ||
		imageConfig.Width > 4096 || imageConfig.Height > 4096 {
		return "", fmt.Errorf("logo %q is not a valid PNG image with dimensions up to 4096x4096", path)
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(content)), nil
}

func resolveInputPath(runDir, configured, fallback string) string {
	path := strings.TrimSpace(configured)
	if path == "" {
		path = fallback
	}
	if !filepath.IsAbs(path) {
		if _, err := os.Stat(path); err == nil {
			absolute, absErr := filepath.Abs(path)
			if absErr == nil {
				return absolute
			}
		}
		path = filepath.Join(runDir, path)
	}
	return path
}

func safeArtifactPath(runDir, configured string) (string, bool) {
	path := configured
	configuredAbsolute := filepath.IsAbs(path)
	if !configuredAbsolute {
		if candidate, err := filepath.Abs(path); err == nil {
			path = candidate
		}
	}
	runAbs, _ := filepath.Abs(runDir)
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(runAbs, pathAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		if configuredAbsolute {
			return "", false
		}
		// Some summaries store paths relative to the run directory itself.
		pathAbs, err = filepath.Abs(filepath.Join(runAbs, configured))
		if err != nil {
			return "", false
		}
		relative, err = filepath.Rel(runAbs, pathAbs)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", false
		}
	}
	return pathAbs, true
}

func relativeDisplayPath(runDir, path string) string {
	resolved, ok := safeArtifactPath(runDir, path)
	if !ok {
		return filepath.Base(path)
	}
	relative, err := filepath.Rel(runDir, resolved)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(relative)
}

func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var out bytes.Buffer
	if json.Indent(&out, raw, "", "  ") == nil {
		return out.String()
	}
	return string(raw)
}

func displayValue(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Local().Format("2006-01-02 15:04:05 MST")
}

func validationClass(status string, recovered bool) string {
	if recovered {
		return "warning"
	}
	if strings.EqualFold(status, "error") || strings.EqualFold(status, "fail") {
		return "danger"
	}
	return "success"
}

func actionClass(action string) string {
	switch strings.ToLower(action) {
	case "changed":
		return "success"
	case "rolled-back", "would-change":
		return "warning"
	case "rollback-failed":
		return "danger"
	default:
		return "neutral"
	}
}

func titleStatus(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Unknown"
	}
	return strings.ToUpper(value[:1]) + strings.ToLower(value[1:])
}

var professionalTemplate = template.Must(template.New("professional").Funcs(template.FuncMap{
	"timefmt": formatTime,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--ink:#10233f;--muted:#607086;--paper:#fff;--canvas:#eef3f8;--line:#dce5ee;--brand:#0b5cad;--brand2:#10a7a1;--success:#138a62;--warning:#bd7412;--danger:#c43d4f;--neutral:#637083}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.hero{position:relative;overflow:hidden;padding:38px 48px 62px;color:#fff;background:linear-gradient(125deg,#092a50 0%,#0b5cad 58%,#10a7a1 130%)}
.hero:after{content:"";position:absolute;right:-90px;top:-150px;width:430px;height:430px;border:70px solid rgba(255,255,255,.08);border-radius:50%}
.hero-row,.footer-row{display:flex;align-items:center;justify-content:space-between;gap:28px;position:relative;z-index:1}.logo{max-width:220px;max-height:70px;object-fit:contain}
.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;opacity:.8;font-weight:700}.hero h1{font-size:34px;line-height:1.15;margin:12px 0 8px;max-width:850px}.hero p{margin:0;opacity:.86}
.shell{max-width:1320px;margin:-34px auto 44px;padding:0 28px;position:relative;z-index:2}.cards{display:grid;grid-template-columns:repeat(5,minmax(150px,1fr));gap:14px}.card,.panel{background:var(--paper);border:1px solid rgba(16,35,63,.08);border-radius:14px;box-shadow:0 8px 28px rgba(22,47,78,.08)}
.card{padding:18px}.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}.card .value{font-size:27px;font-weight:760;margin-top:6px}.card.success{border-top:4px solid var(--success)}.card.warning{border-top:4px solid var(--warning)}.card.danger{border-top:4px solid var(--danger)}.card.neutral{border-top:4px solid var(--brand)}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin-top:18px}.panel{padding:22px;margin-top:18px}.grid .panel{margin-top:0}.panel h2{font-size:18px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 16px;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.04em;background:#edf1f5;color:var(--neutral)}.badge.success{background:#e3f5ee;color:var(--success)}.badge.warning{background:#fff0d9;color:#9a5c0a}.badge.danger{background:#fde8eb;color:var(--danger)}
table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em;padding:10px 9px;border-bottom:1px solid var(--line)}td{padding:11px 9px;border-bottom:1px solid #edf1f5;vertical-align:top}tr:last-child td{border-bottom:0}
.mono,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}pre{white-space:pre-wrap;max-height:260px;overflow:auto;background:#f5f8fb;border:1px solid var(--line);border-radius:9px;padding:12px;color:#263b55}
.change{border-left:4px solid var(--brand2);padding:16px 18px;margin:12px 0;background:#f8fbfd;border-radius:0 10px 10px 0}.change-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.change h3{margin:0;font-size:15px}.meta{color:var(--muted);font-size:12px;margin-top:3px}
details{margin-top:10px}summary{cursor:pointer;color:var(--brand);font-weight:650}.timeline{border-left:2px solid var(--line);margin-left:7px;padding-left:20px}.event{position:relative;padding:0 0 18px}.event:before{content:"";position:absolute;left:-27px;top:5px;width:12px;height:12px;background:var(--neutral);border:3px solid #fff;border-radius:50%;box-shadow:0 0 0 1px var(--line)}.event.success:before{background:var(--success)}.event.danger:before{background:var(--danger)}
.event strong{display:block}.empty{padding:18px;border:1px dashed #cbd7e3;border-radius:10px;color:var(--muted);text-align:center}.warning-box{background:#fff7e8;border:1px solid #f1d49d;border-radius:10px;padding:12px 15px;margin:8px 0;color:#754b0d}
footer{background:#0c203a;color:#dbe7f5;padding:24px 48px}.footer-note{font-size:12px;opacity:.74}.footer-logo{max-width:180px;max-height:52px;object-fit:contain}
@media(max-width:980px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.hero{padding:30px 24px 56px}.shell{padding:0 16px}}@media(max-width:560px){.cards{grid-template-columns:1fr}.hero-row,.footer-row{align-items:flex-start;flex-direction:column}.hero h1{font-size:27px}.panel{padding:16px}.table-wrap{overflow-x:auto}}
@media print{body{background:#fff}.hero{print-color-adjust:exact;-webkit-print-color-adjust:exact}.shell{max-width:none;margin:-25px 0 0;padding:0 14px}.panel,.card{box-shadow:none;break-inside:avoid}.change{break-inside:avoid}details>summary{display:none}details>*{display:block!important}footer{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
</style>
</head>
<body>
<header class="hero"><div class="hero-row"><div><div class="eyebrow">Network change assurance</div><h1>{{.Title}}</h1><p>{{.Playbook}} · {{.RunID}}{{if .ChangeReference}} · {{.ChangeReference}}{{end}}</p></div>{{if .HeaderLogo}}<img class="logo" src="{{.HeaderLogo}}" alt="Company logo">{{end}}</div></header>
<main class="shell">
<section class="cards">
<div class="card {{.StatusClass}}"><div class="label">Run outcome</div><div class="value">{{.Status}}</div></div>
<div class="card neutral"><div class="label">Devices</div><div class="value">{{.DeviceCount}}</div></div>
<div class="card success"><div class="label">Validations passed</div><div class="value">{{.ValidationPassed}}</div></div>
<div class="card {{if or .ValidationFailed .ValidationErrors}}danger{{else}}success{{end}}"><div class="label">Failed / errors</div><div class="value">{{.ValidationFailed}} / {{.ValidationErrors}}</div></div>
<div class="card warning"><div class="label">Recovered</div><div class="value">{{.ValidationRecovered}}</div></div>
</section>
<section class="grid">
<div class="panel"><h2>Run details</h2><p class="sub">Immutable identity and timing for this execution.</p><table><tr><th>Started</th><td>{{timefmt .StartedAt}}</td></tr><tr><th>Completed</th><td>{{timefmt .CompletedAt}}</td></tr><tr><th>Duration</th><td>{{.Duration}}</td></tr><tr><th>Change reference</th><td>{{if .ChangeReference}}{{.ChangeReference}}{{else}}Not supplied{{end}}</td></tr></table></div>
<div class="panel"><h2>Device outcomes</h2><p class="sub">{{.DevicePassed}} successful · {{.DeviceFailed}} failed</p>{{if .Devices}}<div class="table-wrap"><table><thead><tr><th>Device</th><th>Address</th><th>Status</th><th>Duration</th></tr></thead><tbody>{{range .Devices}}<tr><td><strong>{{.Hostname}}</strong></td><td class="mono">{{.IP}}</td><td><span class="badge {{if .Failed}}danger{{else}}success{{end}}">{{.Status}}</span></td><td>{{.Duration}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No device outcomes were recorded.</div>{{end}}</div>
</section>
<section class="panel"><h2>Planned and applied changes</h2><p class="sub">Structured desired-state plans extracted from run artifacts.</p>{{if .Changes}}{{range .Changes}}<article class="change"><div class="change-head"><div><h3>{{.Resource}} · {{.Hostname}}</h3><div class="meta">{{.Step}}{{if .Platform}} · {{.Platform}}{{end}} · Evidence: {{.Evidence}}</div></div><span class="badge {{.StatusClass}}">{{.Action}}</span></div>{{if .RollbackStatus}}<p><strong>Rollback:</strong> {{.RollbackStatus}}</p>{{end}}<details><summary>Current and desired state</summary><div class="grid"><pre>{{.Current}}</pre><pre>{{.Desired}}</pre></div></details>{{if .Commands}}<details><summary>Planned commands</summary><pre>{{range .Commands}}{{.}}
{{end}}</pre></details>{{end}}</article>{{end}}{{else}}<div class="empty">No structured desired-state change plans were found.</div>{{end}}</section>
<section class="grid">
<div class="panel"><h2>Exceptions and recovery</h2><p class="sub">Failed, errored, or recovered validation evidence.</p>{{if .FailedValidations}}<div class="table-wrap"><table><thead><tr><th>Device</th><th>Status</th><th>Check</th><th>Evidence</th></tr></thead><tbody>{{range .FailedValidations}}<tr><td>{{.Hostname}}</td><td><span class="badge {{.StatusClass}}">{{if .Recovered}}Recovered{{else}}{{.Status}}{{end}}</span></td><td class="mono">{{.Check}}</td><td>{{.Message}}{{if .Expected}}<div class="meta">Expected {{.Condition}} {{.Expected}} · observed {{.Value}}</div>{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No validation exceptions were recorded.</div>{{end}}</div>
<div class="panel"><h2>gNMI guard events</h2><p class="sub">Event-driven conditions observed during the change window.</p>{{if .Triggers}}<div class="table-wrap"><table><thead><tr><th>Time</th><th>Device</th><th>Path</th><th>Metric / threshold</th></tr></thead><tbody>{{range .Triggers}}<tr><td>{{.Timestamp}}</td><td>{{.Hostname}}</td><td class="mono">{{.Path}}</td><td>{{.Metric}}{{if .Threshold}} / {{.Threshold}}{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No gNMI guard triggers were recorded.</div>{{end}}</div>
</section>
<section class="panel"><h2>Change timeline</h2><p class="sub">The most recent relevant lifecycle events.</p>{{if .Timeline}}<div class="timeline">{{range .Timeline}}<div class="event {{.Class}}"><strong>{{.Summary}}</strong><div class="meta">{{.Timestamp}}{{if .Hostname}} · {{.Hostname}}{{end}}{{if .Step}} · {{.Step}}{{end}}</div></div>{{end}}</div>{{else}}<div class="empty">No lifecycle event file was available.</div>{{end}}</section>
{{if .Warnings}}<section class="panel"><h2>Report warnings</h2>{{range .Warnings}}<div class="warning-box">{{.}}</div>{{end}}</section>{{end}}
<section class="panel"><h2>Evidence index</h2><p class="sub">Artifacts retained with the run bundle.</p>{{if .Artifacts}}<div class="table-wrap"><table><thead><tr><th>Device</th><th>Step</th><th>Kind</th><th>Path</th></tr></thead><tbody>{{range .Artifacts}}<tr><td>{{.Hostname}}</td><td>{{.Step}}</td><td><span class="badge">{{.Kind}}</span></td><td class="mono">{{.Path}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">No artifacts were indexed.</div>{{end}}</section>
</main>
<footer><div class="footer-row"><div><strong>Generated by Network Collector Reporter</strong><div class="footer-note">{{timefmt .GeneratedAt}} · Self-contained evidence report</div></div>{{if .FooterLogo}}<img class="footer-logo" src="{{.FooterLogo}}" alt="Company logo">{{end}}</div></footer>
</body></html>`))
