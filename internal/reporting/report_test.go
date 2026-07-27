package reporting

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeJSON(t *testing.T, path string, value interface{}) {
	t.Helper()
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateProfessionalReportExtractsRelevantEvidenceAndEmbedsLogos(t *testing.T) {
	runDir := t.TempDir()
	artifactDir := filepath.Join(runDir, "001-edge-01")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(artifactDir, "ensure-vrf.raw.txt")
	writeJSON(t, planPath, map[string]interface{}{
		"resource": "vrf", "platform": "cisco_nxos", "changed": true, "action": "changed",
		"current":  map[string]interface{}{"exists": false},
		"desired":  map[string]interface{}{"exists": true, "name": "CUSTOMER-A"},
		"commands": []string{"configure terminal", "vrf context CUSTOMER-A"},
	})
	now := time.Now().UTC().Truncate(time.Second)
	writeJSON(t, filepath.Join(runDir, "results.json"), map[string]interface{}{
		"run_id": "run-test", "playbook": `<script>alert("x")</script>`,
		"started_at": now.Add(-time.Minute), "completed_at": now, "failed": true,
		"devices": []map[string]interface{}{
			{"hostname": "edge-01", "ip": "192.0.2.10", "failed": true, "duration": int64(time.Second)},
		},
		"validations": []map[string]interface{}{{
			"hostname": "edge-01", "recovered": true,
			"result": map[string]interface{}{
				"pass": false, "status": "fail", "pattern_or_path": "interfaces.0.state",
				"expected": "up", "value": "down", "condition": "eq", "message": "interface was down",
				"timestamp": now,
			},
		}},
		"artifacts": []map[string]interface{}{
			{"hostname": "edge-01", "step": "ensure-vrf", "kind": "raw", "path": planPath},
		},
	})
	events := strings.Join([]string{
		`{"type":"run.started","timestamp":"` + now.Add(-time.Minute).Format(time.RFC3339) + `","run_id":"run-test"}`,
		`{"type":"gnmi.triggered","timestamp":"` + now.Format(time.RFC3339) + `","hostname":"edge-01","step":"traffic-guard","data":{"path":"/interfaces/interface/state/counters","metric_value":"81","threshold_value":"80"}}`,
		`{"type":"run.completed","timestamp":"` + now.Format(time.RFC3339) + `","failed":true}`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(runDir, "events.jsonl"), []byte(events), 0o600); err != nil {
		t.Fatal(err)
	}
	logos := filepath.Join(runDir, "branding")
	if err := os.MkdirAll(logos, 0o755); err != nil {
		t.Fatal(err)
	}
	var logo bytes.Buffer
	picture := image.NewRGBA(image.Rect(0, 0, 2, 2))
	picture.Set(0, 0, color.RGBA{R: 11, G: 92, B: 173, A: 255})
	if err := png.Encode(&logo, picture); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logos, "header.png"), logo.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logos, "footer.png"), logo.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := Generate(Config{
		RunDir: runDir, Title: "Core path change", ChangeReference: "CHG-42",
		LogoFolder: logos,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(content)
	for _, wanted := range []string{
		"Core path change", "CHG-42", "CUSTOMER-A", "interface was down",
		"/interfaces/interface/state/counters", "data:image/png;base64,", "Recovered",
	} {
		if !strings.Contains(html, wanted) {
			t.Fatalf("report is missing %q", wanted)
		}
	}
	if strings.Contains(html, `<script>alert("x")</script>`) {
		t.Fatal("untrusted playbook content was rendered as HTML")
	}
	if !strings.Contains(html, `&lt;script&gt;alert`) {
		t.Fatal("escaped untrusted playbook content was not retained")
	}
}

func TestRenderCompactReportUsesAuditedBuiltInTemplate(t *testing.T) {
	runDir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	path, err := Render(Config{
		RunDir:   runDir,
		Output:   "compact.html",
		Template: "compact",
	}, Model{
		Title: `<script>alert("x")</script>`,
		RunID: "run-compact", Playbook: "compact-example",
		StartedAt: now.Add(-time.Minute), CompletedAt: now, Duration: time.Minute,
		Status: "Successful", StatusClass: "success",
		DeviceCount: 1, DevicePassed: 1,
		Devices: []Device{{
			Hostname: "edge-01", IP: "192.0.2.10", Status: "Successful",
		}},
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(content)
	for _, wanted := range []string{
		"Network change summary · model v1",
		"run-compact",
		"edge-01",
		`&lt;script&gt;alert`,
	} {
		if !strings.Contains(html, wanted) {
			t.Fatalf("compact report is missing %q", wanted)
		}
	}
	if strings.Contains(html, `<script>alert("x")</script>`) {
		t.Fatal("compact template rendered untrusted content as HTML")
	}
}

func TestValidateTemplateFailsClosedForUnknownTemplate(t *testing.T) {
	for _, name := range []string{"custom", "company.html.tmpl", "../template"} {
		t.Run(name, func(t *testing.T) {
			err := ValidateTemplate(Config{Template: name})
			if err == nil || !strings.Contains(err.Error(), "professional or compact") {
				t.Fatalf("unknown template %q was accepted: %v", name, err)
			}
		})
	}
	if err := ValidateTemplate(Config{}); err != nil {
		t.Fatalf("default professional template was rejected: %v", err)
	}
}

func TestBuildModelWarnsForMalformedOptionalEvent(t *testing.T) {
	runDir := t.TempDir()
	now := time.Now().UTC()
	writeJSON(t, filepath.Join(runDir, "results.json"), map[string]interface{}{
		"run_id": "run-test", "started_at": now, "completed_at": now, "failed": false,
		"validations": []interface{}{}, "artifacts": []interface{}{},
	})
	if err := os.WriteFile(filepath.Join(runDir, "events.jsonl"), []byte("{invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	model, err := BuildModel(Config{RunDir: runDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Warnings) != 1 || !strings.Contains(model.Warnings[0], "malformed event") {
		t.Fatalf("expected visible malformed-event warning, got %+v", model.Warnings)
	}
}

func TestBuildModelRejectsUnsafeOrInvalidLogo(t *testing.T) {
	runDir := t.TempDir()
	now := time.Now().UTC()
	writeJSON(t, filepath.Join(runDir, "results.json"), map[string]interface{}{
		"run_id": "run-test", "started_at": now, "completed_at": now, "failed": false,
	})
	logos := filepath.Join(runDir, "branding")
	if err := os.MkdirAll(logos, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logos, "not-image.png"), []byte("not png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildModel(Config{RunDir: runDir, LogoFolder: logos, HeaderLogo: "../outside.png"}); err == nil {
		t.Fatal("logo path traversal was accepted")
	}
	if _, err := BuildModel(Config{RunDir: runDir, LogoFolder: logos, HeaderLogo: "not-image.png"}); err == nil ||
		!strings.Contains(err.Error(), "not a valid PNG") {
		t.Fatalf("invalid PNG was accepted: %v", err)
	}
}

func TestBuildModelDoesNotReadArtifactsOutsideRunDirectory(t *testing.T) {
	runDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "plan.json")
	writeJSON(t, outside, map[string]interface{}{"resource": "vrf", "changed": true})
	now := time.Now().UTC()
	writeJSON(t, filepath.Join(runDir, "results.json"), map[string]interface{}{
		"run_id": "run-test", "started_at": now, "completed_at": now, "failed": false,
		"artifacts": []map[string]interface{}{
			{"hostname": "edge-01", "step": "change", "kind": "raw", "path": outside},
		},
	})
	model, err := BuildModel(Config{RunDir: runDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Changes) != 0 || len(model.Warnings) != 1 {
		t.Fatalf("outside artifact was consumed: changes=%+v warnings=%+v", model.Changes, model.Warnings)
	}
}
