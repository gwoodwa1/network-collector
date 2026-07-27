package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigDecodesProfessionalReportSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workbook.yaml")
	content := `name_playbook: Reported change
report:
  enabled: true
  format: html
  template: professional
  output: change-report.html
  pdf_output: change-report.pdf
  pdf_browser: /opt/chrome
  title: Core path change
  change_reference: CHG-42
  logo_folder: branding
  header_logo: company-header.png
  footer_logo: company-footer.png
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, _, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Report.Enabled || config.Report.Format != "html" ||
		config.Report.Template != "professional" || config.Report.Output != "change-report.html" ||
		config.Report.PDFOutput != "change-report.pdf" || config.Report.PDFBrowser != "/opt/chrome" ||
		config.Report.Title != "Core path change" || config.Report.ChangeReference != "CHG-42" ||
		config.Report.LogoFolder != "branding" || config.Report.HeaderLogo != "company-header.png" ||
		config.Report.FooterLogo != "company-footer.png" {
		t.Fatalf("unexpected report configuration: %+v", config.Report)
	}
}

func TestReportEnabledRetainsEnsurePlanWithoutGlobalRawOutput(t *testing.T) {
	runDir := t.TempDir()
	artifacts := []outputArtifact{}
	ctx := &stepExecutionContext{
		hostname: "edge-01", deviceIndex: 0, runDir: runDir,
		output: OutputConfig{}, artifacts: &artifacts, events: &eventDispatcher{},
		reportEnabled: true,
	}
	step := StepConfig{Name: "ensure-vrf", Ensure: &EnsureConfig{Resource: "vrf"}}
	if err := saveStepArtifact(ctx, step, step.Name, 1, "raw", `{"resource":"vrf","changed":true}`); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].Kind != "plan" ||
		!strings.HasSuffix(artifacts[0].Path, ".plan.json") {
		t.Fatalf("report evidence plan was not retained: %+v", artifacts)
	}
	if _, err := os.Stat(artifacts[0].Path); err != nil {
		t.Fatalf("report evidence plan was not written: %v", err)
	}
}

func TestReportEnabledRetainsFailedEnsureRollbackPlan(t *testing.T) {
	disabled := readPlatformEnsureFixture(t, "iosxr", "interface-administratively-down.txt")
	executor := &sequenceSSHEnsureExecutor{
		outputs: []string{disabled, "commit complete", disabled, "rollback complete"},
	}
	ctx, failed := interactionContext(t, nil)
	artifacts := []outputArtifact{}
	ctx.deviceType = "cisco_iosxr"
	ctx.sshEnsure = executor
	ctx.runDir = t.TempDir()
	ctx.artifacts = &artifacts
	ctx.reportEnabled = true

	executeSteps(ctx, nil, []StepConfig{{
		Name: "ensure-interface",
		Ensure: &EnsureConfig{
			Resource: "interface", Name: "HundredGigE0/0/0/0", State: "enabled",
			RequireState: "disabled", Transport: "ssh", RollbackOnFailure: true,
		},
	}})
	if !*failed {
		t.Fatal("verification failure unexpectedly succeeded")
	}
	if len(artifacts) != 1 || artifacts[0].Kind != "plan" {
		t.Fatalf("failed ensure plan was not retained: %+v", artifacts)
	}
	content, err := os.ReadFile(artifacts[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"rollback_status": "succeeded"`) {
		t.Fatalf("retained plan is missing rollback evidence: %s", content)
	}
}
