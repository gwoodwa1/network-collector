package reporting

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderPDFUsesConfiguredBrowser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell script")
	}
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	pdfPath := filepath.Join(dir, "report.pdf")
	browserPath := filepath.Join(dir, "fake-browser")
	if err := os.WriteFile(htmlPath, []byte("<!doctype html><title>Report</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --print-to-pdf=*) output="${arg#--print-to-pdf=}" ;;
  esac
done
printf '%%PDF-1.4\n' > "$output"
`
	if err := os.WriteFile(browserPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := RenderPDF(htmlPath, pdfPath, browserPath)
	if err != nil {
		t.Fatalf("RenderPDF returned error: %v", err)
	}
	if got != pdfPath {
		t.Fatalf("unexpected PDF path %q", got)
	}
	content, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), "%PDF-1.4") {
		t.Fatalf("unexpected PDF fixture content %q", content)
	}
}

func TestFindPDFBrowserRejectsMissingConfiguredBrowser(t *testing.T) {
	_, err := FindPDFBrowser(filepath.Join(t.TempDir(), "missing-browser"))
	if err == nil || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("expected missing configured browser error, got %v", err)
	}
}
