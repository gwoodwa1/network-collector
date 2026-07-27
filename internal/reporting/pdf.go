package reporting

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func FindPDFBrowser(configured string) (string, error) {
	if value := strings.TrimSpace(configured); value != "" {
		path, err := exec.LookPath(value)
		if err != nil {
			return "", fmt.Errorf("PDF browser %q was not found: %w", value, err)
		}
		return path, nil
	}
	if value := strings.TrimSpace(os.Getenv("NETWORK_COLLECTOR_PDF_BROWSER")); value != "" {
		path, err := exec.LookPath(value)
		if err != nil {
			return "", fmt.Errorf("NETWORK_COLLECTOR_PDF_BROWSER %q was not found: %w", value, err)
		}
		return path, nil
	}
	candidates := []string{"google-chrome", "chromium", "chromium-browser"}
	if runtime.GOOS == "darwin" {
		candidates = append([]string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}, candidates...)
	}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("PDF output requires Chrome or Chromium; set pdf_browser or NETWORK_COLLECTOR_PDF_BROWSER")
}

func RenderPDF(htmlPath, pdfPath, browser string) (string, error) {
	htmlAbsolute, err := filepath.Abs(strings.TrimSpace(htmlPath))
	if err != nil || strings.TrimSpace(htmlPath) == "" {
		return "", fmt.Errorf("HTML report path is required")
	}
	if _, err := os.Stat(htmlAbsolute); err != nil {
		return "", fmt.Errorf("read HTML report %q: %w", htmlAbsolute, err)
	}
	if strings.TrimSpace(pdfPath) == "" {
		pdfPath = strings.TrimSuffix(htmlAbsolute, filepath.Ext(htmlAbsolute)) + ".pdf"
	}
	pdfAbsolute, err := filepath.Abs(pdfPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(pdfAbsolute), 0o755); err != nil {
		return "", err
	}
	browserPath, err := FindPDFBrowser(browser)
	if err != nil {
		return "", err
	}
	targetURL := (&url.URL{Scheme: "file", Path: htmlAbsolute}).String()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, browserPath,
		"--headless", "--disable-gpu", "--no-pdf-header-footer",
		"--print-to-pdf="+pdfAbsolute, targetURL,
	)
	output, runErr := command.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("PDF renderer timed out after 60s")
	}
	if runErr != nil {
		return "", fmt.Errorf("PDF renderer failed: %w: %s", runErr, strings.TrimSpace(string(output)))
	}
	info, err := os.Stat(pdfAbsolute)
	if err != nil || info.Size() == 0 {
		return "", fmt.Errorf("PDF renderer did not create %q", pdfAbsolute)
	}
	return pdfAbsolute, nil
}
