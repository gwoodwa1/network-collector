package securitycontract

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate security contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func readRepositoryFile(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(content)
}

func requireContains(t *testing.T, file, content string, requirements map[string]string) {
	t.Helper()
	for property, token := range requirements {
		if !strings.Contains(content, token) {
			t.Errorf("%s no longer proves %s; missing %q", file, property, token)
		}
	}
}

func TestContinuousIntegrationEnforcesSecurityPolicyGates(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/test.yml")
	requireContains(t, ".github/workflows/test.yml", workflow, map[string]string{
		"push protection on main":                    "branches:\n      - main",
		"pull-request execution":                     "pull_request:",
		"scheduled execution":                        "schedule:",
		"dependency-file consistency":                "git diff --exit-code -- go.mod go.sum",
		"normal tests":                               "go test ./...",
		"static correctness checks":                  "go vet ./...",
		"race and coverage tests":                    "go test -race -covermode=atomic -coverprofile=coverage.out ./...",
		"selected fuzz tests":                        "-fuzz=FuzzParserModules",
		"source vulnerability scanning":              "govulncheck -show verbose ./...",
		"test vulnerability scanning":                "govulncheck -test -show verbose ./...",
		"all-command binary scanning":                `scripts/scan-go-binaries.sh "${RUNNER_TEMP}/security-scan"`,
		"high-severity static security analysis":     "gosec@v2.25.0 -exclude-generated -severity high ./...",
		"the exact container binary":                 `docker cp "${container_id}:/usr/local/bin/network-collector"`,
		"container binary toolchain inspection":      `go version -m "${RUNNER_TEMP}/network-collector"`,
		"container binary vulnerability scanning":    `govulncheck -mode binary "${RUNNER_TEMP}/network-collector"`,
		"Critical/High runtime image failure policy": "severity: CRITICAL,HIGH",
		"runtime image scan failure":                 `exit-code: "1"`,
	})

	goMod := readRepositoryFile(t, "go.mod")
	match := regexp.MustCompile(`(?m)^go ([0-9.]+)$`).FindStringSubmatch(goMod)
	if len(match) != 2 {
		t.Fatal("go.mod does not contain one parseable Go directive")
	}
	if !strings.Contains(workflow, "EXPECTED_GO_VERSION: go"+match[1]) {
		t.Fatalf("CI expected Go version does not match go.mod Go %s", match[1])
	}
	assertImmutableActionPins(t, ".github/workflows/test.yml", workflow)
}

func TestReleaseScansEveryConfiguredBinaryBeforePublication(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/release.yml")
	requireContains(t, ".github/workflows/release.yml", workflow, map[string]string{
		"race tests":                    "go test -race ./...",
		"source vulnerability scan":     "govulncheck -show verbose ./...",
		"test vulnerability scan":       "govulncheck -test -show verbose ./...",
		"draft release construction":    "args: release --clean --draft",
		"draft binary scanning":         "scripts/scan-release-binaries.sh dist",
		"publication of verified draft": `gh release edit "${GITHUB_REF_NAME}" --draft=false`,
	})
	scanIndex := strings.Index(workflow, "scripts/scan-release-binaries.sh dist")
	publishIndex := strings.Index(workflow, `gh release edit "${GITHUB_REF_NAME}" --draft=false`)
	if scanIndex < 0 || publishIndex < 0 || scanIndex >= publishIndex {
		t.Fatal("release publication is not ordered after draft-binary scanning")
	}
	assertImmutableActionPins(t, ".github/workflows/release.yml", workflow)

	var releaseConfig struct {
		Builds []struct {
			Binary string `yaml:"binary"`
		} `yaml:"builds"`
	}
	if err := yaml.Unmarshal([]byte(readRepositoryFile(t, ".goreleaser.yaml")), &releaseConfig); err != nil {
		t.Fatalf("decode .goreleaser.yaml: %v", err)
	}
	if len(releaseConfig.Builds) == 0 {
		t.Fatal("release configuration contains no binaries")
	}
	scanner := readRepositoryFile(t, "scripts/scan-release-binaries.sh")
	for _, build := range releaseConfig.Builds {
		binary := strings.TrimSpace(build.Binary)
		if binary == "" || !strings.Contains(scanner, "-name "+binary) {
			t.Errorf("release binary %q is not selected by the release scanner", binary)
		}
	}
	requireContains(t, "scripts/scan-release-binaries.sh", scanner, map[string]string{
		"toolchain metadata inspection":  `go version -m "$binary"`,
		"binary vulnerability scanning":  `"$scanner" -mode binary "$binary"`,
		"failure when no binaries exist": "no release binaries found",
	})
}

func TestAllCommandAndContainerBuildContractsRemainScannable(t *testing.T) {
	commandScanner := readRepositoryFile(t, "scripts/scan-go-binaries.sh")
	requireContains(t, "scripts/scan-go-binaries.sh", commandScanner, map[string]string{
		"dynamic discovery of every command":     `./cmd/...`,
		"building every discovered main package": `go build -trimpath -o "$binary" "$package"`,
		"toolchain metadata inspection":          `go version -m "$binary"`,
		"binary vulnerability scanning":          `"$scanner" -mode binary "$binary"`,
	})

	dockerfile := readRepositoryFile(t, "Dockerfile")
	fromPattern := regexp.MustCompile(`(?m)^FROM [^\s]+@sha256:[a-f0-9]{64}(?: AS \w+)?$`)
	if got := len(fromPattern.FindAllString(dockerfile, -1)); got != 2 {
		t.Fatalf("Dockerfile has %d digest-pinned FROM lines, want 2", got)
	}
	requireContains(t, "Dockerfile", dockerfile, map[string]string{
		"unstripped Go metadata": `-ldflags="-X main.version=${VERSION}"`,
		"non-root runtime":       "USER network-collector:network-collector",
		"the scanned executable": "COPY --from=build /out/network-collector /usr/local/bin/network-collector",
	})
}

func TestHostProcessExecutionRemainsIsolatedToAdminCredentialProviders(t *testing.T) {
	root := repositoryRoot(t)
	allowedExecImport := filepath.FromSlash("pkg/credentials/enterprise.go")
	foundAllowedImport := false
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".gocache", ".gomodcache", ".security-private", "dist", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{"syscall.Exec(", "os.StartProcess("} {
			if strings.Contains(string(source), forbidden) {
				t.Errorf("%s introduces an unapproved host-process sink %q", relative, forbidden)
			}
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			if imported.Path.Value != `"os/exec"` {
				continue
			}
			if relative != allowedExecImport {
				t.Errorf("%s imports os/exec outside the administrator-controlled credential provider", relative)
			} else {
				foundAllowedImport = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !foundAllowedImport {
		t.Fatalf("%s no longer contains the explicitly reviewed process-execution boundary", allowedExecImport)
	}
}

func assertImmutableActionPins(t *testing.T, name, workflow string) {
	t.Helper()
	usePattern := regexp.MustCompile(`(?m)^\s*uses:\s*([^#\s]+)`)
	shaPattern := regexp.MustCompile(`^[^@]+@[a-f0-9]{40}$`)
	for _, match := range usePattern.FindAllStringSubmatch(workflow, -1) {
		if !shaPattern.MatchString(match[1]) {
			t.Errorf("%s action is not pinned to a full commit SHA: %s", name, match[1])
		}
	}
}
