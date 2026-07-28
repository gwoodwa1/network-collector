//go:build !unix

package secureartifact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactOperationsFailClosedWithoutCreatingPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "artifacts")
	path := filepath.Join(dir, "result.json")

	if err := EnsureDir(dir); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("EnsureDir error = %v, want ErrUnsupportedPlatform", err)
	}
	if _, err := OpenFile(path, os.O_CREATE|os.O_WRONLY); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("OpenFile error = %v, want ErrUnsupportedPlatform", err)
	}
	if err := WriteFile(path, []byte("{}")); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("WriteFile error = %v, want ErrUnsupportedPlatform", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("non-Unix artifact operation created %q: %v", dir, err)
	}
}
