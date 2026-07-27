//go:build unix

package secureartifact

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateModesUnderUmask0022(t *testing.T) {
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)

	dir := filepath.Join(t.TempDir(), "artifacts")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "result.json")
	if err := WriteFile(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != DirMode {
		t.Fatalf("directory mode under umask 0022 = %#o, want %#o", got, DirMode)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != FileMode {
		t.Fatalf("file mode under umask 0022 = %#o, want %#o", got, FileMode)
	}
}
