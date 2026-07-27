package secureartifact

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateModesAndExistingArtifactRepair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "artifacts")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session.log")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := OpenFile(path, os.O_APPEND|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != DirMode {
		t.Fatalf("directory mode = %#o, want %#o", got, DirMode)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != FileMode {
		t.Fatalf("file mode = %#o, want %#o", got, FileMode)
	}
}

func TestOpenFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(link, os.O_WRONLY); err == nil {
		t.Fatal("symlink artifact was accepted")
	}
}

func TestRejectsSymlinkDirectoryComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "linked")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(filepath.Join(linkDir, "artifact"), os.O_CREATE|os.O_WRONLY); err == nil {
		t.Fatal("symlink directory component was accepted for a file")
	}
	if err := EnsureDir(filepath.Join(linkDir, "nested")); err == nil {
		t.Fatal("symlink directory component was accepted for a directory")
	}
}
