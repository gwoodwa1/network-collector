//go:build unix

package secureartifact

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
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
	if err := WriteFile(link, []byte("replacement")); err == nil {
		t.Fatal("symlink artifact was accepted for atomic replacement")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "target" {
		t.Fatalf("symlink target was modified: %q", content)
	}
}

func TestRejectsSymlinkDirectoryComponent(t *testing.T) {
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

func TestWriteFileRejectsFIFOAndUnixSocketTargets(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "artifact.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	if err := WriteFile(fifo, []byte("unsafe")); err == nil {
		t.Fatal("FIFO artifact target was accepted")
	}

	socket := filepath.Join(dir, "artifact.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("create Unix socket: %v", err)
	}
	defer listener.Close()
	if err := WriteFile(socket, []byte("unsafe")); err == nil {
		t.Fatal("Unix socket artifact target was accepted")
	}
}

func TestHardLinkOpenIsRejectedAndAtomicWriteDoesNotModifyOtherLink(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(original, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, artifact); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenFile(artifact, os.O_WRONLY|os.O_TRUNC); err == nil {
		t.Fatal("artifact with an additional hard link was opened")
	}
	if content, err := os.ReadFile(original); err != nil || string(content) != "original" {
		t.Fatalf("rejected open changed original: content=%q error=%v", content, err)
	}

	if err := WriteFile(artifact, []byte("replacement")); err != nil {
		t.Fatalf("atomic replacement of hard-link name failed: %v", err)
	}
	if content, err := os.ReadFile(original); err != nil || string(content) != "original" {
		t.Fatalf("atomic write changed other hard link: content=%q error=%v", content, err)
	}
	if content, err := os.ReadFile(artifact); err != nil || string(content) != "replacement" {
		t.Fatalf("artifact was not safely replaced: content=%q error=%v", content, err)
	}
}
