//go:build unix

package secureartifact

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestOpenFileNoFollow_PreExisting0644File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.log")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenFile(path, os.O_APPEND|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if !os.SameFile(before, opened) {
		_ = file.Close()
		t.Fatal("opened descriptor does not refer to the expected pre-existing file")
	}
	if opened.Mode().Perm() != FileMode {
		_ = file.Close()
		t.Fatalf("opened descriptor mode = %#o, want %#o", opened.Mode().Perm(), FileMode)
	}
	if _, err := file.WriteString("+new"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old+new" {
		t.Fatalf("append did not preserve existing content: %q", content)
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
	dir, err := os.MkdirTemp("/tmp", "nc-artifact-open-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fifo := filepath.Join(dir, "artifact.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	if err := WriteFile(fifo, []byte("unsafe")); err == nil {
		t.Fatal("FIFO artifact target was accepted")
	}

	socketDir, err := os.MkdirTemp("/tmp", "nc-artifact-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "artifact.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("create Unix socket: %v", err)
	}
	defer listener.Close()
	if err := WriteFile(socket, []byte("unsafe")); err == nil {
		t.Fatal("Unix socket artifact target was accepted")
	}
}

func TestOpenFileNoFollow_SpecialFileTargets(t *testing.T) {
	if fifo := os.Getenv("NETWORK_COLLECTOR_TEST_ARTIFACT_FIFO"); fifo != "" {
		if file, err := OpenFile(fifo, os.O_WRONLY); err == nil {
			_ = file.Close()
			t.Fatal("FIFO artifact target was accepted")
		}
		return
	}

	dir, err := os.MkdirTemp("/tmp", "nc-artifact-special-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fifo := filepath.Join(dir, "artifact.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOpenFileNoFollow_SpecialFileTargets$")
	command.Env = append(os.Environ(), "NETWORK_COLLECTOR_TEST_ARTIFACT_FIFO="+fifo)
	if output, err := command.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("FIFO rejection blocked until timeout: %v", ctx.Err())
		}
		t.Fatalf("FIFO rejection helper failed: %v\n%s", err, output)
	}

	socket := filepath.Join(dir, "artifact.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	directory := filepath.Join(dir, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	targets := []string{socket, directory}
	if _, err := os.Stat("/dev/null"); err == nil {
		targets = append(targets, "/dev/null")
	}
	for _, target := range targets {
		t.Run(filepath.Base(target), func(t *testing.T) {
			if file, err := OpenFile(target, os.O_WRONLY); err == nil {
				_ = file.Close()
				t.Fatalf("special artifact target %q was accepted", target)
			}
			link := filepath.Join(dir, "link-"+filepath.Base(target))
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if file, err := OpenFile(link, os.O_WRONLY); err == nil {
				_ = file.Close()
				t.Fatalf("symlink to special artifact target %q was accepted", target)
			}
		})
	}
}

func TestWriteFileAtomicNoFollow_ConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "artifacts")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "result.json")
	initial := strings.Repeat("I", 4096)
	if err := WriteFile(path, []byte(initial)); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}

	const writerCount = 24
	payloads := make([]string, writerCount)
	allowed := map[string]bool{initial: true}
	for index := range payloads {
		header := fmt.Sprintf("%04d:", index)
		payloads[index] = header + strings.Repeat(string(rune('A'+index)), len(initial)-len(header))
		allowed[payloads[index]] = true
	}

	start := make(chan struct{})
	done := make(chan struct{})
	errors := make(chan error, writerCount+8)
	var readers sync.WaitGroup
	for index := 0; index < 8; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for {
				select {
				case <-done:
					return
				default:
				}
				content, err := os.ReadFile(path)
				if err != nil {
					errors <- fmt.Errorf("concurrent reader: %w", err)
					return
				}
				if !allowed[string(content)] {
					errors <- fmt.Errorf("concurrent reader observed partial or interleaved payload")
					return
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for _, payload := range payloads {
		payload := payload
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			if err := WriteFile(path, []byte(payload)); err != nil {
				errors <- fmt.Errorf("concurrent writer: %w", err)
			}
		}()
	}
	close(start)
	writers.Wait()
	close(done)
	readers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	final := string(content)
	if final == initial || !allowed[final] {
		t.Fatalf("final content is not one complete submitted replacement")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("final artifact mode = %v, want owner-only regular file", info.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary artifact remained after concurrent replacement: %s", entry.Name())
		}
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "unchanged" {
		t.Fatalf("concurrent replacement modified outside object: content=%q error=%v", content, err)
	}
}

func TestWriteFileAtomic_FailureBeforeRenamePreservesOldArtifact(t *testing.T) {
	for _, test := range []struct {
		name   string
		inject func(*testing.T, atomicWriteOperations) atomicWriteOperations
	}{
		{
			name: "fsync",
			inject: func(t *testing.T, operations atomicWriteOperations) atomicWriteOperations {
				t.Helper()
				operations.syncFile = func(file *os.File) error {
					info, err := file.Stat()
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm()&0o077 != 0 {
						t.Fatalf("temporary artifact mode = %#o, want owner-only", info.Mode().Perm())
					}
					return errors.New("injected fsync failure")
				}
				return operations
			},
		},
		{
			name: "rename",
			inject: func(t *testing.T, operations atomicWriteOperations) atomicWriteOperations {
				t.Helper()
				originalSync := operations.syncFile
				operations.syncFile = func(file *os.File) error {
					info, err := file.Stat()
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm()&0o077 != 0 {
						t.Fatalf("temporary artifact mode = %#o, want owner-only", info.Mode().Perm())
					}
					return originalSync(file)
				}
				operations.renameAt = func(int, string, int, string) error {
					return errors.New("injected rename failure")
				}
				return operations
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "result.json")
			if err := WriteFile(path, []byte("previous-complete-artifact")); err != nil {
				t.Fatal(err)
			}
			operations := test.inject(t, defaultAtomicWriteOperations())
			err := writeFileAtomicNoFollowWithOperations(path, []byte("new-complete-artifact"), operations)
			if err == nil || !strings.Contains(err.Error(), "injected "+test.name+" failure") {
				t.Fatalf("injected %s failure was not returned: %v", test.name, err)
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(content) != "previous-complete-artifact" {
				t.Fatalf("failure replaced or partially modified old artifact: %q", content)
			}
			entries, readDirErr := os.ReadDir(dir)
			if readDirErr != nil {
				t.Fatal(readDirErr)
			}
			if len(entries) != 1 || entries[0].Name() != "result.json" {
				t.Fatalf("failure left temporary filesystem objects: %+v", entries)
			}
		})
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

func TestTrustedSystemSymlinkMetadataPredicate(t *testing.T) {
	tests := []struct {
		name                  string
		symlinkUID, parentUID uint32
		parentMode            os.FileMode
		trusted               bool
	}{
		{name: "root-controlled", symlinkUID: 0, parentUID: 0, parentMode: 0o755, trusted: true},
		{name: "user-owned-link", symlinkUID: 501, parentUID: 0, parentMode: 0o755},
		{name: "user-owned-parent", symlinkUID: 0, parentUID: 501, parentMode: 0o755},
		{name: "group-writable-parent", symlinkUID: 0, parentUID: 0, parentMode: 0o775},
		{name: "world-writable-parent", symlinkUID: 0, parentUID: 0, parentMode: 0o777},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := trustedSystemSymlinkMetadata(test.symlinkUID, test.parentUID, test.parentMode); got != test.trusted {
				t.Fatalf("trustedSystemSymlinkMetadata() = %v, want %v", got, test.trusted)
			}
		})
	}
}

func TestCanonicalizeTrustedSystemSymlinks_RejectsNonRootOwned(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.Symlink(target, second); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, first); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(first, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(second, 65534, -1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := canonicalizeTrustedSystemSymlinks(filepath.Join(first, "artifact")); err == nil ||
		!strings.Contains(err.Error(), "untrusted symlink component") {
		t.Fatalf("non-root-owned symlink chain was not rejected: %v", err)
	}
}
