//go:build unix

package secureartifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func pathParts(path string) (int, []string, error) {
	cleaned, err := canonicalizeTrustedSystemSymlinks(filepath.Clean(path))
	if err != nil {
		return -1, nil, err
	}
	start := "."
	if filepath.IsAbs(cleaned) {
		start = string(filepath.Separator)
		cleaned = strings.TrimPrefix(cleaned, string(filepath.Separator))
	}
	parts := strings.Split(cleaned, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return -1, nil, fmt.Errorf("artifact path %q must not contain parent traversal", path)
		}
	}
	fd, err := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	return fd, parts, nil
}

// canonicalizeTrustedSystemSymlinks permits conventional root-controlled
// filesystem aliases such as macOS /var -> /private/var. Symlinks owned by a
// non-root user or located in a writable parent remain forbidden.
func canonicalizeTrustedSystemSymlinks(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return path, nil
	}
	for attempts := 0; attempts < 16; attempts++ {
		parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
		prefix := string(filepath.Separator)
		for index, part := range parts {
			if part == "" {
				continue
			}
			prefix = filepath.Join(prefix, part)
			info, err := os.Lstat(prefix)
			if err != nil {
				if os.IsNotExist(err) {
					return path, nil
				}
				return "", err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			parentInfo, parentErr := os.Stat(filepath.Dir(prefix))
			if !ok || parentErr != nil || stat.Uid != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
				return "", fmt.Errorf("artifact path %q contains untrusted symlink component %q", path, prefix)
			}
			resolved, err := filepath.EvalSymlinks(prefix)
			if err != nil {
				return "", err
			}
			path = filepath.Join(append([]string{resolved}, parts[index+1:]...)...)
			break
		}
		return path, nil
	}
	return "", fmt.Errorf("artifact path %q contains too many symbolic links", path)
}

func openDirectoryAt(parent int, name string) (int, error) {
	return unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func walkParentNoFollow(path string) (int, string, error) {
	fd, parts, err := pathParts(path)
	if err != nil {
		return -1, "", err
	}
	if len(parts) == 0 || parts[len(parts)-1] == "." || parts[len(parts)-1] == "" {
		_ = unix.Close(fd)
		return -1, "", fmt.Errorf("artifact path %q must name a file", path)
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." {
			continue
		}
		next, err := openDirectoryAt(fd, part)
		_ = unix.Close(fd)
		if err != nil {
			return -1, "", fmt.Errorf("open artifact directory component %q: %w", part, err)
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

func unixOpenFlags(flags int) int {
	result := unix.O_CLOEXEC | unix.O_NOFOLLOW
	switch {
	case flags&os.O_RDWR != 0:
		result |= unix.O_RDWR
	case flags&os.O_WRONLY != 0:
		result |= unix.O_WRONLY
	default:
		result |= unix.O_RDONLY
	}
	for _, mapping := range []struct {
		osFlag, unixFlag int
	}{
		{os.O_APPEND, unix.O_APPEND},
		{os.O_CREATE, unix.O_CREAT},
		{os.O_EXCL, unix.O_EXCL},
		{os.O_SYNC, unix.O_SYNC},
		{os.O_TRUNC, unix.O_TRUNC},
	} {
		if flags&mapping.osFlag != 0 {
			result |= mapping.unixFlag
		}
	}
	return result
}

func openFileNoFollow(path string, flags int) (*os.File, error) {
	parent, name, err := walkParentNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unixOpenFlags(flags), uint32(FileMode))
	if err != nil {
		return nil, fmt.Errorf("open private artifact %q: %w", path, err)
	}
	// #nosec G115 -- unix.Openat returned a valid non-negative file descriptor.
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open private artifact %q: invalid file descriptor", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("artifact path %q must be a regular file", path)
	}
	if err := file.Chmod(FileMode); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func ensureDirNoFollow(path string) error {
	fd, parts, err := pathParts(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, openErr := openDirectoryAt(fd, part)
		if openErr != nil {
			if openErr != unix.ENOENT {
				return fmt.Errorf("open artifact directory component %q: %w", part, openErr)
			}
			if err := unix.Mkdirat(fd, part, uint32(DirMode)); err != nil && err != unix.EEXIST {
				return fmt.Errorf("create artifact directory component %q: %w", part, err)
			}
			next, openErr = openDirectoryAt(fd, part)
			if openErr != nil {
				return fmt.Errorf("open created artifact directory component %q: %w", part, openErr)
			}
		}
		_ = unix.Close(fd)
		fd = next
		if index == len(parts)-1 {
			if err := unix.Fchmod(fd, uint32(DirMode)); err != nil {
				return fmt.Errorf("set private artifact directory mode: %w", err)
			}
		}
	}
	return nil
}
