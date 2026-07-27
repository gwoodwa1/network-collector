// Package secureartifact creates operational artifacts with owner-only access.
package secureartifact

import (
	"fmt"
	"os"
)

const (
	DirMode  = 0o700
	FileMode = 0o600
)

// EnsureDir creates path and tightens an existing directory to owner-only access.
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, DirMode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("artifact path %q must be a real directory", path)
	}
	return os.Chmod(path, DirMode)
}

// OpenFile opens a regular, non-symlink artifact and tightens its mode even
// when the file existed before this process started.
func OpenFile(path string, flags int) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("artifact path %q must be a regular, non-symlink file", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(path, flags, FileMode)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(FileMode); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// WriteFile replaces a private artifact's content.
func WriteFile(path string, content []byte) error {
	file, err := OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
