//go:build !unix

package secureartifact

import (
	"fmt"
	"os"
	"path/filepath"
)

func ensureDirNoFollow(path string) error {
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

func openFileNoFollow(path string, flags int) (*os.File, error) {
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

func writeFileAtomicNoFollow(path string, content []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("artifact path %q must be a regular, non-symlink file", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(FileMode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}
