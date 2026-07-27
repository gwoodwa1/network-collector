// Package secureartifact creates operational artifacts with owner-only access.
package secureartifact

import (
	"os"
)

const (
	DirMode  = 0o700
	FileMode = 0o600
)

// EnsureDir creates path and tightens an existing directory to owner-only access.
func EnsureDir(path string) error {
	return ensureDirNoFollow(path)
}

// OpenFile opens a regular, non-symlink artifact and tightens its mode even
// when the file existed before this process started.
func OpenFile(path string, flags int) (*os.File, error) {
	return openFileNoFollow(path, flags)
}

// WriteFile replaces a private artifact's content.
func WriteFile(path string, content []byte) error {
	return writeFileAtomicNoFollow(path, content)
}
