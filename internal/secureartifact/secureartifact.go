// Package secureartifact creates operational artifacts with owner-only access.
package secureartifact

import (
	"errors"
	"os"
)

const (
	DirMode  = 0o700
	FileMode = 0o600
)

// ErrUnsupportedPlatform is returned when the operating system cannot provide
// the descriptor-relative no-follow operations required for secure artifacts.
var ErrUnsupportedPlatform = errors.New("secure artifact writing requires a supported Unix platform")

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
