//go:build unix

package credentials

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func secureOpenCredentialFile(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	// #nosec G115 -- unix.Open returned a valid non-negative native file
	// descriptor; os.NewFile requires its uintptr representation.
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("create credential file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}
