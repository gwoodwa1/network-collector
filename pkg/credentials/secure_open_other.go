//go:build !unix

package credentials

import (
	"fmt"
	"os"
)

func secureOpenCredentialFile(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("symbolic links are not allowed")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("credential file changed while opening")
	}
	return file, opened, nil
}
