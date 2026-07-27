//go:build !unix

package credentials

import (
	"fmt"
	"os"
)

func validateProviderExecutablePermissions(fileInfo, parentInfo os.FileInfo) error {
	if fileInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("executable must not be group- or world-writable")
	}
	if parentInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("parent directory must not be group- or world-writable")
	}
	return nil
}
