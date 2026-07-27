//go:build unix

package credentials

import (
	"fmt"
	"os"
	"syscall"
)

func validateProviderExecutablePermissions(fileInfo, parentInfo os.FileInfo) error {
	fileStat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect executable ownership")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect parent ownership")
	}
	euid := os.Geteuid()
	if fileStat.Uid != 0 && int64(fileStat.Uid) != int64(euid) {
		return fmt.Errorf("executable must be owned by root or the collector account")
	}
	if fileInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("executable must not be group- or world-writable")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("inspect collector groups: %w", err)
	}
	inParentGroup := int64(parentStat.Gid) == int64(os.Getegid())
	for _, group := range groups {
		if int64(parentStat.Gid) == int64(group) {
			inParentGroup = true
			break
		}
	}
	mode := parentInfo.Mode().Perm()
	switch {
	case int64(parentStat.Uid) == int64(euid) && mode&0200 != 0:
		return fmt.Errorf("parent directory is writable by the collector account")
	case inParentGroup && mode&0020 != 0:
		return fmt.Errorf("parent directory is group-writable by the collector account")
	case mode&0002 != 0:
		return fmt.Errorf("parent directory is world-writable")
	}
	return nil
}
