package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func secureProviderExecutable(configuredPath, setting string) (string, error) {
	configuredPath = strings.TrimSpace(configuredPath)
	if configuredPath == "" {
		return "", fmt.Errorf("%s must name an administrator-controlled absolute executable path", setting)
	}
	if !filepath.IsAbs(configuredPath) {
		return "", fmt.Errorf("%s must be an absolute path", setting)
	}
	info, err := os.Lstat(configuredPath)
	if err != nil {
		return "", fmt.Errorf("inspect %s executable: %w", setting, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s must not reference a symbolic link", setting)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must reference a regular file", setting)
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%s is not executable", setting)
	}
	parent := filepath.Dir(configuredPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect %s parent directory: %w", setting, err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return "", fmt.Errorf("%s parent must be a real directory", setting)
	}
	if err := validateProviderExecutablePermissions(info, parentInfo); err != nil {
		return "", fmt.Errorf("%s is not administrator-controlled: %w", setting, err)
	}
	return filepath.Clean(configuredPath), nil
}
