//go:build !unix

package secureartifact

import (
	"fmt"
	"os"
)

func ensureDirNoFollow(path string) error {
	return unsupportedPlatformError("create artifact directory", path)
}

func openFileNoFollow(path string, _ int) (*os.File, error) {
	return nil, unsupportedPlatformError("open artifact", path)
}

func writeFileAtomicNoFollow(path string, _ []byte) error {
	return unsupportedPlatformError("write artifact", path)
}

func unsupportedPlatformError(operation, path string) error {
	return fmt.Errorf("%w: cannot %s %q", ErrUnsupportedPlatform, operation, path)
}
