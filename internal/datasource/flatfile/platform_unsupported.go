//go:build !linux && !darwin

package flatfile

import "errors"

// newFilesystemOps rejects targets without the required confined descriptor primitives.
func newFilesystemOps() (filesystemOps, error) {
	return nil, errors.New("unsupported")
}
