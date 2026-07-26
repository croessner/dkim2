//go:build !linux && !darwin

package config

// statDescriptor rejects descriptor metadata inspection on unsupported
// platforms.
func statDescriptor(_ int) (descriptorMetadata, error) {
	return descriptorMetadata{}, newError(CodeProtectedUnsupported)
}

// statAtNoFollow rejects descriptor-relative child inspection on unsupported
// platforms.
func statAtNoFollow(_ int, _ string) (descriptorMetadata, error) {
	return descriptorMetadata{}, newError(CodeProtectedUnsupported)
}
