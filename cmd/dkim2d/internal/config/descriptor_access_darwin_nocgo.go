//go:build darwin && !cgo

package config

// inspectDescriptorAccess rejects protected descriptor inspection when Darwin
// libc ACL support is unavailable.
func inspectDescriptorAccess(_ int, _ bool, _ uint32) error {
	return newError(CodeProtectedUnsupported)
}

// inspectTrustedRootAccess rejects root inspection without Darwin ACL support.
func inspectTrustedRootAccess(_ int, _ uint32) error {
	return newError(CodeProtectedUnsupported)
}

// inspectTrustedAncestorAccess rejects traversal without Darwin ACL support.
func inspectTrustedAncestorAccess(_ int, _ uint32, _ bool) error {
	return newError(CodeProtectedUnsupported)
}

// descriptorAccessFingerprint rejects protected descriptor inspection when
// Darwin libc ACL support is unavailable.
func descriptorAccessFingerprint(_ int, _ bool, _ uint32) ([32]byte, error) {
	return [32]byte{}, newError(CodeProtectedUnsupported)
}
