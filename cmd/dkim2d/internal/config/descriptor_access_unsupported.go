//go:build !linux && !darwin

package config

// inspectDescriptorAccess rejects protected descriptor inspection on
// platforms without an approved filesystem and descriptor-native ACL policy.
func inspectDescriptorAccess(_ int, _ bool, _ uint32) error {
	return newError(CodeProtectedUnsupported)
}

// inspectTrustedRootAccess rejects root inspection on unsupported platforms.
func inspectTrustedRootAccess(_ int, _ uint32) error {
	return newError(CodeProtectedUnsupported)
}

// inspectTrustedAncestorAccess rejects traversal on unsupported platforms.
func inspectTrustedAncestorAccess(_ int, _ uint32, _ bool) error {
	return newError(CodeProtectedUnsupported)
}

// descriptorAccessFingerprint rejects protected descriptor inspection on
// platforms without an approved filesystem and descriptor-native ACL policy.
func descriptorAccessFingerprint(_ int, _ bool, _ uint32) ([32]byte, error) {
	return [32]byte{}, newError(CodeProtectedUnsupported)
}
