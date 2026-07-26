//go:build !linux && !darwin

package config

// inspectDescriptorAccess rejects protected descriptor inspection on
// platforms without an approved filesystem and descriptor-native ACL policy.
func inspectDescriptorAccess(_ int, _ bool, _ uint32) error {
	return newError(CodeProtectedUnsupported)
}

// descriptorAccessFingerprint rejects protected descriptor inspection on
// platforms without an approved filesystem and descriptor-native ACL policy.
func descriptorAccessFingerprint(_ int, _ bool, _ uint32) ([32]byte, error) {
	return [32]byte{}, newError(CodeProtectedUnsupported)
}
