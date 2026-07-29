//go:build darwin && !cgo

package securefile

// descriptorAccessFingerprint rejects protected loading without Darwin ACL inspection.
func descriptorAccessFingerprint(_ int, _ bool, _ uint32) ([32]byte, error) {
	return [32]byte{}, &Error{}
}

// rootDescriptorAccessFingerprint preserves the fail-closed no-CGO policy.
func rootDescriptorAccessFingerprint(fd int, acceptedMode uint32) ([32]byte, error) {
	return descriptorAccessFingerprint(fd, true, acceptedMode)
}

// ancestryDescriptorAccessFingerprint preserves the fail-closed no-CGO policy.
func ancestryDescriptorAccessFingerprint(fd int, acceptedMode uint32) ([32]byte, error) {
	return descriptorAccessFingerprint(fd, true, acceptedMode)
}
