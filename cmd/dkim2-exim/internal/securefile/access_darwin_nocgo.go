//go:build darwin && !cgo

package securefile

// descriptorAccessFingerprint rejects protected loading without Darwin ACL inspection.
func descriptorAccessFingerprint(_ int, _ bool, _ uint32) ([32]byte, error) {
	return [32]byte{}, &Error{}
}
