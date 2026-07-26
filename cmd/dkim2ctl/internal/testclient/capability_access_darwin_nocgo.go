//go:build darwin && !cgo

package testclient

// inspectCapabilityAccess fails closed without libc ACL inspection.
func inspectCapabilityAccess(_ int) error {
	return NewExitError(ExitCapability)
}
