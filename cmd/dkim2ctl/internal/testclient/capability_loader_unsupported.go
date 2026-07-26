//go:build !linux && !darwin

package testclient

// LoadCapability fails closed when descriptor-safe inspection is unavailable.
func LoadCapability(_ string) (*Capability, error) {
	return nil, NewExitError(ExitCapability)
}
