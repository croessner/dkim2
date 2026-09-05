//go:build !linux && !darwin

package daemon

// LoadCapability fails closed on unreviewed protected-file platforms.
func LoadCapability(string) (*Capability, error) { return nil, &Error{} }
