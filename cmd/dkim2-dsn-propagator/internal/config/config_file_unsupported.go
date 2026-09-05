//go:build !linux && !darwin

package config

// readConfiguration fails closed on unreviewed configuration-file platforms.
func readConfiguration(string) ([]byte, error) { return nil, &Error{} }
