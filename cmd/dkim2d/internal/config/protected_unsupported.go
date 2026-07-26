//go:build !linux && !darwin

package config

// LoadProtected rejects platforms without descriptor-native protected-file support.
func LoadProtected(string, FlagValues) (*Prebootstrap, error) {
	return nil, newError(CodeProtectedUnsupported)
}
