//go:build !linux && !darwin

package config

import "context"

// ReadProtectedDocument rejects platforms without the central descriptor authority.
func ReadProtectedDocument(string, int) ([]byte, error) {
	return nil, newError(CodeProtectedUnsupported)
}

// ReadProtectedDocumentIfExists rejects platforms without descriptor-native protected reads.
func ReadProtectedDocumentIfExists(string, int) ([]byte, bool, error) {
	return nil, false, newError(CodeProtectedUnsupported)
}

// CreateProtectedDocument rejects platforms without descriptor-native protected creation.
func CreateProtectedDocument(context.Context, string, []byte, int) error {
	return newError(CodeProtectedUnsupported)
}
