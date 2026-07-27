//go:build !linux && !darwin

package signingstore

// duplicateRootDescriptor fails closed on unreviewed platforms.
func duplicateRootDescriptor(int) (int, error) { return -1, &Error{} }

// closeRootDescriptor fails closed on unreviewed platforms.
func closeRootDescriptor(int) error { return &Error{} }
