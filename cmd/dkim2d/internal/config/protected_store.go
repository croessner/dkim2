package config

import (
	"context"
	"fmt"
	"io"
)

// ProtectedStore serializes one bounded owner-only replaceable document through a stable sibling lock.
type ProtectedStore struct {
	platform protectedStorePlatform
}

// OpenProtectedStore acquires and verifies one descriptor-native protected document transaction.
func OpenProtectedStore(ctx context.Context, path string, maximum int) (*ProtectedStore, error) {
	return openProtectedStore(ctx, path, maximum, nil)
}

// OpenExistingProtectedStore acquires an already-established transaction lock without creating artifacts.
func OpenExistingProtectedStore(ctx context.Context, path string, maximum int) (*ProtectedStore, error) {
	return openExistingProtectedStore(ctx, path, maximum, nil)
}

// Read returns detached protected bytes and whether the document exists.
func (s *ProtectedStore) Read(ctx context.Context) ([]byte, bool, error) {
	if s == nil {
		return nil, false, newError(CodeProtectedClosed)
	}
	return s.platform.read(ctx)
}

// Replace atomically replaces the protected document while retaining the stable sibling lock.
func (s *ProtectedStore) Replace(ctx context.Context, content []byte) error {
	if s == nil {
		return newError(CodeProtectedClosed)
	}
	return s.platform.replace(ctx, content)
}

// Close releases the stable sibling lock and retained directory descriptors.
func (s *ProtectedStore) Close() error {
	if s == nil {
		return nil
	}
	return s.platform.close()
}

// String returns a constant protected store representation.
func (*ProtectedStore) String() string { return protectedRedactedText }

// GoString returns a constant protected store representation.
func (*ProtectedStore) GoString() string { return protectedRedactedText }

// Format prevents protected paths and document state from reaching formatting sinks.
func (*ProtectedStore) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, protectedRedactedText)
}

// MarshalJSON rejects generic protected-store serialization.
func (*ProtectedStore) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }
