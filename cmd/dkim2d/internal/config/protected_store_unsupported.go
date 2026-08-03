//go:build !linux && !darwin

package config

import "context"

type protectedStoreObserver func(protectedStoreEvent)

type protectedStoreEvent uint8

type protectedStorePlatform struct{}

func openProtectedStore(context.Context, string, int, protectedStoreObserver) (*ProtectedStore, error) {
	return nil, newError(CodeProtectedUnsupported)
}

// openExistingProtectedStore rejects platforms without descriptor-native protected stores.
func openExistingProtectedStore(context.Context, string, int, protectedStoreObserver) (*ProtectedStore, error) {
	return nil, newError(CodeProtectedUnsupported)
}

func (protectedStorePlatform) read(context.Context) ([]byte, bool, error) {
	return nil, false, newError(CodeProtectedUnsupported)
}

func (protectedStorePlatform) replace(context.Context, []byte) error {
	return newError(CodeProtectedUnsupported)
}

func (protectedStorePlatform) close() error { return nil }
