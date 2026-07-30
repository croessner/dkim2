//go:build !linux && !darwin

package signingstore

func openRegistrySourceParent(int) (int, error) { return -1, &Error{} }

func openRegistryGeneration(int, string) (int, error) { return -1, &Error{} }
