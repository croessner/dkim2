//go:build !darwin && !linux

package main

import "errors"

type safeRoot struct{}

// openSafeRoot rejects platforms without descriptor-relative confinement.
func openSafeRoot(string) (*safeRoot, error) {
	return nil, errors.New("unsupported")
}

// close releases no state on unsupported platforms.
func (s *safeRoot) close() {}

// prepareDirectory rejects unsupported platforms.
func (s *safeRoot) prepareDirectory(string) error {
	return errors.New("unsupported")
}

// validateFile rejects unsupported platforms.
func (s *safeRoot) validateFile(string) error {
	return errors.New("unsupported")
}

// installFile rejects unsupported platforms.
func (s *safeRoot) installFile(string, string, bool) error {
	return errors.New("unsupported")
}

// replaceFile rejects unsupported platforms.
func (s *safeRoot) replaceFile(string, string, bool) error {
	return errors.New("unsupported")
}
