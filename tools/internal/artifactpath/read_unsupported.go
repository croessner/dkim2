//go:build !darwin && !linux

// Package artifactpath owns descriptor-safe artifact reads.
package artifactpath

import (
	"errors"
	"os"
)

// ReadFile rejects platforms without descriptor-relative file operations.
func ReadFile(string, string, int64) ([]byte, error) {
	return nil, errors.New("artifact_platform")
}

// SnapshotFile rejects platforms without descriptor-relative file operations.
func SnapshotFile(string, string, int64) (FileSnapshot, error) {
	return FileSnapshot{}, errors.New("artifact_platform")
}

// createFile rejects platforms without descriptor-relative file operations.
func createFile(string, string) (*os.File, error) {
	return nil, errors.New("artifact_platform")
}

// openFile rejects platforms without descriptor-relative file operations.
func openFile(string, string, int64) (*os.File, error) {
	return nil, errors.New("artifact_platform")
}

// snapshotOpenFile rejects platforms without descriptor-relative file operations.
func snapshotOpenFile(*os.File, int64) (FileSnapshot, error) {
	return FileSnapshot{}, errors.New("artifact_platform")
}

// snapshotTree rejects platforms without descriptor-relative file operations.
func snapshotTree(string, string, int, int64) ([]TreeEntry, error) {
	return nil, errors.New("artifact_platform")
}
