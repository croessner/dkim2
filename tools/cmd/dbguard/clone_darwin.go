//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// cloneFile creates one copy-on-write clone from an already-open source descriptor.
func cloneFile(source *os.File, target string) error {
	if source == nil {
		return errors.New("database_clone")
	}
	parent, err := os.Open(filepath.Dir(target))
	if err != nil {
		return errors.New("database_clone")
	}
	defer func() {
		_ = parent.Close()
	}()
	if err := unix.Fclonefileat(
		int(source.Fd()),
		int(parent.Fd()),
		filepath.Base(target),
		0,
	); err != nil {
		return errors.New("database_clone")
	}
	return nil
}
