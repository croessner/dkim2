//go:build !darwin && !linux

package main

import (
	"errors"
	"os"
)

// cloneFile rejects platforms without descriptor-based copy-on-write cloning.
func cloneFile(*os.File, string) error {
	return errors.New("database_clone_platform")
}
