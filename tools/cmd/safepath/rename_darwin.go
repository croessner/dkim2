//go:build darwin

package main

import "golang.org/x/sys/unix"

// renameNoReplace publishes one target without replacing an existing entry.
func renameNoReplace(parent int, source string, target string) error {
	return unix.RenameatxNp(parent, source, parent, target, unix.RENAME_EXCL)
}
