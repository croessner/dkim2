//go:build linux

package main

import "golang.org/x/sys/unix"

// renameNoReplace publishes one target without replacing an existing entry.
func renameNoReplace(parent int, source string, target string) error {
	return unix.Renameat2(parent, source, parent, target, unix.RENAME_NOREPLACE)
}
