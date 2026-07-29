//go:build linux

package main

import "golang.org/x/sys/unix"

// platformFlagsSafe accepts Linux metadata after descriptor and mode validation.
func platformFlagsSafe(stat *unix.Stat_t) bool {
	return stat != nil
}
