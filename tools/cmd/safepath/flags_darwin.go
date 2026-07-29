//go:build darwin

package main

import "golang.org/x/sys/unix"

// platformFlagsSafe rejects ambient Darwin file flags on evidence.
func platformFlagsSafe(stat *unix.Stat_t) bool {
	return stat != nil && stat.Flags == 0
}
