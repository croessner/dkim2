//go:build linux

package signingstore

import "golang.org/x/sys/unix"

// descriptorTimestamps returns Linux descriptor mutation timestamps.
func descriptorTimestamps(state unix.Stat_t) (int64, int64, int64, int64) {
	return state.Mtim.Sec, state.Mtim.Nsec, state.Ctim.Sec, state.Ctim.Nsec
}
