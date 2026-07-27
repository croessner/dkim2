//go:build darwin

package signingstore

import "golang.org/x/sys/unix"

// descriptorTimestamps returns Darwin descriptor mutation timestamps.
func descriptorTimestamps(state unix.Stat_t) (int64, int64, int64, int64) {
	return state.Mtim.Sec, state.Mtim.Nsec, state.Ctim.Sec, state.Ctim.Nsec
}
