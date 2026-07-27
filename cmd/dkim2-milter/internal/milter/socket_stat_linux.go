//go:build linux

package milter

import "golang.org/x/sys/unix"

// socketStateFromStat projects Linux metadata without lossy conversions.
func socketStateFromStat(state unix.Stat_t) socketFileState {
	return socketFileState{
		device: state.Dev, inode: state.Ino, uid: state.Uid, gid: state.Gid,
		// Nlink width differs between supported Linux architectures.
		mode: state.Mode, links: uint64(state.Nlink), //nolint:unconvert
	}
}
