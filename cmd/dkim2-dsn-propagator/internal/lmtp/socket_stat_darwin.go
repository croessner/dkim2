//go:build darwin

package lmtp

import "golang.org/x/sys/unix"

// socketStateFromStat projects Darwin metadata without truncation.
func socketStateFromStat(state unix.Stat_t) socketFileState {
	return socketFileState{
		device: uint64(state.Dev), inode: state.Ino, uid: state.Uid, gid: state.Gid,
		mode: uint32(state.Mode), links: uint64(state.Nlink),
	}
}
