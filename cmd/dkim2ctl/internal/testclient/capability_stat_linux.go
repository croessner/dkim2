//go:build linux

package testclient

import "golang.org/x/sys/unix"

// capabilityMetadataFromStat converts Linux descriptor state into the common snapshot.
func capabilityMetadataFromStat(state unix.Stat_t) capabilityMetadata {
	return capabilityMetadata{
		device: uint64(state.Dev), inode: state.Ino, mode: uint32(state.Mode),
		uid: state.Uid, links: uint64(state.Nlink), size: state.Size,
		mtimeSec: state.Mtim.Sec, mtimeNsec: state.Mtim.Nsec,
		ctimeSec: state.Ctim.Sec, ctimeNsec: state.Ctim.Nsec,
	}
}
