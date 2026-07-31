//go:build linux

package inbound

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// samePeerUID admits only the configured exact Exim peer UID.
func samePeerUID(connection *net.UnixConn, expected uint32) bool {
	if connection == nil {
		return false
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	matched := false
	if raw.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		matched = credentialErr == nil && credential.Uid == expected && int(expected) == os.Geteuid()
	}) != nil {
		return false
	}
	return matched
}
