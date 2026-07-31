//go:build !linux

package inbound

import "net"

// samePeerUID fails closed where Linux SO_PEERCRED is unavailable.
func samePeerUID(*net.UnixConn, uint32) bool { return false }
