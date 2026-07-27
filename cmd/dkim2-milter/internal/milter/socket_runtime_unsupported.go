//go:build !linux && !darwin

package milter

import (
	"net"
	"os"
)

type ownedSocket struct{}

// openSocketListener fails closed on platforms without maintained socket evidence.
func openSocketListener(string, os.FileMode) (*net.UnixListener, *ownedSocket, error) {
	return nil, nil, &Error{Class: FailureContract}
}

// cleanup is unreachable because unsupported platforms cannot bind.
func (*ownedSocket) cleanup() error {
	return &Error{Class: FailureContract}
}
