//go:build !linux

package inbound

import (
	"errors"
	"net"
	"os"
)

type ownedSocket struct{}

func openSocketListener(string, os.FileMode) (*net.UnixListener, *ownedSocket, error) {
	return nil, nil, errors.New("unsupported inbound socket")
}

func (*ownedSocket) cleanup() error { return nil }
