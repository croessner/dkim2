//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"golang.org/x/sys/unix"
)

const unixgramNetwork = "unixgram"

// unixgramSink owns one bounded protected local datagram connection.
type unixgramSink struct{ connection *net.UnixConn }

// String prevents destination or descriptor disclosure.
func (unixgramSink) String() string { return "runtime.unixgramSink{redacted}" }

// GoString prevents destination or descriptor disclosure.
func (s unixgramSink) GoString() string { return s.String() }

// Format prevents formatter traversal into the retained connection.
func (s unixgramSink) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// MarshalJSON rejects serialization of the protected sink.
func (unixgramSink) MarshalJSON() ([]byte, error) { return nil, errRuntime }

// openUnixgramSink traverses a mode-0700 parent and verifies one mode-0600 socket.
func openUnixgramSink(path string) (sink *unixgramSink, identity securefile.Identity, resultErr error) {
	return openUnixgramSinkWith(path, nil, func(handle *securefile.DirectoryHandle) error {
		return handle.Close()
	})
}

// openUnixgramSinkWith exposes content-free replacement and close-failure test seams.
//
//nolint:gocyclo // The single descriptor transaction keeps every fail-closed recheck visibly ordered.
func openUnixgramSinkWith(
	path string,
	afterDial func(),
	closeDirectory func(*securefile.DirectoryHandle) error,
) (sink *unixgramSink, identity securefile.Identity, resultErr error) {
	if closeDirectory == nil {
		return nil, securefile.Identity{}, errRuntime
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 {
		return nil, securefile.Identity{}, errRuntime
	}
	name := filepath.Base(path)
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return nil, securefile.Identity{}, errRuntime
	}
	parentHandle, err := securefile.OpenDirectory(filepath.Dir(path), securefile.DirectoryRules{
		EffectiveUID: uint32(os.Geteuid()), Mode: 0o700,
	})
	if err != nil {
		return nil, securefile.Identity{}, errRuntime
	}
	defer func() {
		if closeErr := closeDirectory(parentHandle); closeErr != nil && resultErr == nil {
			if sink != nil {
				_ = sink.Close()
			}
			sink = nil
			identity = securefile.Identity{}
			resultErr = errRuntime
		}
	}()
	parent := parentHandle.Descriptor()
	var parentState, childBefore unix.Stat_t
	if parentHandle.Validate() != nil || unix.Fstat(parent, &parentState) != nil ||
		unix.Fstatat(parent, name, &childBefore, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		childBefore.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		childBefore.Mode&0o777 != 0o600 || childBefore.Uid != uint32(os.Geteuid()) ||
		childBefore.Gid != uint32(os.Getegid()) || childBefore.Nlink != 1 {
		return nil, securefile.Identity{}, errRuntime
	}
	address := "/proc/self/fd/" + strconv.Itoa(parent) + "/" + name
	connection, err := net.DialUnix(unixgramNetwork, nil, &net.UnixAddr{Name: address, Net: unixgramNetwork})
	if err != nil {
		return nil, securefile.Identity{}, errRuntime
	}
	// Linux reports unavailable SO_PEERCRED values for a client connected to an
	// unconnected filesystem datagram listener. The verified owner-only parent,
	// socket owner/mode, inode, and link count therefore
	// define the same-identity trust boundary and are rechecked after connect.
	if afterDial != nil {
		afterDial()
	}
	var childAfter unix.Stat_t
	if parentHandle.Validate() != nil ||
		unix.Fstatat(parent, name, &childAfter, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		childAfter.Dev != childBefore.Dev || childAfter.Ino != childBefore.Ino ||
		childAfter.Mode != childBefore.Mode || childAfter.Uid != childBefore.Uid ||
		childAfter.Gid != childBefore.Gid || childAfter.Nlink != childBefore.Nlink {
		_ = connection.Close()
		return nil, securefile.Identity{}, errRuntime
	}
	identity = securefile.NewIdentity(
		uint64(childBefore.Dev), childBefore.Ino, //nolint:unconvert // Normalize Stat_t.Dev across architectures.
		uint64(parentState.Dev), parentState.Ino, //nolint:unconvert // Normalize Stat_t.Dev across architectures.
	)
	return &unixgramSink{connection: connection}, identity, nil
}

// Write emits one complete bounded datagram without indefinite blocking.
func (s *unixgramSink) Write(value []byte) error {
	if s == nil || s.connection == nil || len(value) == 0 || len(value) > 4096 {
		return errRuntime
	}
	_ = s.connection.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	count, err := s.connection.Write(value)
	if err != nil || count != len(value) {
		return errRuntime
	}
	return nil
}

// Close releases the protected local datagram connection.
func (s *unixgramSink) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	err := s.connection.Close()
	s.connection = nil
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return errRuntime
	}
	return nil
}
