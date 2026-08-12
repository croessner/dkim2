//go:build linux || darwin

package milter

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	maxUnixSocketPathBytes = 103
	maxSocketPathParts     = 64
)

var socketUmaskMu sync.Mutex

type socketFileState struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
	links  uint64
}

type ownedSocket struct {
	parent int
	name   string
	state  socketFileState
}

// openSocketListener validates, binds, and verifies one owned socket inode.
func openSocketListener(path string, mode os.FileMode) (*net.UnixListener, *ownedSocket, error) {
	parent, name, err := openSocketParent(path)
	if err != nil {
		return nil, nil, err
	}
	socket := &ownedSocket{parent: parent, name: name}
	state, statErr := statSocketChild(parent, name)
	if statErr == nil || !errors.Is(statErr, unix.ENOENT) || state != (socketFileState{}) {
		_ = unix.Close(parent)
		return nil, nil, &Error{Class: FailureContract}
	}

	listener, err := bindSocketWithRestrictiveUmask(path, mode)
	if err != nil {
		_ = unix.Close(parent)
		return nil, nil, &Error{Class: FailureContract}
	}
	listener.SetUnlinkOnClose(false)
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = socket.cleanup()
		}
	}()

	bound, err := establishBoundSocketOwnership(parent, name)
	if err != nil || !validBoundSocketState(bound, mode) {
		socket.state = bound
		return nil, nil, &Error{Class: FailureContract}
	}
	socket.state = bound
	cleanup = false
	return listener, socket, nil
}

// establishBoundSocketOwnership normalizes the pathname to the process identity.
func establishBoundSocketOwnership(parent int, name string) (socketFileState, error) {
	before, err := statSocketChild(parent, name)
	if err != nil || before.mode&unix.S_IFMT != unix.S_IFSOCK ||
		before.uid != uint32(os.Geteuid()) || before.links != 1 {
		return socketFileState{}, &Error{Class: FailureContract}
	}
	if err := unix.Fchownat(
		parent,
		name,
		os.Geteuid(),
		os.Getegid(),
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return socketFileState{}, &Error{Class: FailureContract}
	}
	after, err := statSocketChild(parent, name)
	if err != nil || !sameSocketObject(before, after) {
		return socketFileState{}, &Error{Class: FailureContract}
	}
	return after, nil
}

// sameSocketObject compares identity while allowing the intended ownership change.
func sameSocketObject(left, right socketFileState) bool {
	return left.device == right.device && left.inode == right.inode &&
		left.links == right.links &&
		left.mode&unix.S_IFMT == unix.S_IFSOCK &&
		right.mode&unix.S_IFMT == unix.S_IFSOCK
}

// openSocketParent traverses owned non-symlink directories to the target parent.
func openSocketParent(path string) (int, string, error) {
	if !validSocketPathShape(path) {
		return -1, "", &Error{Class: FailureContract}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	name := parts[len(parts)-1]
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", &Error{Class: FailureInternal}
	}
	for index, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, "", &Error{Class: FailureContract}
		}
		current = next
		if statErr := validateSocketDirectory(current, index == len(parts)-2); statErr != nil {
			_ = unix.Close(current)
			return -1, "", statErr
		}
	}
	return current, name, nil
}

// validateSocketDirectory makes root or this process identity the path trust boundary.
//
// Same-credential processes and root are administrative peers and are outside
// the boundary; every other identity is denied directory mutation by DAC.
func validateSocketDirectory(descriptor int, final bool) error {
	var state unix.Stat_t
	if err := unix.Fstat(descriptor, &state); err != nil {
		return &Error{Class: FailureInternal}
	}
	mode := uint32(state.Mode) //nolint:unconvert // Stat_t.Mode differs across supported Unix targets.
	if mode&unix.S_IFMT != unix.S_IFDIR ||
		(state.Uid != 0 && state.Uid != uint32(os.Geteuid())) {
		return &Error{Class: FailureContract}
	}
	if mode&0o022 == 0 {
		return nil
	}
	if !final && state.Uid == 0 && mode&unix.S_ISVTX != 0 {
		return nil
	}
	return &Error{Class: FailureContract}
}

// validSocketPathShape bounds one clean absolute direct-child socket path.
func validSocketPathShape(path string) bool {
	if path == "" || path[0] != '/' || path == "/" || filepath.Clean(path) != path ||
		len(path) > maxUnixSocketPathBytes || strings.IndexByte(path, 0) >= 0 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 1 || len(parts) > maxSocketPathParts {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
	}
	return true
}

// bindSocketWithRestrictiveUmask creates exact mode during quiescent startup.
//
// Umask is process-global, so executable composition must bind before starting
// unrelated goroutines that create filesystem entries.
func bindSocketWithRestrictiveUmask(path string, mode os.FileMode) (*net.UnixListener, error) {
	socketUmaskMu.Lock()
	previous := unix.Umask(0o777 &^ int(mode.Perm()))
	defer func() {
		unix.Umask(previous)
		socketUmaskMu.Unlock()
	}()
	return net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
}

// statSocketChild reads target metadata without following a symlink.
func statSocketChild(parent int, name string) (socketFileState, error) {
	var state unix.Stat_t
	if err := unix.Fstatat(parent, name, &state, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return socketFileState{}, err
	}
	return socketStateFromStat(state), nil
}

// validBoundSocketState enforces type, ownership, links, and requested mode.
func validBoundSocketState(state socketFileState, mode os.FileMode) bool {
	if state.mode&unix.S_IFMT != unix.S_IFSOCK ||
		state.uid != uint32(os.Geteuid()) || state.gid != uint32(os.Getegid()) ||
		state.links != 1 {
		return false
	}
	return state.mode&0o777 == uint32(mode.Perm())
}

// sameSocketInode compares stable filesystem identity across target operations.
func sameSocketInode(left, right socketFileState) bool {
	return left.device == right.device && left.inode == right.inode &&
		left.uid == right.uid && left.gid == right.gid && left.links == right.links &&
		left.mode&unix.S_IFMT == right.mode&unix.S_IFMT
}

// cleanup removes only the unchanged socket inode within the trusted parent.
func (s *ownedSocket) cleanup() error {
	if s == nil || s.parent < 0 {
		return nil
	}
	defer func() {
		_ = unix.Close(s.parent)
		s.parent = -1
	}()
	current, err := statSocketChild(s.parent, s.name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return &Error{Class: FailureInternal}
	}
	if !sameSocketInode(current, s.state) {
		return nil
	}
	if err := unix.Unlinkat(s.parent, s.name, 0); err != nil {
		return &Error{Class: FailureInternal}
	}
	return nil
}
