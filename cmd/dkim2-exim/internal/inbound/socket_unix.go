//go:build linux

package inbound

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"golang.org/x/sys/unix"
)

var socketUmaskMu sync.Mutex

type socketFileState struct {
	device, inode  uint64
	uid, gid, mode uint32
	links          uint64
}

// ownedSocket retains the exact parent descriptor and bound socket identity.
type ownedSocket struct {
	parent *securefile.DirectoryHandle
	name   string
	state  socketFileState
}

// openSocketListener binds and verifies one same-UID mode-0600 socket.
func openSocketListener(path string, mode os.FileMode) (*net.UnixListener, *ownedSocket, error) {
	return openSocketListenerObserved(path, mode, nil)
}

// openSocketListenerObserved exposes a content-free post-bind test seam.
func openSocketListenerObserved(path string, mode os.FileMode, afterBind func() error) (*net.UnixListener, *ownedSocket, error) {
	parentHandle, name, err := openSocketParent(path)
	if err != nil {
		return nil, nil, err
	}
	parent := parentHandle.Descriptor()
	s := &ownedSocket{parent: parentHandle, name: name}
	if _, err = statSocketChild(parent, name); !errors.Is(err, unix.ENOENT) {
		_ = parentHandle.Close()
		return nil, nil, errors.New("socket")
	}
	socketUmaskMu.Lock()
	old := unix.Umask(0o777 &^ int(mode.Perm()))
	bindPath := "/proc/self/fd/" + strconv.Itoa(parent) + "/" + name
	listener, err := net.ListenUnix(unixNetwork, &net.UnixAddr{Name: bindPath, Net: unixNetwork})
	unix.Umask(old)
	socketUmaskMu.Unlock()
	if err != nil {
		_ = parentHandle.Close()
		return nil, nil, err
	}
	listener.SetUnlinkOnClose(false)
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = s.rollback()
		}
	}()
	before, err := statSocketChild(parent, name)
	if err != nil || parentHandle.RebaseAfterOwnedChildMutation() != nil || before.mode&unix.S_IFMT != unix.S_IFSOCK || before.uid != uint32(os.Geteuid()) || before.links != 1 {
		return nil, nil, errors.New("socket")
	}
	s.state = before
	if afterBind != nil && afterBind() != nil {
		return nil, nil, errors.New("socket")
	}
	after, err := statSocketChild(parent, name)
	if err != nil || parentHandle.Validate() != nil || after.device != before.device || after.inode != before.inode ||
		after.mode&unix.S_IFMT != unix.S_IFSOCK ||
		after.mode&0o777 != uint32(mode.Perm()) || after.uid != uint32(os.Geteuid()) ||
		after.gid != uint32(os.Getegid()) || after.links != 1 {
		return nil, nil, errors.New("socket")
	}
	s.state = after
	cleanup = false
	return listener, s, nil
}

// openSocketParent retains a trusted exact-mode final parent without following links.
func openSocketParent(path string) (*securefile.DirectoryHandle, string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 {
		return nil, "", errors.New("socket")
	}
	name := filepath.Base(path)
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return nil, "", errors.New("socket")
	}
	parent, err := securefile.OpenDirectory(filepath.Dir(path), securefile.DirectoryRules{
		EffectiveUID: uint32(os.Geteuid()), Mode: 0o700,
	})
	if err != nil {
		return nil, "", errors.New("socket")
	}
	return parent, name, nil
}

// statSocketChild reads one direct no-follow child identity.
func statSocketChild(parent int, name string) (socketFileState, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return socketFileState{}, err
	}
	return socketFileState{uint64(st.Dev), st.Ino, st.Uid, st.Gid, uint32(st.Mode), uint64(st.Nlink)}, nil //nolint:unconvert // Stat_t fields differ across supported Unix targets.
}

// cleanup removes only the exact fully validated owned socket identity.
func (s *ownedSocket) cleanup() (result error) {
	if s == nil || s.parent == nil || s.parent.Descriptor() < 0 {
		return nil
	}
	parent := s.parent.Descriptor()
	defer func() {
		if closeErr := s.parent.Close(); closeErr != nil && result == nil {
			result = errors.New("socket")
		}
		s.parent = nil
	}()
	if s.parent.Validate() != nil {
		return errors.New("socket")
	}
	now, err := statSocketChild(parent, s.name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if now.device != s.state.device || now.inode != s.state.inode {
		return errors.New("socket")
	}
	if now != s.state {
		return errors.New("socket")
	}
	return unix.Unlinkat(parent, s.name, 0)
}

// rollback removes only the exact socket inode frozen immediately after bind.
func (s *ownedSocket) rollback() (result error) {
	if s == nil || s.parent == nil || s.parent.Descriptor() < 0 {
		return nil
	}
	parent := s.parent.Descriptor()
	defer func() {
		if closeErr := s.parent.Close(); closeErr != nil && result == nil {
			result = errors.New("socket")
		}
		s.parent = nil
	}()
	if s.parent.Validate() != nil {
		return errors.New("socket")
	}
	now, err := statSocketChild(parent, s.name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if now.device != s.state.device || now.inode != s.state.inode ||
		now.mode&unix.S_IFMT != unix.S_IFSOCK || now.links != 1 {
		return errors.New("socket")
	}
	return unix.Unlinkat(parent, s.name, 0)
}
