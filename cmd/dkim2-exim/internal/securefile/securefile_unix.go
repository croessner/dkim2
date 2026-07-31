//go:build linux || darwin

// Package securefile owns descriptor-first reads through trusted Unix ancestry.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxPathBytes      = 4_096
	maxPathComponents = 64
	maxComponentBytes = 255
)

// Error is one content-free secure-file failure.
type Error struct{}

// Error returns a constant diagnostic without path or content.
func (*Error) Error() string { return "secure file access failure" }

// Is recognizes the bounded secure-file error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}

// Rules declares one immutable descriptor policy.
type Rules struct {
	EffectiveUID          uint32
	ExactParent           bool
	ParentMode            uint32
	AllowRootFileOwner    bool
	FileModes             []uint32
	MinimumBytes          int64
	MaximumBytes          int64
	RequiredFileLinkCount uint64
}

// DirectoryRules declares one immutable trusted-directory policy.
type DirectoryRules struct {
	EffectiveUID uint32
	Mode         uint32
}

// Event identifies a content-free deterministic race-test phase.
type Event uint8

const (
	// EventBeforeFinalOpen occurs after no-follow classification and before openat.
	EventBeforeFinalOpen Event = iota + 1
	// EventAfterRead occurs after exact EOF and before final descriptor validation.
	EventAfterRead
)

// Observer receives no path, identity, metadata, or file content.
type Observer func(Event)

// metadata freezes descriptor-native state used for race detection.
type metadata struct {
	device    uint64
	inode     uint64
	links     uint64
	typeBits  uint32
	modeBits  uint32
	uid       uint32
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

// state freezes metadata and descriptor-native access policy for race detection.
type state struct {
	metadata metadata
	access   [32]byte
}

// descriptor owns one file descriptor through at most one close.
type descriptor struct {
	fd int
}

// Handle retains the exact file and parent generation until validation completes.
type Handle struct {
	child        descriptor
	parent       descriptor
	parentBefore state
	childBefore  state
	rules        Rules
	observe      Observer
}

// DirectoryHandle retains one exact trusted directory generation and access state.
type DirectoryHandle struct {
	directory descriptor
	before    state
	rules     Rules
}

// Identity is the exact child and final-parent descriptor identity of one handle.
type Identity struct {
	childDevice  uint64
	childInode   uint64
	parentDevice uint64
	parentInode  uint64
}

// NewIdentity creates an opaque token for an independently descriptor-verified resource.
func NewIdentity(childDevice uint64, childInode uint64, parentDevice uint64, parentInode uint64) Identity {
	return Identity{
		childDevice: childDevice, childInode: childInode,
		parentDevice: parentDevice, parentInode: parentInode,
	}
}

// Open traverses trusted ancestry and opens one policy-conforming direct child.
func Open(path string, rules Rules, observe Observer) (*Handle, error) {
	if len(rules.FileModes) < 1 || len(rules.FileModes) > 8 {
		return nil, &Error{}
	}
	rules = cloneRules(rules)
	if !validRules(rules) {
		return nil, &Error{}
	}
	components, err := pathComponents(path)
	if err != nil {
		return nil, err
	}
	current, err := openRoot(rules)
	if err != nil {
		return nil, err
	}
	for index, component := range components {
		final := index == len(components)-1
		if final {
			parentBefore, inspectErr := inspectDirectory(current.fd, rules, true)
			if inspectErr != nil {
				_ = current.close()
				return nil, inspectErr
			}
			child, openErr := openChild(current.fd, component, false, observe)
			if openErr != nil {
				_ = current.close()
				return nil, openErr
			}
			childBefore, inspectErr := inspectFile(child.fd, rules)
			if inspectErr != nil {
				_ = child.close()
				_ = current.close()
				return nil, inspectErr
			}
			return &Handle{
				child: child, parent: current, parentBefore: parentBefore,
				childBefore: childBefore, rules: rules, observe: observe,
			}, nil
		}
		next, openErr := openChild(current.fd, component, true, nil)
		if openErr != nil {
			_ = current.close()
			return nil, openErr
		}
		if _, inspectErr := inspectDirectory(next.fd, rules, false); inspectErr != nil {
			_ = next.close()
			_ = current.close()
			return nil, inspectErr
		}
		if closeErr := current.close(); closeErr != nil {
			_ = next.close()
			return nil, closeErr
		}
		current = next
	}
	_ = current.close()
	return nil, &Error{}
}

// OpenDirectory traverses trusted ancestry and retains one exact protected directory.
func OpenDirectory(path string, policy DirectoryRules) (*DirectoryHandle, error) {
	if policy.Mode > 0o7777 {
		return nil, &Error{}
	}
	components, err := pathComponents(path)
	if err != nil {
		return nil, err
	}
	rules := Rules{EffectiveUID: policy.EffectiveUID, ExactParent: true, ParentMode: policy.Mode}
	current, err := openRoot(rules)
	if err != nil {
		return nil, err
	}
	for index, component := range components {
		next, openErr := openChild(current.fd, component, true, nil)
		if openErr != nil {
			_ = current.close()
			return nil, openErr
		}
		final := index == len(components)-1
		nextState, inspectErr := inspectDirectory(next.fd, rules, final)
		if inspectErr != nil {
			_ = next.close()
			_ = current.close()
			return nil, inspectErr
		}
		if closeErr := current.close(); closeErr != nil {
			_ = next.close()
			return nil, closeErr
		}
		if final {
			return &DirectoryHandle{directory: next, before: nextState, rules: rules}, nil
		}
		current = next
	}
	_ = current.close()
	return nil, &Error{}
}

// Descriptor returns the retained directory descriptor for descriptor-relative operations.
func (h *DirectoryHandle) Descriptor() int {
	if h == nil {
		return -1
	}
	return h.directory.fd
}

// Validate rejects directory metadata or access-policy drift.
func (h *DirectoryHandle) Validate() error {
	if h == nil || h.directory.fd < 0 {
		return &Error{}
	}
	after, err := inspectDirectory(h.directory.fd, h.rules, true)
	if err != nil || after != h.before {
		return &Error{}
	}
	return nil
}

// RebaseAfterOwnedChildMutation accepts only the directory timestamp and size
// changes caused by a caller-owned direct-child creation, then refreshes the
// strict baseline used by all later validations.
func (h *DirectoryHandle) RebaseAfterOwnedChildMutation() error {
	if h == nil || h.directory.fd < 0 {
		return &Error{}
	}
	after, err := inspectDirectory(h.directory.fd, h.rules, true)
	if err != nil || !sameDirectorySecurityState(h.before, after) {
		return &Error{}
	}
	h.before = after
	return nil
}

// sameDirectorySecurityState compares every stable directory security invariant.
func sameDirectorySecurityState(before, after state) bool {
	return before.metadata.device == after.metadata.device &&
		before.metadata.inode == after.metadata.inode &&
		before.metadata.links == after.metadata.links &&
		before.metadata.typeBits == after.metadata.typeBits &&
		before.metadata.modeBits == after.metadata.modeBits &&
		before.metadata.uid == after.metadata.uid &&
		before.access == after.access
}

// Close releases the retained directory descriptor.
func (h *DirectoryHandle) Close() error {
	if h == nil {
		return nil
	}
	return h.directory.close()
}

// String returns a content-free directory-handle diagnostic.
func (DirectoryHandle) String() string { return "securefile.DirectoryHandle{redacted}" }

// GoString returns a content-free Go directory-handle diagnostic.
func (h DirectoryHandle) GoString() string { return h.String() }

// Format prevents formatter traversal into directory descriptor state.
func (h DirectoryHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, h.String())
}

// MarshalJSON rejects directory-handle serialization.
func (DirectoryHandle) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// Read reads the descriptor-declared byte count, requires exact EOF, and revalidates state.
func (h *Handle) Read() ([]byte, error) {
	if h == nil || h.child.fd < 0 || h.parent.fd < 0 ||
		h.childBefore.metadata.size < h.rules.MinimumBytes ||
		h.childBefore.metadata.size > h.rules.MaximumBytes {
		return nil, &Error{}
	}
	data := make([]byte, int(h.childBefore.metadata.size))
	if err := readExact(h.child.fd, data); err != nil {
		clear(data)
		return nil, err
	}
	notify(h.observe, EventAfterRead)
	childAfter, err := inspectFile(h.child.fd, h.rules)
	if err != nil || childAfter != h.childBefore {
		clear(data)
		return nil, &Error{}
	}
	parentAfter, err := inspectDirectory(h.parent.fd, h.rules, true)
	if err != nil || parentAfter != h.parentBefore {
		clear(data)
		return nil, &Error{}
	}
	return data, nil
}

// Close releases both retained descriptors and reports ambiguous cleanup.
func (h *Handle) Close() error {
	if h == nil {
		return nil
	}
	var result error
	if err := h.child.close(); err != nil {
		result = err
	}
	if err := h.parent.close(); err != nil && result == nil {
		result = err
	}
	return result
}

// Identity returns a descriptor-native alias token without exposing paths or content.
func (h *Handle) Identity() Identity {
	if h == nil {
		return Identity{}
	}
	return Identity{childDevice: h.childBefore.metadata.device, childInode: h.childBefore.metadata.inode, parentDevice: h.parentBefore.metadata.device, parentInode: h.parentBefore.metadata.inode}
}

// Equal reports whether two protected resources share the same protected child.
func (i Identity) Equal(other Identity) bool {
	return i.childDevice == other.childDevice && i.childInode == other.childInode
}

// SameParent reports whether two resources share their final trusted parent.
func (i Identity) SameParent(other Identity) bool {
	return i.parentDevice == other.parentDevice && i.parentInode == other.parentInode
}

// MatchesDirectory reports whether an opaque token aliases one retained directory descriptor.
func (i Identity) MatchesDirectory(device, inode uint64) bool {
	return i.childDevice == device && i.childInode == inode || i.parentDevice == device && i.parentInode == inode
}

// String prevents filesystem identity disclosure.
func (Identity) String() string { return "securefile.Identity{redacted}" }

// GoString prevents filesystem identity disclosure.
func (Identity) GoString() string { return "securefile.Identity{redacted}" }

// Format prevents formatter traversal into filesystem identity state.
func (Identity) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "securefile.Identity{redacted}")
}

// MarshalJSON rejects filesystem identity serialization.
func (Identity) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// String returns a content-free handle diagnostic.
func (*Handle) String() string { return "securefile.Handle{redacted}" }

// GoString returns a content-free Go representation.
func (h *Handle) GoString() string { return h.String() }

// Format prevents formatter traversal into descriptor state.
func (h *Handle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, h.String())
}

// validRules validates one bounded immutable policy.
func validRules(rules Rules) bool {
	if rules.MaximumBytes < 1 || rules.MinimumBytes < 1 ||
		rules.MinimumBytes > rules.MaximumBytes || rules.MaximumBytes > maxPathBytes*64 ||
		rules.RequiredFileLinkCount == 0 || len(rules.FileModes) == 0 ||
		len(rules.FileModes) > 8 {
		return false
	}
	for _, mode := range rules.FileModes {
		if mode > 0o7777 {
			return false
		}
	}
	return !rules.ExactParent || rules.ParentMode <= 0o7777
}

// cloneRules detaches caller-owned mode storage from the retained policy.
func cloneRules(rules Rules) Rules {
	rules.FileModes = append([]uint32(nil), rules.FileModes...)
	return rules
}

// openRoot opens the filesystem root as the first trusted descriptor.
func openRoot(rules Rules) (descriptor, error) {
	fd, err := retryOpen(func() (int, error) {
		return unix.Open("/", directoryFlags(), 0)
	})
	if err != nil {
		return invalidDescriptor(), err
	}
	result := descriptor{fd: fd}
	if _, err := inspectDirectory(fd, rules, false); err != nil {
		_ = result.close()
		return invalidDescriptor(), err
	}
	return result, nil
}

// openChild proves type and inode equality across no-follow stat and openat.
func openChild(parentFD int, name string, directory bool, observe Observer) (descriptor, error) {
	before, err := statAt(parentFD, name)
	if err != nil {
		return invalidDescriptor(), err
	}
	expectedType := uint32(unix.S_IFREG)
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		expectedType = unix.S_IFDIR
		flags = directoryFlags()
	}
	if before.typeBits != expectedType {
		return invalidDescriptor(), &Error{}
	}
	notify(observe, EventBeforeFinalOpen)
	fd, err := retryOpen(func() (int, error) {
		return unix.Openat(parentFD, name, flags, 0)
	})
	if err != nil {
		return invalidDescriptor(), err
	}
	result := descriptor{fd: fd}
	after, err := statDescriptor(fd)
	if err != nil || after.typeBits != expectedType ||
		before.device != after.device || before.inode != after.inode {
		_ = result.close()
		return invalidDescriptor(), &Error{}
	}
	return result, nil
}

// inspectDirectory enforces trusted ancestry and an optional exact final parent.
func inspectDirectory(fd int, rules Rules, final bool) (state, error) {
	current, err := statDescriptor(fd)
	if err != nil {
		return state{}, err
	}
	if current.typeBits != unix.S_IFDIR || current.links == 0 {
		return state{}, &Error{}
	}
	if final && rules.ExactParent {
		if current.uid != rules.EffectiveUID || current.modeBits != rules.ParentMode {
			return state{}, &Error{}
		}
	} else {
		trustedOwner := current.uid == 0 || current.uid == rules.EffectiveUID
		rootStickyAncestor := current.uid == 0 && current.modeBits&unix.S_ISVTX != 0
		if !trustedOwner || current.modeBits&0o022 != 0 && !rootStickyAncestor {
			return state{}, &Error{}
		}
	}
	access, err := descriptorAccessFingerprint(fd, true, current.modeBits)
	if err != nil {
		return state{}, err
	}
	return state{metadata: current, access: access}, nil
}

// inspectFile enforces exact final file owner, mode, links, type, and size.
func inspectFile(fd int, rules Rules) (state, error) {
	current, err := statDescriptor(fd)
	if err != nil {
		return state{}, err
	}
	ownerAccepted := current.uid == rules.EffectiveUID ||
		rules.AllowRootFileOwner && current.uid == 0
	if current.typeBits != unix.S_IFREG || !ownerAccepted ||
		current.links != rules.RequiredFileLinkCount ||
		!slices.Contains(rules.FileModes, current.modeBits) ||
		current.size < rules.MinimumBytes || current.size > rules.MaximumBytes {
		return state{}, &Error{}
	}
	access, err := descriptorAccessFingerprint(fd, false, current.modeBits)
	if err != nil {
		return state{}, err
	}
	return state{metadata: current, access: access}, nil
}

// statAt obtains one no-follow child metadata snapshot.
func statAt(parentFD int, name string) (metadata, error) {
	var state unix.Stat_t
	err := retryOperation(func() error {
		return unix.Fstatat(parentFD, name, &state, unix.AT_SYMLINK_NOFOLLOW)
	})
	if err != nil {
		return metadata{}, err
	}
	return metadataFromStat(state), nil
}

// statDescriptor obtains one descriptor-native metadata snapshot.
func statDescriptor(fd int) (metadata, error) {
	var state unix.Stat_t
	err := retryOperation(func() error { return unix.Fstat(fd, &state) })
	if err != nil {
		return metadata{}, err
	}
	return metadataFromStat(state), nil
}

// metadataFromStat freezes platform-common Stat_t fields.
func metadataFromStat(state unix.Stat_t) metadata {
	return metadata{
		device: uint64(state.Dev), inode: state.Ino, links: uint64(state.Nlink),
		typeBits: uint32(state.Mode) & unix.S_IFMT,
		modeBits: uint32(state.Mode) & 0o7777,
		uid:      state.Uid, size: state.Size,
		mtimeSec: state.Mtim.Sec, mtimeNsec: state.Mtim.Nsec,
		ctimeSec: state.Ctim.Sec, ctimeNsec: state.Ctim.Nsec,
	}
}

// readExact reads one declared size and then requires exact EOF.
func readExact(fd int, destination []byte) error {
	offset := 0
	for offset < len(destination) {
		count, err := unix.Read(fd, destination[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count <= 0 || count > len(destination)-offset {
			return &Error{}
		}
		offset += count
	}
	var extra [1]byte
	for {
		count, err := unix.Read(fd, extra[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count != 0 {
			return &Error{}
		}
		return nil
	}
}

// pathComponents validates lexical bounds before descriptor traversal.
func pathComponents(path string) ([]string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		len(path) > maxPathBytes || strings.ContainsRune(path, 0) {
		return nil, &Error{}
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 0 || len(components) > maxPathComponents {
		return nil, &Error{}
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			len(component) > maxComponentBytes {
			return nil, &Error{}
		}
	}
	return components, nil
}

// retryOpen retries an interrupted open and maps failures content-free.
func retryOpen(open func() (int, error)) (int, error) {
	for {
		fd, err := open()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return -1, &Error{}
		}
		return fd, nil
	}
}

// retryOperation retries one interrupted descriptor operation.
func retryOperation(operation func() error) error {
	for {
		err := operation()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return &Error{}
		}
		return nil
	}
}

// directoryFlags returns the exact no-follow traversal flags.
func directoryFlags() int {
	return unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
}

// close releases one descriptor at most once without unsafe EINTR retries.
func (d *descriptor) close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	fd := d.fd
	d.fd = -1
	if err := unix.Close(fd); err != nil {
		return &Error{}
	}
	return nil
}

// invalidDescriptor returns one inert close-safe descriptor.
func invalidDescriptor() descriptor { return descriptor{fd: -1} }

// notify emits one content-free deterministic phase marker.
func notify(observe Observer, event Event) {
	if observe != nil {
		observe(event)
	}
}
