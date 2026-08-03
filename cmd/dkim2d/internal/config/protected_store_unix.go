//go:build linux || darwin

package config

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type protectedStoreEvent uint8

const (
	protectedStoreAfterLock protectedStoreEvent = iota + 1
	protectedStoreAfterAbsentOpen
	protectedStoreBeforeRename
	protectedStoreAfterRename
	protectedStoreAfterDirectorySync
)

type protectedStoreObserver func(protectedStoreEvent)

type protectedStorePlatform struct{ state *protectedStoreState }

type protectedStoreState struct {
	mu            sync.Mutex
	directory     ownedDescriptor
	lock          ownedDescriptor
	directoryPath string
	documentName  string
	lockName      string
	directoryPre  descriptorState
	lockPre       descriptorState
	maximum       int
	effectiveUID  uint32
	observe       protectedStoreObserver
	viewKnown     bool
	expectedEntry *descriptorState
	poisoned      bool
	closed        bool
}

// openProtectedStore opens and locks one protected replaceable document owner.
func openProtectedStore(
	ctx context.Context,
	path string,
	maximum int,
	observe protectedStoreObserver,
) (*ProtectedStore, error) {
	return openProtectedStoreMode(ctx, path, maximum, observe, true)
}

// openExistingProtectedStore opens only an already-established stable sibling lock.
func openExistingProtectedStore(
	ctx context.Context,
	path string,
	maximum int,
	observe protectedStoreObserver,
) (*ProtectedStore, error) {
	return openProtectedStoreMode(ctx, path, maximum, observe, false)
}

// openProtectedStoreMode owns common descriptor validation for creating and read-only transactions.
func openProtectedStoreMode(
	ctx context.Context,
	path string,
	maximum int,
	observe protectedStoreObserver,
	createLock bool,
) (*ProtectedStore, error) {
	if ctx == nil || ctx.Err() != nil || maximum <= 0 || maximum > maxYAMLDocumentBytes {
		return nil, newError(CodeProtectedContent)
	}
	if _, err := protectedPathComponents(path); err != nil || filepath.Clean(path) != path {
		return nil, newError(CodeProtectedPath)
	}
	directoryPath, documentName := filepath.Dir(path), filepath.Base(path)
	lockName := documentName + ".lock"
	if documentName == "." || documentName == string(filepath.Separator) || len(lockName) > maxProtectedComponentBytes {
		return nil, newError(CodeProtectedPath)
	}
	effectiveUID := uint32(os.Geteuid())
	directory, err := openProtectedPathWithUID(directoryPath, true, effectiveUID)
	if err != nil {
		return nil, err
	}
	directoryPre, err := validateProtectedStoreDirectory(directory.fd, effectiveUID)
	if err != nil {
		_ = directory.close()
		return nil, err
	}
	lock, created, err := openProtectedStoreLock(directory.fd, lockName, createLock)
	if err != nil {
		_ = directory.close()
		return nil, err
	}
	if created {
		if err := syncDescriptor(lock.fd); err != nil || syncDescriptor(directory.fd) != nil {
			_ = lock.close()
			_ = directory.close()
			return nil, newError(CodeProtectedIO)
		}
	}
	lockPre, err := validateProtectedStoreLock(lock.fd, effectiveUID)
	if err != nil {
		_ = lock.close()
		_ = directory.close()
		return nil, err
	}
	if err := flockExclusive(lock.fd); err != nil {
		_ = lock.close()
		_ = directory.close()
		return nil, err
	}
	state := &protectedStoreState{
		directory: directory, lock: lock, directoryPath: directoryPath,
		documentName: documentName, lockName: lockName, directoryPre: directoryPre,
		lockPre: lockPre, maximum: maximum, effectiveUID: effectiveUID, observe: observe,
	}
	if observe != nil {
		observe(protectedStoreAfterLock)
	}
	if err := state.verifySerializationFence(); err != nil {
		_ = state.closeLocked()
		return nil, err
	}
	return &ProtectedStore{platform: protectedStorePlatform{state: state}}, nil
}

// openProtectedStoreLock creates or opens the stable sibling lock relative to the proven directory.
func openProtectedStoreLock(directoryFD int, name string, create bool) (ownedDescriptor, bool, error) {
	if !create {
		fd, err := retryOpenatRaw(directoryFD, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return ownedDescriptor{fd: -1}, false, newError(CodeProtectedIO)
		}
		return newOwnedDescriptor(fd), false, nil
	}
	flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	fd, err := retryOpenatRaw(directoryFD, name, flags, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = retryOpenatRaw(directoryFD, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return ownedDescriptor{fd: -1}, false, newError(CodeProtectedIO)
	}
	descriptor := newOwnedDescriptor(fd)
	if created {
		if err := retryDescriptorOperation(func() error { return unix.Fchmod(fd, 0o600) }); err != nil {
			_ = descriptor.close()
			return ownedDescriptor{fd: -1}, false, err
		}
	}
	return descriptor, created, nil
}

// validateProtectedStoreDirectory requires one exact owner-only mutable journal directory.
func validateProtectedStoreDirectory(fd int, effectiveUID uint32) (descriptorState, error) {
	state, err := captureDescriptorState(fd, 0o700, true)
	if err != nil {
		return descriptorState{}, err
	}
	if state.metadata.typeBits != unix.S_IFDIR || state.metadata.uid != effectiveUID ||
		state.metadata.modeBits != 0o700 || state.metadata.linkCount == 0 {
		return descriptorState{}, newError(CodeProtectedAccess)
	}
	return state, nil
}

// validateProtectedStoreLock requires one stable empty owner-only regular inode.
func validateProtectedStoreLock(fd int, effectiveUID uint32) (descriptorState, error) {
	state, err := captureDescriptorState(fd, 0o600, false)
	if err != nil {
		return descriptorState{}, err
	}
	if state.metadata.typeBits != unix.S_IFREG || state.metadata.uid != effectiveUID ||
		state.metadata.modeBits != 0o600 || state.metadata.linkCount != 1 || state.metadata.size != 0 {
		return descriptorState{}, newError(CodeProtectedAccess)
	}
	return state, nil
}

// flockExclusive acquires one nonblocking stable-inode serialization fence.
func flockExclusive(fd int) error {
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return newError(CodeProtectedBusy)
		}
		if err != nil {
			return newError(CodeProtectedIO)
		}
		return nil
	}
}

// read returns one exact bounded regular document through the held serialization fence.
func (p protectedStorePlatform) read(ctx context.Context) (content []byte, exists bool, resultErr error) {
	if p.state == nil {
		return nil, false, newError(CodeProtectedClosed)
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.closed || ctx == nil || ctx.Err() != nil {
		return nil, false, newError(CodeProtectedClosed)
	}
	if p.state.poisoned {
		return nil, false, newError(CodeProtectedAmbiguous)
	}
	if err := p.state.verifySerializationFence(); err != nil {
		return nil, false, err
	}
	fd, err := retryOpenatRaw(p.state.directory.fd, p.state.documentName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		if p.state.observe != nil {
			p.state.observe(protectedStoreAfterAbsentOpen)
		}
		if p.state.verifySerializationFence() != nil {
			return nil, false, newError(CodeProtectedAccess)
		}
		if ctx.Err() != nil {
			return nil, false, newError(CodeProtectedIO)
		}
		p.state.viewKnown = true
		p.state.expectedEntry = nil
		return nil, false, nil
	}
	if err != nil {
		return nil, false, newError(CodeProtectedIO)
	}
	document := newOwnedDescriptor(fd)
	defer func() {
		if closeErr := document.close(); closeErr != nil && resultErr == nil {
			clear(content)
			content = nil
			exists = false
			resultErr = closeErr
		}
	}()
	pre, err := p.state.validateDocument(fd)
	if err != nil {
		return nil, false, err
	}
	content, err = readProtectedDescriptor(fd, p.state.maximum)
	if err != nil || len(content) == 0 {
		clear(content)
		return nil, false, newError(CodeProtectedContent)
	}
	if ctx.Err() != nil {
		clear(content)
		return nil, false, newError(CodeProtectedIO)
	}
	final, finalErr := p.state.validateDocument(fd)
	entry, entryErr := statAtNoFollow(p.state.directory.fd, p.state.documentName)
	if finalErr != nil || entryErr != nil || final != pre || entry != pre.metadata ||
		p.state.verifySerializationFence() != nil {
		clear(content)
		return nil, false, newError(CodeProtectedAccess)
	}
	if ctx.Err() != nil {
		clear(content)
		return nil, false, newError(CodeProtectedIO)
	}
	p.state.viewKnown = true
	expected := final
	p.state.expectedEntry = &expected
	return content, true, nil
}

// validateDocument validates one exact bounded owner-only journal descriptor.
func (s *protectedStoreState) validateDocument(fd int) (descriptorState, error) {
	state, err := captureDescriptorState(fd, 0o600, false)
	if err != nil {
		return descriptorState{}, err
	}
	if state.metadata.typeBits != unix.S_IFREG || state.metadata.uid != s.effectiveUID ||
		state.metadata.modeBits != 0o600 || state.metadata.linkCount != 1 ||
		state.metadata.size <= 0 || state.metadata.size > int64(s.maximum) {
		return descriptorState{}, newError(CodeProtectedAccess)
	}
	return state, nil
}

// replace writes, syncs, and atomically renames one same-directory protected document.
func (p protectedStorePlatform) replace(ctx context.Context, content []byte) error {
	if p.state == nil {
		return newError(CodeProtectedClosed)
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.closed || ctx == nil || ctx.Err() != nil || len(content) == 0 || len(content) > p.state.maximum {
		return newError(CodeProtectedContent)
	}
	owned := append([]byte(nil), content...)
	defer clear(owned)
	if p.state.poisoned {
		return newError(CodeProtectedAmbiguous)
	}
	if !p.state.viewKnown {
		return newError(CodeProtectedConflict)
	}
	if err := p.state.verifySerializationFence(); err != nil {
		return err
	}
	temporary, temporaryName, err := p.state.createTemporary()
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		_ = temporary.close()
		if !renamed {
			_ = unix.Unlinkat(p.state.directory.fd, temporaryName, 0)
		}
	}()
	if err := writeAllDescriptor(ctx, temporary.fd, owned); err != nil || syncDescriptor(temporary.fd) != nil {
		return newError(CodeProtectedIO)
	}
	temporaryPre, err := p.state.validateDocument(temporary.fd)
	if err != nil || temporaryPre.metadata.size != int64(len(owned)) {
		return newError(CodeProtectedAccess)
	}
	if p.state.observe != nil {
		p.state.observe(protectedStoreBeforeRename)
	}
	if err := p.state.verifySerializationFence(); err != nil {
		return err
	}
	if !p.state.documentMatchesExpected() {
		return newError(CodeProtectedConflict)
	}
	if ctx.Err() != nil {
		return newError(CodeProtectedIO)
	}
	if err := retryDescriptorOperation(func() error {
		return unix.Renameat(p.state.directory.fd, temporaryName, p.state.directory.fd, p.state.documentName)
	}); err != nil {
		return err
	}
	renamed = true
	if p.state.observe != nil {
		p.state.observe(protectedStoreAfterRename)
	}
	if ctx.Err() != nil || p.state.verifySerializationFence() != nil {
		return p.state.markAmbiguous()
	}
	if err := syncDescriptor(p.state.directory.fd); err != nil {
		return p.state.markAmbiguous()
	}
	if p.state.observe != nil {
		p.state.observe(protectedStoreAfterDirectorySync)
	}
	temporaryFinal, finalErr := p.state.validateDocument(temporary.fd)
	entry, entryErr := statAtNoFollow(p.state.directory.fd, p.state.documentName)
	if finalErr != nil || entryErr != nil || entry != temporaryFinal.metadata ||
		p.state.verifySerializationFence() != nil {
		return p.state.markAmbiguous()
	}
	p.state.viewKnown = true
	expected := temporaryFinal
	p.state.expectedEntry = &expected
	return nil
}

// documentMatchesExpected proves the exact absent or inode-bound view read under this lock.
func (s *protectedStoreState) documentMatchesExpected() bool {
	fd, err := retryOpenatRaw(s.directory.fd, s.documentName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if s.expectedEntry == nil {
		if errors.Is(err, unix.ENOENT) {
			return s.verifySerializationFence() == nil
		}
		if err == nil {
			_ = unix.Close(fd)
		}
		return false
	}
	if err != nil {
		return false
	}
	document := newOwnedDescriptor(fd)
	defer document.close() //nolint:errcheck // A failed close cannot make a mismatched entry acceptable.
	state, stateErr := s.validateDocument(fd)
	entry, entryErr := statAtNoFollow(s.directory.fd, s.documentName)
	return stateErr == nil && entryErr == nil && state == *s.expectedEntry &&
		entry == s.expectedEntry.metadata && s.verifySerializationFence() == nil
}

// markAmbiguous poisons the owner after a mutation may already have happened.
func (s *protectedStoreState) markAmbiguous() error {
	s.poisoned = true
	s.viewKnown = false
	s.expectedEntry = nil
	return newError(CodeProtectedAmbiguous)
}

// createTemporary creates one unpredictable same-directory owner-only regular file.
func (s *protectedStoreState) createTemporary() (ownedDescriptor, string, error) {
	for range 32 {
		var randomBytes [16]byte
		if _, err := io.ReadFull(rand.Reader, randomBytes[:]); err != nil {
			clear(randomBytes[:])
			return ownedDescriptor{fd: -1}, "", newError(CodeProtectedIO)
		}
		name := ".dkim2-journal-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes[:])) + ".tmp"
		clear(randomBytes[:])
		fd, err := retryOpenatRaw(s.directory.fd, name,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return ownedDescriptor{fd: -1}, "", newError(CodeProtectedIO)
		}
		descriptor := newOwnedDescriptor(fd)
		if err := retryDescriptorOperation(func() error { return unix.Fchmod(fd, 0o600) }); err != nil {
			_ = descriptor.close()
			_ = unix.Unlinkat(s.directory.fd, name, 0)
			return ownedDescriptor{fd: -1}, "", err
		}
		return descriptor, name, nil
	}
	return ownedDescriptor{fd: -1}, "", newError(CodeProtectedIO)
}

// verifySerializationFence re-proves parent path identity and sibling lock entry identity.
func (s *protectedStoreState) verifySerializationFence() error {
	directoryNow, err := captureDescriptorState(s.directory.fd, 0o700, true)
	if err != nil || !sameDirectorySecurityState(directoryNow, s.directoryPre) {
		return newError(CodeProtectedAccess)
	}
	lockNow, err := validateProtectedStoreLock(s.lock.fd, s.effectiveUID)
	lockEntry, entryErr := statAtNoFollow(s.directory.fd, s.lockName)
	if err != nil || entryErr != nil || lockNow != s.lockPre || lockEntry != s.lockPre.metadata {
		return newError(CodeProtectedAccess)
	}
	reopened, err := openProtectedPathWithUID(s.directoryPath, true, s.effectiveUID)
	if err != nil {
		return newError(CodeProtectedAccess)
	}
	defer reopened.close() //nolint:errcheck // Identity proof failure is already content-free.
	reopenedState, err := validateProtectedStoreDirectory(reopened.fd, s.effectiveUID)
	if err != nil || !sameDirectorySecurityState(reopenedState, s.directoryPre) {
		return newError(CodeProtectedAccess)
	}
	return nil
}

// sameDirectorySecurityState ignores mutable directory size and timestamps only.
func sameDirectorySecurityState(left, right descriptorState) bool {
	return sameDescriptorIdentity(left.metadata, right.metadata) &&
		left.metadata.typeBits == right.metadata.typeBits && left.metadata.uid == right.metadata.uid &&
		left.metadata.modeBits == right.metadata.modeBits && left.access == right.access
}

// writeAllDescriptor writes every byte or fails on cancellation and no progress.
func writeAllDescriptor(ctx context.Context, fd int, content []byte) error {
	for offset := 0; offset < len(content); {
		if ctx.Err() != nil {
			return newError(CodeProtectedIO)
		}
		count, err := unix.Write(fd, content[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || count <= 0 || count > len(content)-offset {
			return newError(CodeProtectedIO)
		}
		offset += count
	}
	return nil
}

// syncDescriptor retries one interrupted fsync operation.
func syncDescriptor(fd int) error {
	return retryDescriptorOperation(func() error { return unix.Fsync(fd) })
}

// retryOpenatRaw preserves only error identity needed for absence and exclusive-create races.
func retryOpenatRaw(parentFD int, name string, flags int, mode uint32) (int, error) {
	for {
		fd, err := unix.Openat(parentFD, name, flags, mode)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return fd, err
	}
}

// close releases flock before closing every retained descriptor.
func (p protectedStorePlatform) close() error {
	if p.state == nil {
		return nil
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	return p.state.closeLocked()
}

// closeLocked releases all retained filesystem ownership exactly once.
func (s *protectedStoreState) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	unlockErr := unix.Flock(s.lock.fd, unix.LOCK_UN)
	lockErr := s.lock.close()
	directoryErr := s.directory.close()
	s.directoryPath, s.documentName, s.lockName = "", "", ""
	s.observe = nil
	s.expectedEntry = nil
	if unlockErr != nil || lockErr != nil || directoryErr != nil {
		return newError(CodeProtectedIO)
	}
	return nil
}
