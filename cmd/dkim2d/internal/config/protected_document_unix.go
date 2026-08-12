//go:build linux || darwin

package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type protectedDocumentEvent uint8

const (
	protectedDocumentAfterRead protectedDocumentEvent = iota + 1
	protectedDocumentBeforeFinalProof
)

type protectedCreateEvent uint8

const (
	protectedCreateAfterLink protectedCreateEvent = iota + 1
	protectedCreateBeforeFinalReadback
)

// ReadProtectedDocument reads one bounded document through the central descriptor authority.
func ReadProtectedDocument(path string, maximum int) ([]byte, error) {
	data, exists, err := readProtectedDocumentIfExistsObserved(path, maximum, nil)
	if err != nil || !exists {
		clear(data)
		if err != nil {
			return nil, err
		}
		return nil, newError(CodeProtectedAccess)
	}
	return data, nil
}

// ReadProtectedDocumentIfExists reads an exact protected document without creating filesystem state.
func ReadProtectedDocumentIfExists(path string, maximum int) ([]byte, bool, error) {
	return readProtectedDocumentIfExistsObserved(path, maximum, nil)
}

// readProtectedDocumentObserved exposes content-free race points to deterministic package tests.
func readProtectedDocumentObserved(
	path string,
	maximum int,
	observe func(protectedDocumentEvent),
) (data []byte, resultErr error) {
	data, exists, err := readProtectedDocumentIfExistsObserved(path, maximum, observe)
	if err != nil || !exists {
		clear(data)
		if err != nil {
			return nil, err
		}
		return nil, newError(CodeProtectedAccess)
	}
	return data, nil
}

// readProtectedDocumentIfExistsObserved distinguishes exact absence through a proven parent descriptor.
func readProtectedDocumentIfExistsObserved(
	path string,
	maximum int,
	observe func(protectedDocumentEvent),
) (data []byte, exists bool, resultErr error) {
	if maximum <= 0 || maximum > maxYAMLDocumentBytes {
		return nil, false, newError(CodeProtectedContent)
	}
	defer func() {
		if resultErr != nil {
			clear(data)
			data = nil
			exists = false
		}
	}()
	parent, parentPre, effectiveUID, err := openProtectedDocumentParent(path)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if closeErr := parent.close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	fd, err := retryOpenatRaw(parent.fd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		parentFinal, finalErr := captureDescriptorState(parent.fd, parentPre.metadata.modeBits, true)
		if finalErr != nil || !sameDirectorySecurityState(parentFinal, parentPre) {
			return nil, false, newError(CodeProtectedAccess)
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, newError(CodeProtectedIO)
	}
	document := newOwnedDescriptor(fd)
	defer func() {
		if closeErr := document.close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	pre, err := validateProtectedDescriptor(document.fd, protectedYAML, effectiveUID)
	if err != nil || pre.metadata.size <= 0 || pre.metadata.size > int64(maximum) {
		return nil, false, newError(CodeProtectedAccess)
	}
	data, err = readProtectedDescriptor(document.fd, maximum)
	if err != nil || len(data) == 0 {
		clear(data)
		return nil, false, newError(CodeProtectedContent)
	}
	if observe != nil {
		observe(protectedDocumentAfterRead)
	}
	immediate, err := captureDescriptorState(document.fd, pre.metadata.modeBits, false)
	if err != nil || immediate != pre {
		clear(data)
		return nil, false, newError(CodeProtectedAccess)
	}
	if observe != nil {
		observe(protectedDocumentBeforeFinalProof)
	}
	if err := proveProtectedDocumentBytes(document.fd, maximum, data); err != nil {
		clear(data)
		return nil, false, err
	}
	final, err := captureDescriptorState(document.fd, pre.metadata.modeBits, false)
	parentFinal, parentErr := captureDescriptorState(parent.fd, parentPre.metadata.modeBits, true)
	pathFinal, pathErr := statAtNoFollow(parent.fd, filepath.Base(path))
	if err != nil || parentErr != nil || pathErr != nil || final != pre || final != immediate ||
		parentFinal != parentPre || pathFinal != pre.metadata {
		clear(data)
		return nil, false, newError(CodeProtectedAccess)
	}
	return data, true, nil
}

// proveProtectedDocumentBytes catches same-size rewrites even when a filesystem
// does not advance descriptor timestamps between the two observations.
func proveProtectedDocumentBytes(fd, maximum int, expected []byte) error {
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return newError(CodeProtectedIO)
	}
	proof, err := readProtectedDescriptor(fd, maximum)
	defer clear(proof)
	if err != nil || !bytes.Equal(proof, expected) {
		return newError(CodeProtectedAccess)
	}
	return nil
}

// openProtectedDocumentParent proves and retains one trusted final parent directory.
func openProtectedDocumentParent(path string) (ownedDescriptor, descriptorState, uint32, error) {
	effectiveUID := uint32(os.Geteuid())
	if _, err := protectedPathComponents(path); err != nil || filepath.Clean(path) != path {
		return ownedDescriptor{fd: -1}, descriptorState{}, 0, newError(CodeProtectedPath)
	}
	parent, err := openProtectedPathWithUID(filepath.Dir(path), true, effectiveUID)
	if err != nil {
		return ownedDescriptor{fd: -1}, descriptorState{}, 0, err
	}
	if err := validateTrustedDirectory(parent.fd, effectiveUID); err != nil {
		_ = parent.close()
		return ownedDescriptor{fd: -1}, descriptorState{}, 0, err
	}
	metadata, err := statDescriptor(parent.fd)
	if err != nil {
		_ = parent.close()
		return ownedDescriptor{fd: -1}, descriptorState{}, 0, err
	}
	state, err := captureDescriptorState(parent.fd, metadata.modeBits, true)
	if err != nil {
		_ = parent.close()
		return ownedDescriptor{fd: -1}, descriptorState{}, 0, err
	}
	return parent, state, effectiveUID, nil
}

// CreateProtectedDocument atomically installs one owner-only document only when the final path is absent.
func CreateProtectedDocument(ctx context.Context, path string, content []byte, maximum int) error {
	return createProtectedDocumentObserved(ctx, path, content, maximum, nil)
}

// createProtectedDocumentObserved uses a hard-link install and exposes a content-free test seam.
func createProtectedDocumentObserved(
	ctx context.Context,
	path string,
	content []byte,
	maximum int,
	observe func(protectedCreateEvent),
) error {
	if ctx == nil || ctx.Err() != nil || len(content) == 0 || maximum <= 0 ||
		maximum > maxYAMLDocumentBytes || len(content) > maximum {
		return newError(CodeProtectedContent)
	}
	directory, _, effectiveUID, err := openProtectedDocumentParent(path)
	if err != nil {
		return err
	}
	defer directory.close() //nolint:errcheck // A create result remains authoritative over cleanup.
	directoryPre, err := validateProtectedStoreDirectory(directory.fd, effectiveUID)
	if err != nil {
		return err
	}
	directoryPath := filepath.Dir(path)
	state := &protectedStoreState{
		directory: directory, directoryPath: directoryPath, documentName: filepath.Base(path),
		directoryPre: directoryPre, maximum: maximum, effectiveUID: effectiveUID,
	}
	temporary, temporaryName, err := state.createTemporary()
	if err != nil {
		return err
	}
	defer func() {
		_ = temporary.close()
		_ = unix.Unlinkat(directory.fd, temporaryName, 0)
	}()
	owned := append([]byte(nil), content...)
	defer clear(owned)
	if err := prepareProtectedTemporary(ctx, state, temporary.fd, owned); err != nil {
		return err
	}
	return installProtectedTemporary(ctx, state, temporaryName, owned, observe)
}

// prepareProtectedTemporary writes, syncs, and validates one bounded installation candidate.
func prepareProtectedTemporary(
	ctx context.Context,
	state *protectedStoreState,
	fd int,
	content []byte,
) error {
	if err := writeAllDescriptor(ctx, fd, content); err != nil || syncDescriptor(fd) != nil {
		return newError(CodeProtectedIO)
	}
	pre, err := state.validateDocument(fd)
	if err != nil || pre.metadata.size != int64(len(content)) {
		return newError(CodeProtectedAccess)
	}
	directoryNow, err := validateProtectedStoreDirectory(state.directory.fd, state.effectiveUID)
	if err != nil || ctx.Err() != nil || !sameDirectorySecurityState(directoryNow, state.directoryPre) {
		return newError(CodeProtectedIO)
	}
	return nil
}

// installProtectedTemporary links one absent final name and proves durable exact bytes.
func installProtectedTemporary(
	ctx context.Context,
	state *protectedStoreState,
	temporaryName string,
	content []byte,
	observe func(protectedCreateEvent),
) error {
	err := unix.Linkat(state.directory.fd, temporaryName, state.directory.fd, state.documentName, 0)
	if errors.Is(err, unix.EEXIST) {
		return newError(CodeProtectedConflict)
	}
	if err != nil {
		return newError(CodeProtectedIO)
	}
	if observe != nil {
		observe(protectedCreateAfterLink)
	}
	if unlinkErr := unix.Unlinkat(state.directory.fd, temporaryName, 0); unlinkErr != nil {
		return newError(CodeProtectedAmbiguous)
	}
	if ctx.Err() != nil || syncDescriptor(state.directory.fd) != nil {
		return newError(CodeProtectedAmbiguous)
	}
	if observe != nil {
		observe(protectedCreateBeforeFinalReadback)
	}
	return proveCreatedDocument(state, content)
}

// proveCreatedDocument reads back exact final bytes and descriptor identity after installation.
func proveCreatedDocument(state *protectedStoreState, content []byte) error {
	fd, err := retryOpenatRaw(state.directory.fd, state.documentName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return newError(CodeProtectedAmbiguous)
	}
	document := newOwnedDescriptor(fd)
	defer document.close() //nolint:errcheck // A final proof failure is already ambiguous.
	pre, preErr := state.validateDocument(fd)
	readback, readErr := readProtectedDescriptor(fd, state.maximum)
	defer clear(readback)
	final, finalErr := state.validateDocument(fd)
	entry, entryErr := statAtNoFollow(state.directory.fd, state.documentName)
	directoryNow, directoryErr := validateProtectedStoreDirectory(state.directory.fd, state.effectiveUID)
	if preErr != nil || readErr != nil || finalErr != nil || pre != final || !bytes.Equal(readback, content) ||
		entryErr != nil || entry != final.metadata || final.metadata.size != int64(len(content)) ||
		directoryErr != nil || !sameDirectorySecurityState(directoryNow, state.directoryPre) {
		return newError(CodeProtectedAmbiguous)
	}
	return nil
}
