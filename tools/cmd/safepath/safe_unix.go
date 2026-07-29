//go:build darwin || linux

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumArtifactBytes = int64(1 << 30)

type safeRoot struct {
	fd int
}

// openSafeRoot opens one immutable directory descriptor without following links.
func openSafeRoot(path string) (*safeRoot, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(
		absolute,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := validateDirectoryFD(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &safeRoot{fd: fd}, nil
}

// close releases the root descriptor.
func (s *safeRoot) close() {
	if s != nil && s.fd >= 0 {
		_ = unix.Close(s.fd)
		s.fd = -1
	}
}

// prepareDirectory creates every component through owned directory descriptors.
func (s *safeRoot) prepareDirectory(relative string) error {
	fd, err := s.openDirectory(relative, true)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// validateFile opens and validates one confined one-link regular file.
func (s *safeRoot) validateFile(relative string) error {
	parent, base, err := s.openParent(relative, false)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(parent)
	}()
	fd, err := unix.Openat(parent, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(fd)
	}()
	return validateRegularFD(fd, maximumArtifactBytes)
}

// installFile copies one stable source descriptor and publishes without replacement.
func (s *safeRoot) installFile(sourceRelative string, targetRelative string, executable bool) error {
	return s.publishFile(sourceRelative, targetRelative, executable, false)
}

// replaceFile copies one stable source descriptor and atomically replaces a validated target.
func (s *safeRoot) replaceFile(sourceRelative string, targetRelative string, executable bool) error {
	return s.publishFile(sourceRelative, targetRelative, executable, true)
}

// publishFile copies one stable source and applies the selected publication policy.
func (s *safeRoot) publishFile(
	sourceRelative string,
	targetRelative string,
	executable bool,
	replace bool,
) error {
	sourceParent, sourceBase, err := s.openParent(sourceRelative, false)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(sourceParent)
	}()
	sourceFD, err := unix.Openat(
		sourceParent,
		sourceBase,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(sourceFD)
	}()
	var sourceBefore unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceBefore); err != nil ||
		validateRegularStat(&sourceBefore, maximumArtifactBytes) != nil {
		return errors.New("source")
	}
	targetParent, targetBase, err := s.openParent(targetRelative, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(targetParent)
	}()
	if same, exists, err := sameExistingTarget(
		targetParent,
		targetBase,
		sourceFD,
		sourceBefore,
	); err != nil {
		return err
	} else if exists {
		if same {
			return nil
		}
		if !replace {
			return errors.New("target exists")
		}
	}
	temporaryName, temporaryFD, err := createTemporary(targetParent)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		_ = unix.Close(temporaryFD)
		if !published {
			_ = unix.Unlinkat(targetParent, temporaryName, 0)
		}
	}()
	if _, err := unix.Seek(sourceFD, 0, io.SeekStart); err != nil {
		return err
	}
	written, err := copyDescriptors(temporaryFD, sourceFD, sourceBefore.Size)
	if err != nil || written != sourceBefore.Size {
		return errors.New("copy")
	}
	var one [1]byte
	if count, readErr := unix.Read(sourceFD, one[:]); count != 0 || readErr != nil {
		return errors.New("source growth")
	}
	var sourceAfter unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceAfter); err != nil ||
		!sameStableFile(sourceBefore, sourceAfter) {
		return errors.New("source changed")
	}
	mode := uint32(0o600)
	if executable {
		mode = 0o500
	}
	if err := unix.Fchmod(temporaryFD, mode); err != nil ||
		unix.Fsync(temporaryFD) != nil {
		return errors.New("target sync")
	}
	if replace {
		if err := unix.Renameat(targetParent, temporaryName, targetParent, targetBase); err != nil {
			return err
		}
	} else {
		if err := renameNoReplace(targetParent, temporaryName, targetBase); err != nil {
			return err
		}
	}
	if err := unix.Fsync(targetParent); err != nil {
		return errors.New("parent sync")
	}
	published = true
	return nil
}

// openParent opens the parent descriptor and returns a validated basename.
func (s *safeRoot) openParent(relative string, create bool) (int, string, error) {
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return -1, "", err
	}
	base := filepath.Base(cleaned)
	if base == "." || base == string(filepath.Separator) {
		return -1, "", errors.New("base")
	}
	parentPath := filepath.Dir(cleaned)
	if parentPath == "." {
		duplicate, err := unix.Dup(s.fd)
		return duplicate, base, err
	}
	parent, err := s.openDirectory(parentPath, create)
	return parent, base, err
}

// openDirectory walks only O_NOFOLLOW directory descriptors.
func (s *safeRoot) openDirectory(relative string, create bool) (int, error) {
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return -1, err
	}
	current, err := unix.Dup(s.fd)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(cleaned, string(filepath.Separator)) {
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(current, component, 0o700); mkdirErr != nil &&
				!errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(current)
				return -1, mkdirErr
			}
			next, openErr = unix.Openat(
				current,
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
		}
		_ = unix.Close(current)
		if openErr != nil || validateDirectoryFD(next) != nil {
			if next >= 0 {
				_ = unix.Close(next)
			}
			return -1, errors.New("directory")
		}
		current = next
	}
	return current, nil
}

// sameExistingTarget compares an existing target through stable descriptors.
func sameExistingTarget(
	parent int,
	name string,
	sourceFD int,
	sourceBefore unix.Stat_t,
) (bool, bool, error) {
	targetFD, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, false, nil
	}
	if err != nil {
		return false, true, err
	}
	defer func() {
		_ = unix.Close(targetFD)
	}()
	if err := validateRegularFD(targetFD, maximumArtifactBytes); err != nil {
		return false, true, err
	}
	var targetStat unix.Stat_t
	if err := unix.Fstat(targetFD, &targetStat); err != nil ||
		targetStat.Size != sourceBefore.Size {
		return false, true, nil
	}
	if _, err := unix.Seek(sourceFD, 0, io.SeekStart); err != nil {
		return false, true, err
	}
	equal, err := compareDescriptors(sourceFD, targetFD, sourceBefore.Size)
	if err != nil {
		return false, true, err
	}
	var sourceAfter unix.Stat_t
	var targetAfter unix.Stat_t
	if unix.Fstat(sourceFD, &sourceAfter) != nil ||
		unix.Fstat(targetFD, &targetAfter) != nil ||
		!sameStableFile(sourceBefore, sourceAfter) ||
		!sameStableFile(targetStat, targetAfter) {
		return false, true, errors.New("comparison changed")
	}
	return equal, true, nil
}

// copyDescriptors copies an exact bounded byte count with no file-wrapper alias.
func copyDescriptors(targetFD int, sourceFD int, size int64) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for total < size {
		want := int64(len(buffer))
		if remaining := size - total; remaining < want {
			want = remaining
		}
		count, err := unix.Read(sourceFD, buffer[:want])
		if err != nil || count == 0 {
			return total, errors.New("read")
		}
		offset := 0
		for offset < count {
			written, writeErr := unix.Write(targetFD, buffer[offset:count])
			if writeErr != nil || written == 0 {
				return total, errors.New("write")
			}
			offset += written
		}
		total += int64(count)
	}
	return total, nil
}

// compareDescriptors compares exact bytes with constant bounded memory.
func compareDescriptors(leftFD int, rightFD int, size int64) (bool, error) {
	if _, err := unix.Seek(leftFD, 0, io.SeekStart); err != nil {
		return false, err
	}
	if _, err := unix.Seek(rightFD, 0, io.SeekStart); err != nil {
		return false, err
	}
	left := make([]byte, 64<<10)
	right := make([]byte, 64<<10)
	var total int64
	for total < size {
		want := int64(len(left))
		if remaining := size - total; remaining < want {
			want = remaining
		}
		leftCount, leftErr := unix.Read(leftFD, left[:want])
		rightCount, rightErr := unix.Read(rightFD, right[:want])
		if leftErr != nil || rightErr != nil || leftCount != rightCount || leftCount == 0 {
			return false, errors.New("compare")
		}
		if !bytes.Equal(left[:leftCount], right[:rightCount]) {
			return false, nil
		}
		total += int64(leftCount)
	}
	return true, nil
}

// createTemporary allocates one unpredictable exclusive file in the target directory.
func createTemporary(parent int) (string, int, error) {
	var random [16]byte
	for attempts := 0; attempts < 8; attempts++ {
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return "", -1, err
		}
		name := fmt.Sprintf(".install-%x", random[:])
		fd, err := unix.Openat(
			parent,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, err
		}
	}
	return "", -1, errors.New("temporary")
}

// validateDirectoryFD enforces one owned non-writable directory descriptor.
func validateDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		int(stat.Uid) != os.Geteuid() ||
		stat.Mode&0o022 != 0 {
		return errors.New("directory")
	}
	return nil
}

// validateRegularFD enforces one bounded owned one-link regular descriptor.
func validateRegularFD(fd int, limit int64) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	return validateRegularStat(&stat, limit)
}

// validateRegularStat enforces stable regular-file metadata.
func validateRegularStat(stat *unix.Stat_t, limit int64) error {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 ||
		stat.Mode&0o022 != 0 ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 ||
		!platformFlagsSafe(stat) ||
		stat.Size < 0 || stat.Size > limit {
		return errors.New("file")
	}
	return nil
}

// sameStableFile compares the descriptor identity and mutable metadata.
func sameStableFile(before unix.Stat_t, after unix.Stat_t) bool {
	return before.Dev == after.Dev &&
		before.Ino == after.Ino &&
		before.Size == after.Size &&
		samePlatformTimes(before, after) &&
		before.Mode == after.Mode &&
		before.Nlink == after.Nlink &&
		before.Uid == after.Uid
}

// samePlatformTimes compares mutation and status-change timestamps.
func samePlatformTimes(before unix.Stat_t, after unix.Stat_t) bool {
	return before.Mtim == after.Mtim &&
		before.Ctim == after.Ctim
}

// cleanRelative rejects absolute, empty, dot, and escaping paths.
func cleanRelative(value string) (string, error) {
	if value == "" || filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return "", errors.New("relative")
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("relative")
	}
	return cleaned, nil
}
