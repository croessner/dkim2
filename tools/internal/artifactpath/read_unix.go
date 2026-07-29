//go:build darwin || linux

// Package artifactpath owns descriptor-safe artifact reads.
package artifactpath

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// ReadFile reads one stable confined regular file without following links.
func ReadFile(rootPath string, relative string, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("artifact_limit")
	}
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(
		rootPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() {
		_ = unix.Close(rootFD)
	}()
	if err := validateDirectory(rootFD); err != nil {
		return nil, err
	}
	parentFD, err := openDirectory(rootFD, filepath.Dir(cleaned))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = unix.Close(parentFD)
	}()
	fileFD, err := unix.Openat(
		parentFD,
		filepath.Base(cleaned),
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("artifact_file")
	}
	defer func() {
		_ = unix.Close(fileFD)
	}()
	var before unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || validateRegular(&before, limit) != nil {
		return nil, errors.New("artifact_file")
	}
	content := make([]byte, before.Size)
	offset := 0
	for offset < len(content) {
		count, readErr := unix.Read(fileFD, content[offset:])
		if readErr != nil || count == 0 {
			return nil, errors.New("artifact_read")
		}
		offset += count
	}
	var extra [1]byte
	if count, readErr := unix.Read(fileFD, extra[:]); count != 0 || readErr != nil {
		return nil, errors.New("artifact_growth")
	}
	var after unix.Stat_t
	if unix.Fstat(fileFD, &after) != nil || !sameStable(before, after) {
		return nil, errors.New("artifact_changed")
	}
	return content, nil
}

// SnapshotFile hashes one stable confined regular file with constant memory.
func SnapshotFile(rootPath string, relative string, limit int64) (FileSnapshot, error) {
	if limit < 0 {
		return FileSnapshot{}, errors.New("artifact_limit")
	}
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return FileSnapshot{}, err
	}
	rootFD, err := unix.Open(
		rootPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return FileSnapshot{}, errors.New("artifact_root")
	}
	defer func() {
		_ = unix.Close(rootFD)
	}()
	if err := validateDirectory(rootFD); err != nil {
		return FileSnapshot{}, err
	}
	parentFD, err := openDirectory(rootFD, filepath.Dir(cleaned))
	if err != nil {
		return FileSnapshot{}, err
	}
	defer func() {
		_ = unix.Close(parentFD)
	}()
	fileFD, err := unix.Openat(
		parentFD,
		filepath.Base(cleaned),
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return FileSnapshot{}, errors.New("artifact_file")
	}
	defer func() {
		_ = unix.Close(fileFD)
	}()
	return snapshotFileFD(fileFD, limit)
}

// snapshotOpenFile hashes an existing file descriptor from offset zero.
func snapshotOpenFile(file *os.File, limit int64) (FileSnapshot, error) {
	if file == nil || limit < 0 {
		return FileSnapshot{}, errors.New("artifact_file")
	}
	duplicate, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return FileSnapshot{}, errors.New("artifact_file")
	}
	defer func() {
		_ = unix.Close(duplicate)
	}()
	if _, err := unix.Seek(duplicate, 0, io.SeekStart); err != nil {
		return FileSnapshot{}, errors.New("artifact_file")
	}
	snapshot, err := snapshotFileFD(duplicate, limit)
	if _, seekErr := unix.Seek(duplicate, 0, io.SeekStart); err == nil && seekErr != nil {
		err = errors.New("artifact_file")
	}
	return snapshot, err
}

// snapshotFileFD hashes one regular descriptor and rejects concurrent mutation.
func snapshotFileFD(fileFD int, limit int64) (FileSnapshot, error) {
	var before unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || validateRegular(&before, limit) != nil {
		return FileSnapshot{}, errors.New("artifact_file")
	}
	hasher := sha256.New()
	buffer := make([]byte, 1<<20)
	var total int64
	for {
		count, readErr := unix.Read(fileFD, buffer)
		if count > 0 {
			total += int64(count)
			if total > before.Size {
				return FileSnapshot{}, errors.New("artifact_growth")
			}
			if _, err := hasher.Write(buffer[:count]); err != nil {
				return FileSnapshot{}, errors.New("artifact_hash")
			}
		}
		if readErr != nil {
			return FileSnapshot{}, errors.New("artifact_read")
		}
		if count == 0 {
			break
		}
	}
	var after unix.Stat_t
	if total != before.Size || unix.Fstat(fileFD, &after) != nil ||
		!sameStable(before, after) {
		return FileSnapshot{}, errors.New("artifact_changed")
	}
	return FileSnapshot{
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		Device:      uint64(before.Dev),
		Inode:       before.Ino,
		Size:        before.Size,
		Mode:        uint32(before.Mode),
		Links:       uint64(before.Nlink),
		UID:         before.Uid,
		ModifiedSec: before.Mtim.Sec,
		ModifiedNS:  before.Mtim.Nsec,
		ChangedSec:  before.Ctim.Sec,
		ChangedNS:   before.Ctim.Nsec,
	}, nil
}

// createFile creates one owned mode-0600 file through a confined parent descriptor.
func createFile(rootPath string, relative string) (*os.File, error) {
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(
		rootPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() {
		_ = unix.Close(rootFD)
	}()
	if err := validateDirectory(rootFD); err != nil {
		return nil, err
	}
	parentFD, err := openDirectory(rootFD, filepath.Dir(cleaned))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = unix.Close(parentFD)
	}()
	fileFD, err := unix.Openat(
		parentFD,
		filepath.Base(cleaned),
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, errors.New("artifact_create")
	}
	var stat unix.Stat_t
	if unix.Fstat(fileFD, &stat) != nil || validateRegular(&stat, 0) != nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("artifact_create")
	}
	return os.NewFile(uintptr(fileFD), filepath.Base(cleaned)), nil
}

// openFile opens one validated regular descriptor for a later bound consumer.
func openFile(rootPath string, relative string, limit int64) (*os.File, error) {
	if limit < 0 {
		return nil, errors.New("artifact_limit")
	}
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(
		rootPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() {
		_ = unix.Close(rootFD)
	}()
	if err := validateDirectory(rootFD); err != nil {
		return nil, err
	}
	parentFD, err := openDirectory(rootFD, filepath.Dir(cleaned))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = unix.Close(parentFD)
	}()
	fileFD, err := unix.Openat(
		parentFD,
		filepath.Base(cleaned),
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("artifact_file")
	}
	var stat unix.Stat_t
	if unix.Fstat(fileFD, &stat) != nil || validateRegular(&stat, limit) != nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("artifact_file")
	}
	return os.NewFile(uintptr(fileFD), filepath.Base(cleaned)), nil
}

// snapshotTree walks a directory through descriptors and inventories every entry.
func snapshotTree(
	rootPath string,
	relative string,
	maximumEntries int,
	maximumBytes int64,
) ([]TreeEntry, error) {
	if maximumEntries < 1 || maximumBytes < 0 {
		return nil, errors.New("artifact_tree")
	}
	cleaned, err := cleanRelative(relative)
	if err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(
		rootPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() {
		_ = unix.Close(rootFD)
	}()
	if err := validateDirectory(rootFD); err != nil {
		return nil, err
	}
	treeFD, err := openDirectory(rootFD, cleaned)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = unix.Close(treeFD)
	}()
	var entries []TreeEntry
	var total int64
	if err := walkTree(treeFD, ".", maximumEntries, maximumBytes, &total, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// walkTree inventories one open directory and its descendants in lexical order.
func walkTree(
	directoryFD int,
	relative string,
	maximumEntries int,
	maximumBytes int64,
	total *int64,
	result *[]TreeEntry,
) error {
	var directoryStat unix.Stat_t
	if unix.Fstat(directoryFD, &directoryStat) != nil ||
		validateDirectory(directoryFD) != nil {
		return errors.New("artifact_tree")
	}
	*result = append(*result, TreeEntry{
		Path:     relative,
		Kind:     "directory",
		Snapshot: snapshotFromStat(directoryStat, ""),
	})
	if len(*result) > maximumEntries {
		return errors.New("artifact_tree_entries")
	}
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return errors.New("artifact_tree")
	}
	directory := os.NewFile(uintptr(duplicate), relative)
	children, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.New("artifact_tree")
	}
	sort.Slice(children, func(left int, right int) bool {
		return children[left].Name() < children[right].Name()
	})
	for _, child := range children {
		name := child.Name()
		if name == "" || name == "." || name == ".." ||
			strings.ContainsRune(name, rune(filepath.Separator)) {
			return errors.New("artifact_tree")
		}
		childPath := name
		if relative != "." {
			childPath = filepath.Join(relative, name)
		}
		childFD, openErr := unix.Openat(
			directoryFD,
			name,
			unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil {
			return errors.New("artifact_tree")
		}
		var stat unix.Stat_t
		if unix.Fstat(childFD, &stat) != nil {
			_ = unix.Close(childFD)
			return errors.New("artifact_tree")
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := walkTree(
				childFD,
				childPath,
				maximumEntries,
				maximumBytes,
				total,
				result,
			); err != nil {
				_ = unix.Close(childFD)
				return err
			}
		case unix.S_IFREG:
			remaining := maximumBytes - *total
			if remaining < 0 {
				_ = unix.Close(childFD)
				return errors.New("artifact_tree_bytes")
			}
			snapshot, err := snapshotFileFD(childFD, remaining)
			if err != nil {
				_ = unix.Close(childFD)
				return err
			}
			*total += snapshot.Size
			*result = append(*result, TreeEntry{
				Path: childPath, Kind: "file", Snapshot: snapshot,
			})
			if len(*result) > maximumEntries {
				_ = unix.Close(childFD)
				return errors.New("artifact_tree_entries")
			}
		default:
			_ = unix.Close(childFD)
			return errors.New("artifact_tree_type")
		}
		if unix.Close(childFD) != nil {
			return errors.New("artifact_tree")
		}
	}
	var after unix.Stat_t
	if unix.Fstat(directoryFD, &after) != nil || !sameStable(directoryStat, after) {
		return errors.New("artifact_tree_changed")
	}
	return nil
}

// snapshotFromStat converts one private descriptor identity into a comparable record.
func snapshotFromStat(stat unix.Stat_t, digest string) FileSnapshot {
	return FileSnapshot{
		SHA256: digest, Device: uint64(stat.Dev), Inode: stat.Ino,
		Size: stat.Size, Mode: uint32(stat.Mode), Links: uint64(stat.Nlink), UID: stat.Uid,
		ModifiedSec: stat.Mtim.Sec, ModifiedNS: stat.Mtim.Nsec,
		ChangedSec: stat.Ctim.Sec, ChangedNS: stat.Ctim.Nsec,
	}
}

// openDirectory walks an existing path using only no-follow directory descriptors.
func openDirectory(rootFD int, relative string) (int, error) {
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	if relative == "." {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		_ = unix.Close(current)
		if openErr != nil || validateDirectory(next) != nil {
			if next >= 0 {
				_ = unix.Close(next)
			}
			return -1, errors.New("artifact_directory")
		}
		current = next
	}
	return current, nil
}

// validateDirectory enforces owned non-writable directory descriptors.
func validateDirectory(fd int) error {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		int(stat.Uid) != os.Geteuid() ||
		stat.Mode&0o022 != 0 {
		return errors.New("artifact_directory")
	}
	return nil
}

// validateRegular enforces owned bounded one-link regular evidence.
func validateRegular(stat *unix.Stat_t, limit int64) error {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 ||
		stat.Mode&0o022 != 0 ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 ||
		stat.Size < 0 || stat.Size > limit {
		return errors.New("artifact_file")
	}
	return nil
}

// sameStable rejects descriptor identity or metadata changes across a read.
func sameStable(before unix.Stat_t, after unix.Stat_t) bool {
	return before.Dev == after.Dev &&
		before.Ino == after.Ino &&
		before.Size == after.Size &&
		before.Mode == after.Mode &&
		before.Nlink == after.Nlink &&
		before.Uid == after.Uid &&
		before.Mtim == after.Mtim &&
		before.Ctim == after.Ctim
}

// cleanRelative rejects absolute, dot, and escaping paths.
func cleanRelative(value string) (string, error) {
	if value == "" || filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return "", errors.New("artifact_relative")
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("artifact_relative")
	}
	return cleaned, nil
}
