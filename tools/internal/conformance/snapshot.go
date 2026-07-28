package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxSnapshotFileBytes  = int64(256 << 20)
	maxSnapshotTotalBytes = int64(2 << 30)
	maxSnapshotPaths      = 65536
	maxSnapshotPathBytes  = 4096
	gitTimeout            = 30 * time.Second
)

// SnapshotEntry records one framed candidate path for independent review.
type SnapshotEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Snapshot contains the candidate digest and independently auditable inventory.
type Snapshot struct {
	Schema       string          `json:"schema"`
	BaseRevision string          `json:"base_revision"`
	SHA256       string          `json:"sha256"`
	Entries      []SnapshotEntry `json:"entries"`
}

type snapshotInventory struct {
	names   []byte
	deleted []byte
	paths   [][]byte
}

// CurrentRevision returns the trusted full lowercase Git HEAD identity.
func CurrentRevision(root string) (string, error) {
	output, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return "", errors.New("snapshot_base")
	}
	revision := strings.TrimSpace(string(output))
	if !isRevision(revision) {
		return "", errors.New("snapshot_base")
	}
	return revision, nil
}

// ProduceSnapshot hashes the exact tracked and non-ignored untracked durable tree.
func ProduceSnapshot(root, expectedBase string) (Snapshot, error) {
	if !isRevision(expectedBase) {
		return Snapshot{}, errors.New("snapshot_base")
	}
	head, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != expectedBase {
		return Snapshot{}, errors.New("snapshot_base")
	}
	if err := gitIndexClean(root); err != nil {
		return Snapshot{}, errors.New("snapshot_index")
	}
	inventory, err := loadSnapshotInventory(root)
	if err != nil {
		return Snapshot{}, err
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return Snapshot{}, errors.New("snapshot_root")
	}
	defer func() { _ = rootHandle.Close() }()
	hasher := sha256.New()
	writeFrame(hasher, []byte(SnapshotSchema))
	writeFrame(hasher, []byte(expectedBase))
	entries, err := hashSnapshotEntries(rootHandle, inventory.paths, hasher)
	if err != nil {
		return Snapshot{}, err
	}
	finalHead, err := CurrentRevision(root)
	if err != nil || finalHead != expectedBase {
		return Snapshot{}, errors.New("snapshot_unstable")
	}
	finalInventory, err := loadSnapshotInventory(root)
	if err != nil || !bytes.Equal(inventory.names, finalInventory.names) ||
		!bytes.Equal(inventory.deleted, finalInventory.deleted) {
		return Snapshot{}, errors.New("snapshot_unstable")
	}
	if err := gitIndexClean(root); err != nil {
		return Snapshot{}, errors.New("snapshot_unstable")
	}
	verificationHasher := sha256.New()
	writeFrame(verificationHasher, []byte(SnapshotSchema))
	writeFrame(verificationHasher, []byte(expectedBase))
	verificationEntries, err := hashSnapshotEntries(rootHandle, finalInventory.paths, verificationHasher)
	if err != nil || !equalSnapshotEntries(entries, verificationEntries) ||
		!bytes.Equal(hasher.Sum(nil), verificationHasher.Sum(nil)) {
		return Snapshot{}, errors.New("snapshot_unstable")
	}
	lastHead, err := CurrentRevision(root)
	if err != nil || lastHead != expectedBase || gitIndexClean(root) != nil {
		return Snapshot{}, errors.New("snapshot_unstable")
	}
	lastInventory, err := loadSnapshotInventory(root)
	if err != nil || !bytes.Equal(finalInventory.names, lastInventory.names) ||
		!bytes.Equal(finalInventory.deleted, lastInventory.deleted) {
		return Snapshot{}, errors.New("snapshot_unstable")
	}
	return Snapshot{
		Schema: SnapshotSchema, BaseRevision: expectedBase,
		SHA256: hex.EncodeToString(hasher.Sum(nil)), Entries: entries,
	}, nil
}

// equalSnapshotEntries compares exact path, mode, and content evidence.
func equalSnapshotEntries(left, right []SnapshotEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// loadSnapshotInventory reads bounded tracked/untracked and deleted path sets.
func loadSnapshotInventory(root string) (snapshotInventory, error) {
	names, err := gitOutput(root, "ls-files", "-c", "-o", "--exclude-standard", "-z")
	if err != nil {
		return snapshotInventory{}, errors.New("snapshot_inventory")
	}
	paths := bytes.Split(bytes.TrimSuffix(names, []byte{0}), []byte{0})
	if len(paths) > maxSnapshotPaths {
		return snapshotInventory{}, errors.New("snapshot_inventory")
	}
	deleted, err := gitOutput(root, "ls-files", "--deleted", "-z")
	if err != nil {
		return snapshotInventory{}, errors.New("snapshot_inventory")
	}
	deletedSet := make(map[string]struct{})
	for _, path := range bytes.Split(bytes.TrimSuffix(deleted, []byte{0}), []byte{0}) {
		if len(path) > 0 {
			deletedSet[string(path)] = struct{}{}
		}
	}
	current := paths[:0]
	for _, path := range paths {
		if _, isDeleted := deletedSet[string(path)]; !isDeleted {
			current = append(current, path)
		}
	}
	sort.Slice(current, func(i, j int) bool { return bytes.Compare(current[i], current[j]) < 0 })
	return snapshotInventory{names: names, deleted: deleted, paths: current}, nil
}

// hashSnapshotEntries streams one stable current-tree inventory into the framing digest.
func hashSnapshotEntries(
	rootHandle *os.Root,
	paths [][]byte,
	hasher interface{ Write([]byte) (int, error) },
) ([]SnapshotEntry, error) {
	entries := make([]SnapshotEntry, 0, len(paths))
	seenFolded := make(map[string]struct{}, len(paths))
	var totalBytes int64
	for _, rawPath := range paths {
		path := string(rawPath)
		if len(rawPath) == 0 || len(rawPath) > maxSnapshotPathBytes {
			return nil, errors.New("snapshot_path")
		}
		if err := validateArtifactPath(path); err != nil {
			return nil, errors.New("snapshot_path")
		}
		folded := strings.ToLower(path)
		if _, collision := seenFolded[folded]; collision {
			return nil, errors.New("snapshot_collision")
		}
		seenFolded[folded] = struct{}{}
		if err := rejectPathSymlinks(rootHandle, path); err != nil {
			return nil, errors.New("snapshot_type")
		}
		file, err := rootHandle.Open(filepath.FromSlash(path))
		if err != nil {
			return nil, errors.New("snapshot_read")
		}
		before, err := file.Stat()
		if err != nil || !before.Mode().IsRegular() {
			_ = file.Close()
			return nil, errors.New("snapshot_type")
		}
		contentHasher := sha256.New()
		size, copyErr := io.Copy(contentHasher, io.LimitReader(file, maxSnapshotFileBytes+1))
		after, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil || size > maxSnapshotFileBytes ||
			!os.SameFile(before, after) || before.Size() != after.Size() ||
			before.ModTime() != after.ModTime() {
			return nil, errors.New("snapshot_unstable")
		}
		if err := rejectPathSymlinks(rootHandle, path); err != nil {
			return nil, errors.New("snapshot_type")
		}
		pathInfo, err := rootHandle.Stat(filepath.FromSlash(path))
		if err != nil || !os.SameFile(after, pathInfo) {
			return nil, errors.New("snapshot_unstable")
		}
		totalBytes += size
		if totalBytes > maxSnapshotTotalBytes {
			return nil, errors.New("snapshot_size")
		}
		mode := "100644"
		if before.Mode()&0o111 != 0 {
			mode = "100755"
		}
		digest := hex.EncodeToString(contentHasher.Sum(nil))
		writeFrame(hasher, []byte(mode))
		writeFrame(hasher, rawPath)
		writeUint64(hasher, uint64(size))
		digestBytes, _ := hex.DecodeString(digest)
		_, _ = hasher.Write(digestBytes)
		entries = append(entries, SnapshotEntry{Path: path, Mode: mode, SHA256: digest})
	}
	return entries, nil
}

// gitOutput executes one closed Git inventory operation.
func gitOutput(root string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = root
	output, err := command.Output()
	if ctx.Err() != nil {
		return nil, errors.New("git_timeout")
	}
	return output, err
}

// gitIndexClean proves the real Git index is empty within a bounded deadline.
func gitIndexClean(root string) error {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "diff", "--cached", "--quiet")
	command.Dir = root
	if err := command.Run(); err != nil {
		return errors.New("snapshot_index")
	}
	return nil
}

// writeFrame writes one fixed-width length and exact byte string.
func writeFrame(writer interface{ Write([]byte) (int, error) }, value []byte) {
	writeUint64(writer, uint64(len(value)))
	_, _ = writer.Write(value)
}

// writeUint64 writes one unsigned big-endian length.
func writeUint64(writer interface{ Write([]byte) (int, error) }, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}
