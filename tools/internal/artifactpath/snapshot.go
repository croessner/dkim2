// Package artifactpath owns descriptor-safe artifact reads.
package artifactpath

import "os"

// FileSnapshot records one stable descriptor identity and content digest.
type FileSnapshot struct {
	SHA256      string `json:"sha256"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
	Links       uint64 `json:"links"`
	UID         uint32 `json:"uid"`
	ModifiedSec int64  `json:"modified_sec"`
	ModifiedNS  int64  `json:"modified_ns"`
	ChangedSec  int64  `json:"changed_sec"`
	ChangedNS   int64  `json:"changed_ns"`
}

// TreeEntry records one private descriptor identity in a confined directory tree.
type TreeEntry struct {
	Path     string
	Kind     string
	Snapshot FileSnapshot
}

// CreateFile creates one new confined regular file without following path links.
func CreateFile(rootPath string, relative string) (*os.File, error) {
	return createFile(rootPath, relative)
}

// OpenFile opens one confined regular file without following path links.
func OpenFile(rootPath string, relative string, limit int64) (*os.File, error) {
	return openFile(rootPath, relative, limit)
}

// SnapshotOpenFile hashes one already-open regular file with constant memory.
func SnapshotOpenFile(file *os.File, limit int64) (FileSnapshot, error) {
	return snapshotOpenFile(file, limit)
}

// SnapshotTree inventories a confined directory tree using descriptor-relative walks.
func SnapshotTree(
	rootPath string,
	relative string,
	maximumEntries int,
	maximumBytes int64,
) ([]TreeEntry, error) {
	return snapshotTree(rootPath, relative, maximumEntries, maximumBytes)
}
