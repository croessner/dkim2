package interop

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// ArchiveEntry records one content-free regular source-file identity.
type ArchiveEntry struct {
	Path   string `json:"path"`
	Mode   int64  `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// InspectArchive validates one gzip-or-plain tar stream without extracting it.
func InspectArchive(input io.Reader, policy RetrievalPolicy) ([]ArchiveEntry, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	buffered := newPrefixReader(io.LimitReader(input, policy.MaxResponseBytes+1))
	reader, closeReader, err := archiveReader(buffered)
	if err != nil {
		return nil, err
	}
	if closeReader != nil {
		defer func() { _ = closeReader.Close() }()
	}
	entries, err := inspectTar(reader, policy)
	if err != nil {
		return nil, err
	}
	if buffered.ReadBytes() > policy.MaxResponseBytes {
		return nil, errors.New("archive_compressed_size")
	}
	return entries, nil
}

// inspectTar checks every path, type, mode, size, collision, and content digest.
//
//nolint:gocyclo // The closed tar type/path/resource matrix is intentionally linear.
func inspectTar(reader io.Reader, policy RetrievalPolicy) ([]ArchiveEntry, error) {
	tarReader := tar.NewReader(reader)
	entries := make([]ArchiveEntry, 0)
	seen := make(map[string]struct{})
	seenFolded := make(map[string]struct{})
	var total int64
	headers := 0
	globalHeaders := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("archive_format")
		}
		headers++
		if headers > policy.MaxFiles {
			return nil, errors.New("archive_file_count")
		}
		clean, err := validateArchivePath(header.Name, policy)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[clean]; exists {
			return nil, errors.New("archive_duplicate")
		}
		seen[clean] = struct{}{}
		folded := strings.ToLower(clean)
		if _, exists := seenFolded[folded]; exists {
			return nil, errors.New("archive_collision")
		}
		seenFolded[folded] = struct{}{}
		if header.Linkname != "" {
			return nil, errors.New("archive_link")
		}
		if !safePAXRecords(header.PAXRecords) {
			return nil, errors.New("archive_pax")
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink ||
			header.Typeflag == tar.TypeChar || header.Typeflag == tar.TypeBlock ||
			header.Typeflag == tar.TypeFifo {
			return nil, errors.New("archive_type")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return nil, errors.New("archive_type")
			}
			continue
		case tar.TypeXGlobalHeader:
			globalHeaders++
			if globalHeaders > 1 || header.Size < 0 || header.Size > 4096 ||
				total > policy.MaxTotalBytes-header.Size {
				return nil, fmt.Errorf("archive_global_header_%d_%d", globalHeaders, header.Size)
			}
			total += header.Size
			if read, err := io.CopyN(io.Discard, tarReader, header.Size); err != nil || read != header.Size {
				return nil, errors.New("archive_read")
			}
			continue
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // NUL is a valid historical regular-file typeflag.
		default:
			return nil, fmt.Errorf("archive_type_%d", header.Typeflag)
		}
		if header.Size < 0 || header.Size > policy.MaxFileBytes ||
			total > policy.MaxTotalBytes-header.Size {
			return nil, errors.New("archive_size")
		}
		total += header.Size
		hasher := sha256.New()
		read, err := io.CopyN(hasher, tarReader, header.Size)
		if err != nil || read != header.Size {
			return nil, errors.New("archive_read")
		}
		mode := header.Mode & 0o777
		if mode&0o400 == 0 {
			return nil, errors.New("archive_mode")
		}
		mode = 0o644
		if header.Mode&0o111 != 0 {
			mode = 0o755
		}
		entries = append(entries, ArchiveEntry{
			Path: clean, Mode: mode, Size: header.Size,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Path < entries[right].Path
	})
	return entries, nil
}

// safePAXRecords admits only a bounded source-commit comment and ignores its value.
func safePAXRecords(records map[string]string) bool {
	for key, value := range records {
		if key != "comment" || len(value) == 0 || len(value) > 128 ||
			strings.ContainsAny(value, "\r\n") {
			return false
		}
	}
	return true
}

// validateArchivePath rejects path escape, non-ASCII ambiguity, and excessive depth.
func validateArchivePath(value string, policy RetrievalPolicy) (string, error) {
	if value == "" || len(value) > policy.MaxPathBytes || strings.Contains(value, "\\") ||
		strings.HasPrefix(value, "/") || strings.ContainsRune(value, 0) {
		return "", errors.New("archive_path")
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", errors.New("archive_path")
		}
	}
	clean := path.Clean(value)
	if clean == "." || clean != strings.TrimSuffix(value, "/") ||
		clean == ".." || strings.HasPrefix(clean, "../") ||
		len(strings.Split(clean, "/")) > policy.MaxDepth {
		return "", errors.New("archive_path")
	}
	for _, component := range strings.Split(clean, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return "", errors.New("archive_path")
		}
	}
	return clean, nil
}

// archiveReader detects an optional gzip wrapper without consuming its prefix.
func archiveReader(reader *prefixReader) (io.Reader, io.Closer, error) {
	prefix, err := reader.PeekTwo()
	if err != nil {
		return nil, nil, errors.New("archive_format")
	}
	if prefix[0] == 0x1f && prefix[1] == 0x8b {
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, errors.New("archive_format")
		}
		return gzipReader, gzipReader, nil
	}
	return reader, nil, nil
}

type prefixReader struct {
	reader   io.Reader
	prefix   []byte
	consumed int64
}

// newPrefixReader constructs one counted two-byte lookahead reader.
func newPrefixReader(reader io.Reader) *prefixReader {
	return &prefixReader{reader: reader}
}

// PeekTwo returns the first two bytes while retaining them for subsequent reads.
func (r *prefixReader) PeekTwo() ([2]byte, error) {
	var result [2]byte
	if len(r.prefix) < 2 {
		missing := make([]byte, 2-len(r.prefix))
		if _, err := io.ReadFull(r.reader, missing); err != nil {
			return result, err
		}
		r.prefix = append(r.prefix, missing...)
	}
	copy(result[:], r.prefix[:2])
	return result, nil
}

// Read supplies retained prefix bytes before reading the underlying stream.
func (r *prefixReader) Read(buffer []byte) (int, error) {
	if len(r.prefix) > 0 {
		count := copy(buffer, r.prefix)
		r.prefix = r.prefix[count:]
		r.consumed += int64(count)
		return count, nil
	}
	count, err := r.reader.Read(buffer)
	r.consumed += int64(count)
	return count, err
}

// ReadBytes reports compressed bytes consumed through this reader.
func (r *prefixReader) ReadBytes() int64 {
	return r.consumed
}
