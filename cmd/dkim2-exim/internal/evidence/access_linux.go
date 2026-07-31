//go:build linux

package evidence

import (
	"bytes"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxAccessXattrBytes = 65_536
	maxAccessXattrNames = 256
)

// noExtendedAccess rejects ACL-bearing or ambiguous system access metadata.
func noExtendedAccess(fd int) error {
	names, err := readAccessNames(fd)
	if err != nil {
		return ErrEvidence
	}
	if len(names) == 0 {
		return nil
	}
	if names[len(names)-1] != 0 {
		return ErrEvidence
	}
	parts := bytes.Split(names[:len(names)-1], []byte{0})
	if len(parts) > maxAccessXattrNames {
		return ErrEvidence
	}
	seen := make(map[string]struct{}, len(parts))
	for _, raw := range parts {
		if len(raw) == 0 {
			return ErrEvidence
		}
		name := string(raw)
		if _, duplicate := seen[name]; duplicate {
			return ErrEvidence
		}
		seen[name] = struct{}{}
		if strings.HasPrefix(name, "system.") {
			return ErrEvidence
		}
	}
	return nil
}

// readAccessNames performs a bounded probe, read, and stable-size reprobe.
func readAccessNames(fd int) ([]byte, error) {
	size, err := listAccessNames(fd, nil)
	if err != nil || size < 0 || size > maxAccessXattrBytes {
		return nil, ErrEvidence
	}
	if size == 0 {
		confirmed, confirmErr := listAccessNames(fd, nil)
		if confirmErr != nil || confirmed != 0 {
			return nil, ErrEvidence
		}
		return nil, nil
	}
	names := make([]byte, size+1)
	count, err := listAccessNames(fd, names)
	if err != nil || count != size {
		clear(names)
		return nil, ErrEvidence
	}
	confirmed, confirmErr := listAccessNames(fd, nil)
	if confirmErr != nil || confirmed != size {
		clear(names)
		return nil, ErrEvidence
	}
	return names[:count], nil
}

// listAccessNames retries interrupted descriptor-native xattr enumeration.
func listAccessNames(fd int, destination []byte) (int, error) {
	for {
		count, err := unix.Flistxattr(fd, destination)
		if err == unix.EINTR {
			continue
		}
		return count, err
	}
}
