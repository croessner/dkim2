package flatfile

import (
	"io"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/niliface"
)

const maxFilenameBytes = 255

// operationFailure is one content-free platform operation outcome.
type operationFailure uint8

const (
	operationSucceeded operationFailure = iota
	operationFailed
	operationNotFound
	operationUnsupported
	operationPanicked
)

// fileMetadata contains only confinement facts needed by common validation.
type fileMetadata struct {
	mode  uint32
	uid   uint32
	links uint64
}

// filesystemOps isolates the exact descriptor operations owned by the provider.
type filesystemOps interface {
	duplicateRoot(int) (int, operationFailure)
	metadata(int) (fileMetadata, operationFailure)
	openFile(int, string) (int, operationFailure)
	read(int, []byte) (int, operationFailure)
	close(int) operationFailure
	effectiveUID() uint32
}

// descriptorReader adapts one same-descriptor read stream to DecodeReader.
type descriptorReader struct {
	ops filesystemOps
	fd  int
}

// Read reads from the already-validated descriptor without reopening by name.
func (r *descriptorReader) Read(output []byte) (int, error) {
	count, failure := callRead(r.ops, r.fd, output)
	switch failure {
	case operationSucceeded:
		if count == 0 {
			return 0, io.EOF
		}
		return count, nil
	case operationPanicked:
		panic("filesystem read boundary")
	default:
		return count, io.ErrUnexpectedEOF
	}
}

// validateFilename accepts one bounded cross-platform-safe component.
func validateFilename(filename string) error {
	if len(filename) == 0 || !utf8.ValidString(filename) {
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if len(filename) > maxFilenameBytes {
		return datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	if filename == "." || filename == ".." ||
		strings.ContainsAny(filename, "/\\:\x00") ||
		strings.HasSuffix(filename, ".") || strings.HasSuffix(filename, " ") {
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	for index := 0; index < len(filename); index++ {
		if filename[index] < 0x20 || filename[index] == 0x7f {
			return datasource.NewError(datasource.ErrorCodeInvalidRequest)
		}
	}
	stem := filename
	if separator := strings.IndexByte(stem, '.'); separator >= 0 {
		stem = stem[:separator]
	}
	stem = strings.TrimRight(stem, " .")
	upperStem := strings.ToUpper(stem)
	switch upperStem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if len(upperStem) == 4 &&
		(upperStem[:3] == "COM" || upperStem[:3] == "LPT") &&
		upperStem[3] >= '1' && upperStem[3] <= '9' {
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if strings.HasPrefix(upperStem, prefix) {
			switch strings.TrimPrefix(upperStem, prefix) {
			case "¹", "²", "³":
				return datasource.NewError(datasource.ErrorCodeInvalidRequest)
			}
		}
	}
	return nil
}

// validateRootMetadata enforces the exact owned directory capability policy.
func validateRootMetadata(metadata fileMetadata, expectedUID uint32) error {
	const (
		fileTypeMask     = uint32(0170000)
		directoryType    = uint32(0040000)
		ownerReadExecute = uint32(0500)
		groupWorldWrite  = uint32(0022)
	)
	if metadata.mode&fileTypeMask != directoryType ||
		metadata.uid != expectedUID ||
		metadata.mode&ownerReadExecute != ownerReadExecute ||
		metadata.mode&groupWorldWrite != 0 {
		return datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	return nil
}

// validateFileMetadata enforces exact 0400 or 0600 single-link regular files.
func validateFileMetadata(metadata fileMetadata, expectedUID uint32) error {
	const (
		fileTypeMask  = uint32(0170000)
		regularType   = uint32(0100000)
		permissionSet = uint32(07777)
	)
	permissions := metadata.mode & permissionSet
	if metadata.mode&fileTypeMask != regularType ||
		metadata.uid != expectedUID || metadata.links != 1 ||
		(permissions != 0400 && permissions != 0600) {
		return datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	return nil
}

// failureError maps one platform outcome into the closed datasource taxonomy.
func failureError(failure operationFailure) error {
	switch failure {
	case operationNotFound:
		return datasource.NewError(datasource.ErrorCodeNotFound)
	case operationUnsupported:
		return datasource.NewError(datasource.ErrorCodeUnsupportedPlatform)
	case operationPanicked:
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	case operationFailed:
		return datasource.NewError(datasource.ErrorCodeUnavailable)
	default:
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
}

// callDuplicateRoot contains panics at the atomic descriptor-copy boundary.
func callDuplicateRoot(ops filesystemOps, rootFD int) (descriptor int, failure operationFailure) {
	defer func() {
		if recover() != nil {
			descriptor = -1
			failure = operationPanicked
		}
	}()
	return ops.duplicateRoot(rootFD)
}

// callMetadata contains panics at one fstat boundary.
func callMetadata(ops filesystemOps, descriptor int) (metadata fileMetadata, failure operationFailure) {
	defer func() {
		if recover() != nil {
			metadata = fileMetadata{}
			failure = operationPanicked
		}
	}()
	metadata, failure = ops.metadata(descriptor)
	if failure != operationSucceeded && metadata != (fileMetadata{}) {
		return fileMetadata{}, operationPanicked
	}
	return metadata, failure
}

// callOpenFile contains panics at the descriptor-relative open boundary.
func callOpenFile(
	ops filesystemOps,
	rootFD int,
	filename string,
) (descriptor int, failure operationFailure) {
	defer func() {
		if recover() != nil {
			descriptor = -1
			failure = operationPanicked
		}
	}()
	return ops.openFile(rootFD, filename)
}

// callRead contains panics and invalid counts at the descriptor read boundary.
func callRead(
	ops filesystemOps,
	descriptor int,
	output []byte,
) (count int, failure operationFailure) {
	defer func() {
		if recover() != nil {
			count = 0
			failure = operationPanicked
		}
	}()
	count, failure = ops.read(descriptor, output)
	if count < 0 || count > len(output) {
		return 0, operationPanicked
	}
	if failure != operationSucceeded && count != 0 {
		return 0, operationPanicked
	}
	return count, failure
}

// callClose contains panics while preserving exactly one close invocation.
func callClose(ops filesystemOps, descriptor int) (failure operationFailure) {
	defer func() {
		if recover() != nil {
			failure = operationPanicked
		}
	}()
	return ops.close(descriptor)
}

// callEffectiveUID contains panics while capturing the expected owner.
func callEffectiveUID(ops filesystemOps) (uid uint32, failure operationFailure) {
	defer func() {
		if recover() != nil {
			uid = 0
			failure = operationPanicked
		}
	}()
	return ops.effectiveUID(), operationSucceeded
}

// filesystemOpsAvailable reports whether one usable production implementation exists.
func filesystemOpsAvailable(ops filesystemOps, err error) error {
	unavailable := niliface.IsNil(ops)
	if unavailable && err != nil {
		return datasource.NewError(datasource.ErrorCodeUnsupportedPlatform)
	}
	if unavailable || err != nil {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return nil
}
