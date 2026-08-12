package flatfile

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
)

// TestFilenameValidationCoversExactLimitAndPlatformEscapes verifies pure caller-input policy.
func TestFilenameValidationCoversExactLimitAndPlatformEscapes(t *testing.T) {
	t.Parallel()

	if err := validateFilename(strings.Repeat("a", maxFilenameBytes)); err != nil {
		t.Fatalf("validateFilename(exact) code=%s", datasource.ErrorCodeOf(err))
	}
	if err := validateFilename(strings.Repeat("a", maxFilenameBytes+1)); datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("validateFilename(one over) code=%s", datasource.ErrorCodeOf(err))
	}
	for _, filename := range []string{
		"", ".", "..", "/", "\\", "a/b", `a\b`, "\x00", "/absolute",
		`C:relative`, `C:\absolute`, flatfileReservedConsole, "con.txt", "PRN", "aux.json",
		flatfileReservedNullName, "nul.txt", "COM1", "com9.txt", "LPT1", "lpt9.txt",
		"COM¹", "com².txt", "CoM³ .json", "LPT¹", "lpt².txt", "LpT³ .json",
		"provider.", "provider ", "line\nfeed", string([]byte{0xff}),
	} {
		if datasource.ErrorCodeOf(validateFilename(filename)) != datasource.ErrorCodeInvalidRequest {
			t.Fatalf("validateFilename(invalid) code=%s",
				datasource.ErrorCodeOf(validateFilename(filename)))
		}
	}
}

// TestRootMetadataPolicyMatchesFrozenConfinementRules verifies exact type, owner, and permission facts.
func TestRootMetadataPolicyMatchesFrozenConfinementRules(t *testing.T) {
	t.Parallel()

	const uid uint32 = 1000
	for _, mode := range []uint32{0040500, 0040700, 0040755, 0041700} {
		if err := validateRootMetadata(fileMetadata{mode: mode, uid: uid, links: 1}, uid); err != nil {
			t.Fatalf("validateRootMetadata(valid) code=%s", datasource.ErrorCodeOf(err))
		}
	}
	for _, metadata := range []fileMetadata{
		{mode: 0100600, uid: uid, links: 1},
		{mode: 0040700, uid: uid + 1, links: 1},
		{mode: 0040300, uid: uid, links: 1},
		{mode: 0040400, uid: uid, links: 1},
		{mode: 0040720, uid: uid, links: 1},
		{mode: 0040702, uid: uid, links: 1},
	} {
		if datasource.ErrorCodeOf(validateRootMetadata(metadata, uid)) !=
			datasource.ErrorCodeUnavailable {
			t.Fatalf("validateRootMetadata(invalid) code=%s",
				datasource.ErrorCodeOf(validateRootMetadata(metadata, uid)))
		}
	}
}

// TestFileMetadataPolicyAcceptsOnlyOwnedSingleLinkRegular0400Or0600 verifies exact file facts.
func TestFileMetadataPolicyAcceptsOnlyOwnedSingleLinkRegular0400Or0600(t *testing.T) {
	t.Parallel()

	const uid uint32 = 1000
	for _, mode := range []uint32{0100400, 0100600} {
		if err := validateFileMetadata(fileMetadata{mode: mode, uid: uid, links: 1}, uid); err != nil {
			t.Fatalf("validateFileMetadata(valid) code=%s", datasource.ErrorCodeOf(err))
		}
	}
	for _, metadata := range []fileMetadata{
		{mode: 0010600, uid: uid, links: 1},
		{mode: 0020600, uid: uid, links: 1},
		{mode: 0040600, uid: uid, links: 1},
		{mode: 0060600, uid: uid, links: 1},
		{mode: 0120600, uid: uid, links: 1},
		{mode: 0140600, uid: uid, links: 1},
		{mode: 0100600, uid: uid + 1, links: 1},
		{mode: 0100600, uid: uid, links: 0},
		{mode: 0100600, uid: uid, links: 2},
		{mode: 0100000, uid: uid, links: 1},
		{mode: 0100200, uid: uid, links: 1},
		{mode: 0100640, uid: uid, links: 1},
		{mode: 0104600, uid: uid, links: 1},
		{mode: 0102600, uid: uid, links: 1},
		{mode: 0101600, uid: uid, links: 1},
	} {
		if datasource.ErrorCodeOf(validateFileMetadata(metadata, uid)) !=
			datasource.ErrorCodeUnavailable {
			t.Fatalf("validateFileMetadata(invalid) code=%s",
				datasource.ErrorCodeOf(validateFileMetadata(metadata, uid)))
		}
	}
}

// TestFilesystemBoundaryWrappersContainPanicsAndInvalidCounts verifies closed injected-operation behavior.
func TestFilesystemBoundaryWrappersContainPanicsAndInvalidCounts(t *testing.T) {
	t.Parallel()

	ops := panicFilesystemOps{}
	if descriptor, failure := callDuplicateRoot(ops, 1); descriptor != -1 || failure != operationPanicked {
		t.Fatalf("callDuplicateRoot(panic) descriptor=%d failure=%d", descriptor, failure)
	}
	if metadata, failure := callMetadata(ops, 1); metadata != (fileMetadata{}) || failure != operationPanicked {
		t.Fatalf("callMetadata(panic) nonzero=%t failure=%d",
			metadata != (fileMetadata{}), failure)
	}
	if descriptor, failure := callOpenFile(ops, 1, "provider.json"); descriptor != -1 || failure != operationPanicked {
		t.Fatalf("callOpenFile(panic) descriptor=%d failure=%d", descriptor, failure)
	}
	if count, failure := callRead(ops, 1, make([]byte, 1)); count != 0 || failure != operationPanicked {
		t.Fatalf("callRead(panic) count=%d failure=%d", count, failure)
	}
	if failure := callClose(ops, 1); failure != operationPanicked {
		t.Fatalf("callClose(panic) failure=%d", failure)
	}
	if uid, failure := callEffectiveUID(ops); uid != 0 || failure != operationPanicked {
		t.Fatalf("callEffectiveUID(panic) uid=%d failure=%d", uid, failure)
	}

	for _, count := range []int{-1, 2} {
		invalid := resultFilesystemOps{readCount: count}
		if got, failure := callRead(invalid, 1, make([]byte, 1)); got != 0 || failure != operationPanicked {
			t.Fatalf("callRead(invalid count) count=%d failure=%d", got, failure)
		}
	}
}

// TestFilesystemOpsAvailabilityRejectsContradictoryFactoryResults verifies factory invariants.
func TestFilesystemOpsAvailabilityRejectsContradictoryFactoryResults(t *testing.T) {
	t.Parallel()

	factoryErr := errors.New("factory failure")
	var typedNil *scriptedFilesystem
	usable := newScriptedFilesystem(nil)
	tests := []struct {
		name string
		ops  filesystemOps
		err  error
		code datasource.ErrorCode
	}{
		{name: "nil with error", err: factoryErr, code: datasource.ErrorCodeUnsupportedPlatform},
		{
			name: "typed nil with error", ops: typedNil, err: factoryErr,
			code: datasource.ErrorCodeUnsupportedPlatform,
		},
		{name: "nil without error", code: datasource.ErrorCodeInternalInvariant},
		{name: "typed nil without error", ops: typedNil, code: datasource.ErrorCodeInternalInvariant},
		{name: "usable without error", ops: usable},
		{
			name: "usable with error", ops: usable, err: factoryErr,
			code: datasource.ErrorCodeInternalInvariant,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := filesystemOpsAvailable(test.ops, test.err)
			if test.code == "" {
				if err != nil {
					t.Fatalf("filesystemOpsAvailable() code=%s want success",
						datasource.ErrorCodeOf(err))
				}
				return
			}
			if datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("filesystemOpsAvailable() code=%s want=%s",
					datasource.ErrorCodeOf(err), test.code)
			}
		})
	}
}

// panicFilesystemOps panics at every injected descriptor boundary.
type panicFilesystemOps struct{}

// duplicateRoot provides the deliberate duplicate panic.
func (panicFilesystemOps) duplicateRoot(int) (int, operationFailure) { panic("duplicate") }

// metadata provides the deliberate metadata panic.
func (panicFilesystemOps) metadata(int) (fileMetadata, operationFailure) { panic("metadata") }

// openFile provides the deliberate open panic.
func (panicFilesystemOps) openFile(int, string) (int, operationFailure) { panic("open") }

// read provides the deliberate read panic.
func (panicFilesystemOps) read(int, []byte) (int, operationFailure) { panic("read") }

// close provides the deliberate close panic.
func (panicFilesystemOps) close(int) operationFailure { panic("close") }

// effectiveUID provides the deliberate owner lookup panic.
func (panicFilesystemOps) effectiveUID() uint32 { panic("effective UID") }

// resultFilesystemOps provides one configurable reader count.
type resultFilesystemOps struct {
	readCount int
}

// duplicateRoot returns one inert descriptor.
func (resultFilesystemOps) duplicateRoot(int) (int, operationFailure) {
	return 10, operationSucceeded
}

// metadata returns one valid root metadata value.
func (resultFilesystemOps) metadata(int) (fileMetadata, operationFailure) {
	return fileMetadata{mode: 0040700, uid: 1000, links: 1}, operationSucceeded
}

// openFile returns one inert descriptor.
func (resultFilesystemOps) openFile(int, string) (int, operationFailure) {
	return 11, operationSucceeded
}

// read returns the configured count without touching output.
func (o resultFilesystemOps) read(int, []byte) (int, operationFailure) {
	return o.readCount, operationSucceeded
}

// close reports success.
func (resultFilesystemOps) close(int) operationFailure { return operationSucceeded }

// effectiveUID provides the expected test owner.
func (resultFilesystemOps) effectiveUID() uint32 { return 1000 }
