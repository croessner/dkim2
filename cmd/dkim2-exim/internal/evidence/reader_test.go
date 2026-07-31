//go:build linux || darwin

package evidence

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"golang.org/x/sys/unix"
)

const (
	testIncomingSender     = "<incoming@example.test>"
	unexpectedManifestName = "unexpected"
)

// readerFixture owns one exact protected read-only evidence state.
type readerFixture struct {
	root          string
	keyPath       string
	readinessPath string
	recordPath    string
	key           []byte
	record        Record
	now           time.Time
	writerLock    int
}

// TestReaderRejectsDirtyLivePublicationWithoutMutation proves sole-writer
// temporary state remains unchanged while revision fails closed on DIRTY.
func TestReaderRejectsDirtyLivePublicationWithoutMutation(t *testing.T) {
	fixture := newReaderFixture(t)
	writeTestReadiness(t, fixture, readinessDirty, 2)
	inProgressPath := filepath.Join(
		fixture.root,
		".put-"+fixture.record.Locator()+"-AAAAAAAAAAAAAAAAAAAAAA",
	)
	inProgress := []byte("writer-owned-incomplete-record")
	if err := os.WriteFile(inProgressPath, inProgress, 0o600); err != nil {
		t.Fatal("in-progress publication fixture failed")
	}
	before, err := os.Lstat(inProgressPath)
	if err != nil {
		t.Fatal("in-progress publication stat failed")
	}
	reader := openReaderFixture(t, fixture)
	_, err = reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	)
	if err == nil {
		t.Fatal("dirty live publication reached revision evidence")
	}
	after, err := os.Lstat(inProgressPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("read-only evidence owner renamed writer state")
	}
	afterBytes, err := os.ReadFile(inProgressPath)
	if err != nil || !bytes.Equal(afterBytes, inProgress) {
		clear(afterBytes)
		t.Fatal("read-only evidence owner changed writer bytes")
	}
	clear(afterBytes)
}

// TestReaderRejectsMarkerFailures proves torn, forged, closed, and changing
// authenticated generations cannot authorize target evidence.
func TestReaderRejectsMarkerFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, readerFixture)
	}{
		{
			name: "torn",
			mutate: func(t *testing.T, fixture readerFixture) {
				t.Helper()
				if err := os.WriteFile(
					fixture.readinessPath,
					[]byte("DXR1"),
					0o600,
				); err != nil {
					t.Fatal("torn readiness fixture failed")
				}
			},
		},
		{
			name: "forged",
			mutate: func(t *testing.T, fixture readerFixture) {
				t.Helper()
				encoded, err := os.ReadFile(fixture.readinessPath)
				if err != nil {
					t.Fatal("forged readiness fixture read failed")
				}
				encoded[10] ^= 1
				if err = os.WriteFile(
					fixture.readinessPath,
					encoded,
					0o600,
				); err != nil {
					clear(encoded)
					t.Fatal("forged readiness fixture write failed")
				}
				clear(encoded)
			},
		},
		{
			name: "closed",
			mutate: func(t *testing.T, fixture readerFixture) {
				t.Helper()
				writeTestReadiness(t, fixture, readinessClosed, 2)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReaderFixture(t)
			test.mutate(t, fixture)
			reader := openReaderFixture(t, fixture)
			if _, err := reader.LoadContext(
				context.Background(),
				fixture.record.Locator(),
			); err == nil {
				t.Fatal("unsafe readiness marker reached evidence")
			}
		})
	}
}

// TestReaderRejectsGenerationChangeDuringAuthorization proves the two clean
// snapshots bracketing target acquisition must remain byte-identical.
func TestReaderRejectsGenerationChangeDuringAuthorization(t *testing.T) {
	fixture := newReaderFixture(t)
	reader := openReaderFixture(t, fixture)
	reader.afterFirstRead = func() {
		writeTestReadiness(t, fixture, readinessDirty, 2)
	}
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err == nil {
		t.Fatal("changing readiness generation authorized evidence")
	}
}

// TestReaderRejectsMutationAfterTargetAcquisition proves a writer entering
// DIRTY and unlinking the target between authorization snapshots cannot pass.
func TestReaderRejectsMutationAfterTargetAcquisition(t *testing.T) {
	fixture := newReaderFixture(t)
	reader := openReaderFixture(t, fixture)
	reader.afterTargetOpen = func() {
		writeTestReadiness(t, fixture, readinessDirty, 2)
		if err := os.Remove(fixture.recordPath); err != nil {
			panic(err)
		}
	}
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err == nil {
		t.Fatal("post-acquisition writer mutation reused stale CLEAN readiness")
	}
}

// TestReaderRequiresLiveSoleWriter proves stale CLEAN state after writer exit
// cannot authorize a new revision process.
func TestReaderRequiresLiveSoleWriter(t *testing.T) {
	fixture := newReaderFixture(t)
	if err := unix.Flock(fixture.writerLock, unix.LOCK_UN); err != nil {
		t.Fatal("readiness writer release fixture failed")
	}
	reader := openReaderFixture(t, fixture)
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err == nil {
		t.Fatal("clean marker without live sole writer authorized evidence")
	}
}

// TestReaderBoundsMarkerParent proves one exact live atomic temporary is
// tolerated while arbitrary or multiple siblings close authorization.
func TestReaderBoundsMarkerParent(t *testing.T) {
	t.Run("one live temporary", func(t *testing.T) {
		fixture := newReaderFixture(t)
		name := readinessTemporaryPrefix + "AAAAAAAAAAAAAAAAAAAAAA"
		parent := filepath.Dir(fixture.readinessPath)
		if err := os.WriteFile(
			filepath.Join(parent, name),
			[]byte("partial"),
			0o600,
		); err != nil {
			t.Fatal("live readiness temporary fixture failed")
		}
		reader := openReaderFixture(t, fixture)
		if _, err := reader.LoadContext(
			context.Background(),
			fixture.record.Locator(),
		); err != nil {
			t.Fatal("one exact live readiness temporary was rejected")
		}
	})
	t.Run("arbitrary", func(t *testing.T) {
		fixture := newReaderFixture(t)
		if err := os.WriteFile(
			filepath.Join(filepath.Dir(fixture.readinessPath), "unexpected"),
			[]byte("x"),
			0o600,
		); err != nil {
			t.Fatal("unexpected readiness child fixture failed")
		}
		reader := openReaderFixture(t, fixture)
		if _, err := reader.LoadContext(
			context.Background(),
			fixture.record.Locator(),
		); err == nil {
			t.Fatal("unexpected readiness child authorized evidence")
		}
	})
}

// TestReaderRejectsGloballyUnsafeManifest proves unrelated corruption closes
// evidence-dependent revision while exact live publication remains tolerated.
func TestReaderRejectsGloballyUnsafeManifest(t *testing.T) {
	for _, test := range []struct {
		name  string
		child string
	}{
		{name: unexpectedManifestName, child: unexpectedManifestName},
		{
			name:  "malformed final",
			child: "QEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA.ev1",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReaderFixture(t)
			if err := os.WriteFile(
				filepath.Join(fixture.root, test.child),
				[]byte("unsafe"),
				0o600,
			); err != nil {
				t.Fatal("unsafe manifest fixture failed")
			}
			reader := openReaderFixture(t, fixture)
			if _, err := reader.LoadContext(
				context.Background(),
				fixture.record.Locator(),
			); err == nil {
				t.Fatal("globally unsafe manifest reached revision evidence")
			}
		})
	}
}

// TestReaderEnforcesExactRootAndRecordModes proves generic owner-only modes
// cannot weaken the evidence-specific 0700/0600 contract.
func TestReaderEnforcesExactRootAndRecordModes(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		fixture := newReaderFixture(t)
		if err := os.Chmod(fixture.root, 0o500); err != nil {
			t.Fatal("unsafe root mode fixture failed")
		}
		t.Cleanup(func() { _ = os.Chmod(fixture.root, 0o700) })
		if reader, err := NewReader(
			fixture.root,
			fixture.keyPath,
			fixture.readinessPath,
			func() time.Time { return fixture.now },
		); err == nil {
			_ = reader.Close()
			t.Fatal("non-0700 evidence root was accepted")
		}
	})
	t.Run("record", func(t *testing.T) {
		fixture := newReaderFixture(t)
		reader := openReaderFixture(t, fixture)
		if err := os.Chmod(fixture.recordPath, 0o400); err != nil {
			t.Fatal("unsafe record mode fixture failed")
		}
		if _, err := reader.LoadContext(
			context.Background(),
			fixture.record.Locator(),
		); err == nil {
			t.Fatal("non-0600 evidence record was accepted")
		}
	})
}

// TestReaderDetectsRootPolicyChangeAfterRecordRead proves post-open root
// weakening cannot race a successful authenticated return.
func TestReaderDetectsRootPolicyChangeAfterRecordRead(t *testing.T) {
	fixture := newReaderFixture(t)
	reader := openReaderFixture(t, fixture)
	reader.afterValidate = func() {
		if err := os.Chmod(fixture.root, 0o500); err != nil {
			panic(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(fixture.root, 0o700) })
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err == nil {
		t.Fatal("mid-read evidence root weakening was accepted")
	}
}

// TestReaderRejectsRootPathReplacement proves a configured-path replacement
// cannot reuse a stale authenticated clean generation.
func TestReaderRejectsRootPathReplacement(t *testing.T) {
	fixture := newReaderFixture(t)
	reader := openReaderFixture(t, fixture)
	heldPath := fixture.root + ".held"
	if err := os.Rename(fixture.root, heldPath); err != nil {
		t.Fatal("evidence root replacement fixture rename failed")
	}
	t.Cleanup(func() { _ = os.RemoveAll(heldPath) })
	if err := os.Mkdir(fixture.root, 0o700); err != nil {
		t.Fatal("evidence root replacement fixture creation failed")
	}
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err == nil {
		t.Fatal("configured-path replacement reused stale readiness")
	}
}

// TestReaderLeaseSurvivesConcurrentGC proves authorization brackets target
// acquisition and an owned immutable descriptor may finish across GC unlink.
func TestReaderLeaseSurvivesConcurrentGC(t *testing.T) {
	fixture := newReaderFixture(t)
	reader := openReaderFixture(t, fixture)
	reader.afterValidate = func() {
		if err := os.Remove(fixture.recordPath); err != nil {
			panic(err)
		}
	}
	if _, err := reader.LoadContext(
		context.Background(),
		fixture.record.Locator(),
	); err != nil {
		t.Fatal("owned record descriptor did not survive cooperative GC")
	}
}

// newReaderFixture creates one exact root, key, and authenticated final record.
func newReaderFixture(t *testing.T) readerFixture {
	t.Helper()
	root := t.TempDir()
	keyRoot := t.TempDir()
	readinessRoot := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("evidence root fixture mode failed")
	}
	key := bytes.Repeat([]byte{0x6a}, KeyBytes)
	keyPath := filepath.Join(keyRoot, "evidence.key")
	if err := os.WriteFile(keyPath, key, 0o400); err != nil {
		clear(key)
		t.Fatal("evidence key fixture failed")
	}
	if err := os.Chmod(keyRoot, 0o500); err != nil {
		clear(key)
		t.Fatal("evidence key parent fixture failed")
	}
	t.Cleanup(func() { _ = os.Chmod(keyRoot, 0o700) })
	if err := os.Chmod(readinessRoot, 0o700); err != nil {
		clear(key)
		t.Fatal("readiness parent fixture failed")
	}
	incoming, err := adapter.NewIncomingEvidence(
		[]byte(testIncomingSender),
		[][]byte{[]byte("<recipient@example.test>")},
		adapter.SessionSMTP,
	)
	if err != nil {
		clear(key)
		t.Fatal("incoming evidence fixture failed")
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	record, err := NewRecord(
		now,
		MinimumRetention,
		incoming,
		bytes.NewReader(bytes.Repeat([]byte{0x3c}, LocatorBytes)),
	)
	if err != nil {
		clear(key)
		t.Fatal("evidence record fixture failed")
	}
	encoded, err := record.Encode(key)
	if err != nil {
		clear(key)
		t.Fatal("evidence record encoding failed")
	}
	recordPath := filepath.Join(root, record.Locator()+finalSuffix)
	if err = os.WriteFile(recordPath, encoded, 0o600); err != nil {
		clear(encoded)
		clear(key)
		t.Fatal("evidence record fixture write failed")
	}
	readinessPath := filepath.Join(readinessRoot, "readiness")
	fixture := readerFixture{
		root: root, keyPath: keyPath, readinessPath: readinessPath,
		recordPath: recordPath, key: key, record: record,
		now: now.Add(time.Second),
	}
	writeTestReadiness(t, fixture, readinessClean, 1)
	writerLock, err := unix.Open(
		readinessRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil || unix.Flock(writerLock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		clear(encoded)
		clear(key)
		t.Fatal("readiness writer lock fixture failed")
	}
	fixture.writerLock = writerLock
	t.Cleanup(func() {
		_ = unix.Flock(writerLock, unix.LOCK_UN)
		_ = unix.Close(writerLock)
	})
	clear(encoded)
	t.Cleanup(func() { clear(key) })
	return fixture
}

// openReaderFixture opens and registers cleanup for one reader fixture.
func openReaderFixture(t *testing.T, fixture readerFixture) *Reader {
	t.Helper()
	reader, err := NewReader(
		fixture.root,
		fixture.keyPath,
		fixture.readinessPath,
		func() time.Time { return fixture.now },
	)
	if err != nil {
		t.Fatal("read-only evidence owner construction failed")
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader
}

// writeTestReadiness writes one independently encoded fixed marker fixture.
func writeTestReadiness(
	t *testing.T,
	fixture readerFixture,
	state byte,
	generation uint64,
) {
	t.Helper()
	info, err := os.Stat(fixture.recordPath)
	if err != nil {
		t.Fatal("readiness record accounting fixture failed")
	}
	encoded, err := encodeReadiness(readinessSnapshot{
		state: state, generation: generation,
		root:  testRootFingerprint(t, fixture.root),
		stats: Stats{Records: 1, Bytes: info.Size()},
	}, fixture.key)
	if err != nil {
		t.Fatal("readiness marker encoding fixture failed")
	}
	if err = os.WriteFile(fixture.readinessPath, encoded, 0o600); err != nil {
		clear(encoded)
		t.Fatal("readiness marker fixture write failed")
	}
	clear(encoded)
}
