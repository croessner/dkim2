//go:build linux

package evidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"golang.org/x/sys/unix"
)

// lockedClock provides race-safe injected evidence time.
type lockedClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current injected wall time.
func (c *lockedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set atomically changes the injected wall time.
func (c *lockedClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// TestStorePublishesLoadsAndAccountsImmutableRecords proves normal durable
// operation, retry reuse, and immutable read semantics.
func TestStorePublishesLoadsAndAccountsImmutableRecords(t *testing.T) {
	store, clock, key := newStoreFixture(t, Limits{MaxRecords: 4, MaxBytes: MinimumMaxBytes})
	incoming := testIncoming(t, []byte("old"), [][]byte{[]byte("r1"), []byte("r2")}, adapter.SessionSMTP)
	record, err := store.Publish(MinimumRetention, incoming)
	if err != nil {
		t.Fatal("evidence publication failed")
	}
	loaded, err := store.Load(record.Locator())
	if err != nil || loaded.Locator() != record.Locator() ||
		string(loaded.Incoming().MailFrom()) != "<old>" {
		t.Fatal("immutable evidence load failed")
	}
	again, err := store.Load(record.Locator())
	if err != nil || again.Locator() != record.Locator() {
		t.Fatal("retry did not reuse immutable evidence")
	}
	encoded, err := record.Encode(key)
	if err != nil {
		t.Fatal("accounting fixture encode failed")
	}
	stats, err := store.Stats()
	if err != nil || stats != (Stats{Records: 1, Bytes: int64(len(encoded))}) {
		t.Fatalf("actual accounting mismatch: %+v", stats)
	}
	clock.Set(record.ExpiresAt().Add(-time.Second))
	if _, err = store.Load(record.Locator()); err != nil {
		t.Fatal("record expired before authenticated boundary")
	}
}

// TestReadinessAuthorityOrdersMutationsAndEnforcesSoleWriter proves DIRTY
// precedes root mutation, CLEAN follows accounting, and the lifetime lock is exclusive.
func TestReadinessAuthorityOrdersMutationsAndEnforcesSoleWriter(t *testing.T) {
	root, key, now := newRawRoot(t)
	readinessRoot := t.TempDir()
	if err := os.Chmod(readinessRoot, 0o700); err != nil {
		t.Fatal("readiness parent fixture failed")
	}
	readinessPath := filepath.Join(readinessRoot, "readiness")
	store, err := NewStoreWithReadiness(
		root,
		key,
		readinessPath,
		func() time.Time { return now },
		Limits{MaxRecords: 4, MaxBytes: MinimumMaxBytes},
	)
	if err != nil {
		t.Fatal("readiness store construction failed")
	}
	defer func() { _ = store.Close() }()
	if second, secondErr := NewStoreWithReadiness(
		root,
		key,
		readinessPath,
		func() time.Time { return now },
		Limits{MaxRecords: 4, MaxBytes: MinimumMaxBytes},
	); secondErr == nil {
		_ = second.Close()
		t.Fatal("second readiness writer acquired the lifetime lock")
	}
	dirtySeen := false
	cleanSeen := false
	store.readiness.afterPublish = func(snapshot readinessSnapshot) error {
		names, namesErr := store.readManifestNames()
		if namesErr != nil {
			return ErrEvidence
		}
		switch snapshot.state {
		case readinessDirty:
			dirtySeen = len(names) == 0 && snapshot.stats == (Stats{})
		case readinessClean:
			cleanSeen = len(names) == 1 &&
				snapshot.stats.Records == 1 && snapshot.stats.Bytes > 0
		}
		return nil
	}
	if _, err = store.Publish(
		MinimumRetention,
		testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionSMTP),
	); err != nil || !dirtySeen || !cleanSeen {
		t.Fatal("readiness mutation ordering changed")
	}
}

// TestReadinessAuthorityConsumesGenerationAndClosesDurably proves a
// post-rename failure cannot reuse a generation and Close publishes CLOSED.
func TestReadinessAuthorityConsumesGenerationAndClosesDurably(t *testing.T) {
	root, key, now := newRawRoot(t)
	readinessRoot := t.TempDir()
	if err := os.Chmod(readinessRoot, 0o700); err != nil {
		t.Fatal("readiness parent fixture failed")
	}
	readinessPath := filepath.Join(readinessRoot, "readiness")
	store, err := NewStoreWithReadiness(
		root,
		key,
		readinessPath,
		func() time.Time { return now },
		DefaultLimits(),
	)
	if err != nil {
		t.Fatal("readiness store construction failed")
	}
	reader, err := newReadinessReader(readinessPath, key)
	if err != nil {
		_ = store.Close()
		t.Fatal("readiness reader fixture failed")
	}
	defer func() { _ = reader.close() }()
	before := store.readiness.generation
	failOnce := true
	store.readiness.afterPublish = func(readinessSnapshot) error {
		if failOnce {
			failOnce = false
			return ErrEvidence
		}
		return nil
	}
	if err = store.writeReadiness(readinessDirty); err == nil {
		_ = store.Close()
		t.Fatal("post-rename readiness failure fixture did not fail")
	}
	store.readiness.afterPublish = nil
	if err = store.writeReadiness(readinessDirty); err != nil ||
		store.readiness.generation != before+2 {
		_ = store.Close()
		t.Fatal("readiness generation was reused after rename")
	}
	if err = store.Close(); err != nil {
		t.Fatal("store close did not publish terminal readiness")
	}
	snapshot, err := reader.read()
	if err != nil || snapshot.state != readinessClosed ||
		reader.writerLive() {
		t.Fatal("closed store retained clean or live readiness")
	}
	reopened, err := NewStoreWithReadiness(
		root,
		key,
		readinessPath,
		func() time.Time { return now },
		DefaultLimits(),
	)
	if err != nil {
		t.Fatal("closed writer did not release the lifetime lock")
	}
	if reopened.readiness.generation <= snapshot.generation {
		_ = reopened.Close()
		t.Fatal("reopened writer reused a terminal generation")
	}
	_ = reopened.Close()
}

// TestReadinessDirtyFailureInvalidatesWriterLiveness proves old CLEAN cannot
// remain authoritative when DIRTY publication fails before root mutation.
func TestReadinessDirtyFailureInvalidatesWriterLiveness(t *testing.T) {
	root, key, now := newRawRoot(t)
	readinessRoot := t.TempDir()
	if err := os.Chmod(readinessRoot, 0o700); err != nil {
		t.Fatal("readiness parent fixture failed")
	}
	readinessPath := filepath.Join(readinessRoot, "readiness")
	store, err := NewStoreWithReadiness(
		root,
		key,
		readinessPath,
		func() time.Time { return now },
		DefaultLimits(),
	)
	if err != nil {
		t.Fatal("readiness store construction failed")
	}
	store.readiness.beforePublish = func(snapshot readinessSnapshot) error {
		if snapshot.state == readinessDirty {
			return ErrEvidence
		}
		return nil
	}
	if _, err = store.Publish(
		MinimumRetention,
		testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionSMTP),
	); err == nil {
		_ = store.Close()
		t.Fatal("failed DIRTY publication reached root mutation")
	}
	reader, readerErr := newReadinessReader(readinessPath, key)
	if readerErr != nil {
		_ = store.Close()
		t.Fatal("readiness liveness reader fixture failed")
	}
	if reader.writerLive() {
		_ = reader.close()
		_ = store.Close()
		t.Fatal("failed DIRTY publication retained live CLEAN authority")
	}
	_ = reader.close()
	_ = store.Close()
}

// TestReadinessPanicAfterRootMutationNeverPublishesClean proves publish and
// collection panics cannot expose a live CLEAN generation after root mutation.
func TestReadinessPanicAfterRootMutationNeverPublishesClean(t *testing.T) {
	const collectOperation = "collect"
	for _, operation := range []string{"publish", collectOperation} {
		t.Run(operation, func(t *testing.T) {
			root, key, now := newRawRoot(t)
			readinessRoot := t.TempDir()
			if err := os.Chmod(readinessRoot, 0o700); err != nil {
				t.Fatal("readiness panic parent fixture failed")
			}
			readinessPath := filepath.Join(readinessRoot, "readiness")
			clock := &lockedClock{now: now}
			store, err := NewStoreWithReadiness(
				root,
				key,
				readinessPath,
				clock.Now,
				DefaultLimits(),
			)
			if err != nil {
				t.Fatal("readiness panic store construction failed")
			}
			defer func() { _ = store.Close() }()
			reader, err := newReadinessReader(readinessPath, key)
			if err != nil {
				t.Fatal("readiness panic reader construction failed")
			}
			defer func() { _ = reader.close() }()
			if operation == collectOperation {
				record, publishErr := store.Publish(
					MinimumRetention,
					testIncoming(
						t,
						nil,
						[][]byte{[]byte("r")},
						adapter.SessionSMTP,
					),
				)
				if publishErr != nil {
					t.Fatal("readiness panic collection fixture failed")
				}
				clock.Set(record.ExpiresAt())
			}
			dirtyAtMutation := false
			store.afterMutation = func() {
				snapshot, readErr := reader.read()
				dirtyAtMutation = readErr == nil &&
					snapshot.state == readinessDirty &&
					reader.writerLive()
				panic("panic after root mutation")
			}
			switch operation {
			case "publish":
				_, err = store.Publish(
					MinimumRetention,
					testIncoming(
						t,
						nil,
						[][]byte{[]byte("r")},
						adapter.SessionSMTP,
					),
				)
			case collectOperation:
				err = store.Collect()
			}
			if !errors.Is(err, ErrEvidence) || !dirtyAtMutation {
				t.Fatal("post-mutation panic escaped DIRTY containment")
			}
			snapshot, readErr := reader.read()
			if readErr != nil || snapshot.state != readinessDirty ||
				!reader.writerLive() {
				t.Fatal("post-mutation panic exposed live CLEAN readiness")
			}
		})
	}
}

// TestStoreRetriesOnlyFreshLocatorCollisions proves temporary nonce collisions
// retain the locator while final-name collisions consume a fresh locator.
func TestStoreRetriesOnlyFreshLocatorCollisions(t *testing.T) {
	store, _, _ := newStoreFixture(t, Limits{MaxRecords: 4, MaxBytes: MinimumMaxBytes})
	incoming := testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionLocal)
	locatorA := bytes.Repeat([]byte{1}, LocatorBytes)
	locatorB := bytes.Repeat([]byte{2}, LocatorBytes)
	nonceA := bytes.Repeat([]byte{3}, nonceBytes)
	nonceB := bytes.Repeat([]byte{4}, nonceBytes)
	nonceC := bytes.Repeat([]byte{5}, nonceBytes)
	store.random = bytes.NewReader(append(append(bytes.Clone(locatorA), nonceA...), nil...))
	first, err := store.Publish(MinimumRetention, incoming)
	if err != nil {
		t.Fatal("first deterministic publication failed")
	}
	stream := append(bytes.Clone(locatorA), nonceB...)
	stream = append(stream, locatorB...)
	stream = append(stream, nonceC...)
	store.random = bytes.NewReader(stream)
	second, err := store.Publish(MinimumRetention, incoming)
	if err != nil || second.Locator() == first.Locator() ||
		second.Locator() != canonicalLocator(locatorB) {
		t.Fatal("final collision did not use exactly one fresh locator")
	}

	locatorC := bytes.Repeat([]byte{6}, LocatorBytes)
	nonceD := bytes.Repeat([]byte{7}, nonceBytes)
	nonceE := bytes.Repeat([]byte{8}, nonceBytes)
	hostile := publicationPrefix + canonicalLocator(locatorC) + "-" + canonicalNonce(nonceD)
	fd, openErr := unix.Openat(
		store.directory, hostile,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if openErr != nil {
		t.Fatal("temporary collision fixture creation failed")
	}
	closeFD(fd)
	defer func() { _ = unix.Unlinkat(store.directory, hostile, 0) }()
	stream = append(bytes.Clone(locatorC), nonceD...)
	stream = append(stream, nonceE...)
	store.random = bytes.NewReader(stream)
	third, err := store.Publish(MinimumRetention, incoming)
	if err != nil || third.Locator() != canonicalLocator(locatorC) {
		t.Fatal("temporary collision incorrectly changed the locator")
	}
}

// TestStoreExactCountAndByteCapacity proves admission uses live count and
// actual encoded bytes without estimates or destructive eviction.
func TestStoreExactCountAndByteCapacity(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		store, _, _ := newStoreFixture(t, Limits{MaxRecords: 1, MaxBytes: MinimumMaxBytes})
		incoming := testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionLocal)
		if _, err := store.Publish(MinimumRetention, incoming); err != nil {
			t.Fatal("first count-bounded publication failed")
		}
		if _, err := store.Publish(MinimumRetention, incoming); !errors.Is(err, ErrCapacity) {
			t.Fatal("count exhaustion did not fail as capacity")
		}
	})

	t.Run("actual bytes", func(t *testing.T) {
		store, _, _ := newStoreFixture(t, Limits{MaxRecords: 3, MaxBytes: MinimumMaxBytes})
		large := maximalIncoming(t)
		for index := 0; index < 2; index++ {
			if _, err := store.Publish(MinimumRetention, large); err != nil {
				t.Fatal("large record within aggregate cap failed")
			}
		}
		recipients := make([][]byte, 100)
		for index := range recipients {
			recipients[index] = append([]byte{'<'}, append(bytes.Repeat([]byte{'r'}, maxPathBytes-2), '>')...)
		}
		over := testIncoming(t, nil, recipients, adapter.SessionSMTP)
		before, _ := store.Stats()
		if _, err := store.Publish(MinimumRetention, over); !errors.Is(err, ErrCapacity) {
			t.Fatal("actual-byte exhaustion did not fail as capacity")
		}
		after, _ := store.Stats()
		if after != before {
			t.Fatal("failed byte admission changed live accounting")
		}
	})
}

// TestStoreExpiryGCLeavesOwnedReaderValid proves quarantine unlink cannot
// invalidate a reader that already owns the immutable inode descriptor.
func TestStoreExpiryGCLeavesOwnedReaderValid(t *testing.T) {
	store, clock, key := newStoreFixture(t, Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes})
	record, err := store.Publish(
		MinimumRetention,
		testIncoming(t, []byte("old"), [][]byte{[]byte("r")}, adapter.SessionSMTP),
	)
	if err != nil {
		t.Fatal("publication failed")
	}
	fd, err := unix.Openat(
		store.directory, record.Locator()+finalSuffix,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		t.Fatal("reader lease fixture open failed")
	}
	defer closeFD(fd)
	state, err := inspectRecord(fd)
	if err != nil {
		t.Fatal("reader lease metadata failed")
	}
	clock.Set(record.ExpiresAt())
	if err = store.Collect(); err != nil {
		t.Fatal("authenticated expiry collection failed")
	}
	if _, err = os.Stat(filepath.Join(testRootPath(store), record.Locator()+finalSuffix)); !os.IsNotExist(err) {
		t.Fatal("expired final directory entry survived GC")
	}
	encoded, err := readExactRecord(context.Background(), store.stop, fd, state.size)
	if err != nil {
		t.Fatal("owned reader descriptor was invalidated by GC")
	}
	defer clear(encoded)
	if decoded, decodeErr := decodeAuthenticated(encoded, key); decodeErr != nil ||
		decoded.Locator() != record.Locator() {
		t.Fatal("owned reader lost immutable authenticated evidence")
	}
	stats, err := store.Stats()
	if err != nil || stats != (Stats{}) {
		t.Fatal("GC did not update exact accounting")
	}
}

// TestStoreGCReplacementRaceNeverUnlinksReplacement proves inode comparison
// restores and preserves an attacker replacement instead of unlinking it.
func TestStoreGCReplacementRaceNeverUnlinksReplacement(t *testing.T) {
	store, clock, _ := newStoreFixture(t, Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes})
	record, err := store.Publish(
		MinimumRetention,
		testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionLocal),
	)
	if err != nil {
		t.Fatal("publication failed")
	}
	name := record.Locator() + finalSuffix
	entry, err := store.openRecord(context.Background(), name, manifestFinal)
	if err != nil {
		t.Fatal("GC snapshot failed")
	}
	backup := ".saved-test-inode"
	if err = unix.Renameat2(store.directory, name, store.directory, backup, unix.RENAME_NOREPLACE); err != nil {
		t.Fatal("original-inode displacement failed")
	}
	defer func() { _ = unix.Unlinkat(store.directory, backup, 0) }()
	replacement := []byte("replacement-must-survive")
	fd, err := unix.Openat(
		store.directory, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil || !writeAll(fd, replacement) || unix.Close(fd) != nil {
		t.Fatal("replacement creation failed")
	}
	clock.Set(record.ExpiresAt())
	if err = store.quarantineAndRemove(context.Background(), entry); err == nil {
		t.Fatal("GC replacement mismatch succeeded")
	}
	got, err := os.ReadFile(filepath.Join(testRootPath(store), name))
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatal("GC race removed or changed the replacement")
	}
}

// TestStoreRejectsRestoredInPlaceMutation proves authenticated bytes alone
// cannot hide a changed live descriptor generation.
func TestStoreRejectsRestoredInPlaceMutation(t *testing.T) {
	store, _, key := newStoreFixture(t, Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes})
	record, err := store.Publish(
		MinimumRetention,
		testIncoming(t, []byte("old"), [][]byte{[]byte("r")}, adapter.SessionSMTP),
	)
	if err != nil {
		t.Fatal("publication failed")
	}
	encoded, err := record.Encode(key)
	if err != nil {
		t.Fatal("mutation fixture encoding failed")
	}
	defer clear(encoded)
	fd, err := unix.Openat(
		store.directory, record.Locator()+finalSuffix,
		unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil ||
		!writeAllContext(context.Background(), nil, fd, encoded) ||
		unix.Fsync(fd) != nil || unix.Close(fd) != nil {
		t.Fatal("restored in-place mutation fixture failed")
	}
	if _, err = store.Load(record.Locator()); !errors.Is(err, ErrNotReady) {
		t.Fatal("restored in-place mutation retained readiness")
	}
}

// TestStoreStartupRecoveryHandlesOnlyAuthenticatedReservedState proves valid
// publication and quarantine leftovers recover while corrupt state fails closed.
func TestStoreStartupRecoveryHandlesOnlyAuthenticatedReservedState(t *testing.T) {
	t.Run("publication", func(t *testing.T) {
		root, key, now := newRawRoot(t)
		record := deterministicRecord(t, now, MinimumRetention, 0x11)
		writeRecordChild(t, root, publicationName(record, 0x21), record, key)
		store, err := NewStoreWithLimits(
			root, key, func() time.Time { return now },
			Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
		)
		if err != nil {
			t.Fatal("valid publication recovery failed")
		}
		t.Cleanup(func() { _ = store.Close() })
		if _, err = store.Load(record.Locator()); err != nil {
			t.Fatal("recovered publication is not loadable")
		}
	})

	t.Run("unexpired quarantine", func(t *testing.T) {
		root, key, now := newRawRoot(t)
		record := deterministicRecord(t, now, MinimumRetention, 0x12)
		writeRecordChild(t, root, quarantineName(record, 0x22), record, key)
		store, err := NewStoreWithLimits(
			root, key, func() time.Time { return now },
			Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
		)
		if err != nil {
			t.Fatal("unexpired quarantine restore failed")
		}
		t.Cleanup(func() { _ = store.Close() })
		if _, err = store.Load(record.Locator()); err != nil {
			t.Fatal("restored quarantine is not loadable")
		}
	})

	t.Run("expired quarantine", func(t *testing.T) {
		root, key, now := newRawRoot(t)
		record := deterministicRecord(t, now.Add(-2*time.Hour), MinimumRetention, 0x13)
		name := quarantineName(record, 0x23)
		writeRecordChild(t, root, name, record, key)
		store, err := NewStoreWithLimits(
			root, key, func() time.Time { return now },
			Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
		)
		if err != nil {
			t.Fatal("expired quarantine cleanup failed")
		}
		t.Cleanup(func() { _ = store.Close() })
		if _, err = os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("expired quarantine survived startup")
		}
	})

	for _, current := range []struct {
		name   string
		create func(*testing.T, string, []byte, time.Time)
	}{
		{unexpectedManifestName, func(t *testing.T, root string, _ []byte, _ time.Time) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, unexpectedManifestName), []byte("x"), 0o600); err != nil {
				t.Fatal("unexpected child fixture failed")
			}
		}},
		{"corrupt final", func(t *testing.T, root string, _ []byte, _ time.Time) {
			t.Helper()
			name := canonicalLocator(bytes.Repeat([]byte{0x30}, LocatorBytes)) + finalSuffix
			if err := os.WriteFile(filepath.Join(root, name), []byte("DXE1"), 0o600); err != nil {
				t.Fatal("corrupt child fixture failed")
			}
		}},
		{"expired put", func(t *testing.T, root string, key []byte, now time.Time) {
			t.Helper()
			record := deterministicRecord(t, now.Add(-2*time.Hour), MinimumRetention, 0x14)
			writeRecordChild(t, root, publicationName(record, 0x24), record, key)
		}},
	} {
		t.Run(current.name, func(t *testing.T) {
			root, key, now := newRawRoot(t)
			current.create(t, root, key, now)
			store, err := NewStoreWithLimits(
				root, key, func() time.Time { return now },
				Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
			)
			if store != nil || !errors.Is(err, ErrNotReady) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatal("unsafe startup state did not fail readiness")
			}
		})
	}
}

// TestStoreRejectsUnsafeFileKindsLinksAndModes proves symlink, FIFO,
// hard-link, and unsafe root metadata cannot enter recovery.
func TestStoreRejectsUnsafeFileKindsLinksAndModes(t *testing.T) {
	locator := canonicalLocator(bytes.Repeat([]byte{0x41}, LocatorBytes))
	cases := []struct {
		name   string
		create func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Symlink("/dev/null", filepath.Join(root, locator+finalSuffix)); err != nil {
				t.Fatal("symlink fixture failed")
			}
		}},
		{"fifo", func(t *testing.T, root string) {
			t.Helper()
			if err := unix.Mkfifo(filepath.Join(root, locator+finalSuffix), 0o600); err != nil {
				t.Fatal("FIFO fixture failed")
			}
		}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			root, key, now := newRawRoot(t)
			current.create(t, root)
			store, err := NewStoreWithLimits(
				root, key, func() time.Time { return now },
				Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
			)
			if store != nil || !errors.Is(err, ErrNotReady) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatal("unsafe file kind entered readiness")
			}
		})
	}

	t.Run("hard link", func(t *testing.T) {
		root, key, now := newRawRoot(t)
		record := deterministicRecord(t, now, MinimumRetention, 0x42)
		final := filepath.Join(root, record.Locator()+finalSuffix)
		writeRecordChild(t, root, record.Locator()+finalSuffix, record, key)
		if err := os.Link(final, filepath.Join(root, publicationName(record, 0x43))); err != nil {
			t.Fatal("hard-link fixture failed")
		}
		store, err := NewStoreWithLimits(
			root, key, func() time.Time { return now },
			Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
		)
		if store != nil || !errors.Is(err, ErrNotReady) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatal("hard-linked record entered readiness")
		}
	})

	t.Run("root mode", func(t *testing.T) {
		root, key, now := newRawRoot(t)
		if err := os.Chmod(root, 0o750); err != nil {
			t.Fatal("unsafe root mode fixture failed")
		}
		store, err := NewStoreWithLimits(
			root, key, func() time.Time { return now },
			Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes},
		)
		if store != nil || err == nil {
			t.Fatal("unsafe root mode entered readiness")
		}
	})
}

// TestStoreCancellationClosePrivacyAndPanicContainment proves bounded caller
// cancellation, use-after-close rejection, key wiping, and redacted diagnostics.
func TestStoreCancellationClosePrivacyAndPanicContainment(t *testing.T) {
	store, _, _ := newStoreFixture(t, Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes})
	incoming := testIncoming(t, []byte("private-mail"), [][]byte{[]byte("private-recipient")}, adapter.SessionSMTP)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PublishContext(ctx, MinimumRetention, incoming); err == nil {
		t.Fatal("cancelled publication succeeded")
	}
	if stats, err := store.Stats(); err != nil || stats != (Stats{}) {
		t.Fatal("cancelled publication changed accounting")
	}
	store.random = panicReader{}
	if _, err := store.Publish(MinimumRetention, incoming); err == nil {
		t.Fatal("panicking entropy source escaped containment")
	}
	if err := store.Ready(); !errors.Is(err, ErrNotReady) {
		t.Fatal("dependency panic did not degrade readiness")
	}
	for _, format := range []string{
		protectedDefaultFormat, protectedDetailFormat, protectedGoFormat,
		protectedStringFormat, protectedQuotedFormat,
	} {
		rendered := fmt.Sprintf(format, store)
		if strings.Contains(rendered, "private") || len(rendered) > 64 {
			t.Fatal("store formatting exposed protected state")
		}
	}

	store, _, _ = newStoreFixture(t, Limits{MaxRecords: 2, MaxBytes: MinimumMaxBytes})
	ownedKey := store.key
	if err := store.Close(); err != nil {
		t.Fatal("store close failed")
	}
	for _, current := range ownedKey {
		if current != 0 {
			t.Fatal("close retained HMAC key material")
		}
	}
	if _, err := store.Load(canonicalLocator(make([]byte, LocatorBytes))); !errors.Is(err, ErrClosed) {
		t.Fatal("closed store accepted a read")
	}
	if err := store.Close(); err != nil {
		t.Fatal("idempotent close failed")
	}
}

// TestStoreConcurrentReadSweepAndCloseIsRaceSafe exercises live descriptor
// leases and serialized writers under the race detector.
func TestStoreConcurrentReadSweepAndCloseIsRaceSafe(t *testing.T) {
	store, _, _ := newStoreFixture(t, Limits{MaxRecords: 32, MaxBytes: MinimumMaxBytes})
	record, err := store.Publish(
		MaximumRetention,
		testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionLocal),
	)
	if err != nil {
		t.Fatal("race fixture publication failed")
	}
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				_, _ = store.Load(record.Locator())
				_ = store.Collect()
			}
		}()
	}
	workers.Wait()
	if err = store.Close(); err != nil {
		t.Fatal("race fixture close failed")
	}
}

// TestLoadKeyFileRequiresProtectedExactGeneration proves key contents,
// owner-only metadata, EOF, hard-link, and symlink checks.
func TestLoadKeyFileRequiresProtectedExactGeneration(t *testing.T) {
	makeFixture := func(t *testing.T, content []byte, mode os.FileMode) (string, string) {
		t.Helper()
		parent := t.TempDir()
		path := filepath.Join(parent, "evidence.key")
		if err := os.WriteFile(path, content, mode); err != nil {
			t.Fatal("key fixture write failed")
		}
		if err := os.Chmod(path, mode); err != nil || os.Chmod(parent, 0o500) != nil {
			t.Fatal("key fixture mode failed")
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		return parent, path
	}
	key := bytes.Repeat([]byte{0x9a}, KeyBytes)
	_, path := makeFixture(t, key, 0o400)
	got, err := LoadKeyFile(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("valid protected key rejected")
	}
	clear(got)
	for _, current := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{"short", key[:KeyBytes-1], 0o400},
		{"suffix", append(bytes.Clone(key), 0), 0o400},
		{"mode", key, 0o644},
	} {
		t.Run(current.name, func(t *testing.T) {
			_, candidate := makeFixture(t, current.content, current.mode)
			if loaded, loadErr := LoadKeyFile(candidate); loadErr == nil || loaded != nil {
				clear(loaded)
				t.Fatal("unsafe key generation accepted")
			}
		})
	}
	t.Run("hard link", func(t *testing.T) {
		parent, candidate := makeFixture(t, key, 0o400)
		if err := os.Chmod(parent, 0o700); err != nil ||
			os.Link(candidate, filepath.Join(parent, "alias")) != nil ||
			os.Chmod(parent, 0o500) != nil {
			t.Fatal("hard-link key fixture failed")
		}
		if loaded, loadErr := LoadKeyFile(candidate); loadErr == nil || loaded != nil {
			clear(loaded)
			t.Fatal("hard-linked key accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		parent, target := makeFixture(t, key, 0o400)
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Fatal("symlink fixture parent mode failed")
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil ||
			os.Chmod(parent, 0o500) != nil {
			t.Fatal("symlink key fixture failed")
		}
		if loaded, loadErr := LoadKeyFile(link); loadErr == nil || loaded != nil {
			clear(loaded)
			t.Fatal("symlink key accepted")
		}
	})
}

// newStoreFixture opens one clean store and registers close cleanup.
func newStoreFixture(t *testing.T, limits Limits) (*Store, *lockedClock, []byte) {
	t.Helper()
	root, key, now := newRawRoot(t)
	clock := &lockedClock{now: now}
	store, err := NewStoreWithLimits(root, key, clock.Now, limits)
	if err != nil {
		t.Fatal("store fixture construction failed")
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, clock, key
}

// newRawRoot creates one owner-only state root and opaque key.
func newRawRoot(t *testing.T) (string, []byte, time.Time) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("state root mode failed")
	}
	return root, bytes.Repeat([]byte{0x5a}, KeyBytes), time.Unix(1_700_000_000, 0).UTC()
}

// deterministicRecord constructs one record with a repeated locator byte.
func deterministicRecord(t *testing.T, now time.Time, retention time.Duration, value byte) Record {
	t.Helper()
	record, err := NewRecord(
		now, retention,
		testIncoming(t, nil, [][]byte{[]byte("r")}, adapter.SessionLocal),
		bytes.NewReader(bytes.Repeat([]byte{value}, LocatorBytes)),
	)
	if err != nil {
		t.Fatal("deterministic record construction failed")
	}
	return record
}

// writeRecordChild writes one exact owner-only authenticated fixture.
func writeRecordChild(t *testing.T, root, name string, record Record, key []byte) {
	t.Helper()
	encoded, err := record.Encode(key)
	if err != nil {
		t.Fatal("record fixture encoding failed")
	}
	defer clear(encoded)
	if err = os.WriteFile(filepath.Join(root, name), encoded, 0o600); err != nil {
		t.Fatal("record fixture write failed")
	}
	if err = os.Chmod(filepath.Join(root, name), 0o600); err != nil {
		t.Fatal("record fixture mode failed")
	}
}

// publicationName returns one exact reserved startup publication name.
func publicationName(record Record, nonce byte) string {
	return publicationPrefix + record.Locator() + "-" +
		canonicalNonce(bytes.Repeat([]byte{nonce}, nonceBytes))
}

// quarantineName returns one exact reserved startup quarantine name.
func quarantineName(record Record, nonce byte) string {
	return quarantinePrefix + record.Locator() + "-" +
		canonicalNonce(bytes.Repeat([]byte{nonce}, nonceBytes))
}

// canonicalLocator renders exact test locator bytes.
func canonicalLocator(value []byte) string {
	return base64RawURL(value)
}

// canonicalNonce renders exact test nonce bytes.
func canonicalNonce(value []byte) string {
	return base64RawURL(value)
}

// base64RawURL renders one unpadded base64url test value.
func base64RawURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// maximalIncoming constructs one exact-cap envelope fixture.
func maximalIncoming(t *testing.T) adapter.IncomingEvidence {
	t.Helper()
	recipients := make([][]byte, maxRecipients)
	for index := range recipients {
		recipients[index] = append([]byte{'<'}, append(bytes.Repeat([]byte{'r'}, maxPathBytes-2), '>')...)
	}
	return testIncoming(
		t, append([]byte{'<'}, append(bytes.Repeat([]byte{'m'}, maxPathBytes-2), '>')...), recipients, adapter.SessionSMTP,
	)
}

// testRootPath resolves the retained descriptor only for local test assertions.
func testRootPath(store *Store) string {
	return fmt.Sprintf("/proc/self/fd/%d", store.directory)
}
