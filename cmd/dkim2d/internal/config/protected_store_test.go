//go:build linux || darwin

package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenExistingProtectedStoreDoesNotCreateMissingLock freezes read-only acquisition.
func TestOpenExistingProtectedStoreDoesNotCreateMissingLock(t *testing.T) {
	path := protectedStorePath(t)
	marker := filepath.Join(filepath.Dir(path), "marker")
	if os.WriteFile(marker, []byte("unchanged"), 0o600) != nil {
		t.Fatal("write existing-store marker")
	}
	before, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal("read existing-store directory")
	}
	store, err := OpenExistingProtectedStore(t.Context(), path, 4096)
	if err == nil || store != nil {
		t.Fatal("missing existing lock was created or accepted")
	}
	after, readErr := os.ReadDir(filepath.Dir(path))
	if readErr != nil || len(after) != len(before) {
		t.Fatal("missing existing lock changed directory entries")
	}
	for index := range before {
		if before[index].Name() != after[index].Name() {
			t.Fatal("missing existing lock changed directory entries")
		}
	}
}

// TestOpenExistingProtectedStoreReadsAndSerializesEstablishedStore freezes shared lock semantics.
func TestOpenExistingProtectedStoreReadsAndSerializesEstablishedStore(t *testing.T) {
	path := protectedStorePath(t)
	creator, err := OpenProtectedStore(t.Context(), path, 4096)
	if err != nil {
		t.Fatal("open creating store fixture")
	}
	if content, exists, readErr := creator.Read(t.Context()); readErr != nil || exists || content != nil {
		t.Fatal("read absent creating store fixture")
	}
	if err := creator.Replace(t.Context(), []byte("established")); err != nil {
		t.Fatal("establish protected store fixture")
	}
	if busy, busyErr := OpenExistingProtectedStore(t.Context(), path, 4096); CodeOf(busyErr) != CodeProtectedBusy || busy != nil {
		t.Fatal("existing opener bypassed held stable lock")
	}
	if creator.Close() != nil {
		t.Fatal("close creating store fixture")
	}
	reader, err := OpenExistingProtectedStore(t.Context(), path, 4096)
	if err != nil {
		t.Fatal("open established store without creation")
	}
	defer reader.Close() //nolint:errcheck // Test cleanup has no recovery.
	content, exists, err := reader.Read(t.Context())
	if err != nil || !exists || string(content) != "established" {
		clear(content)
		t.Fatal("existing opener did not retain exact read semantics")
	}
	clear(content)
}

// TestOpenExistingProtectedStoreRejectsInvalidLockInodes freezes lock ownership and identity fences.
func TestOpenExistingProtectedStoreRejectsInvalidLockInodes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, lock string) {
			if os.Remove(lock) != nil || os.Symlink("target", lock) != nil {
				t.Fatal("create symlink lock fixture")
			}
		}},
		{"hardlink", func(t *testing.T, lock string) {
			if os.Link(lock, lock+".alias") != nil {
				t.Fatal("create hardlink lock fixture")
			}
		}},
		{"wrong-mode", func(t *testing.T, lock string) {
			if os.Chmod(lock, 0o640) != nil {
				t.Fatal("change lock mode fixture")
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := protectedStorePath(t)
			creator, err := OpenProtectedStore(t.Context(), path, 4096)
			if err != nil || creator.Close() != nil {
				t.Fatal("establish lock fixture")
			}
			test.mutate(t, path+".lock")
			if store, openErr := OpenExistingProtectedStore(t.Context(), path, 4096); openErr == nil || store != nil {
				t.Fatal("invalid existing lock inode was accepted")
			}
		})
	}
}

// TestOpenExistingProtectedStoreRejectsLockReplacementAfterFlock freezes final entry identity.
func TestOpenExistingProtectedStoreRejectsLockReplacementAfterFlock(t *testing.T) {
	path := protectedStorePath(t)
	creator, err := OpenProtectedStore(t.Context(), path, 4096)
	if err != nil || creator.Close() != nil {
		t.Fatal("establish replacement lock fixture")
	}
	lockPath := path + ".lock"
	store, err := openExistingProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event != protectedStoreAfterLock {
			return
		}
		if os.Remove(lockPath) != nil || os.WriteFile(lockPath, nil, 0o600) != nil {
			t.Fatal("replace existing held lock fixture")
		}
	})
	if CodeOf(err) != CodeProtectedAccess || store != nil {
		t.Fatal("existing opener accepted replaced lock entry")
	}
}

// TestProtectedStoreRejectsOversizeBeforeTemporaryAllocation freezes the write resource bound.
func TestProtectedStoreRejectsOversizeBeforeTemporaryAllocation(t *testing.T) {
	path := protectedStorePath(t)
	store, err := OpenProtectedStore(t.Context(), path, 16)
	if err != nil {
		t.Fatal("open bounded protected store")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
	if content, exists, err := store.Read(t.Context()); err != nil || exists || content != nil {
		t.Fatal("establish exact absent CAS view")
	}
	if err := store.Replace(t.Context(), bytes.Repeat([]byte{'x'}, 17)); CodeOf(err) != CodeProtectedContent {
		t.Fatal("oversized replacement crossed the configured bound")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path)+".lock" {
		t.Fatal("oversized replacement created a temporary or final document")
	}
	if err := store.Replace(t.Context(), []byte("bounded")); err != nil {
		t.Fatal("oversized rejection changed the exact CAS view")
	}
}

// TestProtectedStoreCancellationBeforeRenameKeepsOriginal freezes the pre-mutation window.
func TestProtectedStoreCancellationBeforeRenameKeepsOriginal(t *testing.T) {
	path := protectedStorePath(t)
	initial, err := OpenProtectedStore(t.Context(), path, 4096)
	if err != nil {
		t.Fatal("open initial protected store")
	}
	if content, exists, err := initial.Read(t.Context()); err != nil || exists || content != nil {
		t.Fatal("establish initial absent view")
	}
	original := []byte("original")
	if err := initial.Replace(t.Context(), original); err != nil || initial.Close() != nil {
		t.Fatal("create original protected document")
	}
	ctx, cancel := context.WithCancel(t.Context())
	store, err := openProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event == protectedStoreBeforeRename {
			cancel()
		}
	})
	if err != nil {
		t.Fatal("open cancellation fixture")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
	if content, exists, err := store.Read(t.Context()); err != nil || !exists {
		clear(content)
		t.Fatal("read exact original view")
	} else {
		clear(content)
	}
	if err := store.Replace(ctx, []byte("must-not-rename")); CodeOf(err) != CodeProtectedIO {
		t.Fatal("pre-rename cancellation was not a non-ambiguous I/O failure")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, original) {
		clear(stored)
		t.Fatal("pre-rename cancellation changed original content")
	}
	clear(stored)
}

// TestProtectedStoreCancellationBeforeAbsentSuccess freezes the negative-read window.
func TestProtectedStoreCancellationBeforeAbsentSuccess(t *testing.T) {
	path := protectedStorePath(t)
	ctx, cancel := context.WithCancel(t.Context())
	store, err := openProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event == protectedStoreAfterAbsentOpen {
			cancel()
		}
	})
	if err != nil {
		t.Fatal("open absent cancellation fixture")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
	if content, exists, err := store.Read(ctx); CodeOf(err) != CodeProtectedIO || exists || content != nil {
		t.Fatal("cancelled negative read reported absent success")
	}
}

// TestProtectedStoreSerializesAtomicRoundTrip freezes stable-lock and replacement behavior.
func TestProtectedStoreSerializesAtomicRoundTrip(t *testing.T) {
	path := protectedStorePath(t)
	store, err := OpenProtectedStore(t.Context(), path, 4096)
	if err != nil {
		t.Fatalf("open protected store: %s", CodeOf(err))
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
	if content, exists, readErr := store.Read(t.Context()); readErr != nil || exists || content != nil {
		t.Fatal("absent protected document was not distinguished")
	}
	if second, openErr := OpenProtectedStore(t.Context(), path, 4096); CodeOf(openErr) != CodeProtectedBusy || second != nil {
		t.Fatal("stable sibling lock did not serialize concurrent owner")
	}
	want := []byte(`{"version":"one"}`)
	if err := store.Replace(t.Context(), want); err != nil {
		t.Fatal("replace protected document")
	}
	want = []byte(`{"version":"one-without-refresh"}`)
	if err := store.Replace(t.Context(), want); err != nil {
		t.Fatal("replace protected document again without read")
	}
	got, exists, err := store.Read(t.Context())
	if err != nil || !exists || !bytes.Equal(got, want) {
		clear(got)
		t.Fatal("protected document round trip drifted")
	}
	clear(got)
	stale := filepath.Join(filepath.Dir(path), ".dkim2-journal-stale.tmp")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal("create stale temporary fixture")
	}
	next := []byte(`{"version":"two"}`)
	if err := store.Replace(t.Context(), next); err != nil {
		t.Fatal("stale temporary file affected replacement")
	}
}

// TestProtectedStoreRejectsLockPathReplacementAfterFlock freezes split-lock prevention.
func TestProtectedStoreRejectsLockPathReplacementAfterFlock(t *testing.T) {
	path := protectedStorePath(t)
	lockPath := path + ".lock"
	store, err := openProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event != protectedStoreAfterLock {
			return
		}
		if removeErr := os.Remove(lockPath); removeErr != nil {
			t.Fatal("remove held lock entry fixture")
		}
		if writeErr := os.WriteFile(lockPath, nil, 0o600); writeErr != nil {
			t.Fatal("replace held lock entry fixture")
		}
	})
	if CodeOf(err) != CodeProtectedAccess || store != nil {
		t.Fatal("same-uid lock entry replacement created a split lock")
	}
}

// TestProtectedStoreRejectsParentPathReplacementAfterFlock freezes parent identity.
func TestProtectedStoreRejectsParentPathReplacementAfterFlock(t *testing.T) {
	path := protectedStorePath(t)
	directory := filepath.Dir(path)
	moved := directory + ".moved"
	store, err := openProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event != protectedStoreAfterLock {
			return
		}
		if renameErr := os.Rename(directory, moved); renameErr != nil {
			t.Fatal("rename held parent fixture")
		}
		if mkdirErr := os.Mkdir(directory, 0o700); mkdirErr != nil {
			t.Fatal("replace held parent fixture")
		}
	})
	if CodeOf(err) != CodeProtectedAccess || store != nil {
		t.Fatal("same-uid parent replacement retained protected authority")
	}
}

// TestProtectedStoreRechecksFenceBeforeReportingAbsent freezes the negative-read race.
func TestProtectedStoreRechecksFenceBeforeReportingAbsent(t *testing.T) {
	path := protectedStorePath(t)
	lockPath := path + ".lock"
	store, err := openProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event != protectedStoreAfterAbsentOpen {
			return
		}
		if removeErr := os.Remove(lockPath); removeErr != nil {
			t.Fatal("remove absent-read lock fixture")
		}
		if writeErr := os.WriteFile(lockPath, nil, 0o600); writeErr != nil {
			t.Fatal("replace absent-read lock fixture")
		}
	})
	if err != nil {
		t.Fatal("open absent-read race fixture")
	}
	defer store.Close() //nolint:errcheck // Deliberately invalidated fixture.
	if content, exists, readErr := store.Read(t.Context()); readErr == nil || exists || content != nil {
		t.Fatal("absent read returned without a final serialization proof")
	}
}

// TestProtectedStoreRequiresExactReadViewBeforeReplace freezes filesystem CAS semantics.
func TestProtectedStoreRequiresExactReadViewBeforeReplace(t *testing.T) {
	path := protectedStorePath(t)
	store, err := OpenProtectedStore(t.Context(), path, 4096)
	if err != nil {
		t.Fatal("open CAS fixture")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
	if err := store.Replace(t.Context(), []byte("without-read")); CodeOf(err) != CodeProtectedConflict {
		t.Fatal("replace without exact read view was accepted")
	}
	if content, exists, readErr := store.Read(t.Context()); readErr != nil || exists || content != nil {
		t.Fatal("read absent CAS fixture")
	}
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal("insert document after absent view")
	}
	if err := store.Replace(t.Context(), []byte("replacement")); CodeOf(err) != CodeProtectedConflict {
		t.Fatal("document insertion after absent view bypassed CAS")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("remove inserted CAS fixture")
	}
	if content, exists, readErr := store.Read(t.Context()); readErr != nil || exists || content != nil {
		t.Fatal("refresh absent CAS view")
	}
	if err := store.Replace(t.Context(), []byte("original")); err != nil {
		t.Fatal("create CAS original")
	}
	if content, exists, readErr := store.Read(t.Context()); readErr != nil || !exists {
		clear(content)
		t.Fatal("read exact present CAS view")
	} else {
		clear(content)
	}
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal("move exact CAS inode")
	}
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal("replace exact CAS inode")
	}
	if err := store.Replace(t.Context(), []byte("must-not-win")); CodeOf(err) != CodeProtectedConflict {
		t.Fatal("same-uid document inode replacement bypassed CAS")
	}
}

// TestProtectedStoreReportsPostRenameFenceLossAsAmbiguous freezes mutation truth.
func TestProtectedStoreReportsPostRenameFenceLossAsAmbiguous(t *testing.T) {
	path := protectedStorePath(t)
	lockPath := path + ".lock"
	store, err := openProtectedStore(t.Context(), path, 4096, func(event protectedStoreEvent) {
		if event != protectedStoreAfterRename {
			return
		}
		if removeErr := os.Remove(lockPath); removeErr != nil {
			t.Fatal("remove post-rename lock fixture")
		}
		if writeErr := os.WriteFile(lockPath, nil, 0o600); writeErr != nil {
			t.Fatal("replace post-rename lock fixture")
		}
	})
	if err != nil {
		t.Fatal("open observed protected store")
	}
	defer store.Close() //nolint:errcheck // Deliberately invalidated fixture.
	if content, exists, readErr := store.Read(t.Context()); readErr != nil || exists || content != nil {
		t.Fatal("establish absent observed view")
	}
	content := []byte(`{"mutation":"may-have-happened"}`)
	if err := store.Replace(t.Context(), content); CodeOf(err) != CodeProtectedAmbiguous {
		t.Fatal("post-rename fence loss denied an ambiguous mutation")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, content) {
		clear(stored)
		t.Fatal("ambiguous result did not retain the already-renamed document")
	}
	clear(stored)
	if readContent, exists, readErr := store.Read(t.Context()); CodeOf(readErr) != CodeProtectedAmbiguous || exists || readContent != nil {
		t.Fatal("ambiguous store permitted a follow-up read")
	}
	if replaceErr := store.Replace(t.Context(), []byte("second")); CodeOf(replaceErr) != CodeProtectedAmbiguous {
		t.Fatal("ambiguous store permitted a follow-up replacement")
	}
}

// TestProtectedStoreRejectsUnsafeDocumentAndGenericSinks freezes filesystem and privacy policy.
func TestProtectedStoreRejectsUnsafeDocumentAndGenericSinks(t *testing.T) {
	path := protectedStorePath(t)
	if err := os.WriteFile(path, []byte("unsafe"), 0o600); err != nil {
		t.Fatal("write protected document fixture")
	}
	alias := path + ".alias"
	if err := os.Link(path, alias); err != nil {
		t.Fatal("link protected document fixture")
	}
	store, err := OpenProtectedStore(t.Context(), path, 4096)
	if err != nil {
		t.Fatal("open hard-link read fixture")
	}
	if content, exists, readErr := store.Read(t.Context()); readErr == nil || exists || content != nil {
		t.Fatal("hard-linked protected document was accepted")
	}
	marker := path
	rendered := fmt.Sprintf("%+v", store)
	if !strings.Contains(rendered, protectedRedactedText) || strings.Contains(rendered, marker) {
		t.Fatal("protected store reached formatting sink")
	}
	if _, marshalErr := json.Marshal(store); marshalErr == nil {
		t.Fatal("protected store reached JSON sink")
	}
	_ = store.Close()
}

// protectedStorePath creates one exact owner-only test directory and journal path.
func protectedStorePath(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve store directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal("protect store directory")
	}
	return filepath.Join(directory, "operation.json")
}
