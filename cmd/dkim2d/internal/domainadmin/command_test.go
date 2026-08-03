package domainadmin

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestOpenStatusJournalStoreLeavesMissingOperationDirectoryUnchanged freezes read-only status access.
func TestOpenStatusJournalStoreLeavesMissingOperationDirectoryUnchanged(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect missing-status fixture")
	}
	marker := filepath.Join(directory, "marker")
	if os.WriteFile(marker, []byte("unchanged"), 0o600) != nil {
		t.Fatal("write missing-status marker")
	}
	before, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("read missing-status directory")
	}
	store, openErr := OpenStatusJournalStore(t.Context(), filepath.Join(directory, "missing.json"), DefaultLimits())
	if openErr == nil || store != nil {
		t.Fatal("missing status operation unexpectedly opened")
	}
	after, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("reread missing-status directory")
	}
	beforeNames := make([]string, 0, len(before))
	afterNames := make([]string, 0, len(after))
	for _, entry := range before {
		beforeNames = append(beforeNames, entry.Name())
	}
	for _, entry := range after {
		afterNames = append(afterNames, entry.Name())
	}
	if !slices.Equal(beforeNames, afterNames) {
		t.Fatal("read-only missing status created a persistent filesystem artifact")
	}
}

// TestPreflightCommandAuthorityRejectsSubstitutionBeforeBackendConstruction freezes the no-I/O authority gate.
func TestPreflightCommandAuthorityRejectsSubstitutionBeforeBackendConstruction(t *testing.T) {
	journal, plan := plannedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery action.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery action.
	path := protectedOnboardingPath(t, "authority-preflight.json")
	store, err := OpenJournalStore(t.Context(), path, DefaultLimits())
	if err != nil {
		t.Fatal("open protected authority preflight store")
	}
	defer store.Close() //nolint:errcheck // Test cleanup has no recovery action.
	if loaded, exists, loadErr := store.Load(t.Context()); loadErr != nil || exists || loaded != nil {
		t.Fatal("load absent authority preflight journal")
	}
	if err := store.Save(t.Context(), journal); err != nil {
		t.Fatal("save authority preflight journal")
	}
	authority := cloneAuthority(plan.authority)
	if err := PreflightCommandAuthority(t.Context(), store, CommandPrepare, plan.backend, authority); err != nil {
		t.Fatal("exact command authority was rejected")
	}
	substituted := cloneAuthority(authority)
	substituted.Endpoints[0].Host = "192.0.2.99"
	if CodeOf(PreflightCommandAuthority(
		t.Context(), store, CommandPrepare, plan.backend, substituted,
	)) != CodeConflict {
		t.Fatal("same-class provider substitution passed pre-I/O authority gate")
	}
}
