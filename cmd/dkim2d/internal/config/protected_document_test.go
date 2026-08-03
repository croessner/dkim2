//go:build linux || darwin

package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateProtectedDocumentReportsPostInstallAmbiguityWithExactBytes freezes retry evidence.
func TestCreateProtectedDocumentReportsPostInstallAmbiguityWithExactBytes(t *testing.T) {
	path := writeProtectedDocumentFixture(t, []byte("placeholder"))
	if os.Remove(path) != nil {
		t.Fatal("prepare absent create-only fixture")
	}
	ctx, cancel := context.WithCancel(t.Context())
	want := []byte("deterministic DNS artifact\n")
	err := createProtectedDocumentObserved(ctx, path, want, 4096, func(event protectedCreateEvent) {
		if event == protectedCreateAfterLink {
			cancel()
		}
	})
	if CodeOf(err) != CodeProtectedAmbiguous {
		t.Fatal("post-install cancellation denied ambiguous creation")
	}
	got, exists, readErr := ReadProtectedDocumentIfExists(path, 4096)
	if readErr != nil || !exists || !bytes.Equal(got, want) {
		clear(got)
		t.Fatal("ambiguous create did not retain exact installed bytes for retry")
	}
	clear(got)
}

// TestCreateProtectedDocumentConcurrentForeignWinnerCannotBeOverwritten freezes no-replace races.
func TestCreateProtectedDocumentConcurrentForeignWinnerCannotBeOverwritten(t *testing.T) {
	path := writeProtectedDocumentFixture(t, []byte("placeholder"))
	if os.Remove(path) != nil {
		t.Fatal("prepare concurrent create-only fixture")
	}
	linked := make(chan struct{})
	release := make(chan struct{})
	foreign := []byte("foreign owner-only document\n")
	desired := []byte("deterministic DNS artifact\n")
	result := make(chan error, 1)
	go func() {
		result <- createProtectedDocumentObserved(t.Context(), path, foreign, 4096, func(event protectedCreateEvent) {
			if event == protectedCreateAfterLink {
				close(linked)
				<-release
			}
		})
	}()
	<-linked
	if err := CreateProtectedDocument(t.Context(), path, desired, 4096); CodeOf(err) != CodeProtectedConflict {
		close(release)
		<-result
		t.Fatal("concurrent foreign winner was overwritten")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal("foreign create-only winner failed")
	}
	got, exists, err := ReadProtectedDocumentIfExists(path, 4096)
	if err != nil || !exists || !bytes.Equal(got, foreign) {
		clear(got)
		t.Fatal("foreign create-only winner bytes changed")
	}
	clear(got)
}

// TestCreateProtectedDocumentRejectsSameSizePostInstallRewrite freezes final byte readback.
func TestCreateProtectedDocumentRejectsSameSizePostInstallRewrite(t *testing.T) {
	path := writeProtectedDocumentFixture(t, []byte("placeholder"))
	if os.Remove(path) != nil {
		t.Fatal("prepare post-install rewrite fixture")
	}
	want := []byte("expected-bytes")
	err := createProtectedDocumentObserved(t.Context(), path, want, 4096, func(event protectedCreateEvent) {
		if event == protectedCreateBeforeFinalReadback && os.WriteFile(path, []byte("modified-bytes"), 0o600) != nil {
			t.Fatal("rewrite installed create-only fixture")
		}
	})
	if CodeOf(err) != CodeProtectedAmbiguous {
		t.Fatal("same-size post-install rewrite passed final byte proof")
	}
}

// TestReadProtectedDocumentRejectsSameSizeRewrite freezes timestamp revalidation.
func TestReadProtectedDocumentRejectsSameSizeRewrite(t *testing.T) {
	path := writeProtectedDocumentFixture(t, []byte("first-value"))
	_, err := readProtectedDocumentObserved(path, 64, func(event protectedDocumentEvent) {
		if event != protectedDocumentAfterRead {
			return
		}
		if writeErr := os.WriteFile(path, []byte("other-value"), 0o600); writeErr != nil {
			t.Fatal("rewrite protected fixture")
		}
	})
	if CodeOf(err) != CodeProtectedAccess {
		t.Fatal("same-size rewrite was not rejected")
	}
}

// TestReadProtectedDocumentRejectsPathReplacement freezes final entry identity.
func TestReadProtectedDocumentRejectsPathReplacement(t *testing.T) {
	path := writeProtectedDocumentFixture(t, []byte("first-value"))
	_, err := readProtectedDocumentObserved(path, 64, func(event protectedDocumentEvent) {
		if event != protectedDocumentAfterRead {
			return
		}
		if renameErr := os.Rename(path, path+".old"); renameErr != nil {
			t.Fatal("rename protected fixture")
		}
		if writeErr := os.WriteFile(path, []byte("other-value"), 0o600); writeErr != nil {
			t.Fatal("replace protected fixture")
		}
	})
	if CodeOf(err) != CodeProtectedAccess {
		t.Fatal("path replacement was not rejected")
	}
}

// TestReadProtectedDocumentUsesPlatformAuthority proves local ACL policy participation.
func TestReadProtectedDocumentUsesPlatformAuthority(t *testing.T) {
	path := writeProtectedDocumentFixture(t, []byte("document"))
	data, err := ReadProtectedDocument(path, 64)
	if err != nil || string(data) != "document" {
		t.Fatal("central protected-document authority rejected valid input")
	}
	clear(data)
}

// writeProtectedDocumentFixture creates one central-authority compatible document.
func writeProtectedDocumentFixture(t *testing.T, value []byte) string {
	t.Helper()
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal("resolve protected fixture directory")
	}
	if err := os.Chmod(resolved, 0o700); err != nil {
		t.Fatal("protect fixture directory")
	}
	path := filepath.Join(resolved, "document.yaml")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal("write protected fixture")
	}
	return path
}
