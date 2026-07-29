//nolint:goconst // Independent hostile metadata cases intentionally repeat wire literals.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

// TestSelectVersionRejectsAmbiguousAndMalformedReleaseTags freezes tag policy.
func TestSelectVersionRejectsAmbiguousAndMalformedReleaseTags(t *testing.T) {
	if version, err := selectVersion(nil); err != nil || version != "0.0.0-dev" {
		t.Fatal("untagged development version was rejected")
	}
	if version, err := selectVersion([]string{"notes", "v1.2.3"}); err != nil ||
		version != "v1.2.3" {
		t.Fatal("exact stable release tag was rejected")
	}
	for _, tags := range [][]string{
		{"v1.2.3-extra"},
		{"v1.2.3/../../escape"},
		{"v01.2.3"},
		{"v1.2"},
		{"v1.2.3", "v2.0.0"},
	} {
		if _, err := selectVersion(tags); err == nil {
			t.Fatalf("unsafe tags were accepted: %v", tags)
		}
	}
}

// TestMaterializeCandidateRejectsHardlinksAndWritesExactPrivateBytes freezes source binding.
func TestMaterializeCandidateRejectsHardlinksAndWritesExactPrivateBytes(t *testing.T) {
	root := t.TempDir()
	content := []byte("candidate")
	if err := os.MkdirAll(filepath.Join(root, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source", "file")
	if err := os.WriteFile(source, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	entry := conformance.SnapshotEntry{
		Path:   "source/file",
		Mode:   "100755",
		SHA256: hex.EncodeToString(sum[:]),
	}
	destination := filepath.Join(
		root,
		".artifacts",
		".product-build-work.test",
		"context",
	)
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := materializeCandidate(
		root,
		".artifacts/.product-build-work.test/context",
		conformance.Snapshot{Entries: []conformance.SnapshotEntry{entry}},
	); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(filepath.Join(destination, "source", "file"))
	if err != nil || string(copied) != string(content) {
		t.Fatal("candidate bytes were not copied exactly")
	}
	if info, err := os.Stat(filepath.Join(destination, "source", "file")); err != nil ||
		info.Mode().Perm() != 0o500 {
		t.Fatal("candidate executable mode was not normalized")
	}
	hardlinkRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hardlinkRoot, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	hardlinkSource := filepath.Join(hardlinkRoot, "source", "file")
	if err := os.WriteFile(hardlinkSource, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hardlinkSource, filepath.Join(hardlinkRoot, "alias")); err != nil {
		t.Fatal(err)
	}
	hardlinkDestination := filepath.Join(
		hardlinkRoot,
		".artifacts",
		".image-build-work.test",
		"context",
	)
	if err := os.MkdirAll(hardlinkDestination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := materializeCandidate(
		hardlinkRoot,
		".artifacts/.image-build-work.test/context",
		conformance.Snapshot{Entries: []conformance.SnapshotEntry{entry}},
	); err == nil {
		t.Fatal("hard-linked candidate source was accepted")
	}
}
