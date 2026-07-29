//nolint:goconst // Independent database-boundary cases intentionally repeat fixture timestamps.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
)

// TestBuildSnapshotRejectsOversizeSymlinkAndHardlinkDatabase freezes descriptor policy.
func TestBuildSnapshotRejectsOversizeSymlinkAndHardlinkDatabase(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string, database string)
	}{
		{
			name: "oversize",
			mutate: func(t *testing.T, _ string, database string) {
				t.Helper()
				if err := os.Truncate(database, maximumDatabaseBytes+1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, root string, database string) {
				t.Helper()
				if err := os.Remove(database); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(root, "outside")
				if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, database); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, root string, database string) {
				t.Helper()
				if err := os.Link(database, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, database := writeDatabaseFixture(t, 8)
			test.mutate(t, root, database)
			if _, err := captureDatabaseFiles(root); err == nil {
				t.Fatal("hostile database was accepted")
			}
		})
	}
}

// TestPortableSnapshotIsDeterministicAndHostIndependent freezes release projection.
func TestPortableSnapshotIsDeterministicAndHostIndependent(t *testing.T) {
	root, _ := writeDatabaseFixture(t, 8)
	files, err := captureDatabaseFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	identity := toolIdentity{
		Schema: "dkim2-image-tool-v1", Name: "trivy", Version: "0.72.0",
		Asset: "trivy.tgz", ArchiveSHA256: strings.Repeat("a", 64),
		BinarySHA256: strings.Repeat("b", 64),
	}
	scanTime := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	first, err := json.Marshal(portableDatabaseSnapshot(
		strings.Repeat("c", 64),
		identity,
		files,
		scanTime,
	))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(portableDatabaseSnapshot(
		strings.Repeat("c", 64),
		identity,
		files,
		scanTime,
	))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("unchanged portable projections differ")
	}
	for _, forbidden := range []string{
		`"device"`, `"inode"`, `"uid"`, `"mode"`, `"links"`,
		`"modified_sec"`, `"changed_sec"`,
	} {
		if bytes.Contains(first, []byte(forbidden)) {
			t.Fatalf("portable evidence contains private field %s", forbidden)
		}
	}
}

// TestValidateMetadataAtRejectsExpiredStaleAndFutureState freezes scanner clock policy.
func TestValidateMetadataAtRejectsExpiredStaleAndFutureState(t *testing.T) {
	now := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	valid := databaseMetadata{
		Version:      2,
		UpdatedAt:    "2026-07-28T13:20:17Z",
		DownloadedAt: "2026-07-28T15:35:54Z",
		NextUpdate:   "2026-07-29T13:20:17Z",
	}
	if err := validateMetadataAt(valid, now); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*databaseMetadata)
	}{
		{
			name: "expired",
			mutate: func(value *databaseMetadata) {
				value.NextUpdate = "2026-07-28T16:00:00Z"
			},
		},
		{
			name: "stale",
			mutate: func(value *databaseMetadata) {
				value.UpdatedAt = "2026-07-26T15:59:59Z"
			},
		},
		{
			name: "future_update",
			mutate: func(value *databaseMetadata) {
				value.UpdatedAt = "2026-07-28T16:05:01Z"
				value.DownloadedAt = "2026-07-28T16:05:02Z"
			},
		},
		{
			name: "future_download",
			mutate: func(value *databaseMetadata) {
				value.DownloadedAt = "2026-07-28T16:05:01Z"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := validateMetadataAt(candidate, now); err == nil {
				t.Fatal("hostile database time was accepted")
			}
		})
	}
}

// TestParseScanTimeRejectsCallerClockDrift freezes shared scan-cycle authority.
func TestParseScanTimeRejectsCallerClockDrift(t *testing.T) {
	now := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	if _, err := parseScanTime("2026-07-28T16:00:00Z", now); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"2026-07-28T16:00:00+00:00",
		"2026-07-28T15:54:59Z",
		"2026-07-28T16:05:01Z",
	} {
		if _, err := parseScanTime(value, now); err == nil {
			t.Fatalf("hostile scan time %q was accepted", value)
		}
	}
}

// TestGuardDatabaseFilesRejectsSameContentSwap freezes descriptor identity binding.
func TestGuardDatabaseFilesRejectsSameContentSwap(t *testing.T) {
	root, database := writeDatabaseFixture(t, 8)
	if err := guardDatabaseFiles(root, func() error {
		replacement := database + ".replacement"
		content, err := os.ReadFile(database)
		if err != nil {
			return err
		}
		if err := os.WriteFile(replacement, content, 0o600); err != nil {
			return err
		}
		return os.Rename(replacement, database)
	}); err == nil {
		t.Fatal("same-content inode swap was accepted")
	}
}

// TestGuardDatabaseFilesRejectsConcurrentWrite reproduces a live scanner-DB write.
func TestGuardDatabaseFilesRejectsConcurrentWrite(t *testing.T) {
	root, database := writeDatabaseFixture(t, 64<<20)
	stop := make(chan struct{})
	started := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		file, err := os.OpenFile(database, os.O_WRONLY, 0)
		if err != nil {
			close(started)
			return
		}
		defer func() {
			_ = file.Close()
		}()
		content := bytes.Repeat([]byte{0x5a}, 1<<20)
		close(started)
		offset := int64(0)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = file.WriteAt(content, offset)
			offset += int64(len(content))
			if offset >= 64<<20 {
				offset = 0
			}
		}
	}()
	<-started
	err := guardDatabaseFiles(root, func() error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	close(stop)
	wait.Wait()
	if err == nil {
		t.Fatal("concurrent database writer was accepted")
	}
}

// TestScannerCommandUsesClosedEnvironment freezes proxy and credential isolation.
func TestScannerCommandUsesClosedEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://attacker.invalid")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("TRIVY_SEVERITY", "LOW")
	command := scannerCommand(
		context.Background(),
		&scanSnapshot{rootPath: "/repo/work/snapshot"},
		"/repo/work",
	)
	environment := strings.Join(command.Env, "\n")
	for _, forbidden := range []string{"PROXY", "AWS_", "SECRET", "TRIVY_"} {
		if strings.Contains(environment, forbidden) {
			t.Fatalf("scanner environment contains %s", forbidden)
		}
	}
	if !strings.Contains(environment, "DOCKER_CONFIG=/repo/work/snapshot/docker-config") {
		t.Fatal("scanner environment lacks private Docker configuration")
	}
}

// TestAddSnapshotFileSurvivesTransientSourceSwap freezes consumed-byte binding.
func TestAddSnapshotFileSurvivesTransientSourceSwap(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "safe", "source")
	if err := os.WriteFile(source, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := artifactpath.SnapshotFile(root, "safe/source", 64)
	if err != nil {
		t.Fatal(err)
	}
	view := filepath.Join(root, "view")
	if err := os.Mkdir(view, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(view, "bound")
	if err := addSnapshotFile(
		root,
		"safe/source",
		target,
		expected,
		64,
	); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "safe", "replacement")
	if err := os.WriteFile(replacement, []byte("hostile"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, source); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "trusted" {
		t.Fatalf("descriptor view consumed %q", content)
	}
}

// TestBoundedWriterRejectsOversizeOutput freezes constant-space scanner output.
func TestBoundedWriterRejectsOversizeOutput(t *testing.T) {
	var destination bytes.Buffer
	writer := boundedWriter{destination: &destination, remaining: 4}
	if _, err := writer.Write([]byte("four")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("oversize scanner output was accepted")
	}
}

// writeDatabaseFixture creates one closed scanner-database tree.
func writeDatabaseFixture(t *testing.T, size int64) (string, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(
		root,
		".artifacts",
		"image-tools",
		"trivy-cache",
		"db",
	)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := []byte(
		`{"Version":2,"NextUpdate":"2026-07-29T13:20:17Z","UpdatedAt":"2026-07-28T13:20:17Z","DownloadedAt":"2026-07-28T15:35:54Z"}`,
	)
	if err := os.WriteFile(filepath.Join(directory, "metadata.json"), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "trivy.db")
	file, err := os.OpenFile(database, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return root, database
}
