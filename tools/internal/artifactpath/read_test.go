//go:build darwin || linux

package artifactpath

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestReadFileRejectsSymlinkHardlinkAndWeakParents freezes file confinement.
func TestReadFileRejectsSymlinkHardlinkAndWeakParents(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "safe", "target")
	if err := os.WriteFile(target, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "safe", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(root, "safe/link", 64); err == nil {
		t.Fatal("symlink was accepted")
	}
	if err := os.Link(target, filepath.Join(root, "safe", "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(root, "safe/target", 64); err == nil {
		t.Fatal("hard-linked file was accepted")
	}
	if err := os.Chmod(filepath.Join(root, "safe"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(root, "safe/target", 64); err == nil {
		t.Fatal("weak parent was accepted")
	}
}

// TestReadFileCannotEscapeDuringParentSwap reproduces directory component races.
func TestReadFileCannotEscapeDuringParentSwap(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	safe := filepath.Join(root, "safe")
	hold := filepath.Join(root, "hold")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(safe, "report"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "report"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Rename(safe, hold)
			_ = os.Symlink(outside, safe)
			_ = os.Remove(safe)
			_ = os.Rename(hold, safe)
		}
	}()
	for attempt := 0; attempt < 1_000; attempt++ {
		content, err := ReadFile(root, "safe/report", 64)
		if err == nil && string(content) != "inside" {
			t.Fatal("descriptor-relative read escaped the root")
		}
	}
	close(stop)
	wait.Wait()
}
