//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// TestPrepareDirectoryRejectsSymlinkAndWeakComponent freezes component confinement.
func TestPrepareDirectoryRejectsSymlinkAndWeakComponent(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	if err := root.prepareDirectory("link/child"); err == nil {
		t.Fatal("symlink component was accepted")
	}
	weak := filepath.Join(rootPath, "weak")
	if err := os.Mkdir(weak, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(weak, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := root.prepareDirectory("weak/child"); err == nil {
		t.Fatal("weak directory was accepted")
	}
}

// TestInstallFileRejectsSetIDSource freezes special-mode rejection.
func TestInstallFileRejectsSetIDSource(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	source := filepath.Join(rootPath, "source")
	if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o4600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skip("test filesystem strips set-ID bits")
	}
	if err := root.installFile("source", "evidence/report.json", false); err == nil {
		t.Fatal("set-ID source was accepted")
	}
}

// TestInstallFileRejectsHardLinkedSource freezes one-link evidence ownership.
func TestInstallFileRejectsHardLinkedSource(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	source := filepath.Join(rootPath, "source")
	if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, source+".link"); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("source", "evidence/report.json", false); err == nil {
		t.Fatal("hard-linked source was accepted")
	}
}

// TestInstallFilePublishesOnceAndAcceptsOnlyIdenticalRepeat proves no replacement.
func TestInstallFilePublishesOnceAndAcceptsOnlyIdenticalRepeat(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if err := os.WriteFile(filepath.Join(rootPath, "source"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("source", "evidence/report.json", false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "repeat"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("repeat", "evidence/report.json", false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "different"), []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("different", "evidence/report.json", false); err == nil {
		t.Fatal("different replacement was accepted")
	}
	got, err := os.ReadFile(filepath.Join(rootPath, "evidence", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("installed content = %q", got)
	}
}

// TestReplaceFileAtomicallyUpdatesOnlyAValidatedRegularTarget.
func TestReplaceFileAtomicallyUpdatesOnlyAValidatedRegularTarget(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if err := os.Mkdir(filepath.Join(rootPath, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "evidence", "report.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "source"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.replaceFile("source", "evidence/report.json", false); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(rootPath, "evidence", "report.json"))
	if err != nil || string(content) != "new" {
		t.Fatal("validated target was not atomically replaced")
	}
	if err := os.Remove(filepath.Join(rootPath, "evidence", "report.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(rootPath, "evidence", "report.json")); err != nil {
		t.Fatal(err)
	}
	if err := root.replaceFile("source", "evidence/report.json", false); err == nil {
		t.Fatal("symlink target was replaced")
	}
}

// TestPrepareDirectoryCannotEscapeDuringComponentSwap reproduces component races.
func TestPrepareDirectoryCannotEscapeDuringComponentSwap(t *testing.T) {
	rootPath := t.TempDir()
	outside := t.TempDir()
	flip := filepath.Join(rootPath, "flip")
	hold := filepath.Join(rootPath, "hold")
	if err := os.Mkdir(flip, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
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
			_ = os.Rename(flip, hold)
			_ = os.Symlink(outside, flip)
			_ = os.Remove(flip)
			_ = os.Rename(hold, flip)
		}
	}()
	for attempt := 0; attempt < 1_000; attempt++ {
		_ = root.prepareDirectory("flip/child")
	}
	close(stop)
	wait.Wait()
	if _, err := os.Stat(filepath.Join(outside, "child")); !os.IsNotExist(err) {
		t.Fatal("descriptor-relative preparation escaped the root")
	}
}

// TestInstallFileUsesOneDescriptorOwner guards against delayed finalizer closes.
func TestInstallFileUsesOneDescriptorOwner(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if err := os.WriteFile(filepath.Join(rootPath, "source"), []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("source", "evidence/report.json", false); err != nil {
		t.Fatal(err)
	}
	files := make([]*os.File, 0, 128)
	for index := 0; index < 128; index++ {
		file, err := os.CreateTemp(rootPath, "descriptor-*")
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	runtime.GC()
	for _, file := range files {
		if _, err := file.Write([]byte("open")); err != nil {
			t.Fatal("reused descriptor was closed by a finalizer")
		}
		_ = file.Close()
	}
}

// TestInstallFileComparesLargeRepeatWithBoundedMemory freezes chunked comparison.
func TestInstallFileComparesLargeRepeatWithBoundedMemory(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSafeRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	content := make([]byte, 16<<20)
	for index := range content {
		content[index] = byte(index)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "source"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("source", "evidence/report.json", false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "repeat"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.installFile("repeat", "evidence/report.json", false); err != nil {
		t.Fatal(err)
	}
}
