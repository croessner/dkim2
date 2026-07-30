package reference

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidModuleRelativePathRejectsHostileTrees proves path confinement.
func TestValidModuleRelativePathRejectsHostileTrees(t *testing.T) {
	for _, value := range []string{"", "../escape", "a/../../escape", "/absolute", `a\b`, ".git/config", "temp/key", ".artifacts/report", "a//b"} {
		if validModuleRelativePath(value) {
			t.Fatalf("validModuleRelativePath(%q) accepted hostile value", value)
		}
	}
	for _, value := range []string{"go.mod", "internal/parser/parser.go", "testdata/vector.json"} {
		if !validModuleRelativePath(value) {
			t.Fatalf("validModuleRelativePath(%q) rejected safe value", value)
		}
	}
}

// TestActiveLocalProxyRejectsCallerSelectedAndLinkedRoots prevents proxy laundering.
func TestActiveLocalProxyRejectsCallerSelectedAndLinkedRoots(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(directory))
	if _, err := activeLocalProxyRoot(); err == nil {
		t.Fatal("caller-selected file proxy was accepted as proof-owned")
	}
	t.Setenv("GOPROXY", "https://proxy.invalid")
	if _, err := activeLocalProxyRoot(); err == nil {
		t.Fatal("network proxy was accepted as proof-owned")
	}
}

// TestRemoveProofWorkRejectsUnownedPaths protects cleanup confinement.
func TestRemoveProofWorkRejectsUnownedPaths(t *testing.T) {
	directory := t.TempDir()
	if err := removeProofWork(directory); err == nil {
		t.Fatal("cleanup accepted a caller-selected directory")
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatal("rejected cleanup changed the caller-selected directory")
	}
}

// TestReadStableRegularRejectsLinkedPaths proves module inputs are opened without link traversal.
func TestReadStableRegularRejectsLinkedPaths(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("module"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableRegular(link, 64); err == nil {
		t.Fatal("descriptor-safe module read followed a symlink")
	}
}

// TestBuildPrivateProxyIsDeterministicAndConfined verifies exact repeatability.
func TestBuildPrivateProxyIsDeterministicAndConfined(t *testing.T) {
	first, firstPath, firstCleanup, err := BuildPrivateProxy(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, secondCleanup, err := BuildPrivateProxy(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if first.ProxySHA256 != second.ProxySHA256 || first.Modules[0] != second.Modules[0] {
		t.Fatal("identical candidate produced different private proxy evidence")
	}
	if firstPath == secondPath || !strings.Contains(firstPath, ".artifacts/reference/.module-proof.") {
		t.Fatal("proxy was not invocation-owned")
	}
	archive := filepath.Join(firstPath, "github.com/croessner/dkim2/@v/v0.1.0-rc.1.zip")
	reader, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	for _, file := range reader.File {
		if strings.Contains(file.Name, "/cmd/") || strings.Contains(file.Name, "/temp/") ||
			strings.Contains(file.Name, "/.artifacts/") || strings.Contains(file.Name, "/.git/") {
			t.Fatalf("candidate module zip admitted forbidden path %q", file.Name)
		}
	}
	info, err := os.Stat(firstPath)
	if err != nil || info.Mode().Perm() != 0o500 {
		t.Fatal("private proxy is not read-only")
	}
	firstWork := filepath.Dir(firstPath)
	secondWork := filepath.Dir(secondPath)
	if err := firstCleanup(); err != nil {
		t.Fatal(err)
	}
	if err := secondCleanup(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{firstWork, secondWork} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("invocation-owned proxy work survived cleanup: %s", path)
		}
	}
}

// FuzzLoadModuleProof proves hostile proof bytes remain bounded and panic-free.
func FuzzLoadModuleProof(f *testing.F) {
	f.Add([]byte(`{"schema":"dkim2.module-proof.v1"}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if len(input) > 1<<20+1 {
			input = input[:1<<20+1]
		}
		_, _ = LoadModuleProof(input)
	})
}
