//go:build moduleproof

package reference

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The private proxy reconstruction reads every committed module go.mod and
// vendored module zip from the host module cache with the network disabled.
// That cache is host-provisioned state, so this test runs only in the
// module-proof gate (make test-module-proof, required by make check-reference)
// and stays out of the hermetic tools-module test gate.

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
