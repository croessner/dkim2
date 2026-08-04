package externalvectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckRepositoryValidatesPinnedPublicCorpus proves the repository ships the reviewed bytes unchanged.
func TestCheckRepositoryValidatesPinnedPublicCorpus(t *testing.T) {
	if err := CheckRepository(repositoryRoot(t)); err != nil {
		t.Fatalf("CheckRepository() error = %v", err)
	}
}

// TestCheckRepositoryRejectsCorpusTampering proves that the retained layout is a closed public-only inventory.
func TestCheckRepositoryRejectsCorpusTampering(t *testing.T) {
	for name, tamper := range map[string]func(*testing.T, string){
		"unlisted private key": func(t *testing.T, directory string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(directory, "messages", "private-key.pem"), []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"), 0o600); err != nil {
				t.Fatal("WriteFile() failed")
			}
		},
		"hard linked fixture": func(t *testing.T, directory string) {
			t.Helper()
			source := filepath.Join(directory, "messages", "algorithm_misnamed.signed")
			target := filepath.Join(directory, "messages", "algorithm_misnamed-copy.signed")
			if err := os.Link(source, target); err != nil {
				t.Fatal("Link() failed")
			}
		},
		"altered provenance": func(t *testing.T, directory string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(directory, "UPSTREAM.md"), []byte("altered\n"), 0o600); err != nil {
				t.Fatal("WriteFile() failed")
			}
		},
		"altered fixture": func(t *testing.T, directory string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(directory, "messages", "algorithm_misnamed.signed"), []byte("altered\n"), 0o600); err != nil {
				t.Fatal("WriteFile() failed")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := copyCorpusRepository(t)
			base := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(ManifestPath, "/manifest.json")))
			tamper(t, base)
			if err := CheckRepository(root); err == nil {
				t.Fatal("CheckRepository() accepted tampered corpus")
			}
		})
	}
}

// TestContainsPrivateKeyRejectsCommonPEMForms keeps private-key filtering independent of one key algorithm.
func TestContainsPrivateKeyRejectsCommonPEMForms(t *testing.T) {
	for _, content := range [][]byte{
		[]byte("-----BEGIN RSA PRIVATE KEY-----\n"),
		[]byte("-----BEGIN EC PRIVATE KEY-----\n"),
		[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
	} {
		if !containsPrivateKey(content) {
			t.Fatal("containsPrivateKey() accepted a private-key marker")
		}
	}
}

// TestLoadManifestRejectsUnsafeOrMisclassifiedCases freezes the closed external-corpus vocabulary.
func TestLoadManifestRejectsUnsafeOrMisclassifiedCases(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), ManifestPath))
	if err != nil {
		t.Fatal("ReadFile() failed")
	}
	for name, mutation := range map[string]func(string) string{
		"unknown disposition": func(value string) string {
			return strings.Replace(value, "upstream_fixture_nonconformant", "equivalent", 1)
		},
		"private path": func(value string) string {
			return strings.Replace(value, "messages/algorithm_misnamed.orig", "messages/private-key.pem", 1)
		},
		"draft confusion": func(value string) string {
			return strings.Replace(value, "draft-ietf-dkim-dkim2-spec-02", "draft-ietf-dkim-dkim2-spec-04", 1)
		},
		"unexpected member": func(value string) string {
			return strings.Replace(value, "{\n  \"schema\"", "{\n  \"unexpected\": true,\n  \"schema\"", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadManifest([]byte(mutation(string(content)))); err == nil {
				t.Fatal("LoadManifest() accepted invalid manifest")
			}
		})
	}
}

// repositoryRoot returns the repository root from this package's stable source location.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal("Abs() failed")
	}
	return root
}

// copyCorpusRepository copies only the fixed corpus subtree into an isolated repository-shaped root.
func copyCorpusRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(repositoryRoot(t), filepath.FromSlash(strings.TrimSuffix(ManifestPath, "/manifest.json")))
	target := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(ManifestPath, "/manifest.json")))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal("MkdirAll() failed")
	}
	if err := os.CopyFS(target, os.DirFS(source)); err != nil {
		t.Fatal("CopyFS() failed")
	}
	return root
}
