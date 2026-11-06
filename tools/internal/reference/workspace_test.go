package reference

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeWorkspaceSums creates every allowlisted checksum file below root with
// one stale candidate line and one unrelated dependency line.
func writeWorkspaceSums(t *testing.T, root string) {
	t.Helper()
	for _, path := range workspaceMetadataPaths {
		if !strings.HasSuffix(path, ".sum") {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		content := "github.com/croessner/dkim2 " + candidateVersion + " h1:stale=\n" +
			"github.com/croessner/dkim2 " + candidateVersion + "/go.mod h1:metadata=\n" +
			"golang.org/x/net v0.61.0 h1:unrelated=\n"
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRefreshCandidateSumsRewritesOnlyTheCandidateZipLine proves the refresh
// replaces exactly the candidate zip checksum and leaves every other line.
func TestRefreshCandidateSumsRewritesOnlyTheCandidateZipLine(t *testing.T) {
	root := t.TempDir()
	writeWorkspaceSums(t, root)
	proof := ModuleProof{Modules: []ModuleIdentity{
		{Path: "github.com/croessner/dkim2", Version: candidateVersion, Mode: "zip", H1: "h1:fresh="},
		{Path: "golang.org/x/net", Version: "v0.61.0", Mode: "zip", H1: "h1:other="},
	}}
	if err := refreshCandidateSums(root, proof); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "cmd", "dkim2d", "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	want := "github.com/croessner/dkim2 " + candidateVersion + " h1:fresh=\n" +
		"github.com/croessner/dkim2 " + candidateVersion + "/go.mod h1:metadata=\n" +
		"golang.org/x/net v0.61.0 h1:unrelated=\n"
	if string(content) != want {
		t.Fatalf("refreshed checksum file = %q", content)
	}
}

// TestRefreshCandidateSumsFailsClosedWithoutCandidateIdentity rejects proofs
// that do not carry the exact candidate zip identity.
func TestRefreshCandidateSumsFailsClosedWithoutCandidateIdentity(t *testing.T) {
	root := t.TempDir()
	writeWorkspaceSums(t, root)
	for _, proof := range []ModuleProof{
		{},
		{Modules: []ModuleIdentity{{Path: "github.com/croessner/dkim2", Version: "v0.0.1", Mode: "zip", H1: "h1:x="}}},
		{Modules: []ModuleIdentity{{Path: "github.com/croessner/dkim2", Version: candidateVersion, Mode: "mod", H1: "h1:x="}}},
		{Modules: []ModuleIdentity{{Path: "github.com/croessner/dkim2", Version: candidateVersion, Mode: "zip", H1: "x"}}},
	} {
		if err := refreshCandidateSums(root, proof); err == nil {
			t.Fatalf("refreshCandidateSums accepted proof %#v", proof)
		}
	}
}
