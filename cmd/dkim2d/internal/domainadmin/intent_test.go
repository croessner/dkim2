package domainadmin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadIntentAcceptsCanonicalDocument freezes the closed operator boundary.
func TestLoadIntentAcceptsCanonicalDocument(t *testing.T) {
	path := writeIntentFixture(t, ""+
		"version: dkim2-domain-intent-v1\n"+
		"domain: example.test\n"+
		"tenant_id: outbound\n"+
		"profile_use: originator\n"+
		"algorithms:\n  - ed25519-sha256\n  - rsa-sha256\n"+
		"rollout: enforce\ncompatibility: strict\n")
	intent, err := LoadIntent(path)
	if err != nil || intent.Domain() != testAdminDomain || len(intent.Algorithms()) != 2 {
		t.Fatalf("canonical intent rejected: %v", err)
	}
}

// TestLoadIntentNormalizesAlgorithmOrder freezes digest-order independence.
func TestLoadIntentNormalizesAlgorithmOrder(t *testing.T) {
	path := writeIntentFixture(t, "version: dkim2-domain-intent-v1\ndomain: example.test\ntenant_id: outbound\nprofile_use: originator\nalgorithms: [rsa-sha256, ed25519-sha256]\nrollout: enforce\ncompatibility: strict\n")
	intent, err := LoadIntent(path)
	algorithms := intent.Algorithms()
	if err != nil || len(algorithms) != 2 || string(algorithms[0]) != "ed25519-sha256" || string(algorithms[1]) != "rsa-sha256" {
		t.Fatal("operator ordering affected canonical intent")
	}
}

// TestLoadIntentRejectsClosedInputFailures covers stable parser and path abuse.
func TestLoadIntentRejectsClosedInputFailures(t *testing.T) {
	cases := map[string]string{
		"unknown field":       "extra: denied\n",
		"duplicate algorithm": "algorithms:\n  - rsa-sha256\n  - rsa-sha256\n",
		"alias":               "domain: &d example.test\ntenant_id: outbound\nprofile_use: originator\nalgorithms: [rsa-sha256]\nrollout: enforce\ncompatibility: strict\ncopy: *d\n",
		"merge":               "defaults: &d {rollout: enforce}\n<<: *d\n",
		"trailing":            "---\nversion: second\n",
	}
	base := "version: dkim2-domain-intent-v1\ndomain: example.test\ntenant_id: outbound\nprofile_use: originator\nalgorithms: [rsa-sha256]\nrollout: enforce\ncompatibility: strict\n"
	for name, suffix := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadIntent(writeIntentFixture(t, base+suffix)); CodeOf(err) == CodeNone {
				t.Fatal("invalid intent accepted")
			}
		})
	}
}

// TestLoadIntentRejectsPathAndSizeAbuse covers path traversal and exact size fences.
func TestLoadIntentRejectsPathAndSizeAbuse(t *testing.T) {
	canonical := "version: dkim2-domain-intent-v1\ndomain: example.test\ntenant_id: outbound\nprofile_use: originator\nalgorithms: [rsa-sha256]\nrollout: enforce\ncompatibility: strict\n"
	path := writeIntentFixture(t, canonical)
	for _, invalid := range []string{"relative.yaml", filepath.Dir(path) + "/./intent.yaml"} {
		if _, err := LoadIntent(invalid); CodeOf(err) != CodeProtectedInput {
			t.Fatal("noncanonical path accepted")
		}
	}
	if err := os.Chmod(filepath.Dir(path), 0o770); err != nil {
		t.Fatal("change parent mode")
	}
	if _, err := LoadIntent(path); CodeOf(err) != CodeProtectedInput {
		t.Fatal("unsafe parent accepted")
	}
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal("create protected parent")
	}
	realPath := filepath.Join(realParent, "intent.yaml")
	if err := os.WriteFile(realPath, []byte(canonical), 0o600); err != nil {
		t.Fatal("write linked-parent fixture")
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal("create parent symlink")
	}
	if _, err := LoadIntent(filepath.Join(linkedParent, "intent.yaml")); CodeOf(err) != CodeProtectedInput {
		t.Fatal("symlinked parent accepted")
	}
	empty := writeIntentFixture(t, "x")
	if err := os.Truncate(empty, 0); err != nil {
		t.Fatal("truncate fixture")
	}
	if _, err := LoadIntent(empty); CodeOf(err) != CodeProtectedInput {
		t.Fatal("empty document accepted by protected reader")
	}
	limit := int(DefaultLimits().MaxDocumentBytes)
	exact := writeIntentFixture(t, protectedCommentPadding(limit-len(canonical))+canonical)
	if _, err := LoadIntent(exact); err != nil {
		t.Fatal("exact document cap rejected")
	}
	over := writeIntentFixture(t, protectedCommentPadding(limit-len(canonical)+1)+canonical)
	if _, err := LoadIntent(over); CodeOf(err) != CodeProtectedInput {
		t.Fatal("over-cap document accepted")
	}
}

// protectedCommentPadding constructs exact-size bounded YAML comments.
func protectedCommentPadding(length int) string {
	if length < 2 {
		return strings.Repeat(" ", length)
	}
	if length%2 == 0 {
		return strings.Repeat("#\n", length/2)
	}
	return "##\n" + strings.Repeat("#\n", (length-3)/2)
}

// TestIntentYAMLNodeBoundary freezes the exact maximum tree size.
func TestIntentYAMLNodeBoundary(t *testing.T) {
	atLimit := "[" + strings.Repeat("x,", 125) + "x]"
	if err := validateIntentYAML([]byte(atLimit)); err != nil {
		t.Fatal("exact YAML node cap rejected")
	}
	overLimit := "[" + strings.Repeat("x,", 126) + "x]"
	if err := validateIntentYAML([]byte(overLimit)); CodeOf(err) != CodeInvalidIntent {
		t.Fatal("YAML node cap exceeded without rejection")
	}
}

// TestLoadIntentRejectsFilesystemAbuse freezes no-link and owner-only input.
func TestLoadIntentRejectsFilesystemAbuse(t *testing.T) {
	path := writeIntentFixture(t, "version: dkim2-domain-intent-v1\n")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal("change fixture mode")
	}
	if _, err := LoadIntent(path); CodeOf(err) != CodeProtectedInput {
		t.Fatal("unsafe mode accepted")
	}
	root := filepath.Dir(path)
	link := filepath.Join(root, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("create symlink")
	}
	if _, err := LoadIntent(link); CodeOf(err) != CodeProtectedInput {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal("restore fixture mode")
	}
	hard := filepath.Join(root, "hard.yaml")
	if err := os.Link(path, hard); err != nil {
		t.Fatal("create hard link")
	}
	if _, err := LoadIntent(path); CodeOf(err) != CodeProtectedInput {
		t.Fatal("hard link accepted")
	}
}

// writeIntentFixture writes one owner-only fixture beneath an owner-only directory.
func writeIntentFixture(t *testing.T, document string) string {
	t.Helper()
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal("resolve fixture directory")
	}
	root = resolved
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("protect fixture directory")
	}
	path := filepath.Join(root, "intent.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal("write fixture")
	}
	return path
}
