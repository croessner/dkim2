package reference

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHardenVendorTreeRelocatesMD4 proves the closed vendor transformation.
func TestHardenVendorTreeRelocatesMD4(t *testing.T) {
	t.Parallel()

	root := createVendorHardeningFixture(t)
	if err := HardenVendorTree(root); err != nil {
		t.Fatalf("HardenVendorTree() error = %v", err)
	}

	bind := readVendorFixture(t, root, "github.com/go-ldap/ldap/v3/bind.go")
	if strings.Contains(bind, "golang.org/x/crypto/md4") ||
		!strings.Contains(bind, `"github.com/go-ldap/ldap/v3/internal/md4"`) {
		t.Fatalf("bind.go import was not hardened:\n%s", bind)
	}
	modules := readVendorFixture(t, root, "modules.txt")
	if strings.Contains(modules, "\ngolang.org/x/crypto/md4\n") ||
		strings.Count(modules, vendorCryptoMetadata) != 1 ||
		!strings.Contains(modules, "github.com/go-ldap/ldap/v3/internal/md4\n") {
		t.Fatalf("modules.txt was not hardened:\n%s", modules)
	}
	for _, path := range []string{"LICENSE", "PATENTS", "md4.go", "md4block.go"} {
		want := "fixture-" + path
		if got := readVendorFixture(t, root, "github.com/go-ldap/ldap/v3/internal/md4/"+path); got != want {
			t.Fatalf("%s content = %q, want %q", path, got, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "vendor", "golang.org", "x", "crypto")); !os.IsNotExist(err) {
		t.Fatalf("golang.org/x/crypto remains after hardening: %v", err)
	}
}

// TestHardenVendorTreeRejectsUnexpectedCryptoFiles proves the transform fails
// closed before changing a vendor tree that does not match its reviewed shape.
func TestHardenVendorTreeRejectsUnexpectedCryptoFiles(t *testing.T) {
	t.Parallel()

	root := createVendorHardeningFixture(t)
	writeVendorFixture(t, root, "golang.org/x/crypto/openpgp/keys.go", "unexpected")
	before := readVendorFixture(t, root, "github.com/go-ldap/ldap/v3/bind.go")

	if err := HardenVendorTree(root); err == nil {
		t.Fatal("HardenVendorTree() error = nil, want rejection")
	}
	if after := readVendorFixture(t, root, "github.com/go-ldap/ldap/v3/bind.go"); after != before {
		t.Fatal("HardenVendorTree() changed bind.go before rejecting the tree")
	}
}

// TestInstallVendorTreeSwapsTrees proves generated vendor installation keeps
// the previous tree confined to invocation-owned ignored state.
func TestInstallVendorTreeSwapsTrees(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	work := filepath.Join(root, ".artifacts", "reference", ".module-proof.fixture")
	current := filepath.Join(root, "vendor")
	generated := filepath.Join(work, "vendor-output")
	writeVendorFixture(t, root, "current.txt", "current")
	if err := os.MkdirAll(generated, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "generated.txt"), []byte("generated"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := installVendorTree(root, generated); err != nil {
		t.Fatalf("installVendorTree() error = %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(current, "generated.txt")); err != nil ||
		string(content) != "generated" {
		t.Fatalf("installed content = %q, %v", content, err)
	}
	if content, err := os.ReadFile(filepath.Join(work, "vendor-previous", "current.txt")); err != nil ||
		string(content) != "current" {
		t.Fatalf("previous content = %q, %v", content, err)
	}
}

// createVendorHardeningFixture creates the exact reviewed upstream tree shape.
func createVendorHardeningFixture(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	writeVendorFixture(t, root, "github.com/go-ldap/ldap/v3/bind.go", `package ldap

import "golang.org/x/crypto/md4" //nolint:staticcheck
`)
	writeVendorFixture(t, root, "golang.org/x/crypto/LICENSE", "fixture-LICENSE")
	writeVendorFixture(t, root, "golang.org/x/crypto/PATENTS", "fixture-PATENTS")
	writeVendorFixture(t, root, "golang.org/x/crypto/md4/md4.go", "fixture-md4.go")
	writeVendorFixture(t, root, "golang.org/x/crypto/md4/md4block.go", "fixture-md4block.go")
	writeVendorFixture(t, root, "modules.txt", `# github.com/go-ldap/ldap/v3 v3.4.14
## explicit; go 1.25.0
github.com/go-ldap/ldap/v3
# golang.org/x/crypto v0.54.0
## explicit; go 1.25.0
golang.org/x/crypto/md4
`)
	return root
}

// writeVendorFixture writes one confined test-vendor file.
func writeVendorFixture(t *testing.T, root, relative, content string) {
	t.Helper()

	path := filepath.Join(root, "vendor", filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readVendorFixture reads one confined test-vendor file.
func readVendorFixture(t *testing.T, root, relative string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(root, "vendor", filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
