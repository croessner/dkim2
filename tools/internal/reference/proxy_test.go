package reference

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCandidateModuleMetadataSumBindsExactSource permits only the generated local module metadata.
func TestCandidateModuleMetadataSumBindsExactSource(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), "lib/go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	line, err := candidateModuleMetadataSum(content)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := candidateModuleMetadataSum(append(append([]byte(nil), content...), '\n'))
	if err != nil || line == changed {
		t.Fatal("metadata digest ignored changed bytes")
	}
	allowed := map[string]bool{line: true}
	if !moduleSumSubset(nil, []byte(line+"\n"), allowed) {
		t.Fatal("candidate metadata rejected")
	}
	for _, hostile := range []string{changed, strings.Replace(line, "/go.mod", "", 1), strings.Replace(line, "croessner/dkim2", "attacker/other", 1)} {
		if moduleSumSubset(nil, []byte(hostile+"\n"), allowed) {
			t.Fatal("unbound checksum admitted")
		}
	}
}

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

// TestModuleDownloadCacheFollowsGoCommandDefaults binds both proxy cache reads to one location rule.
func TestModuleDownloadCacheFollowsGoCommandDefaults(t *testing.T) {
	home := t.TempDir()
	gopath := t.TempDir()
	modules := t.TempDir()
	for _, test := range []struct {
		gomodcache string
		gopath     string
		home       string
		want       string
	}{
		{gomodcache: modules, gopath: gopath, home: home, want: filepath.Join(modules, "cache", "download")},
		{gopath: gopath + string(filepath.ListSeparator) + home, home: home, want: filepath.Join(gopath, "pkg", "mod", "cache", "download")},
		{home: home, want: filepath.Join(home, "go", "pkg", "mod", "cache", "download")},
	} {
		t.Setenv("GOMODCACHE", test.gomodcache)
		t.Setenv("GOPATH", test.gopath)
		t.Setenv("HOME", test.home)
		got, err := moduleDownloadCache()
		if err != nil || got != test.want {
			t.Fatalf("module download cache = %q, %v; want %q", got, err, test.want)
		}
	}
	for _, hostile := range []struct{ gomodcache, gopath, home string }{
		{gomodcache: "relative/mod"},
		{gopath: "relative/gopath"},
		{},
	} {
		t.Setenv("GOMODCACHE", hostile.gomodcache)
		t.Setenv("GOPATH", hostile.gopath)
		t.Setenv("HOME", hostile.home)
		if _, err := moduleDownloadCache(); err == nil {
			t.Fatalf("ambiguous module cache location %+v was accepted", hostile)
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
