package valkey

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	replayRootModule        = "github.com/croessner/dkim2"
	valkeyClientModule      = "github.com/valkey-io/valkey-go"
	valkeyClientVersion     = "v1.0.76"
	valkeyClientModuleGo    = "go 1.25.0"
	valkeyLicenseSHA256     = "283ea6cc2997a1a70da0049e09adf9317bb60ca1b51279b65196b83a69e1996b"
	valkeyNoticeSHA256      = "41824cdce292fe84e7130615e322aae144fdb9e1d147c00ce901b92694fae02c"
	valkeyNoticeContent     = "valkey-go\nCopyright 2024 Rueian (https://github.com/rueian)\n"
	valkeyModuleSum         = "h1:Rcown7FFseVhG9b0+4MWfMs4xWu8otPzHjrsK044ET4="
	valkeyModuleFileSum     = "h1:6X581PhgfeMkJmyfjIsa2eFdq6dy3Qkkg9zwjM1p42M="
	valkeyProviderDirectory = "cmd/dkim2d/internal/replay/valkey"
	dkim2DaemonModule       = "cmd/dkim2d/go.mod"
	dkim2DaemonModuleSum    = "cmd/dkim2d/go.sum"
	dkim2WorkspaceFile      = "go.work"
	dkim2VendorModulesFile  = "vendor/modules.txt"
)

type replayModuleRequirement struct {
	path     string
	version  string
	indirect bool
}

// TestReplayValkeyDependencyBoundary proves the production import and reviewed
// dependency ownership contract from source, module, workspace, and vendor data.
func TestReplayValkeyDependencyBoundary(t *testing.T) {
	root := filepath.Clean("../../../../..")
	requireReplayProductionImports(t, root)
	requireValkeyProductionImportOwnership(t, root)
	requireValkeyModuleOwnership(t, root)
	requireValkeyVendorOwnership(t, root)
	requireValkeyLicenseEvidence(t, root)
}

// TestReplayDependencyClassifiers exercises exact matches, forbidden
// near-misses, and dependency-metadata mutations without changing the tree.
func TestReplayDependencyClassifiers(t *testing.T) {
	t.Run("imports", testReplayImportClassifier)
	t.Run("module requirements", testReplayModuleRequirementClassifier)
	t.Run("sums", testReplaySumClassifier)
	t.Run("vendor metadata", testReplayVendorClassifier)
}

// requireReplayProductionImports validates every production source import in
// the daemon-owned replay provider.
func requireReplayProductionImports(t *testing.T, root string) {
	t.Helper()
	seenRoot := false
	seenValkey := false
	providerRoot := filepath.Join(root, "cmd/dkim2d/internal/replay/valkey")
	for _, path := range productionGoFiles(t, providerRoot) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse production imports %q failed", filepath.Base(path))
		}
		for _, imported := range file.Imports {
			pathValue := strings.Trim(imported.Path.Value, `"`)
			if !allowedReplayProductionImport(pathValue) {
				t.Fatalf("production replay provider has unapproved import %q", pathValue)
			}
			seenRoot = seenRoot || pathValue == replayRootModule
			seenValkey = seenValkey || pathValue == valkeyClientModule
		}
	}
	if !seenRoot || !seenValkey {
		t.Fatal("production replay provider does not exercise both approved external boundaries")
	}
}

// requireValkeyProductionImportOwnership proves no production package outside
// the daemon-owned replay provider imports the client or its internal packages.
func requireValkeyProductionImportOwnership(t *testing.T, root string) {
	t.Helper()
	seen := 0
	for _, sourceRoot := range []string{filepath.Join(root, "cmd"), filepath.Join(root, "lib")} {
		for _, path := range productionGoFiles(t, sourceRoot) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse repository production imports %q failed", filepath.Base(path))
			}
			relative, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				t.Fatal("production import owner is not repository-relative")
			}
			for _, imported := range file.Imports {
				pathValue := strings.Trim(imported.Path.Value, `"`)
				if pathValue != valkeyClientModule &&
					!strings.HasPrefix(pathValue, valkeyClientModule+"/") {
					continue
				}
				if !approvedValkeyImportOwner(filepath.ToSlash(relative), pathValue) {
					t.Fatalf("unapproved production Valkey import owner %q", filepath.ToSlash(relative))
				}
				seen++
			}
		}
	}
	if seen == 0 {
		t.Fatal("production Valkey import ownership proof found no client import")
	}
}

// approvedValkeyImportOwner recognizes only the exact provider directory and
// public client package reviewed for production use.
func approvedValkeyImportOwner(relativeDirectory, importPath string) bool {
	return relativeDirectory == valkeyProviderDirectory &&
		importPath == valkeyClientModule
}

// allowedReplayProductionImport reports whether an import is standard library
// or one of the two exact replay-provider boundaries.
func allowedReplayProductionImport(importPath string) bool {
	if importPath == "" || strings.ContainsAny(importPath, " \t\r\n\\") {
		return false
	}
	if importPath == replayRootModule || importPath == valkeyClientModule {
		return true
	}
	pkg, err := build.Default.Import(importPath, ".", build.FindOnly)
	return err == nil && pkg.Goroot
}

// requireValkeyModuleOwnership proves only the daemon module owns the exact
// direct client version and checksum pair.
func requireValkeyModuleOwnership(t *testing.T, root string) {
	t.Helper()
	modulePaths, err := filepath.Glob(filepath.Join(root, "cmd", "*", "go.mod"))
	if err != nil {
		t.Fatal("module discovery failed")
	}
	modulePaths = append(modulePaths, filepath.Join(root, "lib/go.mod"))
	modulePaths = slices.Compact(modulePaths)
	owners := make([]string, 0, 1)
	for _, modulePath := range modulePaths {
		content := readPolicyFile(t, modulePath)
		isOwner := filepath.ToSlash(modulePath) ==
			filepath.ToSlash(filepath.Join(root, dkim2DaemonModule))
		if !validValkeyModuleDeclaration(content, isOwner) {
			t.Fatalf("unreviewed Valkey dependency declaration in %q", filepath.ToSlash(modulePath))
		}
		if isOwner {
			owners = append(owners, filepath.ToSlash(modulePath))
		}
	}
	wantOwner := filepath.ToSlash(filepath.Join(root, dkim2DaemonModule))
	if !slices.Equal(owners, []string{wantOwner}) {
		t.Fatalf("Valkey dependency owners=%v", owners)
	}

	workspace := readPolicyFile(t, filepath.Join(root, dkim2WorkspaceFile))
	if exactModuleTokenCount(workspace, valkeyClientModule) != 0 {
		t.Fatal("workspace metadata attempts to own or replace the Valkey module")
	}
	sums := readPolicyFile(t, filepath.Join(root, dkim2DaemonModuleSum))
	if !validValkeySums(sums) {
		t.Fatal("daemon Valkey module checksums are missing or drifted")
	}
}

// validValkeyModuleDeclaration requires one exact direct declaration from its
// owner and rejects every Valkey token, including replace directives, elsewhere.
func validValkeyModuleDeclaration(content string, owner bool) bool {
	requirements, valid := parseReplayModuleRequirements(content)
	if !valid {
		return false
	}
	matches := make([]replayModuleRequirement, 0, 1)
	for _, requirement := range requirements {
		if requirement.path == valkeyClientModule {
			matches = append(matches, requirement)
		}
	}
	if !owner {
		return len(matches) == 0 && exactModuleTokenCount(content, valkeyClientModule) == 0
	}
	return len(matches) == 1 &&
		matches[0] == (replayModuleRequirement{
			path: valkeyClientModule, version: valkeyClientVersion,
		}) &&
		exactModuleTokenCount(content, valkeyClientModule) == 1
}

// parseReplayModuleRequirements extracts require directives while rejecting
// malformed require blocks that could hide dependency ownership.
func parseReplayModuleRequirements(content string) ([]replayModuleRequirement, bool) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	requirements := make([]replayModuleRequirement, 0, 8)
	inBlock := false
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		code, comment, _ := strings.Cut(raw, "//")
		code = strings.TrimSpace(code)
		comment = strings.TrimSpace(comment)
		if code == "" {
			continue
		}
		if code == "require (" {
			if inBlock {
				return nil, false
			}
			inBlock = true
			continue
		}
		if code == ")" {
			if !inBlock {
				continue
			}
			inBlock = false
			continue
		}
		fields := strings.Fields(code)
		if inBlock {
			if len(fields) != 2 {
				return nil, false
			}
			requirements = append(requirements, replayModuleRequirement{
				path: fields[0], version: fields[1], indirect: comment == "indirect",
			})
			continue
		}
		if len(fields) > 0 && fields[0] == "require" {
			if len(fields) != 3 {
				return nil, false
			}
			requirements = append(requirements, replayModuleRequirement{
				path: fields[1], version: fields[2], indirect: comment == "indirect",
			})
		}
	}
	return requirements, scanner.Err() == nil && !inBlock
}

// exactModuleTokenCount counts one module path only as a complete metadata
// token, so similarly named dependencies remain distinguishable.
func exactModuleTokenCount(content, modulePath string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		for field := range strings.FieldsSeq(scanner.Text()) {
			if field == modulePath {
				count++
			}
		}
	}
	return count
}

// validValkeySums recognizes exactly the reviewed module and module-file
// checksum records while ignoring unrelated dependency sums.
func validValkeySums(content string) bool {
	expected := []string{
		valkeyClientModule + " " + valkeyClientVersion + " " + valkeyModuleSum,
		valkeyClientModule + " " + valkeyClientVersion + "/go.mod " + valkeyModuleFileSum,
	}
	found := make([]string, 0, len(expected))
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == valkeyClientModule {
			found = append(found, line)
		}
	}
	slices.Sort(found)
	slices.Sort(expected)
	return scanner.Err() == nil && slices.Equal(found, expected)
}

// requireValkeyVendorOwnership proves workspace vendor metadata records one
// exact explicit client module and only its expected compiled packages.
func requireValkeyVendorOwnership(t *testing.T, root string) {
	t.Helper()
	content := readPolicyFile(t, filepath.Join(root, dkim2VendorModulesFile))
	if !validValkeyVendorSection(content) {
		t.Fatal("workspace vendor metadata for Valkey is missing or drifted")
	}
}

// validValkeyVendorSection validates the reviewed module header, Go version,
// and compiled package set without depending on unrelated vendor sections.
func validValkeyVendorSection(content string) bool {
	header := "# " + valkeyClientModule + " " + valkeyClientVersion
	lines := strings.Split(content, "\n")
	sectionStarts := make([]int, 0, 1)
	for index, line := range lines {
		if strings.HasPrefix(line, "# "+valkeyClientModule+" ") {
			sectionStarts = append(sectionStarts, index)
		}
	}
	if len(sectionStarts) != 1 || lines[sectionStarts[0]] != header {
		return false
	}
	start := sectionStarts[0]
	if start+1 >= len(lines) || lines[start+1] != "## explicit; "+valkeyClientModuleGo {
		return false
	}
	packages := make([]string, 0, 3)
	for index := start + 2; index < len(lines) && !strings.HasPrefix(lines[index], "# "); index++ {
		if lines[index] != "" {
			packages = append(packages, lines[index])
		}
	}
	want := []string{
		valkeyClientModule,
		valkeyClientModule + "/internal/cmds",
		valkeyClientModule + "/internal/util",
	}
	return slices.Equal(packages, want)
}

// requireValkeyLicenseEvidence proves the vendored Apache-2.0 license and
// upstream attribution notice are the reviewed v1.0.76 artifacts.
func requireValkeyLicenseEvidence(t *testing.T, root string) {
	t.Helper()
	dependencyRoot := filepath.Join(root, "vendor/github.com/valkey-io/valkey-go")
	license := readPolicyBytes(t, filepath.Join(dependencyRoot, "LICENSE"))
	notice := readPolicyBytes(t, filepath.Join(dependencyRoot, "NOTICE"))
	if sha256Hex(license) != valkeyLicenseSHA256 ||
		!strings.HasPrefix(string(license), "Apache License\n") ||
		!strings.Contains(string(license), "Version 2.0, January 2004") {
		t.Fatal("vendored Valkey Apache-2.0 license is missing or drifted")
	}
	if sha256Hex(notice) != valkeyNoticeSHA256 || string(notice) != valkeyNoticeContent {
		t.Fatal("vendored Valkey attribution notice is missing or drifted")
	}
}

// readPolicyBytes loads one dependency artifact without rendering its content.
func readPolicyBytes(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("dependency artifact %q is unreadable", filepath.Base(path))
	}
	return content
}

// sha256Hex returns the lowercase digest used for exact dependency evidence.
func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// testReplayImportClassifier proves exact external boundaries and near-miss
// paths remain distinct.
func testReplayImportClassifier(t *testing.T) {
	t.Helper()
	allowed := []string{"context", "crypto/tls", replayRootModule, valkeyClientModule}
	for _, imported := range allowed {
		if !allowedReplayProductionImport(imported) {
			t.Fatalf("approved import rejected: %q", imported)
		}
	}
	forbidden := []string{
		"",
		replayRootModule + "/internal/replay",
		replayRootModule + "x",
		valkeyClientModule + "/internal/cmds",
		valkeyClientModule + "-extra",
		"corp/replay",
		"example/provider",
		"example.com/context",
		"github/com/valkey-io/valkey-go",
		"private/pkg",
		"context\\internal\\replay",
	}
	for _, imported := range forbidden {
		if allowedReplayProductionImport(imported) {
			t.Fatalf("unapproved import accepted: %q", imported)
		}
	}
	owners := []struct {
		directory string
		imported  string
		allowed   bool
	}{
		{valkeyProviderDirectory, valkeyClientModule, true},
		{"cmd/dkim2d/internal/replay/other", valkeyClientModule, false},
		{valkeyProviderDirectory, valkeyClientModule + "/internal/cmds", false},
		{"lib/internal/replay", valkeyClientModule, false},
		{"cmd/dkim2d/internal/replay/valkeyish", valkeyClientModule, false},
	}
	for _, owner := range owners {
		if approvedValkeyImportOwner(owner.directory, owner.imported) != owner.allowed {
			t.Fatalf("Valkey import owner classification drifted for %q", owner.directory)
		}
	}
}

// testReplayModuleRequirementClassifier proves direct, indirect, version, and
// similarly named module declarations are classified independently.
func testReplayModuleRequirementClassifier(t *testing.T) {
	t.Helper()
	content := "require (\n\t" + valkeyClientModule + " " + valkeyClientVersion + "\n" +
		"\t" + valkeyClientModule + "-extra v1.0.76\n)\n"
	requirements, valid := parseReplayModuleRequirements(content)
	if !valid || len(requirements) != 2 ||
		requirements[0] != (replayModuleRequirement{
			path: valkeyClientModule, version: valkeyClientVersion,
		}) {
		t.Fatal("exact direct module requirement was not classified")
	}
	if !validValkeyModuleDeclaration(content, true) ||
		validValkeyModuleDeclaration(content, false) {
		t.Fatal("exact module ownership declaration was not classified")
	}
	mutations := []string{
		"require " + valkeyClientModule + " v1.0.75\n",
		"require " + valkeyClientModule + " " + valkeyClientVersion + " // indirect\n",
		"require " + valkeyClientModule + " " + valkeyClientVersion +
			"\nreplace " + valkeyClientModule + " => ../local\n",
		"require (\n" + valkeyClientModule + "\n)\n",
	}
	for _, mutation := range mutations {
		if validValkeyModuleDeclaration(mutation, true) {
			t.Fatal("mutated module requirement retained exact ownership")
		}
	}
	nearMiss := "require " + valkeyClientModule + "-extra " + valkeyClientVersion + "\n"
	if !validValkeyModuleDeclaration(nearMiss, false) {
		t.Fatal("similarly named module was treated as the reviewed dependency")
	}
}

// testReplaySumClassifier proves missing, duplicate, version-drifted, and
// similarly named checksum records cannot satisfy the reviewed pair.
func testReplaySumClassifier(t *testing.T) {
	t.Helper()
	valid := valkeyClientModule + " " + valkeyClientVersion + " " + valkeyModuleSum + "\n" +
		valkeyClientModule + " " + valkeyClientVersion + "/go.mod " + valkeyModuleFileSum + "\n" +
		valkeyClientModule + "-extra v1.0.76 h1:near-miss\n"
	if !validValkeySums(valid) {
		t.Fatal("reviewed checksum pair rejected")
	}
	mutations := []string{
		strings.Replace(valid, valkeyModuleSum, "h1:mutated", 1),
		strings.Replace(valid, valkeyClientVersion+"/go.mod", "v1.0.75/go.mod", 1),
		valid + valkeyClientModule + " " + valkeyClientVersion + " " + valkeyModuleSum + "\n",
	}
	for _, mutation := range mutations {
		if validValkeySums(mutation) {
			t.Fatal("mutated checksum evidence accepted")
		}
	}
}

// testReplayVendorClassifier proves exact header, metadata, package ownership,
// and similarly named module separation.
func testReplayVendorClassifier(t *testing.T) {
	t.Helper()
	valid := "# " + valkeyClientModule + "-extra v1.0.76\n## explicit; go 1.25.0\n" +
		valkeyClientModule + "-extra\n" +
		"# " + valkeyClientModule + " " + valkeyClientVersion + "\n" +
		"## explicit; " + valkeyClientModuleGo + "\n" +
		valkeyClientModule + "\n" +
		valkeyClientModule + "/internal/cmds\n" +
		valkeyClientModule + "/internal/util\n" +
		"# example.com/next v1.0.0\n"
	if !validValkeyVendorSection(valid) {
		t.Fatal("reviewed vendor section rejected")
	}
	exactHeaderAndMetadata := "# " + valkeyClientModule + " " + valkeyClientVersion +
		"\n## explicit; " + valkeyClientModuleGo
	mutations := []string{
		strings.Replace(
			valid,
			"# "+valkeyClientModule+" "+valkeyClientVersion,
			"# "+valkeyClientModule+" v1.0.75",
			1,
		),
		strings.Replace(
			valid,
			exactHeaderAndMetadata,
			"# "+valkeyClientModule+" "+valkeyClientVersion+"\n## explicit; go 1.24.0",
			1,
		),
		strings.Replace(valid, valkeyClientModule+"/internal/util\n", "", 1),
		valid + "# " + valkeyClientModule + " " + valkeyClientVersion + "\n",
	}
	for _, mutation := range mutations {
		if validValkeyVendorSection(mutation) {
			t.Fatal("mutated vendor ownership accepted")
		}
	}
}
