package redisstore

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
	replayRootModule       = "github.com/croessner/dkim2"
	redisClientModule      = "github.com/redis/go-redis/v9"
	redisClientVersion     = "v9.22.0"
	redisClientModuleGo    = "go 1.24"
	redisLicenseSHA256     = "a3a7dff87da3927db65cb4c87b1cfbc96ca2755704461a485d457be7ae300a86"
	redisModuleSum         = "h1:laDvpYXTJtZLloinw1fA5Kqd6HAEH2XKxOkG/PDq2F0="
	redisModuleFileSum     = "h1:y2g0Wj8rQvuK0ELM+oxSudcLtC09JScs98I/X9gRWY4="
	atomicModule           = "go.uber.org/atomic"
	atomicVersion          = "v1.11.0"
	atomicLicenseSHA256    = "edbb5a4d165ac69376c765b551c0662ff42bea87e1f1eda85f42ac90c34b09d0"
	redisProviderDirectory = "cmd/dkim2d/internal/replay/redisstore"
	redisGrammarPackage    = "github.com/croessner/dkim2/cmd/dkim2d/internal/replay/redisgrammar"
	daemonModuleFile       = "cmd/dkim2d/go.mod"
	daemonModuleSumFile    = "cmd/dkim2d/go.sum"
	workspaceFile          = "go.work"
	vendorModulesFile      = "vendor/modules.txt"
)

// approvedRedisImports are the only go-redis packages production code may import.
var approvedRedisImports = []string{redisClientModule, redisClientModule + "/maintnotifications"}

// TestRedisDependencyBoundary proves the reviewed go-redis ownership contract
// from source imports, module metadata, checksums, vendor data, and licenses.
func TestRedisDependencyBoundary(t *testing.T) {
	root := filepath.Clean("../../../../..")
	requireProviderImports(t, root)
	requireRedisImportOwnership(t, root)
	requireRedisModuleOwnership(t, root)
	requireRedisVendorSection(t, root)
	requireLicenseEvidence(t, root)
}

// requireProviderImports allows only the standard library, the root DKIM2
// facade, and the approved go-redis packages in the provider.
func requireProviderImports(t *testing.T, root string) {
	t.Helper()
	seenRoot, seenRedis := false, false
	for _, path := range productionGoFiles(t, filepath.Join(root, redisProviderDirectory)) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports %q failed", filepath.Base(path))
		}
		for _, imported := range file.Imports {
			value := strings.Trim(imported.Path.Value, `"`)
			if !allowedProviderImport(value) {
				t.Fatalf("provider has unapproved import %q", value)
			}
			seenRoot = seenRoot || value == replayRootModule
			seenRedis = seenRedis || value == redisClientModule
		}
	}
	if !seenRoot || !seenRedis {
		t.Fatal("provider does not exercise both approved external boundaries")
	}
}

// allowedProviderImport reports whether one import is standard library or an approved boundary.
func allowedProviderImport(importPath string) bool {
	if importPath == "" || strings.ContainsAny(importPath, " \t\r\n\\") {
		return false
	}
	if importPath == replayRootModule || importPath == redisGrammarPackage ||
		slices.Contains(approvedRedisImports, importPath) {
		return true
	}
	pkg, err := build.Default.Import(importPath, ".", build.FindOnly)
	return err == nil && pkg.Goroot
}

// requireRedisImportOwnership proves no other production package imports go-redis.
func requireRedisImportOwnership(t *testing.T, root string) {
	t.Helper()
	seen := 0
	for _, sourceRoot := range []string{filepath.Join(root, "cmd"), filepath.Join(root, "lib"), filepath.Join(root, "tools")} {
		for _, path := range productionGoFiles(t, sourceRoot) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse repository imports %q failed", filepath.Base(path))
			}
			relative, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				t.Fatal("import owner is not repository-relative")
			}
			for _, imported := range file.Imports {
				value := strings.Trim(imported.Path.Value, `"`)
				if value != redisClientModule && !strings.HasPrefix(value, redisClientModule+"/") {
					continue
				}
				if !approvedRedisImportOwner(filepath.ToSlash(relative), value) {
					t.Fatalf("unapproved go-redis import owner %q", filepath.ToSlash(relative))
				}
				seen++
			}
		}
	}
	if seen == 0 {
		t.Fatal("ownership proof found no go-redis import")
	}
}

// approvedRedisImportOwner recognizes only the provider directory and approved packages.
func approvedRedisImportOwner(relativeDirectory, importPath string) bool {
	return relativeDirectory == redisProviderDirectory && slices.Contains(approvedRedisImports, importPath)
}

// requireRedisModuleOwnership proves only the daemon module requires the exact
// direct version, the workspace does not replace it, and checksums are pinned.
func requireRedisModuleOwnership(t *testing.T, root string) {
	t.Helper()
	modulePaths, err := filepath.Glob(filepath.Join(root, "cmd", "*", "go.mod"))
	if err != nil {
		t.Fatal("module discovery failed")
	}
	modulePaths = append(modulePaths, filepath.Join(root, "lib", "go.mod"), filepath.Join(root, "tools", "go.mod"))
	owner := filepath.ToSlash(filepath.Join(root, daemonModuleFile))
	for _, modulePath := range modulePaths {
		content := readEvidence(t, modulePath)
		isOwner := filepath.ToSlash(modulePath) == owner
		if !validRedisModuleDeclaration(content, isOwner) {
			t.Fatalf("unreviewed go-redis declaration in %q", filepath.ToSlash(modulePath))
		}
	}
	if exactTokenCount(readEvidence(t, filepath.Join(root, workspaceFile)), redisClientModule) != 0 {
		t.Fatal("workspace metadata attempts to own or replace go-redis")
	}
	if !validRedisSums(readEvidence(t, filepath.Join(root, daemonModuleSumFile))) {
		t.Fatal("daemon go-redis checksums are missing or drifted")
	}
}

// validRedisModuleDeclaration requires one exact direct requirement from the
// owner and no go-redis token anywhere else, including replace directives.
func validRedisModuleDeclaration(content string, owner bool) bool {
	if !owner {
		return exactTokenCount(content, redisClientModule) == 0
	}
	matches := 0
	exact := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		code, comment, _ := strings.Cut(strings.TrimSpace(scanner.Text()), "//")
		fields := strings.Fields(code)
		if len(fields) > 0 && fields[0] == "require" {
			fields = fields[1:]
		}
		if len(fields) == 2 && fields[0] == redisClientModule {
			matches++
			exact = fields[1] == redisClientVersion && strings.TrimSpace(comment) == ""
		}
	}
	return scanner.Err() == nil && matches == 1 && exact && exactTokenCount(content, redisClientModule) == 1
}

// exactTokenCount counts one module path only as a complete metadata token.
func exactTokenCount(content, modulePath string) int {
	count := 0
	for field := range strings.FieldsSeq(content) {
		if field == modulePath {
			count++
		}
	}
	return count
}

// validRedisSums recognizes exactly the reviewed module and go.mod checksum records.
func validRedisSums(content string) bool {
	expected := []string{
		redisClientModule + " " + redisClientVersion + " " + redisModuleSum,
		redisClientModule + " " + redisClientVersion + "/go.mod " + redisModuleFileSum,
	}
	found := make([]string, 0, len(expected))
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == redisClientModule {
			found = append(found, line)
		}
	}
	slices.Sort(found)
	slices.Sort(expected)
	return scanner.Err() == nil && slices.Equal(found, expected)
}

// requireRedisVendorSection proves the vendor metadata records the exact
// module and exactly the compiled package set linked by the provider.
func requireRedisVendorSection(t *testing.T, root string) {
	t.Helper()
	content := readEvidence(t, filepath.Join(root, vendorModulesFile))
	want := []string{
		redisClientModule,
		redisClientModule + "/auth",
		redisClientModule + "/internal",
		redisClientModule + "/internal/auth/streaming",
		redisClientModule + "/internal/hashtag",
		redisClientModule + "/internal/hscan",
		redisClientModule + "/internal/interfaces",
		redisClientModule + "/internal/maintnotifications/logs",
		redisClientModule + "/internal/otel",
		redisClientModule + "/internal/pool",
		redisClientModule + "/internal/proto",
		redisClientModule + "/internal/routing",
		redisClientModule + "/internal/util",
		redisClientModule + "/maintnotifications",
		redisClientModule + "/push",
	}
	if !validVendorSection(content, redisClientModule, redisClientVersion, redisClientModuleGo, want) {
		t.Fatal("vendor metadata for go-redis is missing or drifted")
	}
	if !validVendorSection(content, atomicModule, atomicVersion, "go 1.18", []string{atomicModule}) {
		t.Fatal("vendor metadata for the go-redis atomic dependency is missing or drifted")
	}
	for _, unlinked := range []string{"github.com/zeebo/xxh3", "github.com/klauspost/cpuid/v2", "github.com/dgryski/go-rendezvous"} {
		if strings.Contains(content, "# "+unlinked+" ") {
			t.Fatalf("unlinked module %q is vendored", unlinked)
		}
	}
}

// validVendorSection validates one module header, Go version, and package set.
func validVendorSection(content, module, version, goVersion string, want []string) bool {
	lines := strings.Split(content, "\n")
	starts := make([]int, 0, 1)
	for index, line := range lines {
		if strings.HasPrefix(line, "# "+module+" ") {
			starts = append(starts, index)
		}
	}
	if len(starts) != 1 || lines[starts[0]] != "# "+module+" "+version {
		return false
	}
	start := starts[0]
	if start+1 >= len(lines) || lines[start+1] != "## explicit; "+goVersion {
		return false
	}
	packages := make([]string, 0, len(want))
	for index := start + 2; index < len(lines) && !strings.HasPrefix(lines[index], "# "); index++ {
		if lines[index] != "" {
			packages = append(packages, lines[index])
		}
	}
	return slices.Equal(packages, want)
}

// requireLicenseEvidence proves the vendored BSD-2-Clause and MIT licenses are the reviewed artifacts.
func requireLicenseEvidence(t *testing.T, root string) {
	t.Helper()
	redisLicense := readEvidenceBytes(t, filepath.Join(root, "vendor", redisClientModule, "LICENSE"))
	if digest(redisLicense) != redisLicenseSHA256 ||
		!strings.Contains(string(redisLicense), "Redistribution and use in source and binary forms") {
		t.Fatal("vendored go-redis license is missing or drifted")
	}
	atomicLicense := readEvidenceBytes(t, filepath.Join(root, "vendor", atomicModule, "LICENSE.txt"))
	if digest(atomicLicense) != atomicLicenseSHA256 ||
		!strings.Contains(string(atomicLicense), "Permission is hereby granted, free of charge") {
		t.Fatal("vendored atomic license is missing or drifted")
	}
}

// TestDependencyClassifiersRejectNearMisses proves the classifiers distinguish near-miss metadata.
func TestDependencyClassifiersRejectNearMisses(t *testing.T) {
	for _, imported := range []string{"", redisClientModule + "/internal/pool", redisClientModule + "x", "github.com/redis/go-redis", replayRootModule + "/internal/replay", "example.com/context"} {
		if allowedProviderImport(imported) {
			t.Fatalf("unapproved import accepted: %q", imported)
		}
	}
	if approvedRedisImportOwner("cmd/dkim2d/internal/app", redisClientModule) ||
		!approvedRedisImportOwner(redisProviderDirectory, redisClientModule) {
		t.Fatal("import owner classification drifted")
	}
	valid := "require (\n\t" + redisClientModule + " " + redisClientVersion + "\n)\n"
	if !validRedisModuleDeclaration(valid, true) || validRedisModuleDeclaration(valid, false) {
		t.Fatal("exact module declaration misclassified")
	}
	for _, mutation := range []string{
		"require " + redisClientModule + " v9.21.0\n",
		"require " + redisClientModule + " " + redisClientVersion + " // indirect\n",
		valid + "replace " + redisClientModule + " => ../fork\n",
	} {
		if validRedisModuleDeclaration(mutation, true) {
			t.Fatalf("mutated declaration accepted: %q", mutation)
		}
	}
	sums := redisClientModule + " " + redisClientVersion + " " + redisModuleSum + "\n" +
		redisClientModule + " " + redisClientVersion + "/go.mod " + redisModuleFileSum + "\n"
	if !validRedisSums(sums) || validRedisSums(strings.Replace(sums, redisModuleSum, "h1:mutated", 1)) ||
		validRedisSums(sums+redisClientModule+" v9.21.0 h1:extra\n") {
		t.Fatal("checksum classifier drifted")
	}
}

// productionGoFiles lists non-test Go sources below root, skipping vendor and temp trees.
func productionGoFiles(t *testing.T, root string) []string {
	t.Helper()
	files := make([]string, 0, 64)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "vendor", "testdata", ".git", "temp", ".artifacts":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal("production source walk failed")
	}
	return files
}

// readEvidence loads one metadata file without rendering its content.
func readEvidence(t *testing.T, path string) string {
	t.Helper()
	return string(readEvidenceBytes(t, path))
}

// readEvidenceBytes loads one dependency artifact without rendering its content.
func readEvidenceBytes(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("dependency artifact %q is unreadable", filepath.Base(path))
	}
	return content
}

// digest returns the lowercase SHA-256 used for exact dependency evidence.
func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
