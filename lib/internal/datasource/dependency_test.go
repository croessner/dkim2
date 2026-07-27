package datasource

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

const (
	dependencyModulePath        = "github.com/croessner/dkim2"
	datasourceImportPath        = dependencyModulePath + "/internal/datasource"
	signingImportPath           = dependencyModulePath + "/internal/signing"
	datasourcePackage           = "internal/datasource"
	datasourceFlatfilePackage   = "internal/datasource/flatfile"
	datasourceMemoryPackage     = "internal/datasource/memory"
	signingPackage              = "internal/signing"
	signingProfilePackage       = "internal/datasource/signingprofile"
	publicFlatfileProvider      = "provider/flatfile"
	datasourceFuturePackage     = "internal/datasource/future"
	dependencyTestHelperPackage = "internal/helper"
	publicFacadeHarness         = "signing_datasource_integration_test.go"
	dependencyRootPackageName   = "dkim2"
	reviewedExternalModulePath  = "golang.org/x/sys"
	requireDirective            = "require"
	toolDirective               = "tool"
	productionDependencySuffix  = ".go"
	testDependencySuffix        = "_test.go"
)

type dependencySource struct {
	relative     string
	directory    string
	packageName  string
	imports      []string
	declarations []string
	test         bool
}

type dependencyPackage struct {
	directory   string
	packageName string
	imports     []string
}

// TestDatasourceProductionImportBoundaries proves actual production package
// ownership preserves the sole datasource-to-signing bridge.
func TestDatasourceProductionImportBoundaries(t *testing.T) {
	sources := collectDependencySources(t)
	packages := collectProductionPackages(t, sources)
	if violation := productionDependencyGraphViolation(packages); violation != "" {
		t.Fatal(violation)
	}
	bridges := make([]string, 0, 1)
	expectedDatasourcePackages := expectedProductionDatasourcePackages()
	datasourcePackages := make([]string, 0, len(expectedDatasourcePackages))

	for _, current := range packages {
		hasDatasource := importsDatasource(current.imports)
		hasSigning := importsSigning(current.imports)
		if isDatasourceDirectory(current.directory) {
			datasourcePackages = append(datasourcePackages, current.directory)
			if invalidDatasourceSigningOwnership(
				current.directory,
				current.imports,
			) {
				t.Fatalf("production datasource package %q violates signing ownership",
					current.directory)
			}
		}
		if hasDatasource && hasSigning {
			bridges = append(bridges, current.directory)
		}
		if invalidSigningDatasourceOwnership(current.directory, current.imports) {
			t.Fatalf("production signing package %q imports datasource", current.directory)
		}
		if current.directory != publicFlatfileProvider &&
			!isDatasourceDirectory(current.directory) &&
			importsConcreteDatasourceProvider(current.imports) {
			t.Fatalf("production protocol package %q imports a concrete datasource provider",
				current.directory)
		}
	}

	slices.Sort(bridges)
	if !slices.Equal(bridges, []string{signingProfilePackage}) {
		t.Fatalf("production datasource/signing bridge packages=%v", bridges)
	}
	slices.Sort(datasourcePackages)
	if !slices.Equal(datasourcePackages, expectedDatasourcePackages) {
		t.Fatalf("production datasource package set=%v", datasourcePackages)
	}
}

// expectedProductionDatasourcePackages returns the exact executable datasource
// provider set while LDAP and SQL implementations remain deferred.
func expectedProductionDatasourcePackages() []string {
	return []string{
		datasourcePackage,
		datasourceFlatfilePackage,
		datasourceMemoryPackage,
		signingProfilePackage,
	}
}

// TestPublicFacadeHarnessIsTheOnlyExternalBridgeTest records the one gray-box
// test needed to project an internal profile into the package-private facade.
func TestPublicFacadeHarnessIsTheOnlyExternalBridgeTest(t *testing.T) {
	sources := collectDependencySources(t)
	foundHarness := false
	for _, source := range sources {
		if !externalTestTouchesDatasourceProvider(source) {
			continue
		}
		if !approvedPublicFacadeHarness(source) {
			t.Fatalf("unexpected external datasource/signing test bridge %q", source.relative)
		}
		foundHarness = true
	}
	if !foundHarness {
		t.Fatalf("required public-facade bridge harness %q is absent", publicFacadeHarness)
	}
}

// TestDependencyGuardClassifiers exercises forbidden cases and allowed
// near-misses without adding executable provider fixtures.
func TestDependencyGuardClassifiers(t *testing.T) {
	t.Run("signing ownership", testDatasourceSigningOwnershipClassifier)
	t.Run("provider imports", testDatasourceProviderImportClassifier)
	t.Run("transitive graph", testProductionDependencyGraphClassifier)
	t.Run("deferred names", testDeferredNameClassifiers)
	t.Run("dependency classes", testForbiddenDependencyClassifier)
	t.Run("external harness", testExternalHarnessClassifier)
	t.Run("module grammar", testModuleDependencyParser)
}

// TestLibraryExcludesDeferredAndServiceDependencies proves the standalone
// library has no LDAP, SQL, daemon, adapter, or exporter runtime dependency.
func TestLibraryExcludesDeferredAndServiceDependencies(t *testing.T) {
	libRoot := dependencyLibRoot(t)
	moduleData, err := os.ReadFile(filepath.Join(libRoot, "go.mod"))
	if err != nil {
		t.Fatal("library module metadata is unreadable")
	}
	dependencies, valid := parseModuleDependencies(string(moduleData))
	if !valid {
		t.Fatal("library module dependency directives are invalid or unsupported")
	}
	for _, dependency := range dependencies {
		if class, forbidden := forbiddenLibraryDependency(dependency); forbidden {
			t.Fatalf("library module contains forbidden %s dependency", class)
		}
		if !reviewedExternalModule(dependency) {
			t.Fatal("library module contains an external dependency without explicit review")
		}
	}
	for _, source := range collectDependencySources(t) {
		if source.test {
			continue
		}
		for _, imported := range source.imports {
			if class, forbidden := forbiddenLibraryDependency(imported); forbidden {
				t.Fatalf("production package %q imports forbidden %s dependency",
					source.directory, class)
			}
			if !reviewedLibraryImport(imported) {
				t.Fatalf("production package %q imports an external dependency without explicit review",
					source.directory)
			}
		}
	}
}

// TestDeferredProvidersAndDatasourceReplayAPIsRemainAbsent proves future LDAP,
// SQL, Redis, and Valkey work remains absent while datasource owns no replay API.
func TestDeferredProvidersAndDatasourceReplayAPIsRemainAbsent(t *testing.T) {
	for _, source := range collectDependencySources(t) {
		if source.test {
			continue
		}
		if deferredRuntimeDirectory(source.directory) {
			t.Fatalf("deferred executable library package %q exists", source.directory)
		}
		datasourceSource := source.directory == "internal/datasource" ||
			strings.HasPrefix(source.directory, "internal/datasource/")
		if deferredProviderSource(source.relative) ||
			datasourceSource && datasourceReplaySource(source.relative) {
			t.Fatalf("library package %q contains a deferred provider source", source.directory)
		}
		for _, declaration := range source.declarations {
			if deferredProviderDeclaration(declaration) {
				t.Fatalf("library package %q declares deferred provider symbol %q",
					source.directory, declaration)
			}
			if datasourceSource && replayDeclaration(declaration) {
				t.Fatalf("library package %q declares replay API symbol %q",
					source.directory, declaration)
			}
		}
	}
}

// deferredRuntimeDirectory reports package names reserved for design-only
// LDAP, SQL, Redis, or Valkey implementations.
func deferredRuntimeDirectory(directory string) bool {
	base := strings.ToLower(filepath.Base(directory))
	return strings.Contains(base, "ldap") ||
		strings.Contains(base, "sql") ||
		strings.Contains(base, "redis") ||
		strings.Contains(base, "valkey")
}

// collectDependencySources parses every library Go source while retaining the
// production/test distinction needed by the boundary policy.
func collectDependencySources(t *testing.T) []dependencySource {
	t.Helper()
	libRoot := dependencyLibRoot(t)
	sources := make([]dependencySource, 0, 128)
	walkDependencySources(t, libRoot, ".", &sources)
	if len(sources) == 0 {
		t.Fatal("library source discovery returned no Go files")
	}
	return sources
}

// walkDependencySources recursively discovers packages without following
// external paths or reporting absolute host locations.
func walkDependencySources(
	t *testing.T,
	libRoot string,
	relativeDirectory string,
	sources *[]dependencySource,
) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(libRoot, relativeDirectory))
	if err != nil {
		t.Fatalf("library source directory %q is unreadable", filepath.ToSlash(relativeDirectory))
	}
	for _, entry := range entries {
		relative := filepath.Join(relativeDirectory, entry.Name())
		if entry.IsDir() {
			if entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			walkDependencySources(t, libRoot, relative, sources)
			continue
		}
		if !strings.HasSuffix(entry.Name(), productionDependencySuffix) {
			continue
		}
		*sources = append(*sources, parseDependencySource(t, libRoot, relative))
	}
}

// parseDependencySource extracts package ownership, direct imports, and
// declared API/operation identifiers from one source file.
func parseDependencySource(
	t *testing.T,
	libRoot string,
	relative string,
) dependencySource {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(libRoot, relative))
	if err != nil {
		t.Fatalf("library source %q is unreadable", filepath.ToSlash(relative))
	}
	displayPath := filepath.ToSlash(relative)
	parsed, err := parser.ParseFile(
		token.NewFileSet(),
		displayPath,
		content,
		0,
	)
	if err != nil {
		t.Fatalf("library source %q cannot be parsed", displayPath)
	}
	imports := make([]string, 0, len(parsed.Imports))
	for _, spec := range parsed.Imports {
		imported, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("library source %q has an invalid import", displayPath)
		}
		imports = append(imports, imported)
	}
	slices.Sort(imports)
	return dependencySource{
		relative:     displayPath,
		directory:    dependencyDirectory(relative),
		packageName:  parsed.Name.Name,
		imports:      imports,
		declarations: declaredDependencyNames(parsed),
		test:         strings.HasSuffix(relative, testDependencySuffix),
	}
}

// declaredDependencyNames returns every named declaration and interface method
// that could introduce a deferred provider or replay operation.
func declaredDependencyNames(file *ast.File) []string {
	names := make([]string, 0, len(file.Decls))
	ast.Inspect(file, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncDecl:
			names = append(names, current.Name.Name)
		case *ast.TypeSpec:
			names = append(names, current.Name.Name)
		case *ast.ValueSpec:
			for _, name := range current.Names {
				names = append(names, name.Name)
			}
		case *ast.Field:
			for _, name := range current.Names {
				names = append(names, name.Name)
			}
		}
		return true
	})
	slices.Sort(names)
	return slices.Compact(names)
}

// collectProductionPackages groups parsed files by actual package directory
// and rejects discovery or package-clause disagreement.
func collectProductionPackages(
	t *testing.T,
	sources []dependencySource,
) map[string]dependencyPackage {
	t.Helper()
	packages := make(map[string]dependencyPackage)
	for _, source := range sources {
		if source.test {
			continue
		}
		current, found := packages[source.directory]
		if found && current.packageName != source.packageName {
			t.Fatalf("production directory %q contains multiple packages", source.directory)
		}
		current.directory = source.directory
		current.packageName = source.packageName
		current.imports = append(current.imports, source.imports...)
		slices.Sort(current.imports)
		current.imports = slices.Compact(current.imports)
		packages[source.directory] = current
	}
	if len(packages) == 0 {
		t.Fatal("production package discovery returned no packages")
	}
	return packages
}

// productionDependencyGraphViolation reports the first deterministic local
// transitive-ownership or package-resolution failure.
func productionDependencyGraphViolation(
	packages map[string]dependencyPackage,
) string {
	roots := make([]string, 0, len(packages))
	for directory := range packages {
		roots = append(roots, directory)
	}
	slices.Sort(roots)

	for _, root := range roots {
		closure, unresolved := localDependencyClosure(root, packages)
		if unresolved != "" {
			return fmt.Sprintf(
				"production package %q has unresolved local dependency %q",
				root,
				unresolved,
			)
		}
		targets := make([]string, 0, len(closure))
		for target := range closure {
			targets = append(targets, target)
		}
		slices.Sort(targets)

		hasDatasource := false
		hasSigning := false
		for _, target := range targets {
			hasDatasource = hasDatasource || isDatasourceDirectory(target)
			hasSigning = hasSigning || isSigningDirectory(target)
			if isSigningDirectory(root) && isDatasourceDirectory(target) {
				return fmt.Sprintf(
					"production signing package %q transitively reaches datasource package %q",
					root,
					target,
				)
			}
			if isDatasourceDirectory(root) &&
				root != signingProfilePackage &&
				isSigningDirectory(target) {
				return fmt.Sprintf(
					"production datasource package %q transitively reaches signing package %q",
					root,
					target,
				)
			}
			if (isDatasourceDirectory(root) ||
				root == publicFlatfileProvider) &&
				isConcreteDatasourceDirectory(target) &&
				!allowsConcreteDatasourceDependency(root, target) {
				return fmt.Sprintf(
					"production datasource package %q transitively reaches forbidden concrete provider %q",
					root,
					target,
				)
			}
			if root != publicFlatfileProvider &&
				!isDatasourceDirectory(root) &&
				isConcreteDatasourceDirectory(target) {
				return fmt.Sprintf(
					"production package %q transitively reaches concrete datasource provider %q",
					root,
					target,
				)
			}
		}
		if hasDatasource && hasSigning &&
			root != signingProfilePackage &&
			root != publicFlatfileProvider {
			return fmt.Sprintf(
				"production package %q creates an unapproved datasource/signing bridge",
				root,
			)
		}
		if root == signingProfilePackage && (!hasDatasource || !hasSigning) {
			return "production signing-profile bridge does not reach both domain owners"
		}
	}
	return ""
}

// localDependencyClosure computes a cycle-safe closure over production
// packages and reports unresolved imports within the local module.
func localDependencyClosure(
	root string,
	packages map[string]dependencyPackage,
) (map[string]struct{}, string) {
	closure := make(map[string]struct{}, len(packages))
	pending := []string{root}
	for len(pending) > 0 {
		last := len(pending) - 1
		currentDirectory := pending[last]
		pending = pending[:last]
		if _, visited := closure[currentDirectory]; visited {
			continue
		}
		current, found := packages[currentDirectory]
		if !found {
			return nil, currentDirectory
		}
		closure[currentDirectory] = struct{}{}
		localImports := make([]string, 0, len(current.imports))
		for _, imported := range current.imports {
			if directory, local := localDependencyDirectory(imported); local {
				localImports = append(localImports, directory)
			}
		}
		slices.Sort(localImports)
		for index := len(localImports) - 1; index >= 0; index-- {
			directory := localImports[index]
			if _, found := packages[directory]; !found {
				return nil, directory
			}
			if _, visited := closure[directory]; !visited {
				pending = append(pending, directory)
			}
		}
	}
	return closure, ""
}

// localDependencyDirectory maps one exact library-module import to its stable
// package directory without accepting a module-path prefix collision.
func localDependencyDirectory(imported string) (string, bool) {
	if imported == dependencyModulePath {
		return ".", true
	}
	if !strings.HasPrefix(imported, dependencyModulePath+"/") {
		return "", false
	}
	return strings.TrimPrefix(imported, dependencyModulePath+"/"), true
}

// isConcreteDatasourceDirectory reports provider subpackages while excluding
// the provider-neutral datasource contract package.
func isConcreteDatasourceDirectory(directory string) bool {
	return strings.HasPrefix(directory, "internal/datasource/")
}

// allowsConcreteDatasourceDependency enforces the approved provider
// composition direction within the datasource tree.
func allowsConcreteDatasourceDependency(root string, target string) bool {
	switch root {
	case datasourcePackage:
		return false
	case datasourceMemoryPackage:
		return target == datasourceMemoryPackage
	case datasourceFlatfilePackage:
		return target == datasourceFlatfilePackage ||
			target == datasourceMemoryPackage
	case signingProfilePackage:
		return target == signingProfilePackage
	case publicFlatfileProvider:
		return target == datasourceFlatfilePackage ||
			target == datasourceMemoryPackage ||
			target == signingProfilePackage
	default:
		return target == root
	}
}

// externalTestTouchesDatasourceProvider reports test-only imports that can
// instantiate or wrap a concrete datasource integration package.
func externalTestTouchesDatasourceProvider(source dependencySource) bool {
	if !source.test || source.directory == signingProfilePackage {
		return false
	}
	if isDatasourceDirectory(source.directory) {
		return importsSigning(source.imports) ||
			slices.Contains(source.imports, datasourceImportPath+"/signingprofile")
	}
	if isSigningDirectory(source.directory) {
		return importsDatasource(source.imports)
	}
	return importsConcreteDatasourceProvider(source.imports) ||
		importsDatasource(source.imports) && importsSigning(source.imports)
}

// approvedPublicFacadeHarness validates the exact one test-only exception and
// its direct imports of both owners plus the sole production bridge.
func approvedPublicFacadeHarness(source dependencySource) bool {
	return source.test &&
		source.relative == publicFacadeHarness &&
		source.packageName == dependencyRootPackageName &&
		slices.Contains(source.imports, datasourceImportPath) &&
		slices.Contains(source.imports, datasourceImportPath+"/signingprofile") &&
		slices.Contains(source.imports, signingImportPath)
}

// testDatasourceSigningOwnershipClassifier proves arbitrary datasource
// subpackages cannot acquire signing ownership.
func testDatasourceSigningOwnershipClassifier(t *testing.T) {
	t.Helper()
	both := []string{datasourceImportPath, signingImportPath}
	tests := []struct {
		name      string
		directory string
		imports   []string
		invalid   bool
	}{
		{name: "exact bridge", directory: signingProfilePackage, imports: both},
		{
			name: "bridge missing signing", directory: signingProfilePackage,
			imports: []string{datasourceImportPath}, invalid: true,
		},
		{
			name: "arbitrary datasource signing", directory: datasourceFuturePackage,
			imports: []string{signingImportPath}, invalid: true,
		},
		{
			name:      "arbitrary datasource signing subpackage",
			directory: datasourceFuturePackage,
			imports:   []string{signingImportPath + "/future"}, invalid: true,
		},
		{name: "ordinary datasource", directory: datasourceFuturePackage},
		{
			name: "outside datasource", directory: "internal/example",
			imports: []string{signingImportPath},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := invalidDatasourceSigningOwnership(
				test.directory,
				test.imports,
			); got != test.invalid {
				t.Fatalf("invalid ownership=%t, want %t", got, test.invalid)
			}
		})
	}
	if isDatasourceDirectory("internal/datasourcex/future") {
		t.Fatal("datasource prefix near-miss entered the package tree")
	}
	signingOwners := []struct {
		directory string
		imported  string
		invalid   bool
	}{
		{
			directory: signingPackage,
			imported:  datasourceImportPath,
			invalid:   true,
		},
		{
			directory: "internal/signing/future",
			imported:  datasourceImportPath,
			invalid:   true,
		},
		{
			directory: "internal/signingx/future",
			imported:  datasourceImportPath,
		},
	}
	for _, test := range signingOwners {
		if got := invalidSigningDatasourceOwnership(
			test.directory,
			[]string{test.imported},
		); got != test.invalid {
			t.Fatalf("invalid signing ownership=%t, want %t", got, test.invalid)
		}
	}
	if !importsSigning([]string{signingImportPath + "/future"}) ||
		importsSigning([]string{signingImportPath + "x/future"}) {
		t.Fatal("signing import tree accepted a prefix near-miss")
	}
}

// testDatasourceProviderImportClassifier proves every datasource subpackage
// import is concrete while lexical near-misses remain outside the rule.
func testDatasourceProviderImportClassifier(t *testing.T) {
	t.Helper()
	tests := []struct {
		name     string
		imported string
		concrete bool
	}{
		{name: "core contract", imported: datasourceImportPath},
		{
			name: "known provider", imported: datasourceImportPath + "/memory",
			concrete: true,
		},
		{
			name: "future provider", imported: datasourceImportPath + "/future",
			concrete: true,
		},
		{name: "prefix near miss", imported: datasourceImportPath + "x/future"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := importsConcreteDatasourceProvider([]string{test.imported})
			if got != test.concrete {
				t.Fatalf("concrete import=%t, want %t", got, test.concrete)
			}
		})
	}
}

// testProductionDependencyGraphClassifier proves indirect ownership,
// unresolved imports, and cycles are handled without relying on direct edges.
func testProductionDependencyGraphClassifier(t *testing.T) {
	t.Helper()
	localImport := func(directory string) string {
		if directory == "." {
			return dependencyModulePath
		}
		return dependencyModulePath + "/" + directory
	}
	valid := map[string]dependencyPackage{
		datasourcePackage: {
			directory: datasourcePackage,
		},
		datasourceMemoryPackage: {
			directory: datasourceMemoryPackage,
			imports:   []string{datasourceImportPath},
		},
		datasourceFlatfilePackage: {
			directory: datasourceFlatfilePackage,
			imports: []string{
				datasourceImportPath,
				localImport(datasourceMemoryPackage),
			},
		},
		signingPackage: {
			directory: signingPackage,
		},
		signingProfilePackage: {
			directory: signingProfilePackage,
			imports:   []string{datasourceImportPath, signingImportPath},
		},
		"internal/cycle": {
			directory: "internal/cycle",
			imports:   []string{localImport("internal/cycle")},
		},
	}
	tests := []struct {
		name     string
		mutate   func(map[string]dependencyPackage)
		violates bool
	}{
		{name: "valid bridge and self cycle"},
		{
			name: "datasource helper reaches signing",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{signingImportPath},
				}
				current := packages[datasourceMemoryPackage]
				current.imports = []string{localImport(dependencyTestHelperPackage)}
				packages[current.directory] = current
			},
			violates: true,
		},
		{
			name: "datasource core helper reaches provider",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{localImport(datasourceMemoryPackage)},
				}
				current := packages[datasourcePackage]
				current.imports = []string{localImport(dependencyTestHelperPackage)}
				packages[current.directory] = current
			},
			violates: true,
		},
		{
			name: "memory helper reaches flatfile",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{localImport(datasourceFlatfilePackage)},
				}
				current := packages[datasourceMemoryPackage]
				current.imports = []string{localImport(dependencyTestHelperPackage)}
				packages[current.directory] = current
			},
			violates: true,
		},
		{
			name: "signing helper reaches datasource",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{datasourceImportPath},
				}
				current := packages[signingPackage]
				current.imports = []string{localImport(dependencyTestHelperPackage)}
				packages[current.directory] = current
			},
			violates: true,
		},
		{
			name: "protocol helper reaches provider",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{localImport(datasourceMemoryPackage)},
				}
				packages["internal/protocol"] = dependencyPackage{
					directory: "internal/protocol",
					imports:   []string{localImport(dependencyTestHelperPackage)},
				}
			},
			violates: true,
		},
		{
			name: "signing profile helper reaches provider",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{localImport(datasourceMemoryPackage)},
				}
				current := packages[signingProfilePackage]
				current.imports = append(
					current.imports,
					localImport(dependencyTestHelperPackage),
				)
				packages[current.directory] = current
			},
			violates: true,
		},
		{
			name: "unapproved indirect bridge",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{datasourceImportPath, signingImportPath},
				}
			},
			violates: true,
		},
		{
			name: "unresolved local import",
			mutate: func(packages map[string]dependencyPackage) {
				packages[dependencyTestHelperPackage] = dependencyPackage{
					directory: dependencyTestHelperPackage,
					imports:   []string{localImport("internal/missing")},
				}
			},
			violates: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packages := make(map[string]dependencyPackage, len(valid))
			for directory, current := range valid {
				current.imports = slices.Clone(current.imports)
				packages[directory] = current
			}
			if test.mutate != nil {
				test.mutate(packages)
			}
			got := productionDependencyGraphViolation(packages) != ""
			if got != test.violates {
				t.Fatalf("graph violation=%t, want %t", got, test.violates)
			}
		})
	}
	if directory, local := localDependencyDirectory(
		dependencyModulePath + "x/internal/example",
	); local || directory != "" {
		t.Fatal("local dependency classifier accepted a module-path near-miss")
	}
}

// testDeferredNameClassifiers proves executable provider and datasource replay
// names are classified without confusing safe lexical near-misses.
func testDeferredNameClassifiers(t *testing.T) {
	t.Helper()
	directories := map[string]bool{
		"internal/ldapreader":  true,
		"internal/sql":         true,
		"internal/replaystore": false,
		"internal/valkey":      true,
		"internal/reply":       false,
		"internal/squirrel":    false,
	}
	for directory, forbidden := range directories {
		if got := deferredRuntimeDirectory(directory); got != forbidden {
			t.Fatalf("directory classifier=%t, want %t", got, forbidden)
		}
	}
	sources := map[string]bool{
		"ldap_provider.go":  true,
		"provider_sql.go":   true,
		"replay_store.go":   false,
		"valkey_backend.go": true,
		"sqline.go":         false,
		"reply_store.go":    false,
	}
	for source, forbidden := range sources {
		if got := deferredProviderSource(source); got != forbidden {
			t.Fatalf("source classifier=%t, want %t", got, forbidden)
		}
	}
	for source, forbidden := range map[string]bool{
		"replay_store.go": true,
		"reply_store.go":  false,
		"memory.go":       false,
	} {
		if got := datasourceReplaySource(source); got != forbidden {
			t.Fatalf("datasource replay source classifier=%t, want %t", got, forbidden)
		}
	}
	declarations := map[string]bool{
		"LDAPProvider":     true,
		"SQLReader":        true,
		"RedisStore":       true,
		"RedisishProvider": true,
		"ValkeyStore":      true,
		"ValkeyishStore":   true,
		"SQLiteProvider":   true,
		"LDAPishProvider":  true,
		"StoreDisabled":    false,
		"Profile":          false,
	}
	for declaration, forbidden := range declarations {
		if got := deferredProviderDeclaration(declaration); got != forbidden {
			t.Fatalf("provider declaration classifier=%t, want %t", got, forbidden)
		}
	}
	replayNames := map[string]bool{
		"ReplayStore":      true,
		"Replayer":         true,
		"Replayable":       true,
		"CheckAndRemember": true,
		"FirstSeen":        true,
		"SeenMessage":      true,
		"ValkeyProvider":   false,
		"ReplyStore":       false,
		"CheckAndRender":   false,
		"Preplayer":        false,
	}
	for declaration, forbidden := range replayNames {
		if got := replayDeclaration(declaration); got != forbidden {
			t.Fatalf("replay declaration classifier=%t, want %t", got, forbidden)
		}
	}
}

// testForbiddenDependencyClassifier proves deferred and service runtimes are
// rejected while the existing system dependency remains outside the classes.
func testForbiddenDependencyClassifier(t *testing.T) {
	t.Helper()
	tests := map[string]bool{
		"database/sql":                 true,
		"database/sql/driver":          true,
		"ldap.example":                 true,
		"sql.example":                  true,
		"github.com/lib/pq":            true,
		"github.com/spf13/cobra":       true,
		"github.com/redis/go-redis/v9": true,
		"valkey.example":               true,
		"golang.org/x/sys/unix":        false,
		"example.com/safe":             false,
	}
	for imported, forbidden := range tests {
		_, got := forbiddenLibraryDependency(imported)
		if got != forbidden {
			t.Fatalf("dependency classifier=%t, want %t", got, forbidden)
		}
	}
	if !reviewedExternalModule(reviewedExternalModulePath) ||
		reviewedExternalModule("example.com/safe") {
		t.Fatal("external module review gate accepted the wrong module set")
	}
	for imported, reviewed := range map[string]bool{
		"context": true,
		dependencyModulePath + "/internal/datasource": true,
		dependencyModulePath + "/internal/replay":     true,
		reviewedExternalModulePath + "/unix":          true,
		"example.com/safe":                            false,
	} {
		if got := reviewedLibraryImport(imported); got != reviewed {
			t.Fatalf("reviewed import=%t, want %t", got, reviewed)
		}
	}
}

// testExternalHarnessClassifier proves concrete-provider-only and incomplete
// bridge imports cannot create another test exception.
func testExternalHarnessClassifier(t *testing.T) {
	t.Helper()
	exactImports := []string{
		datasourceImportPath,
		datasourceImportPath + "/signingprofile",
		signingImportPath,
	}
	tests := []struct {
		name     string
		source   dependencySource
		touches  bool
		approved bool
	}{
		{
			name: "exact harness",
			source: dependencySource{
				relative: publicFacadeHarness, packageName: dependencyRootPackageName,
				imports: exactImports, test: true,
			},
			touches: true, approved: true,
		},
		{
			name: "missing signing owner",
			source: dependencySource{
				relative: publicFacadeHarness, packageName: dependencyRootPackageName,
				imports: []string{datasourceImportPath + "/signingprofile"}, test: true,
			},
			touches: true,
		},
		{
			name: "other provider test",
			source: dependencySource{
				relative: "other_test.go", packageName: dependencyRootPackageName,
				imports: []string{datasourceImportPath + "/future"}, test: true,
			},
			touches: true,
		},
		{
			name: "contract-only test",
			source: dependencySource{
				relative: "contract_test.go", packageName: dependencyRootPackageName,
				imports: []string{datasourceImportPath}, test: true,
			},
		},
		{
			name: "datasource provider imports signing",
			source: dependencySource{
				relative:  "internal/datasource/memory/bridge_test.go",
				directory: datasourceMemoryPackage, packageName: "memory",
				imports: []string{signingImportPath}, test: true,
			},
			touches: true,
		},
		{
			name: "sole bridge package test",
			source: dependencySource{
				relative:  "internal/datasource/signingprofile/adapter_test.go",
				directory: signingProfilePackage, packageName: "signingprofile",
				imports: exactImports, test: true,
			},
		},
		{
			name: "signing package imports datasource",
			source: dependencySource{
				relative:  "internal/signing/bridge_test.go",
				directory: signingPackage, packageName: "signing",
				imports: []string{datasourceImportPath}, test: true,
			},
			touches: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := externalTestTouchesDatasourceProvider(test.source); got != test.touches {
				t.Fatalf("touches provider=%t, want %t", got, test.touches)
			}
			if got := approvedPublicFacadeHarness(test.source); got != test.approved {
				t.Fatalf("approved harness=%t, want %t", got, test.approved)
			}
		})
	}
}

// testModuleDependencyParser proves require, tool, and replace block grammar,
// no-slash module paths, and malformed/local replacement closure.
func testModuleDependencyParser(t *testing.T) {
	t.Helper()
	valid := `module github.com/croessner/dkim2
go 1.26
require (
	golang.org/x/sys v0.47.0
	ldap.example v1.0.0
)
tool (
	tool.example
)
replace (
	old.example v1.0.0 => new.example v1.1.0
)
`
	dependencies, ok := parseModuleDependencies(valid)
	expected := []string{
		"golang.org/x/sys",
		"ldap.example",
		"new.example",
		"old.example",
		"tool.example",
	}
	if !ok || !slices.Equal(dependencies, expected) {
		t.Fatalf("valid module dependencies=%v valid=%t", dependencies, ok)
	}
	if _, forbidden := forbiddenLibraryDependency("ldap.example"); !forbidden {
		t.Fatal("no-slash forbidden module path was not classified")
	}
	invalid := []string{
		"module github.com/croessner/dkim2\ngo 1.26\nrequire (\nexample.com v1.0.0\n",
		"module github.com/croessner/dkim2\ngo 1.26\nreplace example.com => ../local\n",
		"module github.com/croessner/dkim2\ngo 1.26\ntool (\nexample.com v1.0.0\n)\n",
		"module github.com/croessner/dkim2\ngo 1.26\nreplace (example.com)\n",
	}
	for _, content := range invalid {
		if _, parsed := parseModuleDependencies(content); parsed {
			t.Fatal("malformed module dependency directives were accepted")
		}
	}
}

// dependencyLibRoot resolves the library root from this compiled test without
// returning the absolute location to callers or diagnostics.
func dependencyLibRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("dependency test source location is unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

// dependencyDirectory returns one stable slash-separated package directory.
func dependencyDirectory(relative string) string {
	directory := filepath.ToSlash(filepath.Dir(relative))
	if directory == "." {
		return "."
	}
	return strings.TrimPrefix(directory, "./")
}

// isDatasourceDirectory reports exact membership in the datasource package
// tree without accepting a lexical prefix collision.
func isDatasourceDirectory(directory string) bool {
	return directory == datasourcePackage ||
		strings.HasPrefix(directory, datasourcePackage+"/")
}

// invalidDatasourceSigningOwnership reports a signing import outside the sole
// bridge or an incomplete bridge owner pair.
func invalidDatasourceSigningOwnership(
	directory string,
	imports []string,
) bool {
	hasSigning := importsSigning(imports)
	hasDatasource := importsDatasource(imports)
	if directory == signingProfilePackage {
		return !hasSigning || !hasDatasource
	}
	return isDatasourceDirectory(directory) && hasSigning
}

// invalidSigningDatasourceOwnership reports datasource imports anywhere in
// the signing package tree.
func invalidSigningDatasourceOwnership(
	directory string,
	imports []string,
) bool {
	return isSigningDirectory(directory) && importsDatasource(imports)
}

// isSigningDirectory reports exact membership in the signing package tree
// without accepting a lexical prefix collision.
func isSigningDirectory(directory string) bool {
	return directory == signingPackage ||
		strings.HasPrefix(directory, signingPackage+"/")
}

// importsDatasource reports whether one package imports the datasource
// contract or one of its explicit provider subpackages.
func importsDatasource(imports []string) bool {
	for _, imported := range imports {
		if imported == datasourceImportPath ||
			strings.HasPrefix(imported, datasourceImportPath+"/") {
			return true
		}
	}
	return false
}

// importsSigning reports imports of the signing owner or any of its
// subpackages without accepting a lexical prefix collision.
func importsSigning(imports []string) bool {
	for _, imported := range imports {
		if imported == signingImportPath ||
			strings.HasPrefix(imported, signingImportPath+"/") {
			return true
		}
	}
	return false
}

// importsConcreteDatasourceProvider reports imports of provider-specific
// models that must not enter production protocol packages.
func importsConcreteDatasourceProvider(imports []string) bool {
	for _, imported := range imports {
		if strings.HasPrefix(imported, datasourceImportPath+"/") {
			return true
		}
	}
	return false
}

// forbiddenLibraryDependency classifies dependencies reserved for deferred
// providers, services, adapters, generated HTTP, or concrete exporters.
func forbiddenLibraryDependency(imported string) (string, bool) {
	lower := strings.ToLower(imported)
	switch {
	case imported == "database/sql",
		imported == "database/sql/driver",
		strings.Contains(lower, "ldap"),
		strings.Contains(lower, "sql"),
		strings.Contains(lower, "github.com/lib/pq"),
		strings.Contains(lower, "go-ora"),
		strings.Contains(lower, "godror"),
		strings.Contains(lower, "sqlx"),
		strings.Contains(lower, "go-sql-driver"),
		strings.Contains(lower, "jackc/pgx"),
		strings.Contains(lower, "gorm.io"),
		strings.Contains(lower, "modernc.org/sqlite"):
		return "LDAP/SQL runtime", true
	case strings.Contains(lower, "spf13/cobra"),
		strings.Contains(lower, "spf13/viper"),
		strings.Contains(lower, "go.uber.org/fx"),
		strings.Contains(lower, "prometheus"),
		strings.Contains(lower, "opentelemetry.io/otel/exporters"),
		strings.Contains(lower, "oapi-codegen"),
		strings.Contains(lower, "kin-openapi"),
		strings.Contains(lower, "milter"):
		return "service or adapter runtime", true
	case strings.Contains(lower, "redis"),
		strings.Contains(lower, "valkey"),
		strings.Contains(lower, "go-redis"),
		strings.Contains(lower, "rueidis"):
		return "key-value runtime", true
	default:
		return "", false
	}
}

// reviewedExternalModule permits the current intentionally reviewed external
// module set. Future dependencies may extend this gate only with explicit
// architecture, security, and boundary review.
func reviewedExternalModule(modulePath string) bool {
	return modulePath == reviewedExternalModulePath
}

// reviewedLibraryImport permits standard packages, local packages, and imports
// from the explicitly reviewed external module set.
func reviewedLibraryImport(imported string) bool {
	first, _, _ := strings.Cut(imported, "/")
	if !strings.Contains(first, ".") {
		return true
	}
	return imported == dependencyModulePath ||
		strings.HasPrefix(imported, dependencyModulePath+"/") ||
		reviewedExternalModule(imported) ||
		strings.HasPrefix(imported, reviewedExternalModulePath+"/")
}

// parseModuleDependencies conservatively extracts every require, tool, and
// replace path while rejecting unknown or malformed directive shapes.
func parseModuleDependencies(content string) ([]string, bool) {
	dependencies := make([]string, 0, 8)
	block := ""
	for _, rawLine := range strings.Split(content, "\n") {
		line, _, _ := strings.Cut(rawLine, "//")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 && fields[0] == ")" {
			if block == "" {
				return nil, false
			}
			block = ""
			continue
		}
		if block != "" {
			switch block {
			case requireDirective:
				if len(fields) < 2 {
					return nil, false
				}
				dependencies = append(dependencies, fields[0])
			case toolDirective:
				if len(fields) != 1 {
					return nil, false
				}
				dependencies = append(dependencies, fields[0])
			case "replace":
				replacementPaths, ok := parseReplacementPaths(fields)
				if !ok {
					return nil, false
				}
				dependencies = append(dependencies, replacementPaths...)
			default:
				return nil, false
			}
			continue
		}
		switch fields[0] {
		case "module":
			if len(fields) != 2 || fields[1] != dependencyModulePath {
				return nil, false
			}
		case "go":
			if len(fields) != 2 {
				return nil, false
			}
		case requireDirective, toolDirective:
			switch len(fields) {
			case 2:
				if fields[1] != "(" {
					if fields[0] != toolDirective {
						return nil, false
					}
					dependencies = append(dependencies, fields[1])
					continue
				}
				block = fields[0]
			case 3:
				if fields[0] != requireDirective {
					return nil, false
				}
				dependencies = append(dependencies, fields[1])
			default:
				return nil, false
			}
		case "replace":
			if len(fields) == 2 && fields[1] == "(" {
				block = fields[0]
				continue
			}
			replacementPaths, ok := parseReplacementPaths(fields[1:])
			if !ok {
				return nil, false
			}
			dependencies = append(dependencies, replacementPaths...)
		default:
			return nil, false
		}
	}
	if block != "" {
		return nil, false
	}
	slices.Sort(dependencies)
	return slices.Compact(dependencies), true
}

// parseReplacementPaths extracts both module identities from one replacement
// directive and rejects local targets that cannot be classified durably.
func parseReplacementPaths(fields []string) ([]string, bool) {
	arrow := slices.Index(fields, "=>")
	if arrow < 1 || arrow >= len(fields)-1 {
		return nil, false
	}
	left := fields[0]
	right := fields[arrow+1]
	if strings.HasPrefix(right, ".") || strings.HasPrefix(right, "/") {
		return nil, false
	}
	return []string{left, right}, true
}

// deferredProviderSource reports production filenames that would introduce a
// design-only provider under a generic existing package name.
func deferredProviderSource(relative string) bool {
	name := strings.TrimSuffix(
		strings.ToLower(filepath.Base(relative)),
		productionDependencySuffix,
	)
	for _, part := range strings.FieldsFunc(name, func(value rune) bool {
		return value == '_' || value == '-' || value == '.'
	}) {
		if part == "ldap" || part == "sql" || part == "redis" || part == "valkey" {
			return true
		}
	}
	return false
}

// datasourceReplaySource reports replay storage filenames under datasource ownership.
func datasourceReplaySource(relative string) bool {
	name := strings.TrimSuffix(
		strings.ToLower(filepath.Base(relative)),
		productionDependencySuffix,
	)
	for _, part := range strings.FieldsFunc(name, func(value rune) bool {
		return value == '_' || value == '-' || value == '.'
	}) {
		if part == "replay" {
			return true
		}
	}
	return false
}

// deferredProviderDeclaration reports provider-specific executable symbols
// that are forbidden while LDAP, SQL, Redis, and Valkey remain outside lib.
func deferredProviderDeclaration(name string) bool {
	upper := strings.ToUpper(name)
	if strings.Contains(upper, "LDAP") || strings.Contains(upper, "SQL") {
		return true
	}
	for _, word := range declarationWords(name) {
		lower := strings.ToLower(word)
		if strings.HasPrefix(lower, "redis") || strings.HasPrefix(lower, "valkey") {
			return true
		}
	}
	return false
}

// replayDeclaration reports datasource API names that would prematurely add a
// replay-store interface or replay mutation operation.
func replayDeclaration(name string) bool {
	words := declarationWords(name)
	for index, word := range words {
		lower := strings.ToLower(word)
		if strings.HasPrefix(lower, "replay") {
			return true
		}
		if index+1 < len(words) {
			next := strings.ToLower(words[index+1])
			if lower == "first" && next == "seen" || lower == "seen" && next == "message" {
				return true
			}
		}
		if index+2 < len(words) &&
			lower == "check" &&
			strings.EqualFold(words[index+1], "and") &&
			strings.EqualFold(words[index+2], "remember") {
			return true
		}
	}
	return false
}

// declarationWords splits one Go identifier into exact acronym and camel-case words.
func declarationWords(name string) []string {
	runes := []rune(name)
	words := make([]string, 0, 4)
	start := -1
	for index, current := range runes {
		if current == '_' || !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			if start >= 0 {
				words = append(words, string(runes[start:index]))
				start = -1
			}
			continue
		}
		if start < 0 {
			start = index
			continue
		}
		previous := runes[index-1]
		nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
		if unicode.IsUpper(current) &&
			(unicode.IsLower(previous) || unicode.IsDigit(previous) ||
				unicode.IsUpper(previous) && nextIsLower) {
			words = append(words, string(runes[start:index]))
			start = index
		}
	}
	if start >= 0 {
		words = append(words, string(runes[start:]))
	}
	return words
}
