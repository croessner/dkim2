package policy

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestProjectionPackageDirectionAndNoReparse guards the frozen provenance dependency flow.
func TestProjectionPackageDirectionAndNoReparse(t *testing.T) {
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("module root error = %v", err)
	}
	assertForbiddenProductionImports(t, filepath.Join(moduleRoot, "internal", "policy"), []string{
		"github.com/croessner/dkim2/internal/service",
		"github.com/croessner/dkim2",
		"github.com/croessner/dkim2/internal/signature",
		"github.com/croessner/dkim2/internal/tagvalue",
		"github.com/croessner/dkim2/internal/rawmsg",
		"github.com/croessner/dkim2/internal/instance",
		"github.com/croessner/dkim2/internal/canonical",
		"github.com/croessner/dkim2/internal/recipe",
	})
	assertForbiddenProductionImportsRecursive(t, filepath.Join(moduleRoot, "internal"), []string{
		"github.com/croessner/dkim2",
	})
	assertForbiddenProductionImportsRecursive(t, moduleRoot, []string{
		"github.com/croessner/dkim2/cmd/",
		"github.com/getkin/kin-openapi/",
		"github.com/oapi-codegen/",
		"github.com/spf13/cobra",
		"github.com/spf13/viper",
		"go.uber.org/fx",
		"github.com/prometheus/",
		"go.opentelemetry.io/otel/exporters/",
		"go.opentelemetry.io/otel/sdk/",
		"github.com/emersion/go-milter",
	})
	for _, directory := range []string{filepath.Join(moduleRoot, "internal", "service"), moduleRoot} {
		assertForbiddenProductionImports(t, directory, []string{
			"github.com/croessner/dkim2/internal/signature",
			"github.com/croessner/dkim2/internal/tagvalue",
		})
	}
}

// TestForbiddenImportPrefixRulesRejectSubpackages proves family guards cover concrete OpenAPI and telemetry packages.
func TestForbiddenImportPrefixRulesRejectSubpackages(t *testing.T) {
	for _, imported := range []string{"github.com/getkin/kin-openapi/openapi3", "go.opentelemetry.io/otel/sdk/trace"} {
		t.Run(filepath.Base(imported), func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "guard.go")
			source := "package guard\nimport _ \"" + imported + "\"\n"
			if err := os.WriteFile(filename, []byte(source), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			family := imported[:strings.LastIndex(imported, "/")+1]
			if err := rejectForbiddenFileImports(filename, []string{family}); err == nil {
				t.Fatalf("subpackage import %q was not rejected", imported)
			}
		})
	}
}

// assertForbiddenProductionImportsRecursive rejects exact or prefix-denied imports throughout one production tree.
func assertForbiddenProductionImportsRecursive(t *testing.T, root string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && !libraryModuleDirectory(root, path, entry.Name()) {
				return filepath.SkipDir
			}
			if (entry.Name() == "generated" || entry.Name() == "openapi") && containsGoSource(path) {
				return fmt.Errorf("forbidden generated/runtime scope entered the library: %s", path)
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		return rejectForbiddenFileImports(path, forbidden)
	})
	if err != nil {
		t.Fatalf("recursive production import audit for %q failed: %v", root, err)
	}
}

// libraryModuleDirectory reports whether one directory below root belongs to
// the library module. The library module owns the repository root, so nested
// modules (directories with their own go.mod), the workspace vendor tree, the
// ignored root scratch directory, and directories the go command ignores are
// excluded from the production import audit.
func libraryModuleDirectory(root, path, name string) bool {
	if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") ||
		strings.HasPrefix(name, "_") || path == filepath.Join(root, "temp") {
		return false
	}
	_, err := os.Stat(filepath.Join(path, "go.mod"))
	return errors.Is(err, fs.ErrNotExist)
}

// containsGoSource reports whether one directory tree holds any Go source, so
// documentation-only directories such as the OpenAPI specification tree are
// not mistaken for generated Go scopes while nested generated packages are
// still caught. Unreadable trees count as containing Go source (fail closed).
func containsGoSource(directory string) bool {
	found := false
	err := filepath.WalkDir(directory, func(_ string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found || err != nil
}

// rejectForbiddenFileImports parses one production file and rejects exact or slash-terminated prefix rules.
func rejectForbiddenFileImports(filename string, forbidden []string) error {
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, imported := range file.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			return unquoteErr
		}
		for _, denied := range forbidden {
			prefixRule := strings.HasSuffix(denied, "/")
			if path == denied || prefixRule && strings.HasPrefix(path, denied) {
				return fmt.Errorf("%s imports forbidden dependency %s", filename, path)
			}
		}
	}
	return nil
}

// assertForbiddenProductionImports rejects parser-owner imports outside verify.
func assertForbiddenProductionImports(t *testing.T, directory string, forbidden []string) {
	t.Helper()
	set := token.NewFileSet()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", directory, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filename := filepath.Join(directory, entry.Name())
		file, parseErr := parser.ParseFile(set, filename, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("ParseFile(%q) error = %v", filename, parseErr)
		}
		for _, imported := range file.Imports {
			path, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				t.Fatalf("invalid import in %s: %v", filename, unquoteErr)
			}
			for _, denied := range forbidden {
				if path == denied {
					t.Fatalf("%s imports forbidden provenance owner %s", filename, path)
				}
			}
		}
	}
}
