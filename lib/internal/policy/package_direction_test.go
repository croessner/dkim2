package policy

import (
	"fmt"
	"go/parser"
	"go/token"
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
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			if entry.Name() == "generated" || entry.Name() == "openapi" {
				return fmt.Errorf("forbidden generated/runtime scope entered lib: %s", path)
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
