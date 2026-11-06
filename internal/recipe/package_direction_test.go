package recipe

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestRecipeProductionDependencyDirection keeps protocol coordination outside recipe ownership.
func TestRecipeProductionDependencyDirection(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	directory := filepath.Dir(current)
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != directory && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if forbiddenRecipeProductionImport(name) {
				t.Fatalf("%s imports forbidden owner %s", entry.Name(), name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("recursive recipe dependency scan failed")
	}
}

// forbiddenRecipeProductionImport identifies protocol-owner and runtime/service dependencies outside recipe scope.
func forbiddenRecipeProductionImport(path string) bool {
	const module = "github.com/croessner/dkim2/"
	for _, prefix := range []string{
		module + "internal/canonical", module + "internal/instance", module + "internal/verify", module + "internal/service",
		module + "internal/datasource", module + "internal/observability", module + "internal/signature", module + "internal/keyresolver", module + "internal/policy",
		module + "cmd", module + "runtime", module + "openapi", module + "docs/specs/openapi",
		"github.com/getkin/kin-openapi", "github.com/oapi-codegen/", "github.com/deepmap/oapi-codegen/",
		"github.com/spf13/cobra", "github.com/spf13/viper", "go.uber.org/fx",
		"github.com/prometheus/", "go.opentelemetry.io/",
	} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix+"/") || strings.HasSuffix(prefix, "/") && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	switch path {
	case "encoding/json", "log", "log/slog", "expvar", "runtime", "runtime/trace", "net/http", "flag":
		return true
	default:
		return false
	}
}

// TestForbiddenRecipeProductionImportMatcher proves every required owner class and allowed dependency lane.
func TestForbiddenRecipeProductionImportMatcher(t *testing.T) {
	tests := []struct {
		path      string
		forbidden bool
	}{
		{path: "github.com/croessner/dkim2/internal/canonical", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/instance/subpackage", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/verify", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/service", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/datasource", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/observability", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/signature", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/keyresolver", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/policy", forbidden: true},
		{path: "github.com/croessner/dkim2/cmd/dkim2d", forbidden: true},
		{path: "github.com/croessner/dkim2/runtime", forbidden: true},
		{path: "github.com/croessner/dkim2/openapi/generated", forbidden: true},
		{path: "github.com/getkin/kin-openapi/openapi3", forbidden: true},
		{path: "github.com/spf13/cobra", forbidden: true},
		{path: "github.com/spf13/viper", forbidden: true},
		{path: "go.uber.org/fx", forbidden: true},
		{path: "github.com/prometheus/client_golang/prometheus", forbidden: true},
		{path: "go.opentelemetry.io/otel", forbidden: true},
		{path: "log", forbidden: true},
		{path: "log/slog", forbidden: true},
		{path: "expvar", forbidden: true},
		{path: "runtime/trace", forbidden: true},
		{path: "net/http", forbidden: true},
		{path: "flag", forbidden: true},
		{path: "encoding/json", forbidden: true},
		{path: "github.com/croessner/dkim2/internal/rawmsg", forbidden: false},
		{path: "bytes", forbidden: false},
		{path: "strconv", forbidden: false},
	}
	for _, test := range tests {
		if got := forbiddenRecipeProductionImport(test.path); got != test.forbidden {
			t.Fatal("recipe production import matcher classification differs")
		}
	}
}
