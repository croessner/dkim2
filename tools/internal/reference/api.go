//nolint:goconst // The fixed compatibility base stays explicit at each trust decision.
package reference

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/interop"
	"github.com/croessner/dkim2/tools/internal/strictjson"
	"golang.org/x/mod/modfile"
)

const (
	apiSchemaName   = "dkim2.go-api.v1"
	apiBaselinePath = "testdata/reference/go-api-base.json"
	maxAPIBytes     = int64(2 << 20)
)

// APIBaseline binds the exported library surface to an exact reviewed revision.
type APIBaseline struct {
	Schema       string `json:"schema"`
	BaseRevision string `json:"base_revision"`
	APISHA256    string `json:"api_sha256"`
	Declarations int    `json:"declarations"`
}

// GenerateAPIManifest renders the deterministic exported root library surface.
func GenerateAPIManifest(root string) ([]byte, int, error) {
	moduleContent, err := artifactpath.ReadFile(root, "lib/go.mod", maxAPIBytes)
	if err != nil {
		return nil, 0, errors.New("api_module")
	}
	moduleFile, err := modfile.Parse("lib/go.mod", moduleContent, nil)
	if err != nil || moduleFile.Module == nil || moduleFile.Go == nil ||
		moduleFile.Module.Mod.Path != "github.com/croessner/dkim2" {
		return nil, 0, errors.New("api_module")
	}
	var directDependencies []string
	for _, requirement := range moduleFile.Require {
		if !requirement.Indirect {
			directDependencies = append(
				directDependencies,
				requirement.Mod.Path+"@"+requirement.Mod.Version,
			)
		}
	}
	slices.Sort(directDependencies)
	entries, err := os.ReadDir(filepath.Join(root, "lib"))
	if err != nil {
		return nil, 0, errors.New("api_directory")
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasSuffix(name, ".go") &&
			!strings.HasSuffix(name, "_test.go") {
			paths = append(paths, "lib/"+name)
		}
	}
	slices.Sort(paths)
	fileSet := token.NewFileSet()
	var declarations []string
	for _, path := range paths {
		content, err := artifactpath.ReadFile(root, path, maxAPIBytes)
		if err != nil {
			return nil, 0, errors.New("api_source")
		}
		file, err := parser.ParseFile(fileSet, path, content, parser.ParseComments)
		if err != nil || file.Name.Name != "dkim2" {
			return nil, 0, errors.New("api_parse")
		}
		ast.FileExports(file)
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				if !function.Name.IsExported() || !exportedReceiver(function.Recv) {
					continue
				}
				function.Body = nil
			}
			var output bytes.Buffer
			if err := format.Node(&output, fileSet, declaration); err != nil {
				return nil, 0, errors.New("api_render")
			}
			text := strings.TrimSpace(output.String())
			if text != "" {
				declarations = append(declarations, text)
			}
		}
	}
	slices.Sort(declarations)
	var output bytes.Buffer
	fmt.Fprintln(&output, "schema:", apiSchemaName)
	fmt.Fprintln(&output, "module:", moduleFile.Module.Mod.Path)
	fmt.Fprintln(&output, "go:", moduleFile.Go.Version)
	fmt.Fprintln(&output, "package: dkim2")
	for _, dependency := range directDependencies {
		fmt.Fprintln(&output, "direct:", dependency)
	}
	for _, declaration := range declarations {
		fmt.Fprintln(&output, "---")
		fmt.Fprintln(&output, declaration)
	}
	return output.Bytes(), len(declarations), nil
}

// CheckAPI compares the current exported library surface with the reviewed base.
func CheckAPI(root string) error {
	content, err := artifactpath.ReadFile(root, apiBaselinePath, maxAPIBytes)
	if err != nil {
		return errors.New("api_baseline")
	}
	var baseline APIBaseline
	if err := strictjson.Decode(content, &baseline, 8, 128); err != nil {
		return errors.New("api_baseline")
	}
	if baseline.Schema != apiSchemaName ||
		baseline.BaseRevision != candidateBaseRevision ||
		baseline.Declarations < 1 {
		return errors.New("api_baseline")
	}
	manifest, declarations, err := GenerateAPIManifest(root)
	if err != nil {
		return err
	}
	if declarations != baseline.Declarations || interop.SHA256(manifest) != baseline.APISHA256 {
		return errors.New("api_changed")
	}
	return nil
}

// exportedReceiver reports whether a function or exported receiver is public.
func exportedReceiver(receiver *ast.FieldList) bool {
	if receiver == nil {
		return true
	}
	if len(receiver.List) != 1 {
		return false
	}
	expression := receiver.List[0].Type
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = pointer.X
	}
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.IsExported()
}
