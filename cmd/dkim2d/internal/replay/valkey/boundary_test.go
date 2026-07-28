package valkey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestProductionSourceForbidsReplayFallbacks guards the one-command mutation boundary.
func TestProductionSourceForbidsReplayFallbacks(t *testing.T) {
	forbiddenSelectors := map[string]bool{
		"As":            true,
		"DoCache":       true,
		"DoMulti":       true,
		"DoMultiCache":  true,
		"DoMultiStream": true,
		"DoStream":      true,
		"Error":         true,
		"Eval":          true,
		"Evalsha":       true,
		"Exec":          true,
		"Expire":        true,
		"Get":           true,
		"HasPrefix":     true,
		"Multi":         true,
		"Pexpire":       true,
		"Pttl":          true,
		"ToRetryable":   true,
		"Ttl":           true,
		"Watch":         true,
	}
	forbiddenCommandLiterals := map[string]bool{
		"GET": true, "EVAL": true, "EVALSHA": true, "MULTI": true,
		"EXEC": true, "PTTL": true, "TTL": true, "EXPIRE": true,
		"PEXPIRE": true,
	}
	files := productionGoFiles(t, ".")
	if len(files) == 0 {
		t.Fatal("production source audit found no files")
	}
	for _, path := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse production source %q failed", filepath.Base(path))
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				selector, ok := value.Fun.(*ast.SelectorExpr)
				if ok && forbiddenSelectors[selector.Sel.Name] {
					t.Fatalf("forbidden production selector %q in %q",
						selector.Sel.Name, filepath.Base(path))
				}
			case *ast.BasicLit:
				if value.Kind != token.STRING {
					return true
				}
				literal, err := strconv.Unquote(value.Value)
				upper := strings.ToUpper(literal)
				privilegedConfigGet := upper == "GET" && filepath.Base(path) == "wire.go"
				if err == nil && forbiddenCommandLiterals[upper] && !privilegedConfigGet {
					t.Fatalf("forbidden command literal in %q", filepath.Base(path))
				}
			}
			return true
		})
	}
}

// TestStalePublicationRemainsInsideClockTransaction guards the former lost-heal split.
func TestStalePublicationRemainsInsideClockTransaction(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "store.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "requireFreshSecurityEvidence" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("freshness owner function is missing")
	}

	totalPublications := 0
	transactionPublications := 0
	transactions := 0
	ast.Inspect(target.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "publishStaleEvidenceFailure" {
			totalPublications++
		}
		if selector.Sel.Name != "withSample" {
			return true
		}
		transactions++
		if len(call.Args) != 1 {
			t.Fatal("clock transaction does not own one callback")
		}
		callback, ok := call.Args[0].(*ast.FuncLit)
		if !ok {
			t.Fatal("clock transaction callback is not lexically closed")
		}
		ast.Inspect(callback.Body, func(callbackNode ast.Node) bool {
			callbackCall, ok := callbackNode.(*ast.CallExpr)
			if !ok {
				return true
			}
			callbackSelector, ok := callbackCall.Fun.(*ast.SelectorExpr)
			if ok && callbackSelector.Sel.Name == "publishStaleEvidenceFailure" {
				transactionPublications++
			}
			return true
		})
		return true
	})
	if transactions != 1 || totalPublications != 1 || transactionPublications != 1 {
		t.Fatalf(
			"freshness transaction=%d stale publications=(%d total,%d transactional)",
			transactions,
			totalPublications,
			transactionPublications,
		)
	}
}

// TestWorkspaceBootstrapIsExactAndNonReleasable guards the pre-tag module boundary.
func TestWorkspaceBootstrapIsExactAndNonReleasable(t *testing.T) {
	root := filepath.Clean("../../../../..")
	commandModule := readPolicyFile(t, filepath.Join(root, "cmd/dkim2d/go.mod"))
	workspace := readPolicyFile(t, filepath.Join(root, "go.work"))
	architecture := readPolicyFile(t, filepath.Join(root, "docs/ARCHITECTURE.md"))
	vendorModules := readPolicyFile(t, filepath.Join(root, "vendor/modules.txt"))
	attributes := readPolicyFile(t, filepath.Join(root, ".gitattributes"))
	makefile := readPolicyFile(t, filepath.Join(root, "Makefile"))

	const sentinel = "github.com/croessner/dkim2 v0.0.0"
	const bootstrap = "replace github.com/croessner/dkim2 v0.0.0 => ./lib"
	if strings.Count(commandModule, sentinel) != 1 ||
		strings.Contains(commandModule, "replace github.com/croessner/dkim2") {
		t.Fatal("command module does not declare the exact replace-free root sentinel")
	}
	if strings.Count(workspace, bootstrap) != 1 {
		t.Fatal("workspace does not contain the exact versioned root bootstrap")
	}
	if !strings.Contains(architecture, "non-releasable sentinel") ||
		!strings.Contains(architecture, "GOWORK=off") {
		t.Fatal("architecture does not document the non-releasable bootstrap closeout")
	}
	if !strings.Contains(vendorModules, "# "+sentinel+" => ./lib") {
		t.Fatal("workspace vendor metadata does not record the exact root bootstrap")
	}
	const whitespaceException = "vendor/golang.org/x/sys/unix/symaddr_zos_s390x.s whitespace=-blank-at-eol,-blank-at-eof\n"
	if attributes != whitespaceException {
		t.Fatal("vendor whitespace exception is not exact and path-scoped")
	}
	if !strings.Contains(makefile, "check-vendor:") ||
		!strings.Contains(makefile, "go work vendor -o") ||
		!makeTargetHasPrerequisites(
			makefile,
			"guardrails",
			"check-openapi",
			"check-vendor",
			"govulncheck",
		) {
		t.Fatal("workspace vendor reproducibility gate is missing from guardrails")
	}
}

// makeTargetHasPrerequisites checks exact prerequisite fields without assuming
// that later guardrails cannot be inserted between established requirements.
func makeTargetHasPrerequisites(makefile, target string, required ...string) bool {
	prefix := target + ":"
	for _, line := range strings.Split(makefile, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != prefix {
			continue
		}
		for _, prerequisite := range required {
			found := false
			for _, field := range fields[1:] {
				if field == prerequisite {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}

// productionGoFiles recursively returns hand-written and generated production Go files.
func productionGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".go" && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal("production source walk failed")
	}
	return files
}

// readPolicyFile loads one bounded repository policy artifact.
func readPolicyFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("policy artifact %q read failed", filepath.Base(path))
	}
	return string(content)
}
