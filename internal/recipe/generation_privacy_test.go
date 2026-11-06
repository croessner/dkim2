package recipe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestGenerationTestsDoNotRenderProtectedPayloads guards failure output against message and recipe disclosure.
func TestGenerationTestsDoNotRenderProtectedPayloads(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	directory := filepath.Dir(current)
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "generation") || !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall || !generationTestOutputCall(call) {
				return true
			}
			for index, argument := range call.Args {
				if index == 0 {
					if literal, isLiteral := argument.(*ast.BasicLit); isLiteral && literal.Kind == token.STRING {
						format, unquoteErr := strconv.Unquote(literal.Value)
						if unquoteErr != nil || strings.Contains(format, "%q") || strings.Contains(format, "%x") || strings.Contains(format, "%X") {
							t.Fatal("generation test uses payload-rendering failure format")
						}
					}
				}
				if protectedGenerationTestExpression(argument) {
					position := fileSet.Position(call.Pos())
					t.Fatalf("generation test passes protected payload to test output: file=%s line=%d", entry.Name(), position.Line)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal("generation test privacy scan failed")
	}
}

// generationTestOutputCall reports calls that may write content to Go test output.
func generationTestOutputCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf":
		return true
	default:
		return false
	}
}

// protectedGenerationTestExpression identifies message, recipe, and toxic-marker payload expressions.
func protectedGenerationTestExpression(expression ast.Expr) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		name := strings.ToLower(value.Name)
		return strings.Contains(name, "toxic") || strings.Contains(name, "payload") || strings.Contains(name, "json") ||
			name == "previous" || name == "current" || name == "previousbytes" || name == "currentbytes" ||
			name == "literal" || name == "protected"
	case *ast.SelectorExpr:
		switch value.Sel.Name {
		case "JSON", "decodedJSON", "DecodedJSON", "UnfoldedValue", "OriginalBytes", "RawBytes", "Bytes", "Base64", "Error":
			return true
		default:
			return protectedGenerationTestExpression(value.X)
		}
	case *ast.CallExpr:
		if identifier, ok := value.Fun.(*ast.Ident); ok && (identifier.Name == "len" || identifier.Name == "cap") {
			return false
		}
		if selector, ok := value.Fun.(*ast.SelectorExpr); ok && (selector.Sel.Name == "Contains" || selector.Sel.Name == "Equal") {
			return false
		}
		if protectedGenerationTestExpression(value.Fun) {
			return true
		}
		if slices.ContainsFunc(value.Args, protectedGenerationTestExpression) {
			return true
		}
	case *ast.IndexExpr:
		return protectedGenerationTestExpression(value.X)
	case *ast.SliceExpr:
		return protectedGenerationTestExpression(value.X)
	case *ast.UnaryExpr:
		return protectedGenerationTestExpression(value.X)
	case *ast.BinaryExpr:
		switch value.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return false
		}
		return protectedGenerationTestExpression(value.X) || protectedGenerationTestExpression(value.Y)
	}
	return false
}
