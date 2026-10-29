package redisstore

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

// forbiddenCommandTokens are Redis command names the provider must never
// send: transactions, key deletion or expiry changes, bulk reads, and plain
// GET outside the pinned SET option and the takeover script.
var forbiddenCommandTokens = map[string]bool{
	"multi": true, "exec": true, "discard": true, "watch": true, "unwatch": true,
	"expire": true, "pexpire": true, "expireat": true, "pexpireat": true, "persist": true,
	"del": true, "unlink": true, "getdel": true, "getex": true, "getset": true,
	"incr": true, "keys": true, "scan": true, "flushdb": true, "flushall": true,
	"eval_ro": true, "evalsha_ro": true, "script": true,
}

// forbiddenClientSelectors are go-redis methods that would bypass the pinned builders.
var forbiddenClientSelectors = map[string]bool{
	"Pipeline": true, "Pipelined": true, "TxPipeline": true, "TxPipelined": true,
	"Watch": true, "Get": true, "Set": true, "SetNX": true, "SetXX": true, "SetArgs": true,
	"SetEx": true, "Del": true, "Unlink": true, "Expire": true, "PExpire": true,
	"Eval": true, "EvalSha": true, "EvalRO": true, "EvalShaRO": true, "ScriptLoad": true,
	"Process": true, "Incr": true, "Keys": true, "Scan": true, "AddHook": true,
}

// pinnedOwners are the only functions allowed to carry SET or GET tokens or
// to dispatch argument vectors.
var pinnedOwners = map[string]map[string]bool{
	commandSet:     {ownerInsert: true, ownerCommit: true},
	commandGet:     {ownerInsert: true, ownerCommit: true},
	"nx":           {ownerInsert: true},
	"xx":           {ownerCommit: true},
	"px":           {ownerInsert: true},
	"keepttl":      {ownerCommit: true},
	"Do":           {"pinnedCommand.run": true, "singleBackend.Do": true, "clusterBackend.Do": true},
	"Run":          {"leaseTakeover.run": true},
	"NewScript":    {"newStoreWithDependencies": true},
	"scriptSource": {"": true},
}

// TestProductionSourceUsesOnlyPinnedCommandBuilders is the forbidden-source
// guard: no transactions, pipelines, expiry or deletion commands, plain GET,
// or ad hoc dispatch exist outside the exact pinned builders.
func TestProductionSourceUsesOnlyPinnedCommandBuilders(t *testing.T) {
	if violation := auditPinnedCommandSource(t, "."); violation != "" {
		t.Fatal(violation)
	}
}

// TestSourceGuardRejectsMutationFixtures proves the guard detects escapes.
func TestSourceGuardRejectsMutationFixtures(t *testing.T) {
	for name, source := range map[string]string{
		"pipeline":      "package redisstore\nfunc escape(c interface{ Pipeline() any }) { c.Pipeline() }\n",
		"expire token":  "package redisstore\nfunc escape() []any { return []any{\"EXPIRE\", \"k\", 1} }\n",
		"ad hoc set":    "package redisstore\nfunc escape() []any { return []any{\"set\", \"k\", \"v\"} }\n",
		"ad hoc do":     "package redisstore\nfunc escape(c backend) { c.Do(nil, \"ping\") }\n",
		"plain get":     "package redisstore\nfunc escape(c interface{ Get() any }) { c.Get() }\n",
		"script runner": "package redisstore\nfunc escape(s interface{ Run() any }) { s.Run() }\n",
		"multi":         "package redisstore\nconst escape = \"multi\"\n",
	} {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "escape.go"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if auditPinnedCommandSource(t, directory) == "" {
			t.Fatalf("%s escaped the source guard", name)
		}
	}
}

// auditPinnedCommandSource returns the first violation in one directory's production sources.
func auditPinnedCommandSource(t *testing.T, directory string) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			owner := declarationOwner(declaration)
			if violation := auditDeclaration(declaration, owner, filepath.Base(path)); violation != "" {
				return violation
			}
		}
	}
	return ""
}

// declarationOwner names one function as "Receiver.method" or "function"; other declarations are "".
func declarationOwner(declaration ast.Decl) string {
	function, ok := declaration.(*ast.FuncDecl)
	if !ok {
		return ""
	}
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return function.Name.Name
	}
	receiver := function.Recv.List[0].Type
	if star, ok := receiver.(*ast.StarExpr); ok {
		receiver = star.X
	}
	if identifier, ok := receiver.(*ast.Ident); ok {
		return identifier.Name + "." + function.Name.Name
	}
	return function.Name.Name
}

// auditDeclaration inspects one declaration for forbidden tokens and calls.
func auditDeclaration(declaration ast.Decl, owner, file string) string {
	violation := ""
	ast.Inspect(declaration, func(node ast.Node) bool {
		if violation != "" {
			return false
		}
		switch value := node.(type) {
		case *ast.BasicLit:
			if value.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(value.Value)
			if err != nil {
				violation = file + ": unparsable string literal"
				return false
			}
			if strings.Contains(text, "redis.call(") {
				if !isScriptSourceDeclaration(declaration) {
					violation = file + ": Lua source outside leaseTakeoverScriptSource"
				}
				return false
			}
			token := strings.ToLower(text)
			if forbiddenCommandTokens[token] {
				violation = file + ": forbidden command token " + strconv.Quote(text) + " in " + owner
				return false
			}
			if allowed, pinned := pinnedOwners[token]; pinned && !allowed[owner] {
				violation = file + ": pinned token " + strconv.Quote(text) + " outside its builder in " + owner
				return false
			}
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			// sync.Once.Do takes exactly one function argument; every
			// go-redis Do takes a context plus the argument vector.
			if ok && selector.Sel.Name == "Do" && len(value.Args) != 1 &&
				!pinnedOwners["Do"][owner] {
				violation = file + ": Do outside its pinned owner in " + owner
				return false
			}
		case *ast.SelectorExpr:
			name := value.Sel.Name
			if name == "Do" {
				return true
			}
			if forbiddenClientSelectors[name] {
				violation = file + ": forbidden client call " + name + " in " + owner
				return false
			}
			if allowed, pinned := pinnedOwners[name]; pinned && !allowed[owner] {
				violation = file + ": " + name + " outside its pinned owner in " + owner
				return false
			}
		}
		return true
	})
	return violation
}

// isScriptSourceDeclaration reports whether one declaration is the single script-source constant.
func isScriptSourceDeclaration(declaration ast.Decl) bool {
	general, ok := declaration.(*ast.GenDecl)
	if !ok || general.Tok != token.CONST {
		return false
	}
	for _, specification := range general.Specs {
		value, ok := specification.(*ast.ValueSpec)
		if ok && len(value.Names) == 1 && value.Names[0].Name == "leaseTakeoverScriptSource" {
			return true
		}
	}
	return false
}
