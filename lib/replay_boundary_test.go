package dkim2

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

const (
	replayModulePath             = "github.com/croessner/dkim2"
	replayInternalPrefix         = replayModulePath + "/internal/"
	replayCoreImportPath         = replayModulePath + "/internal/replay"
	approvedValkeyProductionPath = "cmd/dkim2d/internal/replay/valkey"
	replayMemoryConfigType       = "ReplayMemoryConfig"
	useStorageKeyFunction        = "UseStorageKey"
	useReplayStorageKeyFunction  = "UseReplayStorageKey"
)

// TestReplayPublicAPIDeclaresNoConstructorOrRawFactEscape guards the root surface.
func TestReplayPublicAPIDeclaresNoConstructorOrRawFactEscape(t *testing.T) {
	root := replayRepositoryRoot(t)
	files := parseProductionGoTree(t, filepath.Join(root, "lib"))
	audit := auditReplayPublicAPI(root, files)
	if audit.violation != "" {
		t.Fatal(audit.violation)
	}
	if len(audit.functions) != 0 || len(audit.types) != 0 || len(audit.constants) != 0 {
		t.Fatalf("required replay facade declarations absent: functions=%v types=%v constants=%v",
			audit.functions, audit.types, audit.constants)
	}
}

// TestReplayProtectedCallbackProductionCallersAreAllowlisted guards the privacy-sensitive seam.
func TestReplayProtectedCallbackProductionCallersAreAllowlisted(t *testing.T) {
	root := replayRepositoryRoot(t)
	audit := auditProtectedReplayReferences(root, parseProductionGoTree(t, root))
	if audit.violation != "" {
		t.Fatal(audit.violation)
	}
	if audit.internalReferences != 1 {
		t.Fatalf("internal UseStorageKey production references = %d, want 1", audit.internalReferences)
	}
}

// TestReplayBoundaryGuardsRejectMutationFixtures proves indirect and off-file escapes are detected.
func TestReplayBoundaryGuardsRejectMutationFixtures(t *testing.T) {
	t.Run("qualified function value", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(t, root, "cmd/escape/use.go", `package escape
import dkim2 "github.com/croessner/dkim2"
var use = dkim2.UseReplayStorageKey
`)
		audit := auditProtectedReplayReferences(root, parseProductionGoTree(t, root))
		if !strings.Contains(audit.violation, filepath.Join("cmd", "escape", "use.go")) {
			t.Fatalf("qualified function-value violation=%q", audit.violation)
		}
	})
	t.Run("parenthesized qualified reference", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(t, root, "cmd/escape/use.go", `package escape
import dkim2 "github.com/croessner/dkim2"
var use = (dkim2.UseReplayStorageKey)
`)
		audit := auditProtectedReplayReferences(root, parseProductionGoTree(t, root))
		if audit.violation == "" {
			t.Fatal("parenthesized protected reference escaped")
		}
	})
	t.Run("same package function value", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(t, root, "lib/escape.go", `package dkim2
var use = UseReplayStorageKey
`)
		audit := auditProtectedReplayReferences(root, parseProductionGoTree(t, root))
		if audit.violation == "" {
			t.Fatal("same-package protected reference escaped")
		}
	})
	t.Run("internal same package function value", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(
			t,
			root,
			"lib/internal/replay/escape.go",
			"package replay\nvar use = "+useStorageKeyFunction+"\n",
		)
		audit := auditProtectedReplayReferences(root, parseProductionGoTree(t, root))
		if audit.violation == "" {
			t.Fatal("same-package internal protected reference escaped")
		}
	})
	t.Run("approved provider reference", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(t, root, approvedValkeyProductionPath+"/use.go", `package valkey
import dkim2 "github.com/croessner/dkim2"
var use = dkim2.UseReplayStorageKey
`)
		audit := auditProtectedReplayReferences(root, parseProductionGoTree(t, root))
		if audit.violation != "" {
			t.Fatalf("approved provider reference rejected: %s", audit.violation)
		}
	})
	t.Run("generated production reference", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(t, root, "cmd/generated/use.go", `package generated
import dkim2 "github.com/croessner/dkim2"
var use = dkim2.UseReplayStorageKey
`)
		files := parseProductionGoTree(t, root)
		if len(files) != 1 {
			t.Fatalf("generated production files parsed=%d, want 1", len(files))
		}
		audit := auditProtectedReplayReferences(root, files)
		if audit.violation == "" {
			t.Fatal("generated protected reference escaped")
		}
	})
	t.Run("generated command internal import", func(t *testing.T) {
		root := t.TempDir()
		writeReplayGuardSource(t, root, "cmd/generated/import.go", `package generated
import _ "github.com/croessner/dkim2/internal/replay"
`)
		files := parseProductionGoTree(t, filepath.Join(root, "cmd"))
		if violation := commandInternalImportViolation(files); violation == "" {
			t.Fatal("generated command internal import escaped")
		}
	})

	publicCases := []struct {
		name   string
		source string
		want   string
	}{
		{"function", "package dkim2\nfunc UnexpectedReplayFunction() {}\n", "UnexpectedReplayFunction"},
		{"type", "package dkim2\ntype UnexpectedReplayType struct{}\n", "UnexpectedReplayType"},
		{"constant", "package dkim2\nconst UnexpectedReplayConstant = 1\n", "UnexpectedReplayConstant"},
		{"variable", "package dkim2\nvar UnexpectedReplayVariable = 1\n", "UnexpectedReplayVariable"},
		{"method", "package dkim2\ntype carrier struct{}\nfunc (carrier) UnexpectedReplayMethod() {}\n", "UnexpectedReplayMethod"},
		{"replay receiver method", "package dkim2\nfunc (" + replayMemoryConfigType + ") Raw() string { return \"\" }\n", "Raw"},
		{
			"memory config extra field",
			"package dkim2\ntype " + replayMemoryConfigType + " struct { Limits ReplayLimits; Clock ReplayClock; Secret string }\n",
			replayMemoryConfigType,
		},
		{
			"memory config wrong field type",
			"package dkim2\ntype " + replayMemoryConfigType + " struct { Limits int; Clock ReplayClock }\n",
			replayMemoryConfigType,
		},
	}
	for _, test := range publicCases {
		t.Run("public "+test.name, func(t *testing.T) {
			root := t.TempDir()
			writeReplayGuardSource(t, root, "lib/escape.go", test.source)
			audit := auditReplayPublicAPI(root, parseProductionGoTree(t, filepath.Join(root, "lib")))
			if !strings.Contains(audit.violation, test.want) {
				t.Fatalf("public %s violation=%q", test.name, audit.violation)
			}
		})
	}
	t.Run("public replay package", func(t *testing.T) {
		for _, relative := range []string{
			"lib/replay/replay.go",
			"lib/replay/temp/replay.go",
		} {
			t.Run(relative, func(t *testing.T) {
				root := t.TempDir()
				writeReplayGuardSource(t, root, relative, "package replay\ntype Store interface{}\n")
				audit := auditReplayPublicAPI(root, parseProductionGoTree(t, filepath.Join(root, "lib")))
				if !strings.Contains(audit.violation, filepath.Join("lib", "replay")) {
					t.Fatalf("public replay package violation=%q", audit.violation)
				}
			})
		}
	})
}

// TestCommandModulesCannotImportLibraryInternals guards Go internal boundaries at source level.
func TestCommandModulesCannotImportLibraryInternals(t *testing.T) {
	root := replayRepositoryRoot(t)
	if violation := commandInternalImportViolation(parseProductionGoTree(t, filepath.Join(root, "cmd"))); violation != "" {
		t.Fatal(violation)
	}
}

// TestLibraryModuleExcludesValkeyAndRedisFamilies guards exact external module ownership.
func TestLibraryModuleExcludesValkeyAndRedisFamilies(t *testing.T) {
	root := replayRepositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "lib", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for field := range strings.FieldsSeq(string(data)) {
		switch field {
		case "github.com/valkey-io/valkey-go", "github.com/redis/go-redis/v9":
			t.Fatalf("lib/go.mod contains command-owned dependency %q", field)
		}
	}
}

type parsedReplayFile struct {
	path   string
	syntax *ast.File
}

// replayRepositoryRoot returns the stable workspace root from the library package.
func replayRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// parseProductionGoTree parses every production Go source below root.
func parseProductionGoTree(t *testing.T, root string) []parsedReplayFile {
	t.Helper()
	files := make([]parsedReplayFile, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" ||
				exactRepositoryIgnoredEvidence(root, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		syntax, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files = append(files, parsedReplayFile{path: path, syntax: syntax})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// exactRepositoryIgnoredEvidence reports only root temp and artifact directories.
func exactRepositoryIgnoredEvidence(scanRoot, path string) bool {
	repositoryRoot := filepath.Clean(scanRoot)
	switch filepath.Base(repositoryRoot) {
	case "lib", "cmd":
		repositoryRoot = filepath.Dir(repositoryRoot)
	}
	cleaned := filepath.Clean(path)
	return cleaned == filepath.Join(repositoryRoot, "temp") ||
		cleaned == filepath.Join(repositoryRoot, ".artifacts")
}

// importAliases returns exact local aliases for one parsed source file.
func importAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		aliases[name] = path
	}
	return aliases
}

type replayPublicAPIAudit struct {
	functions map[string]bool
	types     map[string]bool
	constants map[string]bool
	violation string
}

// auditReplayPublicAPI validates the exact replay-related root declaration surface.
func auditReplayPublicAPI(root string, files []parsedReplayFile) replayPublicAPIAudit { //nolint:gocyclo // The declaration audit intentionally validates each closed symbol class in one pass.
	audit := replayPublicAPIAudit{
		functions: map[string]bool{
			"ReplayIdentities": true, "NewReplayError": true, "ReplayErrorCodeOf": true,
			"IsReplayError":      true,
			"NewReplayRetention": true, "DefaultReplayRetention": true,
			"NewReplayDeriver": true, "NewReplayMemoryStore": true,
			"NewReplayDisabledStore": true, useReplayStorageKeyFunction: true,
			"NewAuthenticator": true, "NewDisabledAuthenticator": true,
			"NewReplayLease": true, "FormatReplayPropagationPending": true, "ParseReplayPropagationValue": true,
		},
		types: map[string]bool{
			"ReplayKey": true, "ReplayCheck": true, "ReplayStoreState": true,
			"ReplayErrorCode": true, "ReplayError": true, "ReplayRetention": true,
			"ReplayStore": true, "ManagedReplayStore": true,
			"ReplayIdentity": true, "ReplayIdentitySet": true, "ReplayDeriver": true,
			"ReplayLimits": true, "ReplayClock": true, "ReplayClockFunc": true,
			replayMemoryConfigType: true, "ReplayMemoryStore": true, "ReplayDisabledStore": true,
			"AuthenticationReplayClass": true, "AuthenticationReason": true,
			"AuthenticationResult": true, "Authenticator": true,
			"ReplayLease": true, "ReplayPropagationState": true, "ReplayPropagationReservation": true,
			"ReplayPropagationCommit": true, "ReplayPropagationStore": true,
		},
		constants: map[string]bool{
			"ReplayKeyAlgorithm": true, "ReplayStoredValue": true,
			"ReplayCheckFirstSeen": true, "ReplayCheckReplayed": true, "ReplayCheckDisabled": true,
			"ReplayStoreReady": true, "ReplayStoreDegraded": true, "ReplayStoreDisabled": true,
			"ReplayStoreClosing": true, "ReplayStoreClosed": true,
			"ReplayErrorInvalidRequest": true, "ReplayErrorMisconfigured": true,
			"ReplayErrorLimitExceeded": true, "ReplayErrorUnavailable": true,
			"ReplayErrorIndeterminate": true, "ReplayErrorInconsistent": true,
			"ReplayErrorCancelled": true, "ReplayErrorDeadlineExceeded": true,
			"ReplayErrorClosed": true, "ReplayErrorInternalInvariant": true,
			"AuthenticationReasonReplayIndeterminate":             true,
			"AuthenticationReasonReplayEvidenceUnavailable":       true,
			"AuthenticationReasonDuplicateMessageWithoutExploded": true,
			"AuthenticationReplayNotChecked":                      true, "AuthenticationReplayDisabled": true,
			"AuthenticationReplayFirstSeen": true, "AuthenticationReplayExploded": true,
			"AuthenticationReplayReplayed": true, "AuthenticationReplayIndeterminate": true,
			"ReplayPropagationKeyDomainLabel": true, "ReplayPropagationStatePending": true,
			"ReplayPropagationStateCommitted": true, "ReplayPropagationCommittedValue": true,
			"ReplayPropagationPendingPrefix": true, "ReplayPropagationReserved": true,
			"ReplayPropagationPending": true, "ReplayPropagationAlreadyCommitted": true,
			"ReplayPropagationReservationDisabled": true, "ReplayPropagationCommitted": true,
			"ReplayPropagationCommitUnresolved": true, "ReplayPropagationCommitDisabled": true,
		},
	}
	rootPackage := filepath.Join(root, "lib")
	publicReplayPackage := filepath.Join(rootPackage, "replay")
	for _, file := range files {
		directory := filepath.Dir(file.path)
		if directory == publicReplayPackage ||
			strings.HasPrefix(directory, publicReplayPackage+string(filepath.Separator)) {
			audit.violation = "public replay package is forbidden: " + directory
			return audit
		}
		if directory != rootPackage {
			continue
		}
		facade := file.path == filepath.Join(rootPackage, "replay_facade.go") || file.path == filepath.Join(rootPackage, "authenticator.go")
		authenticatorFacade := file.path == filepath.Join(rootPackage, "authenticator.go")
		for _, declaration := range file.syntax.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(typed.Name.Name) {
					continue
				}
				if typed.Recv != nil {
					receiver := replayReceiverBaseName(typed.Recv)
					if !authenticatorFacade && (strings.Contains(typed.Name.Name, "Replay") || strings.Contains(receiver, "Replay")) {
						audit.violation = "unapproved public replay method " + typed.Name.Name + " in " + file.path
						return audit
					}
					continue
				}
				if !facade && !strings.Contains(typed.Name.Name, "Replay") {
					continue
				}
				if !audit.functions[typed.Name.Name] {
					audit.violation = "unapproved public replay function " + typed.Name.Name + " in " + file.path
					return audit
				}
				delete(audit.functions, typed.Name.Name)
			case *ast.GenDecl:
				for _, specification := range typed.Specs {
					switch value := specification.(type) {
					case *ast.TypeSpec:
						if !ast.IsExported(value.Name.Name) ||
							!facade && !strings.Contains(value.Name.Name, "Replay") {
							continue
						}
						if !audit.types[value.Name.Name] {
							audit.violation = "unapproved public replay type " + value.Name.Name + " in " + file.path
							return audit
						}
						if value.Name.Name == replayMemoryConfigType && !exactReplayMemoryConfigType(value.Type) {
							audit.violation = "invalid public replay type ReplayMemoryConfig in " + file.path
							return audit
						}
						delete(audit.types, value.Name.Name)
					case *ast.ValueSpec:
						for _, name := range value.Names {
							if !ast.IsExported(name.Name) ||
								!facade && !strings.Contains(name.Name, "Replay") {
								continue
							}
							if typed.Tok != token.CONST || !audit.constants[name.Name] {
								audit.violation = "unapproved public replay value " + name.Name + " in " + file.path
								return audit
							}
							delete(audit.constants, name.Name)
						}
					}
				}
			}
		}
	}
	return audit
}

// replayReceiverBaseName returns one receiver's declared root type name.
func replayReceiverBaseName(receiver *ast.FieldList) string {
	if receiver == nil || len(receiver.List) != 1 {
		return ""
	}
	return replayTypeBaseName(receiver.List[0].Type)
}

// replayTypeBaseName unwraps pointer, parenthesized, and generic receiver forms.
func replayTypeBaseName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return replayTypeBaseName(value.X)
	case *ast.ParenExpr:
		return replayTypeBaseName(value.X)
	case *ast.IndexExpr:
		return replayTypeBaseName(value.X)
	case *ast.IndexListExpr:
		return replayTypeBaseName(value.X)
	default:
		return ""
	}
}

// exactReplayMemoryConfigType validates the frozen two-field public config shape.
func exactReplayMemoryConfigType(expression ast.Expr) bool {
	structure, ok := expression.(*ast.StructType)
	if !ok || structure.Fields == nil || len(structure.Fields.List) != 2 {
		return false
	}
	expected := []struct {
		name     string
		typeName string
	}{
		{name: "Limits", typeName: "ReplayLimits"},
		{name: "Clock", typeName: "ReplayClock"},
	}
	for index, field := range structure.Fields.List {
		if len(field.Names) != 1 || field.Names[0].Name != expected[index].name ||
			!field.Names[0].IsExported() || field.Tag != nil ||
			replayTypeBaseName(field.Type) != expected[index].typeName {
			return false
		}
		identifier, exact := field.Type.(*ast.Ident)
		if !exact || identifier.Name != expected[index].typeName {
			return false
		}
	}
	return true
}

type protectedReplayReferenceAudit struct {
	internalReferences int
	violation          string
}

// auditProtectedReplayReferences rejects every protected-seam reference outside exact owners.
func auditProtectedReplayReferences(root string, files []parsedReplayFile) protectedReplayReferenceAudit {
	audit := protectedReplayReferenceAudit{}
	for _, file := range files {
		relative, err := filepath.Rel(root, file.path)
		if err != nil {
			audit.violation = "protected replay path cannot be relativized"
			return audit
		}
		imports := importAliases(file.syntax)
		for alias, path := range imports {
			if alias == "." && (path == replayCoreImportPath || path == replayModulePath) {
				audit.violation = "protected replay package dot-imported by " + relative
				return audit
			}
		}
		declarations := protectedReplayDeclarationPositions(file.syntax)
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			if audit.violation != "" {
				return false
			}
			switch value := node.(type) {
			case *ast.SelectorExpr:
				identifier, ok := value.X.(*ast.Ident)
				if !ok {
					return true
				}
				imported := imports[identifier.Name]
				switch {
				case imported == replayCoreImportPath && value.Sel.Name == useStorageKeyFunction:
					audit.internalReferences++
					if relative != filepath.Join("lib", "replay_facade.go") {
						audit.violation = "internal protected-key seam referenced by " + relative
					}
				case imported == replayModulePath && value.Sel.Name == useReplayStorageKeyFunction:
					if filepath.Dir(relative) != approvedValkeyProductionPath {
						audit.violation = "public protected-key seam referenced by " + relative
					}
				}
				return false
			case *ast.Ident:
				if declarations[value.Pos()] {
					return true
				}
				switch value.Name {
				case useStorageKeyFunction:
					if filepath.Dir(relative) == filepath.Join("lib", "internal", "replay") {
						audit.violation = "unqualified internal protected-key seam referenced by " + relative
					}
				case useReplayStorageKeyFunction:
					if filepath.Dir(relative) == "lib" {
						audit.violation = "unqualified public protected-key seam referenced by " + relative
					}
				}
			}
			return true
		})
		if audit.violation != "" {
			return audit
		}
	}
	return audit
}

// protectedReplayDeclarationPositions identifies only exact function declaration identifiers.
func protectedReplayDeclarationPositions(file *ast.File) map[token.Pos]bool {
	positions := make(map[token.Pos]bool, 2)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if function.Name.Name == useStorageKeyFunction || function.Name.Name == useReplayStorageKeyFunction {
			positions[function.Name.Pos()] = true
		}
	}
	return positions
}

// commandInternalImportViolation reports one command-to-library-internal dependency.
func commandInternalImportViolation(files []parsedReplayFile) string {
	for _, file := range files {
		for _, imported := range file.syntax.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return "command source contains an invalid import"
			}
			if strings.HasPrefix(path, replayInternalPrefix) {
				return file.path + " imports library internal package " + path
			}
		}
	}
	return ""
}

// writeReplayGuardSource creates one isolated production mutation fixture.
func writeReplayGuardSource(t *testing.T, root, relative, source string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
}
