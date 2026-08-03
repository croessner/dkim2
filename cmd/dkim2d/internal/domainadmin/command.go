package domainadmin

import (
	"context"
	"path/filepath"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// CommandRequest is the typed identity-bearing input boundary for one offline command.
type CommandRequest struct {
	Command       Command
	ConfigPath    string
	IntentPath    string
	OperationPath string
	OutputPath    string
	Apply         bool
	Machine       bool
	ToolVersion   string
}

// PreflightCommandAuthority rejects provider substitution before concrete backend construction or I/O.
func PreflightCommandAuthority(
	ctx context.Context,
	store *JournalStore,
	command Command,
	backend datasourceadmin.BackendClass,
	authority datasourceadmin.AuthorityDescriptor,
) error {
	if ctx == nil || ctx.Err() != nil || store == nil || !command.Known() ||
		datasourceadmin.ValidateAuthority(backend, authority) != nil {
		return newError(CodeProtectedInput)
	}
	receipt, journal, exists, err := store.LoadOperation(ctx)
	if err != nil {
		return err
	}
	if receipt != nil {
		defer receipt.Close() //nolint:errcheck // Preflight releases only detached protected evidence.
	}
	if journal != nil {
		defer journal.Close() //nolint:errcheck // Preflight releases only detached protected evidence.
	}
	if !exists {
		if command == CommandPlan {
			return nil
		}
		return newError(CodeConflict)
	}
	if receipt != nil {
		if receipt.MatchesAuthority(backend, authority) {
			return nil
		}
		return newError(CodeConflict)
	}
	if journal == nil || !journal.MatchesAuthority(backend, authority) {
		return newError(CodeConflict)
	}
	return nil
}

// Validate rejects incomplete, noncanonical, or overlapping command paths.
func (r CommandRequest) Validate() error {
	if !r.Command.Known() || !cleanAbsolutePath(r.ConfigPath) ||
		!cleanAbsolutePath(r.OperationPath) || r.ConfigPath == r.OperationPath ||
		!validReportToolVersion(r.ToolVersion) || r.Apply != (r.Command == CommandActivate) {
		return newError(CodeProtectedInput)
	}
	paths := []string{r.ConfigPath, r.OperationPath}
	if r.Command == CommandPlan {
		if !cleanAbsolutePath(r.IntentPath) {
			return newError(CodeProtectedInput)
		}
		paths = append(paths, r.IntentPath)
	} else if r.IntentPath != "" {
		return newError(CodeProtectedInput)
	}
	if r.Command == CommandDNSExport {
		if !cleanAbsolutePath(r.OutputPath) {
			return newError(CodeProtectedInput)
		}
		paths = append(paths, r.OutputPath)
	} else if r.OutputPath != "" {
		return newError(CodeProtectedInput)
	}
	for left := range paths {
		for right := left + 1; right < len(paths); right++ {
			if pathsOverlap(paths[left], paths[right]) {
				return newError(CodeProtectedInput)
			}
		}
	}
	return nil
}

// cleanAbsolutePath accepts one exact canonical absolute filesystem path.
func cleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// pathsOverlap rejects equality and ancestor/descendant command artifacts.
func pathsOverlap(left, right string) bool {
	if left == right {
		return true
	}
	leftRelative, leftErr := filepath.Rel(left, right)
	rightRelative, rightErr := filepath.Rel(right, left)
	return leftErr == nil && leftRelative != ".." && !filepath.IsAbs(leftRelative) ||
		rightErr == nil && rightRelative != ".." && !filepath.IsAbs(rightRelative)
}
