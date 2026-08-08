// Package rotationruntime owns the thin offline campaign-command runtime boundary.
package rotationruntime

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
)

var errUnavailable = errors.New("rotation runtime unavailable")

// Command is one closed offline campaign action.
type Command string

// Command values enumerate the closed offline campaign actions.
const (
	CommandRun        Command = "run"
	CommandEmergency  Command = "emergency"
	CommandDNSExport  Command = "dns-export"
	CommandStatus     Command = "status"
	CommandReconcile  Command = "reconcile"
	CommandAbort      Command = "abort"
	CommandPurgePlan  Command = "purge-plan"
	CommandPurgeApply Command = "purge-apply"
)

// Request contains protected command artifacts and identity-bearing emergency input.
type Request struct {
	Command   Command
	Config    string
	Journal   string
	Plan      string
	Automatic bool
	Apply     bool
	DryRun    bool
	Machine   bool
	Emergency rotationadmin.BindingSelector
	Reason    string
	Output    string
	Batch     uint32
}

// Coordinator is the sole semantic owner invoked by the offline transport adapter.
type Coordinator interface {
	Run(context.Context, Request, *rotationadmin.Config) (rotationadmin.CommandReport, error)
}

// RunFile validates protected configuration then invokes the configured real coordinator.
func RunFile(ctx context.Context, request Request, coordinator Coordinator) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || request.Validate() != nil {
		return nil, errUnavailable
	}
	configuration, err := rotationadmin.LoadConfig(request.Config)
	if err != nil {
		return nil, errUnavailable
	}
	defer configuration.Close() //nolint:errcheck // Protected configuration cleanup cannot recover execution.
	bounded, cancel := context.WithTimeout(ctx, configuration.Deadline())
	defer cancel()
	if coordinator == nil {
		runtime, runtimeErr := NewCampaignRuntime(bounded, configuration)
		if runtimeErr != nil {
			return nil, errUnavailable
		}
		defer runtime.Close() //nolint:errcheck // Provider cleanup cannot recover execution.
		coordinator = runtime
	}
	report, runErr := coordinator.Run(bounded, request, configuration)
	encoded, encodeErr := rotationadmin.EncodeCommandReport(report, request.Machine)
	if encodeErr != nil {
		return nil, errUnavailable
	}
	if runErr != nil {
		return encoded, errUnavailable
	}
	return encoded, nil
}

// Validate rejects ambiguous command intent before protected configuration or coordinator access.
func (r Request) Validate() error { //nolint:gocyclo // Closed CLI command combinations are validated in one authoritative matrix.
	if !cleanAbsolute(r.Config) || !cleanAbsolute(r.Journal) || r.Config == r.Journal || !knownCommand(r.Command) || r.DryRun && r.Apply {
		return errUnavailable
	}
	if r.Command == CommandAbort {
		if r.Automatic || !r.Apply || r.DryRun || r.Plan != "" || r.Reason != "" || r.Emergency != (rotationadmin.BindingSelector{}) || r.Output != "" || r.Batch != 0 {
			return errUnavailable
		}
		return nil
	}
	if r.Command == CommandPurgeApply {
		return validatePurgeApply(r)
	}
	if r.Command == CommandDNSExport {
		if r.Automatic || r.Apply || r.DryRun || !cleanAbsolute(r.Output) || r.Output == r.Config || r.Output == r.Journal || r.Batch == 0 || r.Reason != "" || r.Emergency != (rotationadmin.BindingSelector{}) {
			return errUnavailable
		}
		return nil
	}
	if r.Command == CommandPurgePlan {
		if r.Automatic || r.Apply || r.DryRun || !cleanAbsolute(r.Output) || r.Output == r.Config || r.Output == r.Journal || r.Plan != "" || r.Reason != "" || r.Emergency != (rotationadmin.BindingSelector{}) || r.Batch != 0 {
			return errUnavailable
		}
		return nil
	}
	if r.Plan != "" && !cleanAbsolute(r.Plan) {
		return errUnavailable
	}
	if r.Command == CommandRun {
		if !r.Automatic || r.Reason != "" || r.Emergency != (rotationadmin.BindingSelector{}) || r.Apply == r.DryRun {
			return errUnavailable
		}
		return nil
	}
	if r.Command == CommandEmergency {
		if r.Automatic || !r.Apply || r.DryRun || r.Reason == "" || r.Emergency.Tenant == "" || r.Emergency.Domain == "" || r.Emergency.Use == "" || r.Emergency.Profile == "" {
			return errUnavailable
		}
		return nil
	}
	if r.Automatic || r.Apply || r.Reason != "" || r.Emergency != (rotationadmin.BindingSelector{}) || r.Output != "" || r.Batch != 0 {
		return errUnavailable
	}
	return nil
}

// validatePurgeApply requires a distinct exact plan artifact and an explicit bare apply token.
func validatePurgeApply(r Request) error {
	if r.Automatic || !r.Apply || r.DryRun || !cleanAbsolute(r.Plan) || r.Plan == r.Config || r.Plan == r.Journal || r.Output != "" || r.Batch != 0 || r.Reason != "" || r.Emergency != (rotationadmin.BindingSelector{}) {
		return errUnavailable
	}
	return nil
}

// knownCommand accepts the intentionally closed command vocabulary.
func knownCommand(command Command) bool {
	return command == CommandRun || command == CommandEmergency || command == CommandDNSExport || command == CommandStatus || command == CommandReconcile || command == CommandAbort || command == CommandPurgePlan || command == CommandPurgeApply
}

// cleanAbsolute accepts one canonical absolute artifact path.
func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
