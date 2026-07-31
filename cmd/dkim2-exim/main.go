// Package main provides the DKIM2 Exim adapter command.
//
//nolint:goconst // Cobra command names are deliberately asserted at construction sites.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/filter"
	eximruntime "github.com/croessner/dkim2/cmd/dkim2-exim/internal/runtime"
	"github.com/spf13/cobra"
)

const (
	filterCommandName       = "filter"
	filterSignCommandName   = "sign"
	filterReviseCommandName = "revise"
)

var (
	errRuntimeUnavailable = errors.New("exim adapter runtime is not configured")
)

// filterRunner owns one configured sign or revise invocation.
type filterRunner func(
	context.Context,
	adapter.FilterOperation,
	[]string,
	io.Reader,
	io.Writer,
) int

// configuredFilterRunner owns one operation plus its protected config path.
type configuredFilterRunner func(context.Context, string, adapter.FilterOperation, []string, io.Reader, io.Writer) int

// serviceRunner owns one configured inbound service invocation.
type serviceRunner func(context.Context, string) error

// exitStatusError carries a closed process status without rejected input.
type exitStatusError struct {
	status int
}

// Error returns one content-free command failure.
func (*exitStatusError) Error() string { return "exim adapter command failed" }

// ExitCode returns the closed process status.
func (e *exitStatusError) ExitCode() int {
	return filter.ExitDefer
}

// main executes the closed command surface.
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		var status *exitStatusError
		if errors.As(err, &status) {
			os.Exit(status.ExitCode())
		}
		os.Exit(1)
	}
}

// newRootCommand constructs the production one-shot filter command surface.
func newRootCommand() *cobra.Command {
	return newRootCommandWithRuntime(eximruntime.RunFilter, app.Serve)
}

// newRootCommandWithRuntime constructs the production command tree around injected runtimes.
func newRootCommandWithRuntime(run configuredFilterRunner, serve serviceRunner) *cobra.Command {
	var configPath string
	command := newRootCommandWithFilter(func(
		ctx context.Context,
		operation adapter.FilterOperation,
		arguments []string,
		input io.Reader,
		output io.Writer,
	) int {
		if run == nil {
			return filter.ExitDefer
		}
		return run(ctx, configPath, operation, arguments, input, output)
	})
	command.PersistentFlags().StringVar(
		&configPath,
		"config",
		"",
		"absolute protected adapter configuration",
	)
	command.AddCommand(newServeCommand(func(command *cobra.Command) error {
		if configPath == "" || serve == nil {
			return errRuntimeUnavailable
		}
		return serve(command.Context(), configPath)
	}))
	return command
}

// newRootCommandWithFilter constructs the fixed command surface around one runtime.
func newRootCommandWithFilter(run filterRunner) *cobra.Command {
	command := &cobra.Command{
		Use:              "dkim2-exim",
		Short:            "DKIM2 Exim adapter",
		SilenceErrors:    true,
		SilenceUsage:     true,
		TraverseChildren: true,
		RunE: func(*cobra.Command, []string) error {
			return errRuntimeUnavailable
		},
	}
	command.SetIn(os.Stdin)
	command.SetOut(os.Stdout)
	command.SetErr(os.Stderr)
	filter := &cobra.Command{
		Use:           filterCommandName,
		Short:         "Run a one-shot Exim transport filter",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return errRuntimeUnavailable
		},
	}
	filter.AddCommand(
		newFilterCommand(filterSignCommandName, adapter.FilterSign, 2, run),
		newFilterCommand(filterReviseCommandName, adapter.FilterRevise, 3, run),
	)
	command.AddCommand(filter)
	return command
}

// newFilterCommand constructs one exact silent operation command.
func newFilterCommand(
	name string,
	operation adapter.FilterOperation,
	argumentCount int,
	run filterRunner,
) *cobra.Command {
	return &cobra.Command{
		Use:                name,
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableFlagParsing: true,
		Args:               exactFilterArguments(argumentCount),
		RunE: func(command *cobra.Command, arguments []string) error {
			if run == nil {
				return &exitStatusError{status: filter.ExitDefer}
			}
			status := runFilterSafely(
				command.Context(),
				run,
				operation,
				slices.Clone(arguments[1:]),
				command.InOrStdin(),
				command.OutOrStdout(),
			)
			if status == filter.ExitSuccess {
				return nil
			}
			return &exitStatusError{status: status}
		},
	}
}

// runFilterSafely contains an unexpected runtime panic at the process boundary.
func runFilterSafely(
	ctx context.Context,
	run filterRunner,
	operation adapter.FilterOperation,
	arguments []string,
	input io.Reader,
	output io.Writer,
) (status int) {
	status = filter.ExitDefer
	defer func() {
		if recover() != nil {
			status = filter.ExitDefer
		}
	}()
	return run(ctx, operation, arguments, input, output)
}

// exactFilterArguments rejects missing, grouped, or injected positional values.
func exactFilterArguments(count int) cobra.PositionalArgs {
	return func(command *cobra.Command, arguments []string) error {
		if count < 1 || len(arguments) != count+1 ||
			command == nil || arguments[0] != "--" {
			return &exitStatusError{status: filter.ExitDefer}
		}
		return nil
	}
}

// newServeCommand constructs the blocking inbound service command around one configured runtime.
func newServeCommand(run func(*cobra.Command) error) *cobra.Command {
	return &cobra.Command{Use: "serve", SilenceErrors: true, SilenceUsage: true, Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if run == nil {
			return errRuntimeUnavailable
		}
		if err := run(command); err != nil {
			return errRuntimeUnavailable
		}
		return nil
	}}
}
