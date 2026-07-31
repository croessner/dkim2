//nolint:goconst // Exact command names are repeated to prove the public tree.
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/filter"
)

// TestProductionCommandHasOneInvocableServe proves no placeholder shadows the service.
func TestProductionCommandHasOneInvocableServe(t *testing.T) {
	called := false
	var gotPath string
	command := newRootCommandWithRuntime(
		func(context.Context, string, adapter.FilterOperation, []string, io.Reader, io.Writer) int {
			return filter.ExitDefer
		},
		func(_ context.Context, path string) error {
			called, gotPath = true, path
			return nil
		},
	)
	count := 0
	for _, child := range command.Commands() {
		if child.Name() == "serve" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("production command does not have exactly one serve child")
	}
	command.SetArgs([]string{"--config", "/protected/exim.yaml", "serve"})
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatal("injected service runner failed")
	}
	if !called || gotPath != "/protected/exim.yaml" {
		t.Fatal("serve config path was not propagated")
	}
}

const (
	testCommandSender    = "<sender@example.test>"
	testCommandRecipient = "<recipient@example.test>"
)

// TestUnavailableFilterCommandsRemainSilentAndFail proves protocol-channel safety.
func TestUnavailableFilterCommandsRemainSilentAndFail(t *testing.T) {
	for _, arguments := range [][]string{
		{filterCommandName},
		{filterCommandName, filterSignCommandName},
		{filterCommandName, filterReviseCommandName},
	} {
		command := newRootCommand()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(&stderr)
		command.SetArgs(arguments)
		err := command.Execute()
		if err == nil {
			t.Fatal("unavailable filter command returned success")
		}
		if len(arguments) > 1 {
			var status *exitStatusError
			if errors.As(err, &status) && status.ExitCode() != filter.ExitDefer {
				t.Fatal("unavailable filter command did not request deferral")
			}
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("unavailable filter command wrote protocol-channel bytes")
		}
	}
}

// TestUnavailableValidFilterInvocationDefersSilently proves a pre-output
// runtime gap maps to the required sysexits temporary status.
func TestUnavailableValidFilterInvocationDefersSilently(t *testing.T) {
	command := newRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{
		filterCommandName,
		filterSignCommandName,
		"--",
		testCommandSender,
		testCommandRecipient,
	})
	err := command.Execute()
	var status *exitStatusError
	if !errors.As(err, &status) || status.ExitCode() != filter.ExitDefer ||
		stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("unavailable valid filter invocation did not defer silently")
	}
}

// TestFilterCommandPreservesDirectArgumentBoundaries proves Cobra does not
// reinterpret the quoted empty bounce path or opaque revision locator.
func TestFilterCommandPreservesDirectArgumentBoundaries(t *testing.T) {
	tests := []struct {
		arguments []string
		operation adapter.FilterOperation
		want      []string
	}{
		{
			arguments: []string{filterCommandName, filterSignCommandName, "--", "", testCommandRecipient},
			operation: adapter.FilterSign,
			want:      []string{"", "<recipient@example.test>"},
		},
		{
			arguments: []string{
				filterCommandName,
				filterReviseCommandName,
				"--",
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				testCommandSender,
				testCommandRecipient,
			},
			operation: adapter.FilterRevise,
			want: []string{
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				testCommandSender,
				testCommandRecipient,
			},
		},
	}
	for _, testCase := range tests {
		command := newRootCommandWithFilter(func(
			_ context.Context,
			operation adapter.FilterOperation,
			arguments []string,
			_ io.Reader,
			_ io.Writer,
		) int {
			if operation != testCase.operation ||
				len(arguments) != len(testCase.want) {
				t.Fatal("command changed operation or argument count")
			}
			for index := range arguments {
				if arguments[index] != testCase.want[index] {
					t.Fatal("command changed direct argument boundary")
				}
			}
			return filter.ExitSuccess
		})
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(&stderr)
		command.SetArgs(testCase.arguments)
		if err := command.Execute(); err != nil {
			t.Fatal("valid filter command failed")
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("successful command emitted non-message diagnostics")
		}
	}
}

// TestFilterCommandParsesTrustedRootConfigBeforeOpaqueArguments proves the
// protected config flag remains outside the direct Exim expansion boundary.
func TestFilterCommandParsesTrustedRootConfigBeforeOpaqueArguments(t *testing.T) {
	called := false
	var configPath string
	command := newRootCommandWithFilter(func(
		context.Context,
		adapter.FilterOperation,
		[]string,
		io.Reader,
		io.Writer,
	) int {
		called = configPath == "/protected/sign.json"
		return filter.ExitSuccess
	})
	command.PersistentFlags().StringVar(&configPath, "config", "", "")
	command.SetArgs([]string{
		"--config",
		"/protected/sign.json",
		filterCommandName,
		filterSignCommandName,
		"--",
		testCommandSender,
		testCommandRecipient,
	})
	err := command.Execute()
	if err != nil || !called {
		t.Fatalf(
			"trusted root config parsing failed error=%t called=%t configured=%t",
			err != nil,
			called,
			configPath != "",
		)
	}
}

// TestFilterCommandMapsRuntimeFailureToSilentDeferral proves every non-success
// filter result is closed to sysexits temporary failure.
func TestFilterCommandMapsRuntimeFailureToSilentDeferral(t *testing.T) {
	command := newRootCommandWithFilter(func(
		context.Context,
		adapter.FilterOperation,
		[]string,
		io.Reader,
		io.Writer,
	) int {
		return 1
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{
		filterCommandName,
		filterSignCommandName,
		"--",
		testCommandSender,
		testCommandRecipient,
	})
	err := command.Execute()
	var status *exitStatusError
	if !errors.As(err, &status) || status.ExitCode() != filter.ExitDefer {
		t.Fatal("runtime failure did not map to filter deferral")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("failed command emitted protocol-channel diagnostics")
	}
}

// TestFilterCommandContainsRuntimePanic proves an unexpected dependency panic
// cannot emit diagnostics or escape the public filter command boundary.
func TestFilterCommandContainsRuntimePanic(t *testing.T) {
	command := newRootCommandWithFilter(func(
		context.Context,
		adapter.FilterOperation,
		[]string,
		io.Reader,
		io.Writer,
	) int {
		panic("sensitive runtime detail")
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{
		filterCommandName,
		filterSignCommandName,
		"--",
		testCommandSender,
		testCommandRecipient,
	})
	err := command.Execute()
	var status *exitStatusError
	if !errors.As(err, &status) || status.ExitCode() != filter.ExitDefer {
		t.Fatal("runtime panic did not map to filter deferral")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("runtime panic emitted protocol-channel diagnostics")
	}
}

// TestFilterCommandRequiresOptionTerminator proves no untrusted expansion can
// be interpreted on a command line that omitted the explicit separator.
func TestFilterCommandRequiresOptionTerminator(t *testing.T) {
	called := false
	command := newRootCommandWithFilter(func(
		context.Context,
		adapter.FilterOperation,
		[]string,
		io.Reader,
		io.Writer,
	) int {
		called = true
		return filter.ExitSuccess
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{
		filterCommandName,
		filterSignCommandName,
		testCommandSender,
		testCommandRecipient,
	})
	err := command.Execute()
	var status *exitStatusError
	if !errors.As(err, &status) || status.ExitCode() != filter.ExitDefer || called ||
		stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("filter command accepted arguments without option terminator")
	}
}

// TestFilterCommandHelpCannotBecomeProtocolOutput proves Cobra help handling is
// disabled on the transport-filter data path.
func TestFilterCommandHelpCannotBecomeProtocolOutput(t *testing.T) {
	called := false
	command := newRootCommandWithFilter(func(
		context.Context,
		adapter.FilterOperation,
		[]string,
		io.Reader,
		io.Writer,
	) int {
		called = true
		return filter.ExitSuccess
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{filterCommandName, filterSignCommandName, "--help"})
	err := command.Execute()
	var status *exitStatusError
	if !errors.As(err, &status) || status.ExitCode() != filter.ExitDefer || called ||
		stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("filter help flag produced protocol output or reached runtime")
	}
}
