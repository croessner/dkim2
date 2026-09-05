// Package command owns the dkim2ctl Cobra surface and its single exit boundary.
package command

import (
	"io"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient"
	"github.com/spf13/cobra"
)

const (
	commandSmoke   = "smoke"
	commandFixture = "fixture"
)

var buildVersion = "development"

// Execute runs the closed command surface and returns one stable exit status.
func Execute(arguments []string, stdout, stderr io.Writer) int {
	root := NewRoot(stdout, stderr)
	root.SetArgs(arguments)
	if err := root.Execute(); err != nil {
		class := testclient.ExitClassOf(err)
		if !testclient.HasExitClass(err) {
			class = testclient.ExitUsage
		}
		if !testclient.ErrorWasReported(err) {
			_ = testclient.WriteFailure(stdout, class)
		}
		return int(class)
	}
	return int(testclient.ExitOK)
}

// NewRoot constructs one isolated command tree without global mutable state.
func NewRoot(stdout, stderr io.Writer) *cobra.Command {
	options := testclient.DefaultOptions()
	application := testclient.NewApplication(stdout)
	root := &cobra.Command{
		Use:           "dkim2ctl",
		Short:         "Run bounded local DKIM2 daemon conformance checks",
		Version:       buildVersion,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return testclient.NewExitError(testclient.ExitUsage)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("dkim2ctl {{.Version}}\n")
	flags := root.PersistentFlags()
	flags.StringVar(&options.ServerURL, "server-url", options.ServerURL, "canonical loopback daemon URL")
	flags.DurationVar(&options.Timeout, "timeout", options.Timeout, "overall command deadline")
	flags.StringVar(&options.CapabilityFile, "capability-file", "", "absolute protected capability path")
	flags.StringVar(
		&options.SignCapabilityFile,
		"sign-capability-file",
		"",
		"absolute protected sign capability path",
	)
	flags.StringVar(
		&options.ReviseCapabilityFile,
		"revise-capability-file",
		"",
		"absolute protected revise capability path",
	)
	flags.StringVar(
		&options.DSNSignCapabilityFile,
		"dsn-sign-capability-file",
		"",
		"absolute protected DSN sign capability path",
	)
	flags.StringVar(
		&options.DSNPropagateCapabilityFile,
		"dsn-propagate-capability-file",
		"",
		"absolute protected DSN propagate capability path",
	)
	flags.StringVar(&options.Output, "output", options.Output, "output format")

	root.AddCommand(newSmokeCommand(application, &options))
	root.AddCommand(newFixtureCommand(application, &options))
	return root
}

// newSmokeCommand constructs the unauthenticated liveness/readiness command.
func newSmokeCommand(application *testclient.Application, options *testclient.Options) *cobra.Command {
	expectReady := true
	command := &cobra.Command{
		Use:   commandSmoke,
		Short: "Check daemon health and readiness",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := options.Validate(false); err != nil {
				return err
			}
			return application.Smoke(*options, expectReady)
		},
	}
	command.Flags().BoolVar(&expectReady, "expect-ready", true, "expected readiness state")
	return command
}

// newFixtureCommand constructs the offline validation and execution group.
func newFixtureCommand(application *testclient.Application, options *testclient.Options) *cobra.Command {
	fixture := &cobra.Command{
		Use:   commandFixture,
		Short: "Validate or run deterministic fixture documents",
		Args:  cobra.NoArgs,
	}
	fixture.AddCommand(&cobra.Command{
		Use:   "validate PATH...",
		Short: "Validate fixture documents without protected or network access",
		Args:  boundedFixtureArgs,
		RunE: func(_ *cobra.Command, arguments []string) error {
			if err := options.Validate(false); err != nil {
				return err
			}
			return application.Validate(*options, arguments)
		},
	})
	fixture.AddCommand(&cobra.Command{
		Use:   "run PATH...",
		Short: "Run validated fixture documents in deterministic order",
		Args:  boundedFixtureArgs,
		RunE: func(_ *cobra.Command, arguments []string) error {
			if err := options.Validate(false); err != nil {
				return err
			}
			return application.Run(*options, arguments)
		},
	})
	return fixture
}

// boundedFixtureArgs rejects empty and oversized fixture path sets.
func boundedFixtureArgs(_ *cobra.Command, arguments []string) error {
	if len(arguments) == 0 || len(arguments) > 256 {
		return testclient.NewExitError(testclient.ExitUsage)
	}
	return nil
}
