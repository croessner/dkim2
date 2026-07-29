// Package command owns the dkim2d Cobra process surface and process exits.
package command

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson"
	"github.com/spf13/cobra"
)

const (
	serveCommandName          = "serve"
	validateCommandName       = "validate"
	probeCommandName          = "probe"
	helpCommandName           = "help"
	completionCommandName     = "completion"
	hiddenCompletionCommand   = "__complete"
	hiddenNoDescCompletionCmd = "__completeNoDesc"

	commandUsage = `Usage:
  dkim2d serve --config <absolute-path> [flags]
  dkim2d validate --config <absolute-path>
  dkim2d probe
  dkim2d --version

Commands:
  serve    Run the DKIM2 HTTP daemon
  validate Validate configuration and protected state without serving
  probe    Check local daemon readiness

Flags:
      --config string           absolute path to the configuration document
  -h, --help                    help for dkim2d
  -v, --version                 version for dkim2d
      --listen string           override server.listen
      --policy-mode string      override policy.mode
      --replay-backend string   override replay.backend
`
	commandShapeDiagnostic   = "dkim2d: command usage error\n"
	commandRuntimeDiagnostic = "dkim2d: runtime failure\n"
)

var (
	buildVersion      = "development"
	errCommandShape   = errors.New("dkim2d command shape failure")
	errCommandRuntime = errors.New("dkim2d command runtime failure")
)

// bootstrapOwner retains the command-owned protected generation until startup transfers it.
type bootstrapOwner interface {
	Close() error
	stopTimeout() (time.Duration, error)
}

// managedApplication is the explicit Start/Wait/Stop process boundary.
type managedApplication interface {
	Start(context.Context) error
	Wait() <-chan applicationSignal
	Stop(context.Context) error
}

// applicationSignal is the app-owned content-free process exit class.
type applicationSignal = app.ApplicationSignal

// commandDependencies contains deterministic ownership seams for command tests.
type commandDependencies struct {
	load        func(string, config.FlagValues) (bootstrapOwner, error)
	build       func(bootstrapOwner, time.Duration) (managedApplication, error)
	withTimeout func(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

// protectedBootstrap adapts the concrete protected owner without exposing it to tests.
type protectedBootstrap struct {
	owner *config.Prebootstrap
}

// Close releases a generation that has not transferred to the application lifecycle.
func (b *protectedBootstrap) Close() error {
	if b == nil || b.owner == nil {
		return nil
	}
	return b.owner.Close()
}

// stopTimeout derives the exact command and Fx outer shutdown budget.
func (b *protectedBootstrap) stopTimeout() (time.Duration, error) {
	if b == nil || b.owner == nil {
		return 0, errCommandRuntime
	}
	timeout, err := app.LifecycleStopTimeout(b.owner.Snapshot().Server().ShutdownTimeout())
	if err != nil {
		return 0, errCommandRuntime
	}
	return timeout, nil
}

// newProductionApplication builds the pure Fx graph around the prebootstrap owner.
func newProductionApplication(
	owner bootstrapOwner,
	stopTimeout time.Duration,
) (managedApplication, error) {
	protected, ok := owner.(*protectedBootstrap)
	if !ok || protected == nil || protected.owner == nil || stopTimeout <= 0 {
		return nil, errCommandRuntime
	}
	application, err := app.NewApplication(
		protected.owner,
		httpjson.NewServerFactory(),
		stopTimeout,
	)
	if err != nil {
		return nil, errCommandRuntime
	}
	return application, nil
}

// productionDependencies binds Cobra to protected loading and pure Fx assembly.
func productionDependencies() commandDependencies {
	return commandDependencies{
		load: func(path string, flags config.FlagValues) (bootstrapOwner, error) {
			owner, err := config.LoadProtected(path, flags)
			if err != nil {
				return nil, errCommandRuntime
			}
			return &protectedBootstrap{owner: owner}, nil
		},
		build:       newProductionApplication,
		withTimeout: context.WithTimeout,
	}
}

// Execute runs one fresh dkim2d command and returns its stable process exit status.
func Execute(args []string, stdout, stderr io.Writer) int {
	return executeWithDependencies(args, stdout, stderr, productionDependencies())
}

// executeWithDependencies runs a deterministic command instance.
func executeWithDependencies(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) (exit int) {
	defer func() {
		if recover() != nil {
			writeDiagnostic(stderr, commandRuntimeDiagnostic)
			exit = 1
		}
	}()
	root, err := newRootCommand(stdout, stderr, deps)
	if err != nil {
		writeDiagnostic(stderr, commandRuntimeDiagnostic)
		return 1
	}
	root.SetArgs(args)
	if isCompletionProtocol(args) {
		writeDiagnostic(stderr, commandShapeDiagnostic)
		writeUsage(stderr)
		return 2
	}
	err = root.Execute()
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errCommandRuntime):
		writeDiagnostic(stderr, commandRuntimeDiagnostic)
		return 1
	default:
		writeDiagnostic(stderr, commandShapeDiagnostic)
		writeUsage(stderr)
		return 2
	}
}

// newRootCommand constructs one isolated Cobra tree without global state.
func newRootCommand(
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) (*cobra.Command, error) {
	if stdout == nil || stderr == nil || deps.load == nil || deps.build == nil ||
		deps.withTimeout == nil {
		return nil, errCommandRuntime
	}
	root := &cobra.Command{
		Use:           "dkim2d",
		Short:         "DKIM2 HTTP daemon",
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return errCommandShape
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("dkim2d {{.Version}}\n")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpFunc(func(*cobra.Command, []string) {
		writeUsage(stdout)
	})

	serve, err := newServeCommand(deps)
	if err != nil {
		return nil, err
	}
	serve.SetHelpFunc(func(*cobra.Command, []string) {
		writeUsage(stdout)
	})
	validate, err := newValidateCommand(deps)
	if err != nil {
		return nil, err
	}
	validate.SetHelpFunc(func(*cobra.Command, []string) {
		writeUsage(stdout)
	})
	root.AddCommand(serve, validate, newProbeCommand())
	return root, nil
}

// newValidateCommand constructs the non-mutating protected-state validation command.
func newValidateCommand(deps commandDependencies) (*cobra.Command, error) {
	var configPath string
	command := &cobra.Command{
		Use:           validateCommandName,
		Short:         "Validate configuration and protected state without serving",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			return runValidate(configPath, deps)
		},
	}
	command.Flags().StringVar(&configPath, "config", "", "absolute path to the configuration document")
	if err := command.MarkFlagRequired("config"); err != nil {
		return nil, errCommandRuntime
	}
	return command, nil
}

// runValidate loads and releases one complete immutable protected generation.
func runValidate(configPath string, deps commandDependencies) error {
	if !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath ||
		deps.load == nil {
		return errCommandRuntime
	}
	owner, err := loadBootstrap(
		deps.load,
		configPath,
		config.NewFlagValues("", false, "", false, "", false),
	)
	if err != nil {
		if owner != nil {
			_ = closeBootstrap(owner)
		}
		return errCommandRuntime
	}
	if owner == nil {
		return errCommandRuntime
	}
	if err := closeBootstrap(owner); err != nil {
		return errCommandRuntime
	}
	return nil
}

// newServeCommand constructs the zero-argument daemon command.
func newServeCommand(deps commandDependencies) (*cobra.Command, error) {
	var configPath string
	var listen string
	var policyMode string
	var replayBackend string

	serve := &cobra.Command{
		Use:           serveCommandName,
		Short:         "Run the DKIM2 HTTP daemon",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			flags := config.NewFlagValues(
				listen,
				command.Flags().Changed("listen"),
				policyMode,
				command.Flags().Changed("policy-mode"),
				replayBackend,
				command.Flags().Changed("replay-backend"),
			)
			return runServe(command.Context(), configPath, flags, deps)
		},
	}
	serve.Flags().StringVar(&configPath, "config", "", "absolute path to the configuration document")
	serve.Flags().StringVar(&listen, "listen", "", "override server.listen")
	serve.Flags().StringVar(&policyMode, "policy-mode", "", "override policy.mode")
	serve.Flags().StringVar(&replayBackend, "replay-backend", "", "override replay.backend")
	if err := serve.MarkFlagRequired("config"); err != nil {
		return nil, errCommandRuntime
	}
	return serve, nil
}

// runServe transfers protected ownership only after a successful Fx start.
func runServe(
	startContext context.Context,
	configPath string,
	flags config.FlagValues,
	deps commandDependencies,
) error {
	if startContext == nil || !filepath.IsAbs(configPath) {
		return errCommandRuntime
	}
	owner, err := loadBootstrap(deps.load, configPath, flags)
	if err != nil {
		if owner != nil {
			_ = closeBootstrap(owner)
		}
		return errCommandRuntime
	}
	if owner == nil {
		return errCommandRuntime
	}
	commandOwns := true
	defer func() {
		if commandOwns {
			_ = closeBootstrap(owner)
		}
	}()

	stopTimeout, err := owner.stopTimeout()
	if err != nil {
		return errCommandRuntime
	}
	application, err := deps.build(owner, stopTimeout)
	if err != nil || application == nil {
		return errCommandRuntime
	}
	startBound, startCancel := deps.withTimeout(startContext, app.LifecycleStartTimeout)
	if startBound == nil || startCancel == nil {
		return errCommandRuntime
	}
	startErr := startApplication(startBound, application)
	if startErr != nil {
		_ = cancelCommandContext(startCancel)
		return errCommandRuntime
	}
	commandOwns = false
	if err := cancelCommandContext(startCancel); err != nil {
		_ = stopApplication(application, stopTimeout, deps)
		return errCommandRuntime
	}
	return waitAndStop(startContext, application, stopTimeout, deps)
}

// loadBootstrap contains protected-loader and injected dependency panics.
func loadBootstrap(
	load func(string, config.FlagValues) (bootstrapOwner, error),
	path string,
	flags config.FlagValues,
) (owner bootstrapOwner, resultErr error) {
	defer func() {
		if recover() != nil {
			owner = nil
			resultErr = errCommandRuntime
		}
	}()
	if load == nil {
		return nil, errCommandRuntime
	}
	owner, err := load(path, flags)
	if err != nil {
		return owner, errCommandRuntime
	}
	return owner, nil
}

// closeBootstrap contains every command-side protected-owner release.
func closeBootstrap(owner bootstrapOwner) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	if owner == nil {
		return errCommandRuntime
	}
	if err := owner.Close(); err != nil {
		return errCommandRuntime
	}
	return nil
}

// isCompletionProtocol rejects Cobra's undeclared public and hidden completion surfaces.
func isCompletionProtocol(args []string) bool {
	if len(args) == 0 {
		return false
	}
	token := args[0]
	if token == helpCommandName && len(args) > 1 {
		token = args[1]
	}
	switch token {
	case completionCommandName, hiddenCompletionCommand, hiddenNoDescCompletionCmd:
		return true
	default:
		return false
	}
}

// cancelCommandContext contains cancellation seams without changing ownership.
func cancelCommandContext(cancel context.CancelFunc) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	if cancel == nil {
		return errCommandRuntime
	}
	cancel()
	return nil
}

// startApplication contains framework or injected startup panics.
func startApplication(ctx context.Context, application managedApplication) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	return application.Start(ctx)
}

// waitAndStop always attempts one bounded stop after successful ownership transfer.
func waitAndStop(
	commandContext context.Context,
	application managedApplication,
	stopTimeout time.Duration,
	deps commandDependencies,
) (resultErr error) {
	stopped := false
	defer func() {
		if recover() != nil {
			if !stopped {
				_ = stopApplication(application, stopTimeout, deps)
			}
			resultErr = errCommandRuntime
		}
	}()
	wait := application.Wait()
	var signal applicationSignal
	var ok bool
	if wait == nil {
		signal = applicationSignal{Failed: true}
	} else {
		select {
		case signal, ok = <-wait:
		case <-commandContext.Done():
			select {
			case signal, ok = <-wait:
			default:
				signal = applicationSignal{Failed: true}
			}
		}
	}
	stopped = true
	stopErr := stopApplication(application, stopTimeout, deps)
	if !ok || signal.Failed || stopErr != nil {
		return errCommandRuntime
	}
	return nil
}

// stopApplication contains one bounded application stop and every adapter panic.
func stopApplication(
	application managedApplication,
	stopTimeout time.Duration,
	deps commandDependencies,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	stopContext, stopCancel := deps.withTimeout(context.Background(), stopTimeout)
	defer stopCancel()
	return application.Stop(stopContext)
}

// writeUsage emits the static content-free command surface.
func writeUsage(writer io.Writer) {
	if writer != nil {
		_, _ = io.WriteString(writer, commandUsage)
	}
}

// writeDiagnostic emits one stable content-free process diagnostic.
func writeDiagnostic(writer io.Writer, diagnostic string) {
	if writer != nil {
		_, _ = io.WriteString(writer, diagnostic)
	}
}
