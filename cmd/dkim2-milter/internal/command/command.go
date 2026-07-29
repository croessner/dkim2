// Package command owns the dkim2-milter Cobra surface and stable process exits.
package command

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon"
	"github.com/spf13/cobra"
)

var buildVersion = "development"

const (
	serveCommandName    = "serve"
	validateCommandName = "validate"
	probeCommandName    = "probe"

	commandUsage = `Usage:
  dkim2-milter serve --config <absolute-path>
  dkim2-milter validate --config <absolute-path>
  dkim2-milter probe --config <absolute-path>
  dkim2-milter --version

Commands:
  serve    Run the DKIM2 Milter adapter
  validate Validate configuration and route capability without serving
  probe    Check one owned Unix listener

Flags:
      --config string   absolute path to the configuration document
  -h, --help            help for dkim2-milter
  -v, --version         version for dkim2-milter
`
	commandShapeDiagnostic    = "dkim2-milter: command usage error\n"
	commandRuntimeDiagnostic  = "dkim2-milter: runtime failure\n"
	helpCommandName           = "help"
	completionCommandName     = "completion"
	hiddenCompletionCommand   = "__complete"
	hiddenNoDescCompletionCmd = "__completeNoDesc"
)

var (
	errCommandShape   = errors.New("dkim2-milter command shape failure")
	errCommandRuntime = errors.New("dkim2-milter command runtime failure")
)

// managedApplication is the explicit Fx Start/Wait/Stop process boundary.
type managedApplication interface {
	Start(context.Context) error
	Done() <-chan os.Signal
	Stop(context.Context) error
}

// protectedCapability owns one loaded route capability during validation.
type protectedCapability interface {
	Close() error
}

// commandDependencies owns deterministic process seams for tests.
type commandDependencies struct {
	load           func(string) (config.Snapshot, error)
	loadCapability func(string) (protectedCapability, error)
	build          func(config.Snapshot, io.Writer) (managedApplication, error)
	withTimeout    func(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

// productionDependencies connects the strict loader to the Fx graph.
func productionDependencies() commandDependencies {
	return commandDependencies{
		load: config.Load,
		loadCapability: func(path string) (protectedCapability, error) {
			return daemon.LoadCapability(path)
		},
		build: func(snapshot config.Snapshot, stderr io.Writer) (managedApplication, error) {
			return app.New(snapshot, stderr)
		},
		withTimeout: context.WithTimeout,
	}
}

// Execute runs one fresh command and returns its stable process exit status.
func Execute(args []string, stdout, stderr io.Writer) int {
	return executeWithDependencies(args, stdout, stderr, productionDependencies())
}

// executeWithDependencies runs one isolated Cobra tree.
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

// newRootCommand constructs the exact public command and flag surface.
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
		Use:           "dkim2-milter",
		Short:         "DKIM2 Milter adapter",
		Version:       buildVersion,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			return errCommandShape
		},
	}
	root.SetVersionTemplate("dkim2-milter {{.Version}}\n")
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpFunc(func(*cobra.Command, []string) { writeUsage(stdout) })
	serve, err := newServeCommand(stderr, deps)
	if err != nil {
		return nil, err
	}
	serve.SetHelpFunc(func(*cobra.Command, []string) { writeUsage(stdout) })
	validate, err := newValidateCommand(deps)
	if err != nil {
		return nil, err
	}
	validate.SetHelpFunc(func(*cobra.Command, []string) { writeUsage(stdout) })
	root.AddCommand(serve, validate, newProbeCommand(deps.load))
	return root, nil
}

// newValidateCommand constructs the non-mutating protected-state validation command.
func newValidateCommand(deps commandDependencies) (*cobra.Command, error) {
	var configPath string
	command := &cobra.Command{
		Use:           validateCommandName,
		Short:         "Validate configuration and route capability without serving",
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

// runValidate loads configuration and its exact route capability without starting Fx.
func runValidate(configPath string, deps commandDependencies) error {
	if !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath ||
		deps.load == nil || deps.loadCapability == nil {
		return errCommandRuntime
	}
	snapshot, err := loadSnapshot(deps.load, configPath)
	if err != nil {
		return errCommandRuntime
	}
	capability, err := loadProtectedCapability(
		deps.loadCapability,
		snapshot.CapabilityFile(),
	)
	if err != nil {
		if capability != nil {
			_ = closeProtectedCapability(capability)
		}
		return errCommandRuntime
	}
	if capability == nil {
		return errCommandRuntime
	}
	if err := closeProtectedCapability(capability); err != nil {
		return errCommandRuntime
	}
	return nil
}

// loadSnapshot contains strict configuration-loader and injected dependency panics.
func loadSnapshot(
	load func(string) (config.Snapshot, error),
	path string,
) (snapshot config.Snapshot, resultErr error) {
	defer func() {
		if recover() != nil {
			snapshot = config.Snapshot{}
			resultErr = errCommandRuntime
		}
	}()
	if load == nil {
		return config.Snapshot{}, errCommandRuntime
	}
	snapshot, err := load(path)
	if err != nil {
		return config.Snapshot{}, errCommandRuntime
	}
	return snapshot, nil
}

// loadProtectedCapability contains protected-loader and injected dependency panics.
func loadProtectedCapability(
	load func(string) (protectedCapability, error),
	path string,
) (capability protectedCapability, resultErr error) {
	defer func() {
		if recover() != nil {
			capability = nil
			resultErr = errCommandRuntime
		}
	}()
	if load == nil {
		return nil, errCommandRuntime
	}
	capability, err := load(path)
	if err != nil {
		return capability, errCommandRuntime
	}
	return capability, nil
}

// closeProtectedCapability contains every validation-side protected release.
func closeProtectedCapability(capability protectedCapability) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	if capability == nil {
		return errCommandRuntime
	}
	if err := capability.Close(); err != nil {
		return errCommandRuntime
	}
	return nil
}

// newServeCommand constructs the config-only adapter command.
func newServeCommand(stderr io.Writer, deps commandDependencies) (*cobra.Command, error) {
	var configPath string
	serve := &cobra.Command{
		Use:           serveCommandName,
		Short:         "Run the DKIM2 Milter adapter",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			return runServe(command.Context(), configPath, stderr, deps)
		},
	}
	serve.Flags().StringVar(&configPath, "config", "", "absolute path to the configuration document")
	if err := serve.MarkFlagRequired("config"); err != nil {
		return nil, errCommandRuntime
	}
	return serve, nil
}

// runServe loads configuration, starts Fx, waits, and applies the configured stop bound.
func runServe(
	ctx context.Context,
	configPath string,
	stderr io.Writer,
	deps commandDependencies,
) error {
	if ctx == nil || stderr == nil || !filepath.IsAbs(configPath) ||
		filepath.Clean(configPath) != configPath {
		return errCommandRuntime
	}
	snapshot, err := loadSnapshot(deps.load, configPath)
	if err != nil {
		return errCommandRuntime
	}
	application, err := buildApplication(snapshot, stderr, deps)
	if err != nil {
		if application != nil {
			_ = stopApplication(application, snapshot.ShutdownTimeout(), deps)
		}
		return errCommandRuntime
	}
	if application == nil {
		return errCommandRuntime
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			_ = stopApplication(application, snapshot.ShutdownTimeout(), deps)
		}
	}()
	startContext, startCancel := deps.withTimeout(ctx, app.StartTimeout)
	if startContext == nil || startCancel == nil {
		return errCommandRuntime
	}
	if err := startApplication(startContext, application); err != nil {
		startCancel()
		return errCommandRuntime
	}
	startCancel()
	done, err := applicationDone(application)
	if err != nil {
		return errCommandRuntime
	}
	if done == nil {
		cleanupPending = false
		return stopApplication(application, snapshot.ShutdownTimeout(), deps)
	}
	select {
	case <-ctx.Done():
	case <-done:
	}
	cleanupPending = false
	return stopApplication(application, snapshot.ShutdownTimeout(), deps)
}

// buildApplication contains the Fx construction seam and panic boundary.
func buildApplication(
	snapshot config.Snapshot,
	stderr io.Writer,
	deps commandDependencies,
) (application managedApplication, resultErr error) {
	defer func() {
		if recover() != nil {
			application = nil
			resultErr = errCommandRuntime
		}
	}()
	application, err := deps.build(snapshot, stderr)
	if err != nil {
		return application, errCommandRuntime
	}
	return application, nil
}

// startApplication contains the application startup seam and panic boundary.
func startApplication(ctx context.Context, application managedApplication) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	if application == nil || ctx == nil {
		return errCommandRuntime
	}
	if err := application.Start(ctx); err != nil {
		return errCommandRuntime
	}
	return nil
}

// applicationDone contains the application wait seam and panic boundary.
func applicationDone(application managedApplication) (done <-chan os.Signal, resultErr error) {
	defer func() {
		if recover() != nil {
			done = nil
			resultErr = errCommandRuntime
		}
	}()
	if application == nil {
		return nil, errCommandRuntime
	}
	return application.Done(), nil
}

// stopApplication enforces the exact configured Fx shutdown budget.
func stopApplication(
	application managedApplication,
	timeout time.Duration,
	deps commandDependencies,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCommandRuntime
		}
	}()
	if application == nil || timeout <= 0 {
		return errCommandRuntime
	}
	stopContext, stopCancel := deps.withTimeout(context.Background(), timeout)
	if stopContext == nil || stopCancel == nil {
		return errCommandRuntime
	}
	defer stopCancel()
	if err := application.Stop(stopContext); err != nil {
		return errCommandRuntime
	}
	return nil
}

// isCompletionProtocol rejects Cobra's undeclared hidden completion surfaces.
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

// writeDiagnostic emits one constant output without formatting input.
func writeDiagnostic(writer io.Writer, diagnostic string) {
	if writer != nil {
		_, _ = io.WriteString(writer, diagnostic)
	}
}

// writeUsage emits the frozen command shape.
func writeUsage(writer io.Writer) {
	if writer != nil {
		_, _ = io.WriteString(writer, commandUsage)
	}
}
