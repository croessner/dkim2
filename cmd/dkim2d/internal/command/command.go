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
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainruntime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/migration"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationruntime"
	"github.com/spf13/cobra"
)

const (
	serveCommandName          = "serve"
	validateCommandName       = "validate"
	probeCommandName          = "probe"
	datasourceCommandName     = "datasource"
	bootstrapCommandName      = "bootstrap-opendkim"
	rollbackCommandName       = "rollback"
	domainCommandName         = "domain"
	rotationCommandName       = "rotation"
	rotationRunCommandName    = "run"
	rotationEmergencyName     = "emergency"
	rotationDNSExportName     = "dns-export"
	rotationPurgeName         = "purge"
	rotationPurgePlanName     = "plan"
	rotationPurgeApplyName    = "apply"
	domainPlanCommandName     = "plan"
	domainPrepareCommandName  = "prepare"
	domainDNSCommandName      = "dns"
	domainDNSExportName       = "export"
	domainProveCommandName    = "prove"
	domainActivateCommandName = "activate"
	domainStatusCommandName   = "status"
	domainReconcileName       = "reconcile"
	domainAbortCommandName    = "abort"
	automaticFlagName         = "automatic"
	applyFlagName             = "apply"
	applyToken                = "--apply"
	helpCommandName           = "help"
	completionCommandName     = "completion"
	hiddenCompletionCommand   = "__complete"
	hiddenNoDescCompletionCmd = "__completeNoDesc"

	commandUsage = `Usage:
  dkim2d serve --config <absolute-path> [flags]
  dkim2d validate --config <absolute-path>
  dkim2d datasource bootstrap-opendkim --config <absolute-path> [--dry-run|--apply] [--machine]
  dkim2d datasource rollback --config <absolute-path> --generation <new-generation> [--machine]
  dkim2d datasource domain plan --config <absolute-path> --intent <absolute-path> --operation <absolute-path> [--machine]
  dkim2d datasource domain prepare --config <absolute-path> --operation <absolute-path> [--machine]
  dkim2d datasource domain dns export --config <absolute-path> --operation <absolute-path> --output <absolute-path> [--machine]
  dkim2d datasource domain prove --config <absolute-path> --operation <absolute-path> [--machine]
  dkim2d datasource domain activate --config <absolute-path> --operation <absolute-path> --apply [--machine]
  dkim2d datasource domain status --config <absolute-path> --operation <absolute-path> [--machine]
  dkim2d datasource domain reconcile --config <absolute-path> --operation <absolute-path> [--machine]
  dkim2d datasource domain abort --config <absolute-path> --operation <absolute-path> [--machine]
  dkim2d datasource rotation run --config <absolute-path> --journal <absolute-path> --automatic [--dry-run|--apply] [--machine]
  dkim2d datasource rotation emergency --config <absolute-path> --journal <absolute-path> --tenant <value> --domain <value> --use <value> --profile <value> --reason <value> --apply [--machine]
  dkim2d datasource rotation status --config <absolute-path> --journal <absolute-path> [--machine]
  dkim2d datasource rotation reconcile --config <absolute-path> --journal <absolute-path> [--machine]
  dkim2d datasource rotation abort --config <absolute-path> --journal <absolute-path> --apply [--machine]
  dkim2d datasource rotation purge plan --config <absolute-path> --journal <absolute-path> --output <absolute-path> [--machine]
  dkim2d datasource rotation purge apply --config <absolute-path> --journal <absolute-path> --plan <absolute-path> --apply [--machine]
  dkim2d probe
  dkim2d --version

Commands:
  serve    Run the DKIM2 HTTP daemon
  validate Validate configuration and protected state without serving
  datasource Run offline datasource administration
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
	dryRun      func(context.Context, string, bool, string) ([]byte, error)
	apply       func(context.Context, string, bool, string) ([]byte, error)
	rollback    func(context.Context, string, string, bool, string) ([]byte, error)
	domain      func(context.Context, domainadmin.CommandRequest) ([]byte, error)
	rotation    func(context.Context, rotationruntime.Request) ([]byte, error)
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
		dryRun:      migration.RunDryRunFile,
		apply:       migration.RunApplyFile,
		rollback:    migration.RunRollbackFile,
		domain:      domainruntime.RunCommandFile,
		rotation: func(ctx context.Context, request rotationruntime.Request) ([]byte, error) {
			return rotationruntime.RunFile(ctx, request, nil)
		},
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
	if (isDomainActivation(args) || isRotationApply(args)) && !hasExactApplyToken(args) {
		writeDiagnostic(stderr, commandShapeDiagnostic)
		writeUsage(stderr)
		return 2
	}
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
	datasource, err := newDatasourceCommand(stdout, deps)
	if err != nil {
		return nil, err
	}
	root.AddCommand(serve, validate, datasource, newProbeCommand())
	return root, nil
}

// newDatasourceCommand constructs the offline administrative command group.
func newDatasourceCommand(
	stdout io.Writer,
	deps commandDependencies,
) (*cobra.Command, error) {
	group := &cobra.Command{
		Use: datasourceCommandName, Short: "Run offline datasource administration",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error { return errCommandShape },
	}
	var configPath string
	var dryRun bool
	var apply bool
	var machine bool
	bootstrap := &cobra.Command{
		Use: bootstrapCommandName, Short: "Inventory and migrate legacy OpenDKIM data",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if !filepath.IsAbs(configPath) ||
				filepath.Clean(configPath) != configPath {
				return errCommandRuntime
			}
			var output []byte
			var err error
			switch {
			case apply && command.Flags().Changed("dry-run"):
				return errCommandShape
			case apply && deps.apply != nil:
				output, err = deps.apply(
					command.Context(), configPath, machine, buildVersion,
				)
			case !apply && dryRun && deps.dryRun != nil:
				output, err = deps.dryRun(
					command.Context(), configPath, machine, buildVersion,
				)
			default:
				return errCommandRuntime
			}
			if err != nil || len(output) == 0 {
				return errCommandRuntime
			}
			if _, err := stdout.Write(output); err != nil {
				return errCommandRuntime
			}
			return nil
		},
	}
	bootstrap.Flags().StringVar(
		&configPath, "config", "", "absolute protected migration configuration",
	)
	bootstrap.Flags().BoolVar(
		&dryRun, "dry-run", true, "validate without publication",
	)
	bootstrap.Flags().BoolVar(
		&apply, "apply", false, "publish one exact fenced generation",
	)
	bootstrap.Flags().BoolVar(
		&machine, "machine", false, "emit deterministic machine JSON",
	)
	if err := bootstrap.MarkFlagRequired("config"); err != nil {
		return nil, errCommandRuntime
	}
	var rollbackConfigPath string
	var rollbackGeneration string
	var rollbackMachine bool
	rollback := &cobra.Command{
		Use: rollbackCommandName, Short: "Republish prior content under a higher generation",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if deps.rollback == nil || !filepath.IsAbs(rollbackConfigPath) ||
				filepath.Clean(rollbackConfigPath) != rollbackConfigPath ||
				rollbackGeneration == "" {
				return errCommandRuntime
			}
			output, err := deps.rollback(
				command.Context(), rollbackConfigPath, rollbackGeneration,
				rollbackMachine, buildVersion,
			)
			if err != nil || len(output) == 0 {
				return errCommandRuntime
			}
			if _, err := stdout.Write(output); err != nil {
				return errCommandRuntime
			}
			return nil
		},
	}
	rollback.Flags().StringVar(
		&rollbackConfigPath, "config", "", "absolute protected migration configuration",
	)
	rollback.Flags().StringVar(
		&rollbackGeneration, "generation", "", "strictly higher publication generation",
	)
	rollback.Flags().BoolVar(
		&rollbackMachine, "machine", false, "emit deterministic machine JSON",
	)
	if rollback.MarkFlagRequired("config") != nil ||
		rollback.MarkFlagRequired("generation") != nil {
		return nil, errCommandRuntime
	}
	domain, err := newDomainCommand(stdout, deps)
	if err != nil {
		return nil, err
	}
	rotation, err := newRotationCommand(stdout, deps)
	if err != nil {
		return nil, err
	}
	group.AddCommand(bootstrap, rollback, domain, rotation)
	return group, nil
}

// isDomainActivation recognizes only the stable activation command prefix.
func isDomainActivation(args []string) bool {
	return len(args) >= 3 && args[0] == datasourceCommandName &&
		args[1] == domainCommandName && args[2] == domainActivateCommandName
}

// isRotationApply recognizes only destructive campaign command prefixes.
func isRotationApply(args []string) bool {
	return len(args) >= 3 && args[0] == datasourceCommandName && args[1] == rotationCommandName &&
		(args[2] == rotationEmergencyName || args[2] == domainAbortCommandName || len(args) >= 4 && args[2] == rotationPurgeName && args[3] == rotationPurgeApplyName)
}

// hasExactApplyToken accepts exactly one bare authorization token and no variant.
func hasExactApplyToken(args []string) bool {
	count := 0
	for _, argument := range args[3:] {
		if argument == applyToken {
			count++
			continue
		}
		if argument == "-a" || len(argument) > len(applyToken) && argument[:len(applyToken)] == applyToken {
			return false
		}
	}
	return count == 1
}

// domainFlagValues owns one isolated leaf-command flag set.
type domainFlagValues struct {
	config    string
	intent    string
	operation string
	output    string
	apply     bool
	machine   bool
}

// newDomainCommand constructs the exact offline native-domain command tree.
func newDomainCommand(stdout io.Writer, deps commandDependencies) (*cobra.Command, error) {
	group := &cobra.Command{
		Use: domainCommandName, Short: "Run protected native domain onboarding offline",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error { return errCommandShape },
	}
	plan, err := newDomainLeaf(stdout, deps, domainadmin.CommandPlan, domainPlanCommandName, true, false, false)
	if err != nil {
		return nil, err
	}
	prepare, err := newDomainLeaf(stdout, deps, domainadmin.CommandPrepare, domainPrepareCommandName, false, false, false)
	if err != nil {
		return nil, err
	}
	prove, err := newDomainLeaf(stdout, deps, domainadmin.CommandProve, domainProveCommandName, false, false, false)
	if err != nil {
		return nil, err
	}
	activate, err := newDomainLeaf(stdout, deps, domainadmin.CommandActivate, domainActivateCommandName, false, false, true)
	if err != nil {
		return nil, err
	}
	status, err := newDomainLeaf(stdout, deps, domainadmin.CommandStatus, domainStatusCommandName, false, false, false)
	if err != nil {
		return nil, err
	}
	reconcile, err := newDomainLeaf(stdout, deps, domainadmin.CommandReconcile, domainReconcileName, false, false, false)
	if err != nil {
		return nil, err
	}
	abort, err := newDomainLeaf(stdout, deps, domainadmin.CommandAbort, domainAbortCommandName, false, false, false)
	if err != nil {
		return nil, err
	}
	dnsExport, err := newDomainLeaf(stdout, deps, domainadmin.CommandDNSExport, domainDNSExportName, false, true, false)
	if err != nil {
		return nil, err
	}
	dns := &cobra.Command{
		Use: domainDNSCommandName, Short: "Manage export-only DNS proof artifacts",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error { return errCommandShape },
	}
	dns.AddCommand(dnsExport)
	group.AddCommand(plan, prepare, dns, prove, activate, status, reconcile, abort)
	return group, nil
}

// newDomainLeaf translates one isolated flag set into a typed domain request.
func newDomainLeaf(
	stdout io.Writer,
	deps commandDependencies,
	operation domainadmin.Command,
	name string,
	wantIntent bool,
	wantOutput bool,
	wantApply bool,
) (*cobra.Command, error) {
	flags := &domainFlagValues{}
	leaf := &cobra.Command{
		Use: name, Short: domainCommandDescription(operation),
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if deps.domain == nil {
				return errCommandRuntime
			}
			request := domainadmin.CommandRequest{
				Command: operation, ConfigPath: flags.config, IntentPath: flags.intent,
				OperationPath: flags.operation, OutputPath: flags.output,
				Apply: flags.apply, Machine: flags.machine, ToolVersion: buildVersion,
			}
			output, err := deps.domain(command.Context(), request)
			if len(output) > 0 {
				if _, writeErr := stdout.Write(output); writeErr != nil {
					return errCommandRuntime
				}
			}
			if err != nil || len(output) == 0 {
				return errCommandRuntime
			}
			return nil
		},
	}
	leaf.Flags().StringVar(&flags.config, "config", "", "absolute protected domain administration configuration")
	leaf.Flags().StringVar(&flags.operation, "operation", "", "absolute protected operation journal")
	leaf.Flags().BoolVar(&flags.machine, "machine", false, "emit deterministic bounded machine JSON")
	if leaf.MarkFlagRequired("config") != nil || leaf.MarkFlagRequired("operation") != nil {
		return nil, errCommandRuntime
	}
	if wantIntent {
		leaf.Flags().StringVar(&flags.intent, "intent", "", "absolute protected closed domain intent")
		if leaf.MarkFlagRequired("intent") != nil {
			return nil, errCommandRuntime
		}
	}
	if wantOutput {
		leaf.Flags().StringVar(&flags.output, "output", "", "absolute protected DNS export artifact")
		if leaf.MarkFlagRequired("output") != nil {
			return nil, errCommandRuntime
		}
	}
	if wantApply {
		leaf.Flags().BoolVar(&flags.apply, applyFlagName, false, "authorize one exact activation after fresh recursive resolver proof")
		if leaf.MarkFlagRequired(applyFlagName) != nil {
			return nil, errCommandRuntime
		}
	}
	return leaf, nil
}

// domainCommandDescription documents the bounded offline behavior of one command.
func domainCommandDescription(command domainadmin.Command) string {
	switch command {
	case domainadmin.CommandPlan:
		return "Resume or create protected planning evidence before backend mutation"
	case domainadmin.CommandPrepare:
		return "Generate and stage one complete inactive candidate"
	case domainadmin.CommandDNSExport:
		return "Write DNS records only to one protected export artifact"
	case domainadmin.CommandProve:
		return "Prove DNS through one fresh recursive resolver path"
	case domainadmin.CommandActivate:
		return "Reprove DNS and explicitly activate the exact staged candidate"
	case domainadmin.CommandStatus:
		return "Inspect protected operation and backend state without mutation"
	case domainadmin.CommandReconcile:
		return "Explicitly update journal knowledge from exact backend inspection"
	case domainadmin.CommandAbort:
		return "Record an authorized non-destructive stop when exact evidence permits"
	default:
		return ""
	}
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
