package command

import (
	"io"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationruntime"
	"github.com/spf13/cobra"
)

// rotationFlags owns one isolated campaign leaf flag set.
type rotationFlags struct {
	config    string
	journal   string
	plan      string
	automatic bool
	apply     bool
	dryRun    bool
	machine   bool
	tenant    string
	domain    string
	use       string
	profile   string
	reason    string
	output    string
	batch     uint32
}

// newRotationCommand constructs the closed, offline campaign command tree.
func newRotationCommand(stdout io.Writer, deps commandDependencies) (*cobra.Command, error) {
	group := &cobra.Command{Use: rotationCommandName, Short: "Run protected global DKIM2 rotation campaigns offline", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, RunE: func(*cobra.Command, []string) error { return errCommandShape }}
	run, err := newRotationLeaf(stdout, deps, rotationruntime.CommandRun, rotationRunCommandName)
	if err != nil {
		return nil, err
	}
	emergency, err := newRotationLeaf(stdout, deps, rotationruntime.CommandEmergency, rotationEmergencyName)
	if err != nil {
		return nil, err
	}
	dnsExport, err := newRotationLeaf(stdout, deps, rotationruntime.CommandDNSExport, rotationDNSExportName)
	if err != nil {
		return nil, err
	}
	status, err := newRotationLeaf(stdout, deps, rotationruntime.CommandStatus, domainStatusCommandName)
	if err != nil {
		return nil, err
	}
	reconcile, err := newRotationLeaf(stdout, deps, rotationruntime.CommandReconcile, domainReconcileName)
	if err != nil {
		return nil, err
	}
	abort, err := newRotationLeaf(stdout, deps, rotationruntime.CommandAbort, domainAbortCommandName)
	if err != nil {
		return nil, err
	}
	purgePlan, err := newRotationLeaf(stdout, deps, rotationruntime.CommandPurgePlan, rotationPurgePlanName)
	if err != nil {
		return nil, err
	}
	purgeApply, err := newRotationLeaf(stdout, deps, rotationruntime.CommandPurgeApply, rotationPurgeApplyName)
	if err != nil {
		return nil, err
	}
	purge := &cobra.Command{Use: rotationPurgeName, Short: "Plan or apply exact protected generation cleanup", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, RunE: func(*cobra.Command, []string) error { return errCommandShape }}
	purge.AddCommand(purgePlan, purgeApply)
	group.AddCommand(run, emergency, dnsExport, status, reconcile, abort, purge)
	return group, nil
}

// newRotationLeaf translates a closed Cobra leaf directly into the real campaign coordinator request.
func newRotationLeaf(stdout io.Writer, deps commandDependencies, operation rotationruntime.Command, name string) (*cobra.Command, error) {
	flags := &rotationFlags{}
	leaf := &cobra.Command{Use: name, Short: rotationDescription(operation), Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, RunE: func(command *cobra.Command, _ []string) error {
		if deps.rotation == nil {
			return errCommandRuntime
		}
		if command.Flags().Changed("dry-run") && command.Flags().Changed(applyFlagName) {
			return errCommandShape
		}
		request := rotationruntime.Request{Command: operation, Config: flags.config, Journal: flags.journal, Plan: flags.plan, Automatic: flags.automatic, Apply: flags.apply, DryRun: flags.dryRun && !command.Flags().Changed(applyFlagName), Machine: flags.machine, Emergency: rotationadmin.BindingSelector{Tenant: flags.tenant, Domain: flags.domain, Use: flags.use, Profile: flags.profile}, Reason: flags.reason, Output: flags.output, Batch: flags.batch}
		output, err := deps.rotation(command.Context(), request)
		if len(output) > 0 {
			if _, writeErr := stdout.Write(output); writeErr != nil {
				return errCommandRuntime
			}
		}
		if err != nil || len(output) == 0 {
			return errCommandRuntime
		}
		return nil
	}}
	leaf.Flags().StringVar(&flags.config, "config", "", "absolute protected campaign configuration")
	leaf.Flags().StringVar(&flags.journal, "journal", "", "absolute protected campaign journal")
	leaf.Flags().BoolVar(&flags.machine, "machine", false, "emit deterministic bounded machine JSON")
	if leaf.MarkFlagRequired("config") != nil || leaf.MarkFlagRequired("journal") != nil {
		return nil, errCommandRuntime
	}
	switch operation {
	case rotationruntime.CommandRun:
		leaf.Flags().BoolVar(&flags.automatic, automaticFlagName, false, "authorize normal scheduled global rotation only")
		leaf.Flags().BoolVar(&flags.dryRun, "dry-run", true, "plan normal rotation without backend or DNS writes")
		leaf.Flags().BoolVar(&flags.apply, applyFlagName, false, "authorize one campaign execution after dry-run review")
		if leaf.MarkFlagRequired(automaticFlagName) != nil {
			return nil, errCommandRuntime
		}
	case rotationruntime.CommandEmergency:
		leaf.Flags().StringVar(&flags.tenant, "tenant", "", "exact emergency tenant binding")
		leaf.Flags().StringVar(&flags.domain, "domain", "", "exact emergency domain binding")
		leaf.Flags().StringVar(&flags.use, "use", "", "exact emergency profile use")
		leaf.Flags().StringVar(&flags.profile, "profile", "", "exact emergency profile binding")
		leaf.Flags().StringVar(&flags.reason, "reason", "", "bounded emergency reason")
		leaf.Flags().BoolVar(&flags.apply, applyFlagName, false, "authorize one explicit emergency campaign")
		for _, flag := range []string{"tenant", "domain", "use", "profile", "reason", applyFlagName} {
			if leaf.MarkFlagRequired(flag) != nil {
				return nil, errCommandRuntime
			}
		}
	case rotationruntime.CommandDNSExport:
		leaf.Flags().StringVar(&flags.output, "output", "", "absolute protected DNS batch artifact")
		leaf.Flags().Uint32Var(&flags.batch, "batch", 0, "one deterministic DNS batch ordinal")
		if leaf.MarkFlagRequired("output") != nil || leaf.MarkFlagRequired("batch") != nil {
			return nil, errCommandRuntime
		}
	case rotationruntime.CommandPurgeApply:
		leaf.Flags().StringVar(&flags.plan, "plan", "", "absolute protected exact purge plan")
		leaf.Flags().BoolVar(&flags.apply, applyFlagName, false, "authorize destruction only for the exact protected plan")
		if leaf.MarkFlagRequired("plan") != nil || leaf.MarkFlagRequired(applyFlagName) != nil {
			return nil, errCommandRuntime
		}
	case rotationruntime.CommandAbort:
		leaf.Flags().BoolVar(&flags.apply, applyFlagName, false, "persist exact terminal abort evidence before changing the journal")
		if leaf.MarkFlagRequired(applyFlagName) != nil {
			return nil, errCommandRuntime
		}
	case rotationruntime.CommandPurgePlan:
		leaf.Flags().StringVar(&flags.output, "output", "", "absolute protected create-only purge plan artifact")
		if leaf.MarkFlagRequired("output") != nil {
			return nil, errCommandRuntime
		}
	}
	return leaf, nil
}

// rotationDescription documents the one-candidate and explicit destructive intent contract.
func rotationDescription(operation rotationruntime.Command) string {
	switch operation {
	case rotationruntime.CommandRun:
		return "Run or resume one scheduled global campaign with one candidate and one final current move"
	case rotationruntime.CommandEmergency:
		return "Run one explicit exact-binding emergency campaign"
	case rotationruntime.CommandDNSExport:
		return "Write one protected DNS batch artifact for an external authorized publisher"
	case rotationruntime.CommandStatus:
		return "Inspect campaign state without mutation"
	case rotationruntime.CommandReconcile:
		return "Reconcile exact backend state without blind retry"
	case rotationruntime.CommandAbort:
		return "Abort one verified nonactivating campaign with immutable terminal evidence"
	case rotationruntime.CommandPurgePlan:
		return "Create a read-only exact retention purge plan"
	case rotationruntime.CommandPurgeApply:
		return "Apply only one exact previously reviewed purge plan"
	default:
		return ""
	}
}
