package rotationruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
	"github.com/croessner/dkim2/provider"
	"gopkg.in/yaml.v3"
)

const runtimeRedacted = "campaign_runtime{redacted}"

// CampaignRuntime composes the one real provider-backed offline campaign owner.
type CampaignRuntime struct {
	backend   campaignBackend
	purge     rotationadmin.PurgeExecutor
	recovery  datasourceadmin.RetentionRecoveryReader
	terminal  datasourceadmin.TerminalRecorder
	coord     *rotationadmin.Coordinator
	prover    *rotationadmin.DNSBatchProver
	class     string
	limits    datasourceadmin.GenerationLimits
	authority datasourceadmin.AuthorityDescriptor
}

// retentionRecoverySource is the concrete provider path for bounded full
// historical evidence; it is deliberately separate from allocation inventory.
type retentionRecoverySource interface {
	RetentionRecoveryInventory(context.Context) (datasourceadmin.RetentionInventory, error)
}

// retentionRecoveryAdapter supplies the paged recovery interface from one
// provider-owned stable recovery snapshot and confirms it again at completion.
type retentionRecoveryAdapter struct {
	source    retentionRecoverySource
	terminal  datasourceadmin.TerminalRecorder
	inventory datasourceadmin.RetentionInventory
	loaded    bool
	completed bool
}

// campaignBackend is the narrow common provider seam used by the coordinator.
type campaignBackend interface {
	datasourceadmin.SnapshotReader
	datasourceadmin.GenerationPublisher
	datasourceadmin.AdministrationLocker
}

type ldapCredential struct {
	Version      string `yaml:"version"`
	BindDN       string `yaml:"bind_dn"`
	PasswordFile string `yaml:"password_file"`
}

type sqlCredential struct {
	Version      string `yaml:"version"`
	User         string `yaml:"user"`
	PasswordFile string `yaml:"password_file"`
}

// NewCampaignRuntime opens all four exact, distinct protected provider authorities.
func NewCampaignRuntime(ctx context.Context, configuration *rotationadmin.Config) (*CampaignRuntime, error) {
	if ctx == nil || ctx.Err() != nil || configuration == nil {
		return nil, errUnavailable
	}
	paths, closerPath := configuration.AuthorityPaths(), configuration.ClosurePath()
	for _, path := range paths {
		if path == "" {
			return nil, errUnavailable
		}
	}
	limits := datasourceadmin.GenerationLimits{MaxGenerations: 4096, MaxOutstandingCandidates: 8, MaxSnapshotRows: 65536, MaxSnapshotBytes: 512 << 20, BackendDeadline: 2 * time.Minute}
	if closerPath == "" || limits.Validate() != nil {
		return nil, errUnavailable
	}
	policy, lookupTimeout, proofOK := configuration.DNSProofPolicy()
	if !proofOK {
		return nil, errUnavailable
	}
	proof, proofErr := rotationadmin.NewDNSBatchProver(policy, lookupTimeout)
	if proofErr != nil {
		return nil, errUnavailable
	}
	switch configuration.Backend() {
	case "ldap":
		return openLDAPRuntime(ctx, configuration, paths, closerPath, limits, proof)
	case "postgresql":
		return openPostgreSQLRuntime(ctx, configuration, paths, closerPath, limits, proof)
	case "mysql", "mariadb":
		return openMySQLRuntime(ctx, configuration, paths, closerPath, limits, proof)
	default:
		return nil, errUnavailable
	}
}

// Run executes the one complete coordinator only after its strict proof
// authority has been constructed. DNS publication itself remains external.
func (r *CampaignRuntime) Run(ctx context.Context, request Request, configuration *rotationadmin.Config) (rotationadmin.CommandReport, error) {
	if r == nil || r.backend == nil || r.coord == nil || ctx == nil || ctx.Err() != nil || configuration == nil || r.class != configuration.Backend() {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	if request.Command == CommandRun && request.DryRun {
		return r.previewNormal(ctx, request)
	}
	if request.Command == CommandPurgePlan {
		return r.planPurge(ctx, request)
	}
	if request.Command == CommandPurgeApply {
		return r.applyPurge(ctx, request)
	}
	store, err := rotationadmin.OpenJournalStore(ctx, request.Journal)
	if err != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	defer store.Close() //nolint:errcheck // Store lock cleanup cannot recover this command.
	journal, present, err := store.Load(ctx)
	if err != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	if request.Command == CommandRun || request.Command == CommandEmergency {
		intent, intentErr := newIntent(request)
		if intentErr != nil {
			return rotationadmin.CommandReport{}, errUnavailable
		}
		if journal != nil {
			defer journal.Close() //nolint:errcheck // Coordinator owns durable state, not this read handle.
		}
		report, runErr := r.coord.Run(ctx, store, intent)
		if runErr != nil {
			if journal != nil {
				return commandReport(request.Command, journal, r.class, "reconcile_required"), errUnavailable
			}
			return rotationadmin.CommandReport{}, errUnavailable
		}
		return rotationadmin.CommandReport{Command: string(request.Command), Mode: string(report.Mode), State: report.State, Backend: r.class, WorkCount: report.WorkCount, RecordCount: report.RecordCount, BatchCount: report.BatchCount, ResultClass: report.ResultClass}, nil
	}
	if !present || journal == nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	defer journal.Close() //nolint:errcheck // Protected journal cleanup cannot recover this command.
	if request.Command == CommandAbort {
		if journal.State() == rotationadmin.StateAborted {
			return commandReport(request.Command, journal, r.class, "aborted"), nil
		}
		if _, recoverErr := rotationadmin.RecoverStaged(ctx, journal, r.backend, r.limits); recoverErr != nil {
			return commandReport(request.Command, journal, r.class, "reconcile_required"), errUnavailable
		}
		if abortErr := rotationadmin.AbortWithTerminal(ctx, journal, r.terminal, "operator_abort", time.Now().UTC()); abortErr != nil || store.Save(ctx, journal) != nil {
			return commandReport(request.Command, journal, r.class, "reconcile_required"), errUnavailable
		}
		return commandReport(request.Command, journal, r.class, "aborted"), nil
	}
	if journal.State() == rotationadmin.StateStaged || journal.State() == rotationadmin.StateDNSInProgress || journal.State() == rotationadmin.StateDNSComplete || journal.State() == rotationadmin.StateActivating || journal.State() == rotationadmin.StateActivated {
		prepared, recoverErr := rotationadmin.RecoverStaged(ctx, journal, r.backend, r.limits)
		if recoverErr != nil {
			return commandReport(request.Command, journal, r.class, "reconcile_required"), errUnavailable
		}
		defer prepared.Close() //nolint:errcheck // Recovered key-free DNS input cleanup cannot recover this command.
		if request.Command == CommandDNSExport {
			batches, batchErr := rotationadmin.BuildDNSBatches(ctx, prepared, configuration.Limits().MaxDNSBatchRecords, configuration.Limits())
			if batchErr != nil || request.Batch > uint32(len(batches)) {
				return commandReport(request.Command, journal, r.class, "unavailable"), errUnavailable
			}
			if _, exportErr := r.prover.ExportBatchDNS(ctx, request.Output, prepared, batches[request.Batch-1]); exportErr != nil {
				return commandReport(request.Command, journal, r.class, "unavailable"), errUnavailable
			}
			return commandReport(request.Command, journal, r.class, "success"), nil
		}
	}
	if request.Command != CommandStatus && request.Command != CommandReconcile {
		return commandReport(request.Command, journal, r.class, "unavailable"), errUnavailable
	}
	if journal.State() == rotationadmin.StateReconcileRequired {
		return commandReport(request.Command, journal, r.class, "reconcile_required"), errUnavailable
	}
	return commandReport(request.Command, journal, r.class, "success"), nil
}

// planPurge classifies a fresh provider-owned inventory and persists one exact key-free protected artifact.
func (r *CampaignRuntime) planPurge(ctx context.Context, request Request) (rotationadmin.CommandReport, error) {
	if r == nil || r.recovery == nil || request.Command != CommandPurgePlan || request.Output == "" {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	inventory, inventoryErr := datasourceadmin.ReadRetentionRecoveryInventory(ctx, r.recovery, datasourceadmin.DefaultRetentionRecoveryLimits())
	if inventoryErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "unavailable"}, errUnavailable
	}
	classification, classificationErr := datasourceadmin.ClassifyRetention(inventory, datasourceadmin.DefaultRetentionPolicy())
	if classificationErr != nil || classification.EligibleCount() == 0 {
		retained, unresolved := uint32(0), uint32(0)
		if classification != nil {
			retained, unresolved = classification.RetainedCount(), classification.UnresolvedCount()
		}
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, RetainedCount: retained, UnresolvedCount: unresolved, ResultClass: "no_eligible"}, errUnavailable
	}
	plan, planErr := rotationadmin.NewPurgePlan(datasourceadmin.BackendClass(r.class), r.authority, classification)
	if planErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, RetainedCount: classification.RetainedCount(), UnresolvedCount: classification.UnresolvedCount(), ResultClass: "unavailable"}, errUnavailable
	}
	defer plan.Close() //nolint:errcheck // Artifact creation is the only durable action.
	document, marshalErr := rotationadmin.MarshalPurgePlanArtifact(plan)
	if marshalErr != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	defer clear(document)
	if createErr := config.CreateProtectedDocument(ctx, request.Output, document, 262144); createErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, RetainedCount: classification.RetainedCount(), UnresolvedCount: classification.UnresolvedCount(), ResultClass: "artifact_conflict"}, errUnavailable
	}
	report := plan.Report(classification)
	return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, RetainedCount: report.RetainedCount, UnresolvedCount: report.UnresolvedCount, WorkCount: report.TargetCount, ResultClass: report.ResultClass}, nil
}

// applyPurge verifies the exact persisted artifact against a fresh inventory before using the fourth provider authority.
func (r *CampaignRuntime) applyPurge(ctx context.Context, request Request) (rotationadmin.CommandReport, error) {
	if r == nil || r.recovery == nil || r.purge == nil || request.Command != CommandPurgeApply || !request.Apply || request.DryRun || request.Plan == "" {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	document, readErr := config.ReadProtectedDocument(request.Plan, 262144)
	if readErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "artifact_invalid"}, errUnavailable
	}
	defer clear(document)
	plan, parseErr := rotationadmin.ParsePurgePlanArtifact(document)
	if parseErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "artifact_invalid"}, errUnavailable
	}
	defer plan.Close() //nolint:errcheck // Parsed protected targets must not escape this apply attempt.
	apply, applyErr := rotationadmin.NewPurgeApplyRequest(plan, true)
	if applyErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "artifact_invalid"}, errUnavailable
	}
	inventory, inventoryErr := datasourceadmin.ReadRetentionRecoveryInventory(ctx, r.recovery, datasourceadmin.DefaultRetentionRecoveryLimits())
	if inventoryErr != nil {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "unavailable"}, errUnavailable
	}
	result, executeErr := rotationadmin.ExecutePurge(ctx, apply, datasourceadmin.BackendClass(r.class), r.authority, inventory, r.purge)
	if executeErr != nil || !result.Committed || result.Unknown {
		return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "reconcile_required"}, errUnavailable
	}
	return rotationadmin.CommandReport{Command: string(request.Command), Backend: r.class, ResultClass: "purged"}, nil
}

// previewNormal constructs a complete bounded normal plan without opening a
// journal, claiming a datasource lock, generating a key, mutating DNS, or
// writing backend state.
func (r *CampaignRuntime) previewNormal(ctx context.Context, request Request) (rotationadmin.CommandReport, error) {
	if r == nil || r.backend == nil || request.Command != CommandRun || !request.Automatic || !request.DryRun || request.Apply {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	intent, intentErr := newIntent(request)
	if intentErr != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	inventory, inventoryErr := r.backend.Inventory(ctx, r.limits)
	if inventoryErr != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	candidate, allocationErr := datasourceadmin.AllocateGeneration(inventory, r.limits)
	if allocationErr != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	source, sourceErr := r.backend.ReadCurrent(ctx, r.limits)
	if sourceErr != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	defer source.Close() //nolint:errcheck // Preview has no mutation to recover.
	plan, freezeErr := rotationadmin.Freeze(ctx, source, candidate, intent, r.coord.Limits())
	if freezeErr != nil {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	defer plan.Close() //nolint:errcheck // Preview plan is private transient evidence.
	return rotationadmin.CommandReport{Command: string(request.Command), Mode: "normal", State: rotationadmin.StatePlanned, Backend: r.class, WorkCount: uint32(plan.WorkCount()), RecordCount: uint32(plan.DNSRecordCount()), ResultClass: "dry_run"}, nil
}

// Close releases provider-owned transport credentials and pools.
func (r *CampaignRuntime) Close() error {
	if r == nil {
		return nil
	}
	if closer, ok := r.backend.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	if closer, ok := r.backend.(interface{ Close() }); ok {
		closer.Close()
	}
	if closer, ok := r.purge.(interface{ Close() }); ok {
		closer.Close()
	}
	if closer, ok := r.terminal.(interface{ Close() }); ok {
		closer.Close()
	}
	r.backend, r.purge, r.recovery, r.terminal, r.coord, r.class = nil, nil, nil, nil, nil, ""
	return nil
}

// String keeps provider endpoints and principal names out of diagnostics.
func (*CampaignRuntime) String() string { return runtimeRedacted }

// GoString keeps provider endpoints and principal names out of diagnostics.
func (*CampaignRuntime) GoString() string { return runtimeRedacted }

// Format keeps provider endpoints and principal names out of diagnostics.
func (*CampaignRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeRedacted)
}

// commandReport projects only journal counts and a closed result class.
func commandReport(command Command, journal *rotationadmin.Journal, backend, result string) rotationadmin.CommandReport {
	report := journal.Report()
	return rotationadmin.CommandReport{Command: string(command), Mode: string(report.Mode), State: report.State, Backend: backend, WorkCount: report.WorkCount, RecordCount: report.RecordCount, BatchCount: report.BatchCount, ResultClass: result}
}

// openLDAPRuntime builds three lifecycle connectors plus the independent purge connector.
func openLDAPRuntime(ctx context.Context, configuration *rotationadmin.Config, paths [4]string, closerPath string, limits datasourceadmin.GenerationLimits, proof *rotationadmin.DNSBatchProver) (*CampaignRuntime, error) {
	address, serverName, baseDN, caFile, startTLS, ok := configuration.LDAPTransport()
	if !ok {
		return nil, errUnavailable
	}
	roots, err := rotationadmin.LoadTrustRoots(caFile)
	if err != nil {
		return nil, errUnavailable
	}
	credentials := make([]ldapCredential, len(paths))
	connectors := make([]*ldap.GoLDAPConnector, 0, 4)
	seen := make(map[string]struct{}, len(paths))
	for index, path := range paths {
		credential, loadErr := loadLDAPCredential(path)
		if loadErr != nil {
			closeLDAP(connectors)
			return nil, errUnavailable
		}
		if _, duplicate := seen[credential.BindDN]; duplicate {
			closeLDAP(connectors)
			return nil, errUnavailable
		}
		seen[credential.BindDN] = struct{}{}
		credentials[index] = credential
		password, passwordErr := readPassword(credential.PasswordFile)
		if passwordErr != nil {
			closeLDAP(connectors)
			return nil, errUnavailable
		}
		connector, connectorErr := ldap.NewGoLDAPConnector(ldap.ConnectionConfig{Address: address, ServerName: serverName, BaseDN: baseDN, BindDN: credential.BindDN, Password: password, RootCAs: roots, UseStartTLS: startTLS})
		clear(password)
		if connectorErr != nil {
			closeLDAP(connectors)
			return nil, errUnavailable
		}
		connectors = append(connectors, connector)
	}
	closerCredential, closerErr := loadLDAPCredential(closerPath)
	if closerErr != nil {
		closeLDAP(connectors)
		return nil, errUnavailable
	}
	if _, duplicate := seen[closerCredential.BindDN]; duplicate {
		closeLDAP(connectors)
		return nil, errUnavailable
	}
	closerPassword, closerPasswordErr := readPassword(closerCredential.PasswordFile)
	if closerPasswordErr != nil {
		closeLDAP(connectors)
		return nil, errUnavailable
	}
	closerConnector, closerConnectorErr := ldap.NewGoLDAPConnector(ldap.ConnectionConfig{Address: address, ServerName: serverName, BaseDN: baseDN, BindDN: closerCredential.BindDN, Password: closerPassword, RootCAs: roots, UseStartTLS: startTLS})
	clear(closerPassword)
	if closerConnectorErr != nil {
		closeLDAP(connectors)
		return nil, errUnavailable
	}
	connectors = append(connectors, closerConnector)
	administrator, err := ldap.NewAdministrator(connectors[0], connectors[1], connectors[2], provider.ProductionLimits(), limits)
	if err != nil {
		closeLDAP(connectors)
		return nil, errUnavailable
	}
	purger, err := ldap.NewPurgeExecutor(connectors[3], limits)
	if err != nil {
		_ = administrator.Close()
		_ = connectors[3].Close()
		return nil, errUnavailable
	}
	terminal, terminalErr := ldap.NewTerminalExecutor(connectors[4])
	if terminalErr != nil {
		_ = administrator.Close()
		closeLDAP(connectors[3:])
		return nil, errUnavailable
	}
	identities := [4]string{credentials[0].BindDN, credentials[1].BindDN, credentials[2].BindDN, credentials[3].BindDN}
	backendClass, authority, authorityErr := configuration.Authority(identities)
	if authorityErr != nil || backendClass != datasourceadmin.BackendLDAP {
		_ = administrator.Close()
		_ = connectors[3].Close()
		return nil, errUnavailable
	}
	return newComposedRuntime(administrator, purger, newRetentionRecoveryAdapter(administrator, terminal), terminal, "ldap", limits, authority, configuration, proof)
}

// openPostgreSQLRuntime builds three lifecycle pools plus the independent purge pool.
func openPostgreSQLRuntime(ctx context.Context, configuration *rotationadmin.Config, paths [4]string, closerPath string, limits datasourceadmin.GenerationLimits, proof *rotationadmin.DNSBatchProver) (*CampaignRuntime, error) {
	address, serverName, database, caFile, timeout, maximum, idle, pageSize, ok := configuration.SQLTransport()
	if !ok {
		return nil, errUnavailable
	}
	roots, err := rotationadmin.LoadTrustRoots(caFile)
	if err != nil {
		return nil, errUnavailable
	}
	credentials, err := loadSQLCredentials(paths)
	if err != nil {
		return nil, errUnavailable
	}
	closerCredential, closerErr := loadSQLCredential(closerPath)
	if closerErr != nil {
		clearSQLCredentials(credentials)
		return nil, errUnavailable
	}
	for _, credential := range credentials {
		if credential.User == closerCredential.User {
			clearSQLCredentials(credentials)
			return nil, errUnavailable
		}
	}
	configs := make([]postgresql.ConnectionConfig, len(credentials))
	for index, credential := range credentials {
		password, passwordErr := readPassword(credential.PasswordFile)
		if passwordErr != nil {
			clearSQLCredentials(credentials)
			return nil, errUnavailable
		}
		configs[index] = postgresql.ConnectionConfig{Address: address, ServerName: serverName, Database: database, User: credential.User, Password: password, RootCAs: roots, ConnectTimeout: timeout, MaxConnections: int32(maximum), IdleConnections: int32(idle)}
	}
	defer clearConnectionPasswordsPG(configs)
	closerPassword, closerPasswordErr := readPassword(closerCredential.PasswordFile)
	if closerPasswordErr != nil {
		clearSQLCredentials(credentials)
		return nil, errUnavailable
	}
	closerConfig := postgresql.ConnectionConfig{Address: address, ServerName: serverName, Database: database, User: closerCredential.User, Password: closerPassword, RootCAs: roots, ConnectTimeout: timeout, MaxConnections: int32(maximum), IdleConnections: int32(idle)}
	defer clear(closerConfig.Password)
	administrator, err := postgresql.OpenAdministrator(ctx, configs[0], configs[1], configs[2], provider.ProductionLimits(), limits, pageSize)
	if err != nil {
		return nil, errUnavailable
	}
	purger, err := postgresql.OpenPurgeExecutor(ctx, configs[3])
	if err != nil {
		administrator.Close()
		return nil, errUnavailable
	}
	terminal, terminalErr := postgresql.OpenTerminalExecutor(ctx, closerConfig)
	if terminalErr != nil {
		administrator.Close()
		purger.Close()
		return nil, errUnavailable
	}
	identities := [4]string{credentials[0].User, credentials[1].User, credentials[2].User, credentials[3].User}
	backendClass, authority, authorityErr := configuration.Authority(identities)
	if authorityErr != nil || backendClass != datasourceadmin.BackendPostgreSQL {
		administrator.Close()
		purger.Close()
		terminal.Close()
		return nil, errUnavailable
	}
	return newComposedRuntime(administrator, purger, newRetentionRecoveryAdapter(administrator, terminal), terminal, "postgresql", limits, authority, configuration, proof)
}

// openMySQLRuntime builds three lifecycle pools plus the independent purge pool.
func openMySQLRuntime(ctx context.Context, configuration *rotationadmin.Config, paths [4]string, closerPath string, limits datasourceadmin.GenerationLimits, proof *rotationadmin.DNSBatchProver) (*CampaignRuntime, error) {
	address, serverName, database, caFile, timeout, maximum, idle, pageSize, ok := configuration.SQLTransport()
	if !ok {
		return nil, errUnavailable
	}
	roots, err := rotationadmin.LoadTrustRoots(caFile)
	if err != nil {
		return nil, errUnavailable
	}
	credentials, err := loadSQLCredentials(paths)
	if err != nil {
		return nil, errUnavailable
	}
	closerCredential, closerErr := loadSQLCredential(closerPath)
	if closerErr != nil {
		clearSQLCredentials(credentials)
		return nil, errUnavailable
	}
	for _, credential := range credentials {
		if credential.User == closerCredential.User {
			clearSQLCredentials(credentials)
			return nil, errUnavailable
		}
	}
	configs := make([]mysql.ConnectionConfig, len(credentials))
	for index, credential := range credentials {
		password, passwordErr := readPassword(credential.PasswordFile)
		if passwordErr != nil {
			clearSQLCredentials(credentials)
			return nil, errUnavailable
		}
		configs[index] = mysql.ConnectionConfig{Address: address, ServerName: serverName, Database: database, User: credential.User, Password: password, RootCAs: roots, ConnectTimeout: timeout, MaxConnections: maximum, IdleConnections: idle}
	}
	defer clearConnectionPasswordsMySQL(configs)
	closerPassword, closerPasswordErr := readPassword(closerCredential.PasswordFile)
	if closerPasswordErr != nil {
		clearSQLCredentials(credentials)
		return nil, errUnavailable
	}
	closerConfig := mysql.ConnectionConfig{Address: address, ServerName: serverName, Database: database, User: closerCredential.User, Password: closerPassword, RootCAs: roots, ConnectTimeout: timeout, MaxConnections: maximum, IdleConnections: idle}
	defer clear(closerConfig.Password)
	administrator, err := mysql.OpenAdministrator(ctx, configs[0], configs[1], configs[2], provider.ProductionLimits(), limits, pageSize)
	if err != nil {
		return nil, errUnavailable
	}
	purger, err := mysql.OpenPurgeExecutor(ctx, configs[3])
	if err != nil {
		administrator.Close()
		return nil, errUnavailable
	}
	terminal, terminalErr := mysql.OpenTerminalExecutor(ctx, closerConfig)
	if terminalErr != nil {
		administrator.Close()
		purger.Close()
		return nil, errUnavailable
	}
	identities := [4]string{credentials[0].User, credentials[1].User, credentials[2].User, credentials[3].User}
	backendClass, authority, authorityErr := configuration.Authority(identities)
	want := datasourceadmin.BackendClass(configuration.Backend())
	if authorityErr != nil || backendClass != want {
		administrator.Close()
		purger.Close()
		terminal.Close()
		return nil, errUnavailable
	}
	return newComposedRuntime(administrator, purger, newRetentionRecoveryAdapter(administrator, terminal), terminal, configuration.Backend(), limits, authority, configuration, proof)
}

// newComposedRuntime is the sole production constructor for lifecycle mutation.
func newComposedRuntime(backend campaignBackend, purge rotationadmin.PurgeExecutor, recovery datasourceadmin.RetentionRecoveryReader, terminal datasourceadmin.TerminalRecorder, class string, generations datasourceadmin.GenerationLimits, authority datasourceadmin.AuthorityDescriptor, configuration *rotationadmin.Config, proof *rotationadmin.DNSBatchProver) (*CampaignRuntime, error) {
	if backend == nil || purge == nil || recovery == nil || terminal == nil || configuration == nil || proof == nil || datasourceadmin.ValidatePurgeAuthority(datasourceadmin.BackendClass(class), authority) != nil {
		return nil, errUnavailable
	}
	policy, _, ok := configuration.DNSProofPolicy()
	if !ok {
		return nil, errUnavailable
	}
	terminalBackend, terminalErr := rotationadmin.NewTerminalBackend(backend, backend, terminal)
	if terminalErr != nil {
		return nil, errUnavailable
	}
	coordinator, err := rotationadmin.NewCoordinator(terminalBackend, terminalBackend, backend, rotationadmin.NativeKeyFactory{RSABits: 3072}, proof, configuration.Limits(), generations, time.Duration(policy.ProofLifetimeSeconds)*time.Second)
	if err != nil {
		return nil, errUnavailable
	}
	return &CampaignRuntime{backend: backend, purge: purge, recovery: recovery, terminal: terminal, coord: coordinator, prover: proof, class: class, limits: generations, authority: authority}, nil
}

// newIntent creates a fresh opaque operation identity only for a new command.
// The coordinator ignores it for a compatible persisted resume journal.
func newIntent(request Request) (rotationadmin.Intent, error) {
	operation, err := newOperationID()
	if err != nil {
		return rotationadmin.Intent{}, errUnavailable
	}
	if request.Command == CommandEmergency {
		return rotationadmin.NewEmergencyIntent(operation, request.Reason, request.Emergency)
	}
	return rotationadmin.NewIntent("normal", operation, "")
}

// newOperationID returns one canonical nonzero 128-bit lower-case base32 ID.
func newOperationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value)
	clear(value)
	return string(bytes.ToLower([]byte(encoded))), nil
}

// loadLDAPCredential reads one exact LDAP role document without exposing its content.
func loadLDAPCredential(path string) (ldapCredential, error) {
	var credential ldapCredential
	if err := decodeCredential(path, &credential); err != nil || credential.Version != "dkim2-rotation-ldap-authority-v1" || credential.BindDN == "" || !cleanAbsolute(credential.PasswordFile) {
		return ldapCredential{}, errUnavailable
	}
	return credential, nil
}

// loadSQLCredentials reads all exact SQL role documents before opening any pool.
func loadSQLCredentials(paths [4]string) ([]sqlCredential, error) {
	credentials := make([]sqlCredential, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for index, path := range paths {
		if err := decodeCredential(path, &credentials[index]); err != nil || credentials[index].Version != "dkim2-rotation-sql-authority-v1" || credentials[index].User == "" || !cleanAbsolute(credentials[index].PasswordFile) {
			clearSQLCredentials(credentials)
			return nil, errUnavailable
		}
		if _, duplicate := seen[credentials[index].User]; duplicate {
			clearSQLCredentials(credentials)
			return nil, errUnavailable
		}
		seen[credentials[index].User] = struct{}{}
	}
	return credentials, nil
}

// loadSQLCredential reads the one dedicated terminal-closure authority.
func loadSQLCredential(path string) (sqlCredential, error) {
	var credential sqlCredential
	if decodeCredential(path, &credential) != nil || credential.Version != "dkim2-rotation-sql-authority-v1" || credential.User == "" || !cleanAbsolute(credential.PasswordFile) {
		return sqlCredential{}, errUnavailable
	}
	return credential, nil
}

// newRetentionRecoveryAdapter refuses to expose any allocation inventory as a
// retention source; only a concrete provider recovery reader is accepted.
func newRetentionRecoveryAdapter(source retentionRecoverySource, terminal datasourceadmin.TerminalRecorder) datasourceadmin.RetentionRecoveryReader {
	if source == nil || terminal == nil {
		return nil
	}
	return &retentionRecoveryAdapter{source: source, terminal: terminal}
}

// RetentionCurrent begins and completes one stable recovery read.
func (a *retentionRecoveryAdapter) RetentionCurrent(ctx context.Context) (uint64, error) {
	if a == nil || a.source == nil || ctx == nil || ctx.Err() != nil {
		return 0, errUnavailable
	}
	if a.completed {
		a.inventory, a.loaded, a.completed = datasourceadmin.RetentionInventory{}, false, false
	}
	fresh, err := a.source.RetentionRecoveryInventory(ctx)
	if err != nil || fresh.Current == 0 {
		return 0, errUnavailable
	}
	fresh, err = joinRetentionTerminals(ctx, fresh, a.terminal)
	if err != nil {
		return 0, errUnavailable
	}
	if !a.loaded {
		a.inventory, a.loaded = fresh, true
		return fresh.Current, nil
	}
	if a.completed || !sameRetentionInventory(a.inventory, fresh) {
		return 0, errUnavailable
	}
	a.completed = true
	return fresh.Current, nil
}

// joinRetentionTerminals reads one terminal record per frozen operation and
// retains every missing, legacy, foreign, or mismatched record conservatively.
func joinRetentionTerminals(ctx context.Context, inventory datasourceadmin.RetentionInventory, terminal datasourceadmin.TerminalRecorder) (datasourceadmin.RetentionInventory, error) {
	if ctx == nil || ctx.Err() != nil || terminal == nil {
		return datasourceadmin.RetentionInventory{}, errUnavailable
	}
	operations := make(map[string]datasourceadmin.OperationBinding)
	for _, row := range inventory.Generations {
		if row.Schema != datasourceadmin.SchemaVersionV3 || !row.Operation.Initialized() || row.SourceGeneration == 0 {
			continue
		}
		err := row.Operation.WithValue(ctx, func(value string) error {
			operations[value] = row.Operation
			return nil
		})
		if err != nil {
			return datasourceadmin.RetentionInventory{}, errUnavailable
		}
	}
	terminals := make([]datasourceadmin.TerminalRecord, 0, len(operations))
	for _, operation := range operations {
		record, present, err := terminal.ReadTerminal(ctx, operation)
		if err != nil {
			return datasourceadmin.RetentionInventory{}, errUnavailable
		}
		if present {
			terminals = append(terminals, record)
		}
	}
	inventory.Generations = datasourceadmin.JoinTerminalRecovery(inventory.Generations, terminals)
	return inventory, nil
}

// RetentionPage returns detached ordered evidence from the first provider read.
func (a *retentionRecoveryAdapter) RetentionPage(_ context.Context, after uint64, limit uint32) ([]datasourceadmin.RetentionGeneration, error) {
	if a == nil || !a.loaded || limit == 0 {
		return nil, errUnavailable
	}
	result := make([]datasourceadmin.RetentionGeneration, 0, limit)
	for _, row := range a.inventory.Generations {
		if row.Generation > after {
			result = append(result, row)
			if len(result) == int(limit) {
				break
			}
		}
	}
	return result, nil
}

// sameRetentionInventory compares every key-free provider recovery fact.
func sameRetentionInventory(left, right datasourceadmin.RetentionInventory) bool {
	leftVersion, leftErr := datasourceadmin.RetentionInventoryVersion(left, "recovery-stability-v1")
	rightVersion, rightErr := datasourceadmin.RetentionInventoryVersion(right, "recovery-stability-v1")
	return leftErr == nil && rightErr == nil && leftVersion == rightVersion
}

// decodeCredential strictly parses one bounded protected credential document.
func decodeCredential(path string, destination any) error {
	document, err := config.ReadProtectedDocument(path, 65536)
	if err != nil {
		return errUnavailable
	}
	defer clear(document)
	decoder := yaml.NewDecoder(bytes.NewReader(document))
	decoder.KnownFields(true)
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errUnavailable
	}
	return nil
}

// readPassword reads one bounded nonempty protected secret and returns owned bytes.
func readPassword(path string) ([]byte, error) {
	password, err := config.ReadProtectedDocument(path, 16384)
	if err != nil || len(password) == 0 {
		clear(password)
		return nil, errUnavailable
	}
	return password, nil
}

func closeLDAP(connectors []*ldap.GoLDAPConnector) {
	for _, connector := range connectors {
		_ = connector.Close()
	}
}
func clearSQLCredentials(credentials []sqlCredential) {
	for index := range credentials {
		credentials[index] = sqlCredential{}
	}
}
func clearConnectionPasswordsPG(configs []postgresql.ConnectionConfig) {
	for index := range configs {
		clear(configs[index].Password)
		configs[index].Password = nil
	}
}
func clearConnectionPasswordsMySQL(configs []mysql.ConnectionConfig) {
	for index := range configs {
		clear(configs[index].Password)
		configs[index].Password = nil
	}
}
