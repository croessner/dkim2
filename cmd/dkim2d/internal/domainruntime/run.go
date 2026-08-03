// Package domainruntime owns concrete one-shot offline domain administration construction.
package domainruntime

import (
	"context"
	"errors"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
	serviceobservability "github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
	"github.com/croessner/dkim2/provider"
)

const administrationPageSize = 128

// backendOwner binds one provider-neutral authority to its explicit secret/session cleanup.
type backendOwner struct {
	backend domainadmin.OnboardingBackend
	close   func()
}

// backendConstructors is the closed concrete provider construction matrix.
type backendConstructors struct {
	ldap        func(*domainadmin.AdminConnectionMaterial, datasourceadmin.GenerationLimits) (*backendOwner, error)
	postgresql  func(context.Context, *domainadmin.AdminConnectionMaterial, datasourceadmin.GenerationLimits) (*backendOwner, error)
	mysqlFamily func(context.Context, *domainadmin.AdminConnectionMaterial, datasourceadmin.GenerationLimits) (*backendOwner, error)
}

// offlineDomainCoordinator is the narrow command runner boundary implemented by Onboarding.
type offlineDomainCoordinator interface {
	Plan(context.Context, *domainadmin.JournalStore, domainadmin.Intent, datasourceadmin.DNSPolicy) (domainadmin.OnboardingResult, error)
	Prepare(context.Context, *domainadmin.JournalStore) (domainadmin.OnboardingResult, error)
	DNSExport(context.Context, *domainadmin.JournalStore, string) (domainadmin.OnboardingResult, error)
	Prove(context.Context, *domainadmin.JournalStore) (domainadmin.OnboardingResult, error)
	Activate(context.Context, *domainadmin.JournalStore) (domainadmin.OnboardingResult, error)
	Status(context.Context, *domainadmin.JournalStore) (domainadmin.StatusResult, error)
	Reconcile(context.Context, *domainadmin.JournalStore) (domainadmin.OnboardingResult, error)
	Abort(context.Context, *domainadmin.JournalStore) (domainadmin.OnboardingResult, error)
}

// Close releases concrete connector credentials and sessions exactly once.
func (o *backendOwner) Close() {
	if o == nil || o.close == nil {
		return
	}
	closeBackend := o.close
	o.close = nil
	o.backend = nil
	closeBackend()
}

// RunCommandFile executes one complete offline command without daemon or exporter construction.
func RunCommandFile(ctx context.Context, request domainadmin.CommandRequest) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || request.Validate() != nil {
		return nil, errors.New("domain administration unavailable")
	}
	configuration, err := domainadmin.LoadAdminConfig(request.ConfigPath)
	if err != nil {
		return nil, err
	}
	defer configuration.Close() //nolint:errcheck // Secret clearing is unconditional and has no recovery action.
	if configuration.ValidateCommandRequest(request) != nil {
		return nil, errors.New("domain administration unavailable")
	}
	storeOpener := domainadmin.OpenJournalStore
	if request.Command == domainadmin.CommandStatus {
		storeOpener = domainadmin.OpenStatusJournalStore
	}
	store, err := storeOpener(ctx, request.OperationPath, configuration.Limits())
	if err != nil {
		return nil, err
	}
	defer store.Close() //nolint:errcheck // Command failure remains authoritative over local cleanup.
	authority := configuration.Authority()
	if err := domainadmin.PreflightCommandAuthority(
		ctx, store, request.Command, configuration.Backend(), authority,
	); err != nil {
		return nil, err
	}
	var intent domainadmin.Intent
	if request.Command == domainadmin.CommandPlan {
		intent, err = domainadmin.LoadIntent(request.IntentPath)
		if err != nil {
			return nil, err
		}
	}
	owner, err := openBackendWithinDeadline(
		ctx, configuration.Limits().BackendDeadline, configuration, openBackend,
	)
	if err != nil {
		return nil, err
	}
	defer owner.Close()
	observer := serviceobservability.NewLocalDomainObserver()
	coordinator, err := newCoordinator(configuration, owner.backend, authority, observer)
	if err != nil {
		return nil, err
	}
	if request.Command == domainadmin.CommandStatus {
		status, statusErr := executeObservedStatus(
			ctx, coordinator, observer, configuration.Backend(), store,
		)
		if statusErr != nil {
			return nil, statusErr
		}
		report, reportErr := domainadmin.NewStatusReport(request.ToolVersion, configuration.Backend(), status)
		if reportErr != nil {
			return nil, reportErr
		}
		return domainadmin.EncodeReport(report, request.Machine, configuration.Limits().MaxDocumentBytes)
	}
	result, err := executeObservedWorkflow(
		ctx, coordinator, observer, configuration.Backend(), store, request, intent,
		configuration.DNSPolicy(),
	)
	if err != nil {
		report, reportErr := domainadmin.NewCommandReport(
			request.ToolVersion, request.Command, configuration.Backend(), result,
		)
		if reportErr != nil {
			return nil, err
		}
		encoded, encodeErr := domainadmin.EncodeReport(
			report, request.Machine, configuration.Limits().MaxDocumentBytes,
		)
		if encodeErr != nil {
			return nil, err
		}
		return encoded, err
	}
	report, err := domainadmin.NewCommandReport(request.ToolVersion, request.Command, configuration.Backend(), result)
	if err != nil {
		return nil, err
	}
	return domainadmin.EncodeReport(report, request.Machine, configuration.Limits().MaxDocumentBytes)
}

// executeObservedWorkflow couples the actual coordinator call to mandatory local evidence.
func executeObservedWorkflow(
	ctx context.Context,
	coordinator offlineDomainCoordinator,
	observer *serviceobservability.LocalDomainObserver,
	backend datasourceadmin.BackendClass,
	store *domainadmin.JournalStore,
	request domainadmin.CommandRequest,
	intent domainadmin.Intent,
	dns datasourceadmin.DNSPolicy,
) (domainadmin.OnboardingResult, error) {
	if coordinator == nil || observer == nil {
		return domainadmin.OnboardingResult{}, errors.New("domain administration unavailable")
	}
	result, err := executeCommand(ctx, coordinator, store, request, intent, dns)
	if !validWorkflowObservation(observer, request.Command, backend, result) {
		return domainadmin.OnboardingResult{}, errors.New("domain administration unavailable")
	}
	return result, err
}

// executeObservedStatus couples the actual read-only coordinator call to mandatory local evidence.
func executeObservedStatus(
	ctx context.Context,
	coordinator offlineDomainCoordinator,
	observer *serviceobservability.LocalDomainObserver,
	backend datasourceadmin.BackendClass,
	store *domainadmin.JournalStore,
) (domainadmin.StatusResult, error) {
	if coordinator == nil || observer == nil {
		return domainadmin.StatusResult{}, errors.New("domain administration unavailable")
	}
	status, err := coordinator.Status(ctx, store)
	if err != nil {
		return domainadmin.StatusResult{}, err
	}
	if !validStatusObservation(observer, backend, status) {
		return domainadmin.StatusResult{}, errors.New("domain administration unavailable")
	}
	return status, nil
}

// validWorkflowObservation requires one bounded local event to match the command result exactly.
func validWorkflowObservation(
	observer *serviceobservability.LocalDomainObserver,
	command domainadmin.Command,
	backend datasourceadmin.BackendClass,
	result domainadmin.OnboardingResult,
) bool {
	return observer != nil && observer.MatchesResult(command, backend, result)
}

// validStatusObservation requires one bounded local event to match read-only status exactly.
func validStatusObservation(
	observer *serviceobservability.LocalDomainObserver,
	backend datasourceadmin.BackendClass,
	status domainadmin.StatusResult,
) bool {
	return observer != nil && observer.MatchesStatus(backend, status)
}

// backendOpener constructs one concrete provider under an already bounded context.
type backendOpener func(context.Context, *domainadmin.AdminConfig) (*backendOwner, error)

// openBackendWithinDeadline bounds connector construction and role-verification queries.
func openBackendWithinDeadline(
	ctx context.Context,
	deadline time.Duration,
	configuration *domainadmin.AdminConfig,
	opener backendOpener,
) (*backendOwner, error) {
	if ctx == nil || configuration == nil || opener == nil || deadline <= 0 || deadline > 30*time.Second {
		return nil, errors.New("domain administration unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	owner, err := opener(bounded, configuration)
	if err != nil || bounded.Err() != nil || owner == nil {
		if owner != nil {
			owner.Close()
		}
		return nil, errors.New("domain administration unavailable")
	}
	return owner, nil
}

// newCoordinator builds only provider-neutral in-process state-machine owners.
func newCoordinator(
	configuration *domainadmin.AdminConfig,
	backend domainadmin.OnboardingBackend,
	authority datasourceadmin.AuthorityDescriptor,
	observer domainadmin.OnboardingObserver,
) (*domainadmin.Onboarding, error) {
	if observer == nil {
		return nil, errors.New("domain administration unavailable")
	}
	limits := configuration.Limits()
	allocator, err := domainadmin.NewIdentityAllocator(limits)
	if err != nil {
		return nil, err
	}
	generator, err := domainadmin.NewKeyGenerator(domainadmin.DefaultKeyPolicy(), limits)
	if err != nil {
		return nil, err
	}
	proof, err := domainadmin.NewDNSProofEngine(limits)
	if err != nil {
		return nil, err
	}
	return domainadmin.NewOnboarding(
		limits, configuration.GenerationLimits(), allocator, generator, proof,
		backend, configuration.Backend(), authority, time.Now, observer,
	)
}

// executeCommand dispatches only the closed non-status state-machine vocabulary.
func executeCommand(
	ctx context.Context,
	coordinator offlineDomainCoordinator,
	store *domainadmin.JournalStore,
	request domainadmin.CommandRequest,
	intent domainadmin.Intent,
	dns datasourceadmin.DNSPolicy,
) (domainadmin.OnboardingResult, error) {
	switch request.Command {
	case domainadmin.CommandPlan:
		return coordinator.Plan(ctx, store, intent, dns)
	case domainadmin.CommandPrepare:
		return coordinator.Prepare(ctx, store)
	case domainadmin.CommandDNSExport:
		return coordinator.DNSExport(ctx, store, request.OutputPath)
	case domainadmin.CommandProve:
		return coordinator.Prove(ctx, store)
	case domainadmin.CommandActivate:
		if !request.Apply {
			return domainadmin.OnboardingResult{}, errors.New("domain administration unavailable")
		}
		return coordinator.Activate(ctx, store)
	case domainadmin.CommandReconcile:
		return coordinator.Reconcile(ctx, store)
	case domainadmin.CommandAbort:
		return coordinator.Abort(ctx, store)
	default:
		return domainadmin.OnboardingResult{}, errors.New("domain administration unavailable")
	}
}

// openBackend constructs exactly one concrete offline provider authority.
func openBackend(ctx context.Context, configuration *domainadmin.AdminConfig) (*backendOwner, error) {
	if ctx == nil || configuration == nil {
		return nil, errors.New("domain administration unavailable")
	}
	var owner *backendOwner
	err := configuration.WithConnectionMaterial(func(material *domainadmin.AdminConnectionMaterial) error {
		var err error
		owner, err = openMaterialBackend(ctx, material, configuration.GenerationLimits(), productionBackendConstructors())
		return err
	})
	if err != nil || owner == nil || owner.backend == nil {
		if owner != nil {
			owner.Close()
		}
		return nil, errors.New("domain administration unavailable")
	}
	return owner, nil
}

// productionBackendConstructors returns the exact no-daemon concrete adapter matrix.
func productionBackendConstructors() backendConstructors {
	return backendConstructors{
		ldap: openLDAPBackend, postgresql: openPostgreSQLBackend, mysqlFamily: openMySQLBackend,
	}
}

// openMaterialBackend dispatches all four backend classes without alternate provider fallbacks.
func openMaterialBackend(
	ctx context.Context,
	material *domainadmin.AdminConnectionMaterial,
	generations datasourceadmin.GenerationLimits,
	constructors backendConstructors,
) (*backendOwner, error) {
	if ctx == nil || material == nil || constructors.ldap == nil || constructors.postgresql == nil ||
		constructors.mysqlFamily == nil {
		return nil, errors.New("domain administration unavailable")
	}
	switch material.Backend {
	case datasourceadmin.BackendLDAP:
		return constructors.ldap(material, generations)
	case datasourceadmin.BackendPostgreSQL:
		return constructors.postgresql(ctx, material, generations)
	case datasourceadmin.BackendMySQL, datasourceadmin.BackendMariaDB:
		return constructors.mysqlFamily(ctx, material, generations)
	default:
		return nil, errors.New("domain administration unavailable")
	}
}

// openLDAPBackend constructs three distinct connector-owned protected authorities without I/O.
func openLDAPBackend(
	material *domainadmin.AdminConnectionMaterial,
	generations datasourceadmin.GenerationLimits,
) (*backendOwner, error) {
	connectors := make([]*ldap.GoLDAPConnector, 0, 3)
	cleanup := func() {
		for _, connector := range connectors {
			_ = connector.Close()
		}
	}
	roles := []domainadmin.AdminRoleMaterial{material.Snapshot, material.Staging, material.Activation}
	for _, role := range roles {
		connector, err := ldap.NewGoLDAPConnector(ldap.ConnectionConfig{
			Address: material.Address, ServerName: material.ServerName, BaseDN: material.BaseDN,
			BindDN: role.Identity, Password: role.Password, RootCAs: material.RootCAs,
		})
		if err != nil {
			cleanup()
			return nil, err
		}
		connectors = append(connectors, connector)
	}
	administrator, err := ldap.NewAdministrator(
		connectors[0], connectors[1], connectors[2], provider.DefaultLimits(), generations,
	)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &backendOwner{backend: administrator, close: func() { _ = administrator.Close() }}, nil
}

// openPostgreSQLBackend opens three verified role pools for one fixed SQL authority.
func openPostgreSQLBackend(
	ctx context.Context,
	material *domainadmin.AdminConnectionMaterial,
	generations datasourceadmin.GenerationLimits,
) (*backendOwner, error) {
	connections := postgresqlAdminConnections(material)
	administrator, err := postgresql.OpenAdministrator(
		ctx, connections[0], connections[1], connections[2], provider.DefaultLimits(),
		generations, administrationPageSize,
	)
	clearPostgreSQLConnections(&connections)
	if err != nil {
		return nil, err
	}
	return &backendOwner{backend: administrator, close: administrator.Close}, nil
}

// openMySQLBackend opens three verified role pools for MySQL or MariaDB.
func openMySQLBackend(
	ctx context.Context,
	material *domainadmin.AdminConnectionMaterial,
	generations datasourceadmin.GenerationLimits,
) (*backendOwner, error) {
	connections := mysqlAdminConnections(material)
	administrator, err := mysql.OpenAdministrator(
		ctx, connections[0], connections[1], connections[2], provider.DefaultLimits(),
		generations, administrationPageSize,
	)
	clearMySQLConnections(&connections)
	if err != nil {
		return nil, err
	}
	return &backendOwner{backend: administrator, close: administrator.Close}, nil
}

// postgresqlAdminConnections derives three detached role-specific typed configurations.
func postgresqlAdminConnections(material *domainadmin.AdminConnectionMaterial) [3]postgresql.ConnectionConfig {
	roles := []domainadmin.AdminRoleMaterial{material.Snapshot, material.Staging, material.Activation}
	var result [3]postgresql.ConnectionConfig
	for index, role := range roles {
		result[index] = postgresql.ConnectionConfig{
			Address: material.Address, ServerName: material.ServerName, Database: material.Database,
			User: role.Identity, Password: append([]byte(nil), role.Password...), RootCAs: material.RootCAs.Clone(),
			ConnectTimeout: material.Deadline, MaxConnections: 2,
		}
	}
	return result
}

// mysqlAdminConnections derives three detached role-specific typed configurations.
func mysqlAdminConnections(material *domainadmin.AdminConnectionMaterial) [3]mysql.ConnectionConfig {
	roles := []domainadmin.AdminRoleMaterial{material.Snapshot, material.Staging, material.Activation}
	var result [3]mysql.ConnectionConfig
	for index, role := range roles {
		result[index] = mysql.ConnectionConfig{
			Address: material.Address, ServerName: material.ServerName, Database: material.Database,
			User: role.Identity, Password: append([]byte(nil), role.Password...), RootCAs: material.RootCAs.Clone(),
			ConnectTimeout: material.Deadline, MaxConnections: 2,
		}
	}
	return result
}

// clearPostgreSQLConnections clears temporary provider configuration credentials.
func clearPostgreSQLConnections(connections *[3]postgresql.ConnectionConfig) {
	if connections == nil {
		return
	}
	for index := range connections {
		clear(connections[index].Password)
		connections[index] = postgresql.ConnectionConfig{}
	}
}

// clearMySQLConnections clears temporary provider configuration credentials.
func clearMySQLConnections(connections *[3]mysql.ConnectionConfig) {
	if connections == nil {
		return
	}
	for index := range connections {
		clear(connections[index].Password)
		connections[index] = mysql.ConnectionConfig{}
	}
}
