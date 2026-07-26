package valkey

import (
	"context"
	"reflect"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

// ownedApplicationClient is the exact owned production client boundary.
type ownedApplicationClient interface {
	nativeClient
	Mode() valkeygo.ClientMode
	Close()
}

// auditWireFactory publishes ownership as soon as one ephemeral wire exists.
type auditWireFactory func(context.Context, auditAuthority, func(auditWire)) error

// applicationClientFactory publishes ownership as soon as one application client exists.
type applicationClientFactory func(valkeygo.ClientOption, func(ownedApplicationClient)) error

// productionDependencies contains package-private deterministic construction seams.
type productionDependencies struct {
	clock          securityClock
	newAuditWire   auditWireFactory
	newApplication applicationClientFactory
}

// systemSecurityClock retains the process monotonic component of time.Now.
type systemSecurityClock struct{}

// Now returns one process-monotonic security time.
func (systemSecurityClock) Now() time.Time { return time.Now() }

// applicationClientAdapter owns one concrete valkey-go client.
type applicationClientAdapter struct {
	client valkeygo.Client
}

// B returns the pinned concrete client's command builder.
func (c *applicationClientAdapter) B() valkeygo.Builder { return c.client.B() }

// Do dispatches one concrete completed replay command.
func (c *applicationClientAdapter) Do(ctx context.Context, command valkeygo.Completed) valkeygo.ValkeyResult {
	return c.client.Do(ctx, command)
}

// Mode reports the concrete client's discovered deployment shape.
func (c *applicationClientAdapter) Mode() valkeygo.ClientMode { return c.client.Mode() }

// Close releases the concrete owned client exactly once.
func (c *applicationClientAdapter) Close() {
	c.client.Close()
}

// NewProductionStore proves authority before constructing one owned application client.
func NewProductionStore(
	ctx context.Context,
	config ClientConfig,
	attestation OperatorAttestation,
	auditorConfig AuditorConfig,
) (*Store, error) {
	return newProductionStoreWithDependencies(ctx, config, attestation, auditorConfig, productionDependencies{
		clock:          systemSecurityClock{},
		newAuditWire:   newTLSSecurityAuditWire,
		newApplication: newConcreteApplicationClient,
	})
}

// newConcreteApplicationClient creates and immediately publishes one pinned client.
func newConcreteApplicationClient(
	option valkeygo.ClientOption,
	publish func(ownedApplicationClient),
) error {
	client, err := valkeygo.NewClient(option)
	if client != nil {
		publish(&applicationClientAdapter{client: client})
	}
	return err
}

// newProductionStoreWithDependencies provides deterministic package-private construction tests.
func newProductionStoreWithDependencies(
	ctx context.Context,
	config ClientConfig,
	attestation OperatorAttestation,
	auditorConfig AuditorConfig,
	dependencies productionDependencies,
) (store *Store, resultErr error) {
	if err := preflightContext(ctx); err != nil {
		return nil, err
	}
	validated, err := validateClientConfig(config)
	if err != nil {
		return nil, err
	}
	defer validated.clearPassword()
	if !attestation.valid() {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	auditorCredentials, err := validateAuditorConfig(auditorConfig)
	if err != nil {
		return nil, err
	}
	defer auditorCredentials.clear()
	if nilInterface(dependencies.clock) ||
		dependencies.newAuditWire == nil ||
		dependencies.newApplication == nil {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	if err := preflightContext(ctx); err != nil {
		return nil, err
	}
	clock := newSerializedSecurityClock(dependencies.clock)

	auditCompleted, err := acquireAndRunSecurityAudit(
		ctx,
		dependencies.newAuditWire,
		validated.auditAuthority(),
		auditCredentials(auditorCredentials),
		securityAuditPolicyFrom(attestation, validated.username),
		auditPhaseConstruction,
		clock,
	)
	if err != nil {
		return nil, err
	}
	if err := preflightContext(ctx); err != nil {
		return nil, err
	}

	option, err := safeApplicationOption(validated)
	if err != nil {
		return nil, err
	}
	client, err := callApplicationFactory(ctx, dependencies.newApplication, option)
	if err != nil {
		return nil, err
	}
	if nilInterface(client) {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	if err := preflightContext(ctx); err != nil {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	mode, err := applicationClientMode(client)
	if err != nil {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	if err := preflightContext(ctx); err != nil {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	if mode != valkeygo.ClientModeStandalone {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}

	authority := validated.auditAuthority()
	applicationUsername := validated.username
	store = &Store{
		storeCore: &storeCore{
			client:              valkeyCommandClient{client: client},
			gate:                newAdmissionGate(validated.limits.MaxInFlight, validated.limits.MaxAdmissionWaiters),
			securityEnforced:    true,
			clock:               clock,
			authority:           &authority,
			applicationUsername: &applicationUsername,
			attestation:         &attestation,
			auditWireFactory:    dependencies.newAuditWire,
			ownedClient:         client,
		},
	}
	if err := preflightContext(ctx); err != nil {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	if err := store.clock.withSample(func(currentTime time.Time) error {
		if err := preflightContext(ctx); err != nil {
			return err
		}
		return store.evidence.refreshFromAuditSample(auditCompleted, currentTime)
	}); err != nil {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	if err := preflightContext(ctx); err != nil {
		if closeErr := closeApplicationClient(client); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	return store, nil
}

// applicationClientMode contains concrete client mode panics.
func applicationClientMode(client ownedApplicationClient) (mode valkeygo.ClientMode, resultErr error) {
	defer func() {
		if recover() != nil {
			mode = ""
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	return client.Mode(), nil
}

// safeApplicationOption contains impossible validated-state panics.
func safeApplicationOption(config validatedClientConfig) (option valkeygo.ClientOption, resultErr error) {
	defer func() {
		if recover() != nil {
			option = valkeygo.ClientOption{}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	return config.option(), nil
}

// callAuditWireFactory contains connection-factory panics and cleans partial wires.
func callAuditWireFactory(
	ctx context.Context,
	factory auditWireFactory,
	config auditAuthority,
) (wire auditWire, resultErr error) {
	published := false
	var duplicateCleanupErr error
	publish := func(candidate auditWire) {
		if !nilInterface(candidate) && !pointerOwnershipHandle(candidate) {
			duplicateCleanupErr = closeAuditWire(candidate)
			panic("invalid audit wire ownership handle")
		}
		if published {
			if !nilInterface(candidate) && !sameOwnedObject(wire, candidate) {
				duplicateCleanupErr = closeAuditWire(candidate)
			}
			panic("invalid audit wire ownership publication")
		}
		published = true
		wire = candidate
	}
	defer func() {
		if recover() != nil {
			var closeErr error
			if !nilInterface(wire) {
				closeErr = closeAuditWire(wire)
			}
			wire = nil
			if duplicateCleanupErr != nil &&
				dkim2.ReplayErrorCodeOf(duplicateCleanupErr) ==
					dkim2.ReplayErrorInternalInvariant {
				resultErr = duplicateCleanupErr
				return
			}
			if closeErr != nil &&
				dkim2.ReplayErrorCodeOf(closeErr) ==
					dkim2.ReplayErrorInternalInvariant {
				resultErr = closeErr
				return
			}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	err := factory(ctx, config.clone(), publish)
	if err != nil {
		if !nilInterface(wire) {
			if closeErr := closeAuditWire(wire); closeErr != nil {
				wire = nil
				if dkim2.ReplayErrorCodeOf(closeErr) ==
					dkim2.ReplayErrorInternalInvariant {
					return nil, closeErr
				}
			}
			wire = nil
		}
		return nil, boundedFactoryError(ctx, err)
	}
	if nilInterface(wire) {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	return wire, nil
}

// closeAuditWire contains cleanup panics and raw errors.
func closeAuditWire(wire auditWire) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if err := wire.Close(); err != nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	return nil
}

// callApplicationFactory contains client-factory panics.
func callApplicationFactory(
	ctx context.Context,
	factory applicationClientFactory,
	option valkeygo.ClientOption,
) (client ownedApplicationClient, resultErr error) {
	published := false
	var duplicateCleanupErr error
	publish := func(candidate ownedApplicationClient) {
		if !nilInterface(candidate) && !pointerOwnershipHandle(candidate) {
			duplicateCleanupErr = closeApplicationClient(candidate)
			panic("invalid application client ownership handle")
		}
		if published {
			if !nilInterface(candidate) && !sameOwnedObject(client, candidate) {
				duplicateCleanupErr = closeApplicationClient(candidate)
			}
			panic("invalid application client ownership publication")
		}
		published = true
		client = candidate
	}
	defer func() {
		if recover() != nil {
			var closeErr error
			if !nilInterface(client) {
				closeErr = closeApplicationClient(client)
			}
			client = nil
			if duplicateCleanupErr != nil &&
				dkim2.ReplayErrorCodeOf(duplicateCleanupErr) ==
					dkim2.ReplayErrorInternalInvariant {
				resultErr = duplicateCleanupErr
				return
			}
			if closeErr != nil &&
				dkim2.ReplayErrorCodeOf(closeErr) ==
					dkim2.ReplayErrorInternalInvariant {
				resultErr = closeErr
				return
			}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	err := factory(option, publish)
	if err != nil {
		if !nilInterface(client) {
			if closeErr := closeApplicationClient(client); closeErr != nil {
				client = nil
				if dkim2.ReplayErrorCodeOf(closeErr) ==
					dkim2.ReplayErrorInternalInvariant {
					return nil, closeErr
				}
			}
			client = nil
		}
		return nil, boundedFactoryError(ctx, err)
	}
	if nilInterface(client) {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	return client, nil
}

// pointerOwnershipHandle restricts owned resources to unambiguous identities.
func pointerOwnershipHandle(value any) bool {
	if value == nil {
		return false
	}
	return reflect.ValueOf(value).Kind() == reflect.Pointer
}

// sameOwnedObject recognizes one repeated pointer-like ownership publication.
func sameOwnedObject(first, second any) bool {
	if nilInterface(first) || nilInterface(second) ||
		!pointerOwnershipHandle(first) || !pointerOwnershipHandle(second) {
		return false
	}
	left := reflect.ValueOf(first)
	right := reflect.ValueOf(second)
	if left.Type() != right.Type() {
		return false
	}
	return left.Pointer() == right.Pointer()
}

// closeApplicationClient contains owned-client cleanup panics and raw errors.
func closeApplicationClient(client ownedApplicationClient) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	client.Close()
	return nil
}

// boundedFactoryError preserves caller control and rejects impossible typed factory failures.
func boundedFactoryError(ctx context.Context, err error) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	if err == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if !dkim2.IsReplayError(err) {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	switch dkim2.ReplayErrorCodeOf(err) {
	case dkim2.ReplayErrorUnavailable:
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	case dkim2.ReplayErrorInternalInvariant:
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	default:
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
}

// classifiedAuditWire records only the bounded class and deadline state of one sequential round trip.
type classifiedAuditWire struct {
	wire              auditWire
	roundTripFailed   bool
	roundTripCode     dkim2.ReplayErrorCode
	ownedDeadline     bool
	roundTripPanicked bool
	closePanicked     bool
}

// roundTrip delegates one closed audit command and retains no reply or raw error.
func (w *classifiedAuditWire) roundTrip(
	ctx context.Context,
	request auditRequest,
) (value resp2Value, resultErr error) {
	defer func() {
		if recover() != nil {
			w.roundTripPanicked = true
			value.clear()
			value = resp2Value{}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	value, resultErr = w.wire.roundTrip(ctx, request)
	if resultErr == nil {
		return value, nil
	}
	w.roundTripFailed = true
	childErr := preflightContext(ctx)
	w.roundTripCode, w.ownedDeadline = boundedAuditWireErrorCode(resultErr, childErr)
	return value, resultErr
}

// Close delegates exact ownership cleanup while recording panic precedence.
func (w *classifiedAuditWire) Close() (resultErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			w.closePanicked = true
			panic(recovered)
		}
	}()
	return w.wire.Close()
}

// boundedAuditWireErrorCode validates private-wire errors against child context state.
func boundedAuditWireErrorCode(
	err error,
	childErr error,
) (dkim2.ReplayErrorCode, bool) {
	childCode := dkim2.ReplayErrorCodeOf(childErr)
	if childErr != nil &&
		childCode != dkim2.ReplayErrorCancelled &&
		childCode != dkim2.ReplayErrorDeadlineExceeded {
		return dkim2.ReplayErrorInternalInvariant, false
	}
	if !dkim2.IsReplayError(err) {
		return dkim2.ReplayErrorInternalInvariant, false
	}
	switch dkim2.ReplayErrorCodeOf(err) {
	case dkim2.ReplayErrorUnavailable:
		return dkim2.ReplayErrorUnavailable, childErr != nil
	case dkim2.ReplayErrorInconsistent:
		return dkim2.ReplayErrorInconsistent, childErr != nil
	case dkim2.ReplayErrorInternalInvariant:
		return dkim2.ReplayErrorInternalInvariant, false
	case dkim2.ReplayErrorCancelled, dkim2.ReplayErrorDeadlineExceeded:
		if childCode == dkim2.ReplayErrorCodeOf(err) {
			return childCode, true
		}
		return dkim2.ReplayErrorInternalInvariant, false
	default:
		return dkim2.ReplayErrorInternalInvariant, false
	}
}

// boundedAuditResult applies cleanup, caller, owned-deadline, and wire-class precedence.
func boundedAuditResult(
	callerContext context.Context,
	globalContext context.Context,
	wire *classifiedAuditWire,
	err error,
) error {
	if wire == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if wire.closePanicked || wire.roundTripPanicked {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if wire.roundTripFailed &&
		wire.roundTripCode == dkim2.ReplayErrorInternalInvariant {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if dkim2.IsReplayError(err) &&
		dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if callerErr := preflightContext(callerContext); callerErr != nil {
		return callerErr
	}
	if wire.ownedDeadline || globalContext.Err() != nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	if wire.roundTripFailed {
		return dkim2.NewReplayError(wire.roundTripCode)
	}
	if err == nil {
		return nil
	}
	if !dkim2.IsReplayError(err) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	switch dkim2.ReplayErrorCodeOf(err) {
	case dkim2.ReplayErrorMisconfigured:
		return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	case dkim2.ReplayErrorUnavailable:
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	case dkim2.ReplayErrorInconsistent:
		return dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
	default:
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
}

// acquireAndRunSecurityAudit applies one global budget to acquisition and probes.
func acquireAndRunSecurityAudit(
	callerContext context.Context,
	factory auditWireFactory,
	config auditAuthority,
	credentials auditCredentials,
	policy securityAuditPolicy,
	phase auditPhase,
	clock securityClock,
) (completed time.Time, resultErr error) {
	return acquireAndRunSecurityAuditWithBudget(
		callerContext,
		factory,
		config,
		credentials,
		policy,
		phase,
		clock,
		auditGlobalTimeout,
	)
}

// acquireAndRunSecurityAuditWithBudget provides a deterministic timeout test seam.
func acquireAndRunSecurityAuditWithBudget(
	callerContext context.Context,
	factory auditWireFactory,
	config auditAuthority,
	credentials auditCredentials,
	policy securityAuditPolicy,
	phase auditPhase,
	clock securityClock,
	budget time.Duration,
) (completed time.Time, resultErr error) {
	globalContext, cancelGlobal, err := newAuditContextWithBudget(callerContext, budget)
	if err != nil {
		return time.Time{}, err
	}
	defer cancelGlobal()
	wire, err := callAuditWireFactory(globalContext, factory, config)
	if err != nil {
		return time.Time{}, auditDeadlineError(callerContext, globalContext, err)
	}
	classifiedWire := &classifiedAuditWire{wire: wire}
	err = runSecurityAuditWithinDeadline(
		callerContext,
		globalContext,
		classifiedWire,
		credentials,
		policy,
		phase,
		func() error {
			var sampleErr error
			completed, sampleErr = readSecurityClock(clock)
			return sampleErr
		},
	)
	err = boundedAuditResult(callerContext, globalContext, classifiedWire, err)
	if err != nil {
		return time.Time{}, err
	}
	if completed.IsZero() {
		return time.Time{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return completed, nil
}

// newGlobalAuditContext safely starts the exact audit-wide timeout.
func newGlobalAuditContext(
	callerContext context.Context,
) (globalContext context.Context, cancel context.CancelFunc, resultErr error) {
	return newAuditContextWithBudget(callerContext, auditGlobalTimeout)
}

// newAuditContextWithBudget safely starts one bounded audit-wide timeout.
func newAuditContextWithBudget(
	callerContext context.Context,
	budget time.Duration,
) (globalContext context.Context, cancel context.CancelFunc, resultErr error) {
	defer func() {
		if recover() != nil {
			globalContext = nil
			cancel = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if err := preflightContext(callerContext); err != nil {
		return nil, nil, err
	}
	if budget <= 0 || budget > auditGlobalTimeout {
		return nil, nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	globalContext, cancel = context.WithTimeout(callerContext, budget)
	return globalContext, cancel, nil
}

// auditDeadlineError preserves caller state and maps owned expiry to availability.
func auditDeadlineError(
	callerContext context.Context,
	globalContext context.Context,
	err error,
) error {
	if dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if callerErr := preflightContext(callerContext); callerErr != nil {
		return callerErr
	}
	if globalContext.Err() != nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	return err
}

// securityAuditPolicyFrom maps immutable attestation into closed live expectations.
func securityAuditPolicyFrom(attestation OperatorAttestation, username string) securityAuditPolicy {
	if attestation.values == nil {
		return securityAuditPolicy{}
	}
	values := attestation.values
	return securityAuditPolicy{
		applicationUsername:      username,
		persistenceMode:          persistenceModeToken(values.persistenceMode),
		appendFsyncPolicy:        appendFsyncToken(values.appendFsyncPolicy),
		saveSchedule:             values.saveSchedule,
		minReplicasToWrite:       uint64(values.minReplicasToWrite),
		minReplicasMaxLagSeconds: uint64(values.minReplicasMaxLagSeconds),
	}
}

// persistenceModeToken maps one closed attestation enum without formatting it.
func persistenceModeToken(mode PersistenceMode) string {
	switch mode {
	case PersistenceModeRDB:
		return "rdb"
	case PersistenceModeAOF:
		return "aof"
	case PersistenceModeRDBAOF:
		return "rdb_aof"
	default:
		return ""
	}
}

// appendFsyncToken maps one closed attestation enum without formatting it.
func appendFsyncToken(policy AppendFsyncPolicy) string {
	switch policy {
	case AppendFsyncInactive:
		return "inactive"
	case AppendFsyncAlways:
		return "always"
	case AppendFsyncEverySecond:
		return "everysec"
	default:
		return ""
	}
}

// Revalidate performs one exclusive ephemeral audit without changing authority.
func (s *Store) Revalidate(ctx context.Context, config AuditorConfig) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.storeCore == nil || s.gate == nil || !s.securityEnforced ||
		s.authority == nil || s.applicationUsername == nil || s.attestation == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	switch s.lifecycleState() {
	case lifecycleClosing, lifecycleClosed:
		return dkim2.NewReplayError(dkim2.ReplayErrorClosed)
	case lifecycleReady:
	default:
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if !s.revalidation.CompareAndSwap(false, true) {
		return dkim2.NewReplayError(dkim2.ReplayErrorLimitExceeded)
	}
	defer s.revalidation.Store(false)
	finish, err := s.gate.admitLifecycle(ctx)
	if err != nil {
		return err
	}
	defer finish()

	credentials, err := validateAuditorConfig(config)
	if err != nil {
		return err
	}
	defer credentials.clear()
	revalidationGeneration := s.facts.revalidationGeneration()
	auditCompleted, err := acquireAndRunSecurityAudit(
		ctx,
		s.auditWireFactory,
		*s.authority,
		auditCredentials(credentials),
		securityAuditPolicyFrom(*s.attestation, *s.applicationUsername),
		auditPhaseRuntime,
		s.clock,
	)
	if err != nil {
		switch dkim2.ReplayErrorCodeOf(err) {
		case dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInternalInvariant:
			s.publishFailure(recoveryRestart)
		case dkim2.ReplayErrorUnavailable:
			s.publishFailure(recoveryRevalidation)
		}
		return err
	}
	if err := preflightContext(ctx); err != nil {
		return err
	}
	var published bool
	err = s.clock.withSample(func(currentTime time.Time) error {
		if err := preflightContext(ctx); err != nil {
			return err
		}
		var publishErr error
		published, publishErr = s.gate.publishWhileReady(func() error {
			if err := s.evidence.refreshFromAuditSample(auditCompleted, currentTime); err != nil {
				return err
			}
			s.facts.clearStaleEvidence()
			s.facts.clearRevalidationAt(revalidationGeneration)
			return nil
		})
		return publishErr
	})
	if err != nil {
		switch dkim2.ReplayErrorCodeOf(err) {
		case dkim2.ReplayErrorCancelled, dkim2.ReplayErrorDeadlineExceeded:
			return err
		case dkim2.ReplayErrorUnavailable:
			s.publishStaleEvidenceFailure()
		default:
			s.publishFailure(recoveryRestart)
		}
		return err
	}
	if !published {
		return nil
	}
	return nil
}

// Close publishes terminal state, drains admitted work, and closes ownership once.
func (s *Store) Close(ctx context.Context) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.storeCore == nil || s.gate == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	drained, err := s.gate.beginClose()
	if err != nil {
		return err
	}
	if err := waitAdmissionDrain(ctx, drained); err != nil {
		return err
	}
	if !s.gate.publishClosed() {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	s.closeOnce.Do(func() {
		s.closeMu.Lock()
		defer s.closeMu.Unlock()
		if !nilInterface(s.ownedClient) {
			s.closeErr = closeApplicationClient(s.ownedClient)
		}
		s.ownedClient = nil
		s.client = nil
	})
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeErr
}

var _ dkim2.ManagedReplayStore = (*Store)(nil)
