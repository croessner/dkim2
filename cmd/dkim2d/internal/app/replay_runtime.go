package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/valkey"
)

const (
	replayRuntimeErrorText = "dkim2d replay runtime failure"
	replayRuntimeRedacted  = "dkim2d_replay_runtime"
	replayRollbackLimit    = 10 * time.Second
	replayCloseLimit       = 5 * time.Second
)

// ReplayRuntimeError reports one content-free replay composition failure.
type ReplayRuntimeError struct{}

// Error returns a constant content-free composition diagnostic.
func (*ReplayRuntimeError) Error() string { return replayRuntimeErrorText }

// Is recognizes the bounded replay-runtime error type.
func (*ReplayRuntimeError) Is(target error) bool {
	_, ok := target.(*ReplayRuntimeError)
	return ok
}

// replayMaterialSource is the startup-only protected replay boundary.
type replayMaterialSource interface {
	Snapshot() config.Snapshot
	UseReplayMaterial(func([]byte, []byte, []byte, [][]byte) error) error
	ReplayAuditorSource() replayAuditorSource
}

// replayAuditorSource retains only the periodic least-authority credential seam.
type replayAuditorSource interface {
	UseReplayAuditorPassword(func([]byte) error) error
}

// replayRollbackFactory returns the hook-owned shared first-failure rollback context.
type replayRollbackFactory func() context.Context

// replayCleanupStarter starts one attempt only after runtime ownership is claimed.
type replayCleanupStarter func(
	replayCleanupBound,
	dkim2.ManagedReplayStore,
	*dkim2.ReplayDeriver,
	func(context.Context) error,
) (<-chan bool, error)

// replayCleanupBound freezes one caller-owned cleanup deadline before ownership moves.
type replayCleanupBound struct {
	caller   context.Context
	deadline time.Time
	done     <-chan struct{}
}

// preparedReplayMaterial combines phase-specific non-owning handles during construction.
type preparedReplayMaterial struct {
	material config.ReplayRuntimePreparation
}

// Snapshot returns the prepared immutable startup configuration.
func (m preparedReplayMaterial) Snapshot() config.Snapshot { return m.material.Snapshot() }

// UseReplayMaterial lends callback-scoped startup material before commit.
func (m preparedReplayMaterial) UseReplayMaterial(
	use func([]byte, []byte, []byte, [][]byte) error,
) error {
	return m.material.UseReplayMaterial(use)
}

// ReplayAuditorSource narrows retained runtime authority to the auditor handle.
func (m preparedReplayMaterial) ReplayAuditorSource() replayAuditorSource {
	return m.material.ReplayAuditor()
}

// replayAuthorityStore adds the production authority operations owned by M12.
type replayAuthorityStore interface {
	dkim2.ManagedReplayStore
	Revalidate(context.Context, valkey.AuditorConfig) error
	AuthorityReady() bool
}

// replayRuntimeFactories contains deterministic provider-construction seams.
type replayRuntimeFactories struct {
	newDeriver    func([]byte, uint32) (*dkim2.ReplayDeriver, error)
	newMemory     func(dkim2.ReplayMemoryConfig) (*dkim2.ReplayMemoryStore, error)
	newDisabled   func() dkim2.ManagedReplayStore
	newProduction func(
		context.Context,
		valkey.ClientConfig,
		valkey.OperatorAttestation,
		valkey.AuditorConfig,
	) (replayAuthorityStore, error)
	clock dkim2.ReplayClock
}

// ReplayRuntime owns exactly one configured replay backend and its local policy.
type ReplayRuntime struct {
	state *replayRuntimeState
}

// replayRuntimeState owns provider dependencies behind one format-safe handle.
type replayRuntimeState struct {
	backend          config.ReplayBackend
	coordinator      *ReplayCoordinator
	deriver          *dkim2.ReplayDeriver
	retention        dkim2.ReplayRetention
	closeDeriver     func(context.Context) error
	store            dkim2.ManagedReplayStore
	authority        replayAuthorityStore
	auditorSource    replayAuditorSource
	auditorUsername  string
	revalidatePeriod time.Duration
	startCleanup     replayCleanupStarter
	close            replayRuntimeClose
}

// replayRuntimeClose linearizes exact-once store and deriver cleanup.
type replayRuntimeClose struct {
	mu       sync.Mutex
	running  bool
	complete bool
	failed   bool
	done     chan struct{}
}

// replayOwnerTransaction owns partial construction until one runtime commit.
type replayOwnerTransaction struct {
	rollback  replayRollbackFactory
	store     dkim2.ManagedReplayStore
	deriver   *dkim2.ReplayDeriver
	committed bool
}

// retainStore records the exact constructed store before any later failure.
func (t *replayOwnerTransaction) retainStore(store dkim2.ManagedReplayStore) {
	t.store = store
}

// retainDeriver records the exact constructed HMAC owner before any later failure.
func (t *replayOwnerTransaction) retainDeriver(deriver *dkim2.ReplayDeriver) {
	t.deriver = deriver
}

// commit transfers both owners into the returned runtime exactly once.
func (t *replayOwnerTransaction) commit() {
	t.committed = true
}

// rollbackOwners releases every retained owner once in reverse construction order.
func (t *replayOwnerTransaction) rollbackOwners() error {
	if t == nil || t.committed ||
		(nilInterface(t.store) && t.deriver == nil) {
		return nil
	}
	err := closeReplayRuntimeOwners(t.rollback, t.store, t.deriver)
	t.store = nil
	t.deriver = nil
	return err
}

// NewReplayRuntime composes exactly the configured disabled, memory, or Valkey backend.
func NewReplayRuntime(
	acquisitionCtx context.Context,
	rollback replayRollbackFactory,
	preparation *config.RuntimePreparation,
) (*ReplayRuntime, error) {
	if preparation == nil {
		return nil, &ReplayRuntimeError{}
	}
	return newReplayRuntimeWithRollback(
		acquisitionCtx,
		rollback,
		preparedReplayMaterial{material: preparation.ReplayRuntime()},
		productionReplayRuntimeFactories(),
	)
}

// productionReplayRuntimeFactories returns the exact production provider constructors.
func productionReplayRuntimeFactories() replayRuntimeFactories {
	return replayRuntimeFactories{
		newDeriver:  dkim2.NewReplayDeriver,
		newMemory:   dkim2.NewReplayMemoryStore,
		newDisabled: newDisabledReplayStore,
		newProduction: func(
			ctx context.Context,
			client valkey.ClientConfig,
			attestation valkey.OperatorAttestation,
			auditor valkey.AuditorConfig,
		) (replayAuthorityStore, error) {
			return valkey.NewProductionStore(ctx, client, attestation, auditor)
		},
		clock: dkim2.ReplayClockFunc(func() time.Time { return time.Now() }),
	}
}

// newDisabledReplayStore constructs the exact explicit no-storage provider.
func newDisabledReplayStore() dkim2.ManagedReplayStore {
	return dkim2.NewReplayDisabledStore()
}

// newReplayRuntime composes one backend through deterministic construction seams.
func newReplayRuntimeWithRollback(
	acquisitionCtx context.Context,
	rollback replayRollbackFactory,
	material replayMaterialSource,
	factories replayRuntimeFactories,
) (runtime *ReplayRuntime, resultErr error) {
	if err := runtimeContextError(acquisitionCtx); err != nil {
		return nil, err
	}
	if rollback == nil {
		return nil, &ReplayRuntimeError{}
	}
	if nilInterface(material) {
		return nil, &ReplayRuntimeError{}
	}
	snapshot := material.Snapshot()
	if !snapshot.Valid() {
		return nil, &ReplayRuntimeError{}
	}
	replayConfig := snapshot.Replay()
	owners := &replayOwnerTransaction{rollback: rollback}
	defer func() {
		if cleanupErr := owners.rollbackOwners(); cleanupErr != nil {
			runtime = nil
			resultErr = &ReplayRuntimeError{}
		}
	}()

	switch replayConfig.Backend() {
	case config.ReplayDisabled:
		if factories.newDisabled == nil {
			return nil, &ReplayRuntimeError{}
		}
		store := factories.newDisabled()
		owners.retainStore(store)
		if nilInterface(store) || store.State() != dkim2.ReplayStoreDisabled {
			return nil, &ReplayRuntimeError{}
		}
		runtime = &ReplayRuntime{state: &replayRuntimeState{
			backend: replayConfig.Backend(), coordinator: NewDisabledReplayCoordinator(), store: store,
			startCleanup: startReplayRuntimeCleanup,
		}}
	case config.ReplayMemory:
		if !replayConfig.Enabled() || factories.newDeriver == nil ||
			factories.newMemory == nil || nilInterface(factories.clock) {
			return nil, &ReplayRuntimeError{}
		}
		retention, limits, err := enabledReplayParameters(replayConfig)
		if err != nil {
			return nil, err
		}
		runtime = constructMemoryReplayRuntime(
			owners, material, replayConfig, retention, limits, factories,
		)
	case config.ReplayValkey:
		if !replayConfig.Enabled() || factories.newDeriver == nil ||
			factories.newProduction == nil {
			return nil, &ReplayRuntimeError{}
		}
		retention, limits, err := enabledReplayParameters(replayConfig)
		if err != nil {
			return nil, err
		}
		auditorSource := material.ReplayAuditorSource()
		if nilInterface(auditorSource) {
			return nil, &ReplayRuntimeError{}
		}
		runtime = constructValkeyReplayRuntime(
			acquisitionCtx,
			owners,
			material,
			auditorSource,
			replayConfig,
			retention,
			limits,
			factories,
		)
	default:
		return nil, &ReplayRuntimeError{}
	}
	if err := runtimeContextError(acquisitionCtx); err != nil {
		return nil, err
	}
	if runtime == nil || runtime.state == nil || runtime.state.coordinator == nil ||
		nilInterface(runtime.state.store) {
		return nil, &ReplayRuntimeError{}
	}
	owners.commit()
	return runtime, nil
}

// enabledReplayParameters validates only the selected storage-backed configuration.
func enabledReplayParameters(
	replayConfig config.ReplayConfig,
) (dkim2.ReplayRetention, dkim2.ReplayLimits, error) {
	retention, err := dkim2.NewReplayRetention(replayConfig.Retention())
	if err != nil {
		return dkim2.ReplayRetention{}, dkim2.ReplayLimits{}, &ReplayRuntimeError{}
	}
	limits := replayLimits(replayConfig)
	if err := limits.Validate(); err != nil {
		return dkim2.ReplayRetention{}, dkim2.ReplayLimits{}, &ReplayRuntimeError{}
	}
	return retention, limits, nil
}

// constructMemoryReplayRuntime composes one bounded process-local replay backend.
func constructMemoryReplayRuntime(
	owners *replayOwnerTransaction,
	material replayMaterialSource,
	replayConfig config.ReplayConfig,
	retention dkim2.ReplayRetention,
	limits dkim2.ReplayLimits,
	factories replayRuntimeFactories,
) *ReplayRuntime {
	var (
		deriver      *dkim2.ReplayDeriver
		store        *dkim2.ReplayMemoryStore
		coordinator  *ReplayCoordinator
		operationErr error
	)
	borrowErr := material.UseReplayMaterial(func(hmac, _, _ []byte, _ [][]byte) error {
		deriver, operationErr = factories.newDeriver(hmac, replayConfig.Epoch())
		owners.retainDeriver(deriver)
		if operationErr != nil || deriver == nil {
			return nil
		}
		store, operationErr = factories.newMemory(dkim2.ReplayMemoryConfig{
			Limits: limits,
			Clock:  factories.clock,
		})
		owners.retainStore(store)
		if operationErr != nil || store == nil {
			return nil
		}
		coordinator, operationErr = NewEnabledReplayCoordinator(deriver, store, retention)
		if operationErr != nil || coordinator == nil {
			return nil
		}
		return nil
	})
	if borrowErr != nil || operationErr != nil || deriver == nil || store == nil || coordinator == nil {
		return nil
	}
	return &ReplayRuntime{state: &replayRuntimeState{
		backend: config.ReplayMemory, coordinator: coordinator, deriver: deriver,
		retention: retention, closeDeriver: deriver.Close, store: store, startCleanup: startReplayRuntimeCleanup,
	}}
}

// constructValkeyReplayRuntime composes one audited direct production authority.
func constructValkeyReplayRuntime(
	acquisitionCtx context.Context,
	owners *replayOwnerTransaction,
	material replayMaterialSource,
	auditorSource replayAuditorSource,
	replayConfig config.ReplayConfig,
	retention dkim2.ReplayRetention,
	limits dkim2.ReplayLimits,
	factories replayRuntimeFactories,
) *ReplayRuntime {
	valkeyConfig, valkeyPresent := replayConfig.Valkey()
	attestation, attestationPresent := replayConfig.OperatorAttestation()
	if !valkeyPresent || !attestationPresent {
		return nil
	}
	var (
		deriver      *dkim2.ReplayDeriver
		store        replayAuthorityStore
		coordinator  *ReplayCoordinator
		operationErr error
	)
	borrowErr := material.UseReplayMaterial(
		func(hmac, applicationPassword, auditorPassword []byte, rootsDER [][]byte) error {
			deriver, operationErr = factories.newDeriver(hmac, replayConfig.Epoch())
			owners.retainDeriver(deriver)
			if operationErr != nil || deriver == nil {
				return nil
			}
			client := valkey.NewClientConfig(
				valkeyConfig.Address(),
				valkeyConfig.ServerName(),
				rootsDER,
				valkeyConfig.ApplicationUsername(),
				applicationPassword,
				valkeyConfig.DialTimeout(),
				valkeyConfig.TCPKeepalive(),
				valkeyConfig.ConnectionWriteTimeout(),
				replayConfig.Epoch(),
				limits,
			)
			defer client.Close()
			auditor := valkey.NewAuditorConfig(valkeyConfig.AuditorUsername(), auditorPassword)
			defer auditor.Close()
			store, operationErr = factories.newProduction(
				acquisitionCtx, client, attestation, auditor,
			)
			owners.retainStore(store)
			if operationErr != nil || nilInterface(store) {
				return nil
			}
			coordinator, operationErr = NewEnabledReplayCoordinator(deriver, store, retention)
			if operationErr != nil || coordinator == nil {
				return nil
			}
			return nil
		},
	)
	if borrowErr != nil || operationErr != nil || deriver == nil ||
		nilInterface(store) || coordinator == nil {
		return nil
	}
	return &ReplayRuntime{state: &replayRuntimeState{
		backend:          config.ReplayValkey,
		coordinator:      coordinator,
		deriver:          deriver,
		retention:        retention,
		closeDeriver:     deriver.Close,
		store:            store,
		authority:        store,
		auditorSource:    auditorSource,
		auditorUsername:  valkeyConfig.AuditorUsername(),
		revalidatePeriod: replayConfig.RevalidateInterval(),
		startCleanup:     startReplayRuntimeCleanup,
	}}
}

// replayLimits projects the validated stable configuration into public provider limits.
func replayLimits(replayConfig config.ReplayConfig) dkim2.ReplayLimits {
	return dkim2.ReplayLimits{
		MaxEntries:          int(replayConfig.MaxEntries()),
		MaxWaiters:          int(replayConfig.MaxWaiters()),
		PruneBudget:         int(replayConfig.PruneBudget()),
		MaxInFlight:         int(replayConfig.MaxInFlight()),
		MaxAdmissionWaiters: int(replayConfig.MaxAdmissionWaiters()),
	}
}

// NewAuthenticator binds the runtime replay authority to the owned DNS verifier.
func (r *ReplayRuntime) NewAuthenticator(verifier *DNSVerifier) (*dkim2.Authenticator, error) {
	if r == nil || r.state == nil || verifier == nil || verifier.verifier == nil || nilInterface(r.state.store) {
		return nil, &ReplayRuntimeError{}
	}
	var (
		auth *dkim2.Authenticator
		err  error
	)
	if r.state.backend == config.ReplayDisabled {
		auth, err = dkim2.NewDisabledAuthenticator(verifier.verifier)
	} else {
		auth, err = dkim2.NewAuthenticator(verifier.verifier, r.state.store, r.state.deriver, r.state.retention)
	}
	if err != nil || auth == nil {
		return nil, &ReplayRuntimeError{}
	}
	return auth, nil
}

// Coordinate applies the immutable provider-neutral replay policy.
func (r *ReplayRuntime) Coordinate(ctx context.Context, domain DomainResult) (ReplayOutcome, error) {
	if r == nil || r.state == nil || r.state.coordinator == nil {
		return ReplayOutcome{}, &ReplayRuntimeError{}
	}
	return r.state.coordinator.Coordinate(ctx, domain)
}

// AuthorityReady reports one bounded no-I/O backend authority fact.
func (r *ReplayRuntime) AuthorityReady() bool {
	if r == nil || r.state == nil || nilInterface(r.state.store) {
		return false
	}
	switch r.state.backend {
	case config.ReplayDisabled:
		return r.state.store.State() == dkim2.ReplayStoreDisabled
	case config.ReplayMemory:
		return r.state.store.State() == dkim2.ReplayStoreReady
	case config.ReplayValkey:
		return !nilInterface(r.state.authority) && r.state.authority.AuthorityReady()
	default:
		return false
	}
}

// Revalidate performs one least-authority production audit with a fresh credential clone.
func (r *ReplayRuntime) Revalidate(ctx context.Context) error {
	if err := runtimeContextError(ctx); err != nil {
		return err
	}
	if r == nil || r.state == nil || r.state.backend != config.ReplayValkey ||
		nilInterface(r.state.authority) || nilInterface(r.state.auditorSource) ||
		r.state.auditorUsername == "" {
		return &ReplayRuntimeError{}
	}
	var operationErr error
	borrowErr := r.state.auditorSource.UseReplayAuditorPassword(func(auditorPassword []byte) error {
		auditor := valkey.NewAuditorConfig(r.state.auditorUsername, auditorPassword)
		defer auditor.Close()
		operationErr = r.state.authority.Revalidate(ctx, auditor)
		return nil
	})
	if contextErr := runtimeContextError(ctx); contextErr != nil {
		return contextErr
	}
	if borrowErr != nil {
		return &ReplayRuntimeError{}
	}
	if operationErr != nil && !dkim2.IsReplayError(operationErr) {
		return &ReplayRuntimeError{}
	}
	if operationErr != nil && !allowedRevalidationError(operationErr) {
		return &ReplayRuntimeError{}
	}
	return operationErr
}

// freezeReplayCleanupBound validates and snapshots one caller bound exactly once.
func freezeReplayCleanupBound(
	ctx context.Context,
	limit time.Duration,
) (bound replayCleanupBound, resultErr error) {
	defer func() {
		if recover() != nil {
			bound = replayCleanupBound{}
			resultErr = &ReplayRuntimeError{}
		}
	}()
	if nilInterface(ctx) {
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	terminal := ctx.Err()
	deadline, present := ctx.Deadline()
	done := ctx.Done()
	if !present || done == nil {
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	remaining := time.Until(deadline)
	switch terminal {
	case nil:
		if remaining <= 0 {
			return replayCleanupBound{}, context.DeadlineExceeded
		}
		select {
		case <-done:
			return replayCleanupBound{}, &ReplayRuntimeError{}
		default:
		}
	case context.Canceled:
		return replayCleanupBound{}, context.Canceled
	case context.DeadlineExceeded:
		return replayCleanupBound{}, context.DeadlineExceeded
	default:
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	if limit <= 0 || remaining > limit {
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	return replayCleanupBound{caller: ctx, deadline: deadline, done: done}, nil
}

// replayCleanupCallerError reads terminal identity without re-reading Deadline or Done.
func replayCleanupCallerError(bound replayCleanupBound) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &ReplayRuntimeError{}
		}
	}()
	if nilInterface(bound.caller) {
		return &ReplayRuntimeError{}
	}
	switch err := bound.caller.Err(); err {
	case nil:
		if !time.Now().Before(bound.deadline) {
			return context.DeadlineExceeded
		}
		return nil
	case context.Canceled:
		return context.Canceled
	case context.DeadlineExceeded:
		return context.DeadlineExceeded
	default:
		return &ReplayRuntimeError{}
	}
}

// allowedRevalidationError accepts only live nonterminal M12 audit outcomes.
func allowedRevalidationError(err error) bool {
	if !dkim2.IsReplayError(err) {
		return false
	}
	switch dkim2.ReplayErrorCodeOf(err) {
	case dkim2.ReplayErrorLimitExceeded, dkim2.ReplayErrorUnavailable,
		dkim2.ReplayErrorInconsistent, dkim2.ReplayErrorInternalInvariant:
		return true
	default:
		return false
	}
}

// RevalidationInterval returns the validated production audit interval.
func (r *ReplayRuntime) RevalidationInterval() time.Duration {
	if r == nil || r.state == nil || r.state.backend != config.ReplayValkey {
		return 0
	}
	return r.state.revalidatePeriod
}

// Close releases the selected provider and replay-key owner.
func (r *ReplayRuntime) Close(ctx context.Context) error {
	bound, err := freezeReplayCleanupBound(ctx, replayCloseLimit)
	if err != nil {
		return err
	}
	if r == nil || r.state == nil {
		return nil
	}
	if r.state.startCleanup == nil {
		return &ReplayRuntimeError{}
	}
	for {
		r.state.close.mu.Lock()
		if r.state.close.complete {
			failed := r.state.close.failed
			r.state.close.mu.Unlock()
			if err := replayCleanupCallerError(bound); err != nil {
				return err
			}
			if failed {
				return &ReplayRuntimeError{}
			}
			return nil
		}
		if r.state.close.running {
			done := r.state.close.done
			r.state.close.mu.Unlock()
			if err := waitReplayRuntimeWaiter(bound, done); err != nil {
				return err
			}
			continue
		}
		r.state.close.running = true
		r.state.close.done = make(chan struct{})
		done := r.state.close.done
		r.state.close.mu.Unlock()

		result, startErr := r.state.startCleanup(
			bound, r.state.store, r.state.deriver, r.state.closeDeriver,
		)
		if startErr != nil {
			r.abandonCloseAttempt(done)
			return startErr
		}
		go r.finishClose(done, result)
		if err := waitReplayRuntimeStarter(bound, done); err != nil {
			return err
		}
		if err := replayCleanupCallerError(bound); err != nil {
			return err
		}
	}
}

// abandonCloseAttempt wakes waiters and reopens ownership if no child was started.
func (r *ReplayRuntime) abandonCloseAttempt(done chan struct{}) {
	r.state.close.mu.Lock()
	defer r.state.close.mu.Unlock()
	if !r.state.close.running || r.state.close.done != done {
		return
	}
	r.state.close.running = false
	r.state.close.done = nil
	close(done)
}

// waitReplayRuntimeStarter reserves cleanup until join while preserving caller deadline.
func waitReplayRuntimeStarter(bound replayCleanupBound, done <-chan struct{}) error {
	remaining := time.Until(bound.deadline)
	if remaining <= 0 {
		select {
		case <-done:
			return replayCleanupCallerError(bound)
		default:
			return context.DeadlineExceeded
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-done:
		return replayCleanupCallerError(bound)
	case <-timer.C:
		select {
		case <-done:
			return replayCleanupCallerError(bound)
		default:
			if err := replayCleanupCallerError(bound); err != nil {
				return err
			}
			return context.DeadlineExceeded
		}
	}
}

// finishClose publishes terminal cleanup only after every child-close owner joins.
func (r *ReplayRuntime) finishClose(done chan struct{}, result <-chan bool) {
	failed := <-result
	r.finalizeClose(done, failed)
}

// finalizeClose publishes the exact terminal result and releases every waiter.
func (r *ReplayRuntime) finalizeClose(done chan struct{}, failed bool) {
	r.state.close.mu.Lock()
	defer r.state.close.mu.Unlock()
	if !r.state.close.running || r.state.close.done != done {
		return
	}
	r.state.close.failed = failed
	r.state.close.complete = true
	r.state.close.running = false
	close(done)
}

// waitReplayRuntimeWaiter waits for the active cleanup under one frozen caller bound.
func waitReplayRuntimeWaiter(bound replayCleanupBound, done <-chan struct{}) error {
	remaining := time.Until(bound.deadline)
	if remaining <= 0 {
		select {
		case <-done:
			return replayCleanupCallerError(bound)
		default:
			return context.DeadlineExceeded
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-done:
		return replayCleanupCallerError(bound)
	case <-bound.done:
		select {
		case <-done:
			return replayCleanupCallerError(bound)
		default:
		}
		if err := replayCleanupCallerError(bound); err != nil {
			return err
		}
		return &ReplayRuntimeError{}
	case <-timer.C:
		select {
		case <-done:
			return replayCleanupCallerError(bound)
		default:
			return context.DeadlineExceeded
		}
	}
}

// startReplayRuntimeCleanup starts bounded child joins while retaining every owner.
func startReplayRuntimeCleanup(
	bound replayCleanupBound,
	store dkim2.ManagedReplayStore,
	deriver *dkim2.ReplayDeriver,
	closeDeriver func(context.Context) error,
) (<-chan bool, error) {
	storeCtx, cancelStore, deriverCtx, cancelDeriver, err := replayCleanupContexts(bound)
	if err != nil {
		return nil, err
	}
	result := make(chan bool, 1)
	go runReplayRuntimeCleanup(
		storeCtx, deriverCtx, result, cancelStore, cancelDeriver,
		store, deriver, closeDeriver,
	)
	return result, nil
}

// runReplayRuntimeCleanup sequences bounded starts and waits for exact child ownership.
func runReplayRuntimeCleanup(
	storeCtx context.Context,
	deriverCtx context.Context,
	result chan<- bool,
	cancelStore context.CancelFunc,
	cancelDeriver context.CancelFunc,
	store dkim2.ManagedReplayStore,
	deriver *dkim2.ReplayDeriver,
	closeDeriver func(context.Context) error,
) {
	defer cancelStore()
	defer cancelDeriver()
	failed := false
	var storeResult <-chan error
	if !nilInterface(store) {
		storeResult = startReplayStoreClose(storeCtx, store)
		var phaseFailed bool
		storeResult, phaseFailed = waitReplayCleanupPhase(storeCtx, storeResult)
		failed = phaseFailed
	}
	var deriverResult <-chan error
	if deriver != nil {
		deriverResult = startReplayDeriverClose(
			deriverCtx, deriver, closeDeriver,
		)
		var phaseFailed bool
		deriverResult, phaseFailed = waitReplayCleanupPhase(deriverCtx, deriverResult)
		failed = phaseFailed || failed
	}
	if storeResult != nil {
		failed = (<-storeResult) != nil || failed
	}
	if deriverResult != nil {
		failed = (<-deriverResult) != nil || failed
	}
	result <- failed
}

// waitReplayCleanupPhase gives a proven child result precedence at its deadline.
func waitReplayCleanupPhase(
	ctx context.Context,
	result <-chan error,
) (<-chan error, bool) {
	select {
	case err := <-result:
		return nil, err != nil
	case <-ctx.Done():
		select {
		case err := <-result:
			return nil, err != nil
		default:
			return result, true
		}
	}
}

// startReplayStoreClose owns one exact store-close invocation and join result.
func startReplayStoreClose(
	ctx context.Context,
	store dkim2.ManagedReplayStore,
) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- closeReplayStoreContained(ctx, store)
	}()
	return result
}

// startReplayDeriverClose owns one exact deriver-close invocation and join result.
func startReplayDeriverClose(
	ctx context.Context,
	deriver *dkim2.ReplayDeriver,
	closeDeriver func(context.Context) error,
) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- closeReplayDeriverContained(ctx, deriver, closeDeriver)
	}()
	return result
}

// closeReplayRuntimeOwners releases partial owners under one fresh rollback budget.
func closeReplayRuntimeOwners(
	rollback replayRollbackFactory,
	store dkim2.ManagedReplayStore,
	deriver *dkim2.ReplayDeriver,
) error {
	bound, err := freshReplayRollbackBound(rollback)
	if err != nil {
		return err
	}
	return closeReplayRuntimeOwnersWithBound(bound, store, deriver)
}

// closeReplayRuntimeOwnersWithBound closes store then deriver exactly once with reserved phases.
func closeReplayRuntimeOwnersWithBound(
	bound replayCleanupBound,
	store dkim2.ManagedReplayStore,
	deriver *dkim2.ReplayDeriver,
) error {
	result, err := startReplayRuntimeCleanup(bound, store, deriver, nil)
	if err != nil {
		return err
	}
	remaining := time.Until(bound.deadline)
	if remaining <= 0 {
		select {
		case failed := <-result:
			if failed {
				return &ReplayRuntimeError{}
			}
			return nil
		default:
			return &ReplayRuntimeError{}
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case failed := <-result:
		if failed {
			return &ReplayRuntimeError{}
		}
		return nil
	case <-timer.C:
		select {
		case failed := <-result:
			if failed {
				return &ReplayRuntimeError{}
			}
			return nil
		default:
			return &ReplayRuntimeError{}
		}
	}
}

// closeReplayStoreContained maps a hostile store cleanup panic to one bounded failure.
func closeReplayStoreContained(
	ctx context.Context,
	store dkim2.ManagedReplayStore,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &ReplayRuntimeError{}
		}
	}()
	return store.Close(ctx)
}

// closeReplayDeriverContained maps a hostile deriver cleanup panic to one bounded failure.
func closeReplayDeriverContained(
	ctx context.Context,
	deriver *dkim2.ReplayDeriver,
	closeDeriver func(context.Context) error,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &ReplayRuntimeError{}
		}
	}()
	if closeDeriver != nil {
		return closeDeriver(ctx)
	}
	return deriver.Close(ctx)
}

// replayCleanupContexts reserves the final part of one bounded budget for the deriver.
func replayCleanupContexts(
	bound replayCleanupBound,
) (
	storeCtx context.Context,
	cancelStore context.CancelFunc,
	deriverCtx context.Context,
	cancelDeriver context.CancelFunc,
	resultErr error,
) {
	remaining := time.Until(bound.deadline)
	storeDeadline := bound.deadline
	if remaining > 0 {
		reserve := time.Second
		if reserve >= remaining {
			reserve = remaining / 2
		}
		if reserve > 0 {
			storeDeadline = bound.deadline.Add(-reserve)
		}
	}
	storeCtx, cancelStore = context.WithDeadline(context.Background(), storeDeadline)
	deriverCtx, cancelDeriver = context.WithDeadline(context.Background(), bound.deadline)
	return storeCtx, cancelStore, deriverCtx, cancelDeriver, nil
}

// freshReplayRollbackBound obtains one live rollback bound capped at ten seconds.
func freshReplayRollbackBound(
	rollback replayRollbackFactory,
) (bound replayCleanupBound, resultErr error) {
	defer func() {
		if recover() != nil {
			bound = replayCleanupBound{}
			resultErr = &ReplayRuntimeError{}
		}
	}()
	if rollback == nil {
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	ctx := rollback()
	if nilInterface(ctx) {
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	bound, err := freezeReplayCleanupBound(ctx, replayRollbackLimit)
	if err != nil {
		return replayCleanupBound{}, &ReplayRuntimeError{}
	}
	return bound, nil
}

// String returns a content-free replay-runtime representation.
func (ReplayRuntime) String() string { return replayRuntimeRedacted }

// GoString returns a content-free replay-runtime representation.
func (ReplayRuntime) GoString() string { return replayRuntimeRedacted }

// Format prevents formatting from traversing providers or protected material.
func (ReplayRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayRuntimeRedacted)
}

// MarshalJSON rejects serialization of retained replay-runtime dependencies.
func (ReplayRuntime) MarshalJSON() ([]byte, error) {
	return nil, &ReplayRuntimeError{}
}

// MarshalText rejects diagnostic serialization of replay-runtime dependencies.
func (ReplayRuntime) MarshalText() ([]byte, error) {
	return nil, &ReplayRuntimeError{}
}

// IsReplayRuntimeError reports whether an error is a bounded composition failure.
func IsReplayRuntimeError(err error) bool {
	return errors.Is(err, &ReplayRuntimeError{})
}

// runtimeContextError returns only exact terminal identity or a runtime-layer failure.
func runtimeContextError(ctx context.Context) error {
	valid, terminal := boundedContextState(ctx)
	if !valid {
		return &ReplayRuntimeError{}
	}
	return terminal
}
