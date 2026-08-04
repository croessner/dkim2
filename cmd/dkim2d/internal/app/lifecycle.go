package app

import (
	"context"
	"errors"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

const (
	// LifecycleStartTimeout is the exact Fx outer startup contract.
	LifecycleStartTimeout = 115 * time.Second
	// LifecycleAcquisitionTimeout is the single bootstrap acquisition budget.
	LifecycleAcquisitionTimeout = 100 * time.Second
	// LifecycleRollbackTimeout is the shared reverse rollback budget.
	LifecycleRollbackTimeout = 10 * time.Second
	// LifecycleServeJoinTimeout bounds listener closure and serve-loop proof together.
	LifecycleServeJoinTimeout = 5 * time.Second
	// LifecycleRevalidatorJoinTimeout bounds periodic authority-loop shutdown.
	LifecycleRevalidatorJoinTimeout = 30 * time.Second
	// LifecycleFinalCleanupTimeout bounds replay and protected-material release together.
	LifecycleFinalCleanupTimeout = 5 * time.Second
	// LifecycleStopMargin is the fixed non-server portion of the outer stop contract.
	LifecycleStopMargin = 50 * time.Second
)

const lifecycleErrorText = "dkim2d lifecycle failure"

// LifecycleError reports one stable content-free lifecycle failure.
type LifecycleError struct{}

// Error returns the stable lifecycle diagnostic.
func (*LifecycleError) Error() string { return lifecycleErrorText }

// Is recognizes the bounded lifecycle failure class.
func (*LifecycleError) Is(target error) bool {
	_, ok := target.(*LifecycleError)
	return ok
}

// IsLifecycleError reports whether err belongs to the lifecycle failure class.
func IsLifecycleError(err error) bool {
	return errors.Is(err, &LifecycleError{})
}

// LifecycleStopTimeout derives the exact outer stop budget from server configuration.
func LifecycleStopTimeout(shutdown time.Duration) (time.Duration, error) {
	if shutdown <= 0 || shutdown > time.Duration(math.MaxInt64)-LifecycleStopMargin {
		return 0, &LifecycleError{}
	}
	return shutdown + LifecycleStopMargin, nil
}

// lifecycleReplay is the provider-neutral replay owner retained by the lifecycle.
type lifecycleReplay interface {
	ReplayService
	AuthorityReadiness
	Close(context.Context) error
}

// lifecycleRevalidator is the optional periodic authority owner.
type lifecycleRevalidator interface {
	RunObserved(context.Context, ServeReturnObserver) error
	Started() <-chan struct{}
	Activate() error
	Running() bool
}

// lifecycleMaterial is the transferred protected-runtime owner.
type lifecycleMaterial interface {
	Close() error
}

// lifecycleDependencies contains private deterministic construction and clock seams.
type lifecycleDependencies struct {
	withTimeout            func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	newDetachedParent      func() context.Context
	initialShutdownTimeout func(*config.Prebootstrap) (time.Duration, error)
	prepareRuntime         func(*config.Prebootstrap) (*config.RuntimePreparation, error)
	newObservability       func(context.Context, *config.RuntimePreparation) (*observability.Runtime, error)
	newDNSVerifier         func(context.Context, *config.RuntimePreparation, *observability.Runtime) (VerificationService, error)
	newReplayRuntime       func(
		context.Context,
		replayRollbackFactory,
		*config.RuntimePreparation,
	) (lifecycleReplay, error)
	newApplication func(
		*config.RuntimePreparation,
		VerificationService,
		lifecycleReplay,
	) (*InboundProcessor, error)
	newReadiness   func(AuthorityReadiness) (*Readiness, error)
	newRevalidator func(
		*config.RuntimePreparation,
		lifecycleReplay,
	) (lifecycleRevalidator, error)
	newHTTPInput func(
		context.Context,
		*config.RuntimePreparation,
		*InboundProcessor,
		*Readiness,
		FatalNotifier,
		ServeReturnObserver,
		ActivationAuthority,
	) (HTTPAssemblyInput, error)
	commitRuntime func(
		*config.Prebootstrap,
		*config.RuntimePreparation,
	) (lifecycleMaterial, error)
	shutdownTimeout          func(*config.RuntimePreparation) (time.Duration, error)
	beforeStartCancelInstall func()
	beforePublication        func()
}

// lifecyclePhase is the instance-owned startup and shutdown linearization state.
type lifecyclePhase uint8

const (
	lifecycleNew lifecyclePhase = iota
	lifecycleStarting
	lifecycleCommitting
	lifecycleActivating
	lifecycleRunning
	lifecycleFatal
	lifecycleStoppingClean
	lifecycleStoppingFatal
	lifecycleStoppedClean
	lifecycleStoppedFatal
)

type lifecycleActivationState uint32

const (
	lifecycleActivationInactive lifecycleActivationState = iota
	lifecycleActivationArmed
	lifecycleActivationClaimed
	lifecycleActivationPublished
	lifecycleActivationTerminal
)

// Lifecycle owns one daemon instance from pure composition through proven teardown.
type Lifecycle struct {
	state *lifecycleState
}

// lifecycleState retains only instance-owned construction and runtime state.
type lifecycleState struct {
	mu                  sync.Mutex
	phase               lifecyclePhase
	owner               *config.Prebootstrap
	factory             HTTPFactory
	deps                lifecycleDependencies
	shutdown            chan struct{}
	shutdownOnce        sync.Once
	stopDone            chan struct{}
	startDone           chan struct{}
	startDoneOnce       sync.Once
	stopErr             error
	stopAdmissionFailed bool
	fatalPending        atomic.Bool
	stopping            atomic.Bool
	startupInProgress   atomic.Bool
	activationState     atomic.Uint32
	startCancel         context.CancelFunc
	readiness           *Readiness
	telemetry           *observability.Runtime
	replay              lifecycleReplay
	signing             *networkSigningRuntime
	revalidator         lifecycleRevalidator
	revalidatorStop     context.CancelFunc
	revalidatorDone     <-chan struct{}
	dnsStop             context.CancelFunc
	requestStop         context.CancelFunc
	http                HTTPRuntime
	serveDone           <-chan struct{}
	material            lifecycleMaterial
	shutdownLimit       time.Duration
}

// lifecycleStartup owns every partially constructed resource until final transfer.
type lifecycleStartup struct {
	owner           *config.Prebootstrap
	deps            lifecycleDependencies
	rollback        *lifecycleRollback
	readiness       *Readiness
	telemetry       *observability.Runtime
	replay          lifecycleReplay
	signing         *networkSigningRuntime
	authority       AuthorityReadiness
	revalidator     lifecycleRevalidator
	revalidatorStop context.CancelFunc
	revalidatorDone chan struct{}
	dnsStop         context.CancelFunc
	requestStop     context.CancelFunc
	http            HTTPRuntime
	serveDone       chan struct{}
	serveLive       atomic.Bool
	revalidatorLive atomic.Bool
	material        lifecycleMaterial
	operation       OperationService
	shutdownLimit   time.Duration
}

// lifecycleRollback lazily creates one shared aggregate rollback context.
type lifecycleRollback struct {
	once   sync.Once
	deps   lifecycleDependencies
	ctx    context.Context
	cancel context.CancelFunc
}

// context returns the one shared aggregate rollback context.
func (r *lifecycleRollback) context() context.Context {
	r.once.Do(func() {
		parent := r.deps.newDetachedParent()
		r.ctx, r.cancel = r.deps.withTimeout(parent, LifecycleRollbackTimeout)
	})
	return r.ctx
}

// close releases the lazily created rollback timer.
func (r *lifecycleRollback) close() {
	if r.cancel != nil {
		r.cancel()
	}
}

// NewLifecycle constructs one pure app-owned daemon lifecycle.
func NewLifecycle(owner *config.Prebootstrap, factory HTTPFactory) (*Lifecycle, error) {
	return newLifecycleWithDependencies(owner, factory, productionLifecycleDependencies())
}

// newLifecycleWithDependencies constructs one lifecycle through private deterministic seams.
func newLifecycleWithDependencies(
	owner *config.Prebootstrap,
	factory HTTPFactory,
	deps lifecycleDependencies,
) (*Lifecycle, error) {
	if owner == nil || nilInterface(factory) || !deps.valid() {
		return nil, &LifecycleError{}
	}
	shutdownLimit, err := deps.initialShutdownTimeout(owner)
	if err != nil {
		return nil, &LifecycleError{}
	}
	if _, err := LifecycleStopTimeout(shutdownLimit); err != nil {
		return nil, &LifecycleError{}
	}
	return &Lifecycle{state: &lifecycleState{
		phase: lifecycleNew, owner: owner, factory: factory, deps: deps,
		shutdown: make(chan struct{}), startDone: make(chan struct{}),
		stopDone: make(chan struct{}), shutdownLimit: shutdownLimit,
	}}, nil
}

// valid reports whether every mandatory deterministic seam is present.
func (d lifecycleDependencies) valid() bool {
	return d.withTimeout != nil && d.newDetachedParent != nil &&
		d.initialShutdownTimeout != nil &&
		d.prepareRuntime != nil && d.newObservability != nil && d.newDNSVerifier != nil &&
		d.newReplayRuntime != nil && d.newApplication != nil &&
		d.newReadiness != nil && d.newRevalidator != nil &&
		d.newHTTPInput != nil && d.commitRuntime != nil &&
		d.shutdownTimeout != nil && d.beforeStartCancelInstall != nil &&
		d.beforePublication != nil
}

// productionLifecycleDependencies binds lifecycle orchestration to app constructors.
func productionLifecycleDependencies() lifecycleDependencies {
	return lifecycleDependencies{
		withTimeout: context.WithTimeout,
		newDetachedParent: func() context.Context {
			return context.Background()
		},
		initialShutdownTimeout: func(owner *config.Prebootstrap) (time.Duration, error) {
			timeout := owner.Snapshot().Server().ShutdownTimeout()
			if _, err := LifecycleStopTimeout(timeout); err != nil {
				return 0, err
			}
			return timeout, nil
		},
		prepareRuntime: func(owner *config.Prebootstrap) (*config.RuntimePreparation, error) {
			return owner.PrepareRuntime()
		},
		newObservability: func(
			ctx context.Context,
			preparation *config.RuntimePreparation,
		) (*observability.Runtime, error) {
			return observability.NewRuntime(
				ctx,
				preparation.Snapshot().Observability(),
				os.Stderr,
				preparation.TracingMaterial(),
			)
		},
		newDNSVerifier: func(
			parent context.Context,
			preparation *config.RuntimePreparation,
			runtime *observability.Runtime,
		) (VerificationService, error) {
			return NewDNSVerifier(parent, preparation.Snapshot().DNS(), runtime)
		},
		newReplayRuntime: func(
			ctx context.Context,
			rollback replayRollbackFactory,
			preparation *config.RuntimePreparation,
		) (lifecycleReplay, error) {
			return NewReplayRuntime(ctx, rollback, preparation)
		},
		newApplication: func(
			preparation *config.RuntimePreparation,
			verifier VerificationService,
			replay lifecycleReplay,
		) (*InboundProcessor, error) {
			domain, err := NewDomainProcessor(verifier, preparation.Snapshot().PolicyMode())
			if err != nil {
				return nil, err
			}
			return NewInboundProcessor(domain, replay)
		},
		newReadiness: func(authority AuthorityReadiness) (*Readiness, error) {
			return NewReadiness(authority)
		},
		newRevalidator: func(
			preparation *config.RuntimePreparation,
			replay lifecycleReplay,
		) (lifecycleRevalidator, error) {
			if preparation.Snapshot().Replay().Backend() != config.ReplayValkey {
				return nil, nil
			}
			runtime, ok := replay.(*ReplayRuntime)
			if !ok || runtime == nil {
				return nil, &LifecycleError{}
			}
			return NewReplayRevalidator(runtime)
		},
		newHTTPInput: newHTTPAssemblyInput,
		commitRuntime: func(
			owner *config.Prebootstrap,
			preparation *config.RuntimePreparation,
		) (lifecycleMaterial, error) {
			return owner.CommitRuntime(preparation)
		},
		shutdownTimeout: func(preparation *config.RuntimePreparation) (time.Duration, error) {
			timeout := preparation.Snapshot().Server().ShutdownTimeout()
			if _, err := LifecycleStopTimeout(timeout); err != nil {
				return 0, err
			}
			return timeout, nil
		},
		beforeStartCancelInstall: func() {},
		beforePublication:        func() {},
	}
}

// Start contains every startup and cleanup panic behind one stable boundary.
func (l *Lifecycle) Start(caller context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return l.start(caller)
}

// start acquires, validates, and atomically publishes one daemon runtime.
func (l *Lifecycle) start(caller context.Context) (resultErr error) {
	if l == nil || l.state == nil || nilInterface(caller) {
		return &LifecycleError{}
	}
	if !l.beginStart() {
		return &LifecycleError{}
	}
	startup := &lifecycleStartup{
		owner: l.state.owner,
		deps:  l.state.deps,
		rollback: &lifecycleRollback{
			deps: l.state.deps,
		},
	}
	committed := false
	defer func() {
		l.state.mu.Lock()
		l.finishStartupLocked()
		l.state.mu.Unlock()
	}()
	defer func() {
		if recover() != nil {
			l.NotifyFatal()
			resultErr = &LifecycleError{}
		}
		if !committed {
			l.markStartupFailed()
			if startup.rollbackOwners() != nil {
				resultErr = &LifecycleError{}
			}
		}
		startup.rollback.close()
		if resultErr != nil {
			resultErr = &LifecycleError{}
		}
	}()

	outer, outerCancel := l.state.deps.withTimeout(caller, LifecycleStartTimeout)
	defer outerCancel()
	acquisition, acquisitionCancel := l.state.deps.withTimeout(
		outer,
		LifecycleAcquisitionTimeout,
	)
	defer acquisitionCancel()
	l.state.deps.beforeStartCancelInstall()
	l.state.mu.Lock()
	if l.state.phase != lifecycleStarting {
		l.state.mu.Unlock()
		return &LifecycleError{}
	}
	l.state.startCancel = acquisitionCancel
	l.state.mu.Unlock()
	if lifecycleContextFailed(acquisition) {
		return &LifecycleError{}
	}
	preparation, verifier, err := l.acquireProtocol(acquisition, startup)
	if err != nil {
		return err
	}
	processor, err := l.assembleApplication(acquisition, startup, preparation, verifier)
	if err != nil {
		return err
	}
	runtime, err := l.bindTransport(acquisition, startup, preparation, processor)
	if err != nil {
		return err
	}
	if err := l.startProducers(acquisition, startup, runtime); err != nil {
		return err
	}
	if !l.finalizeStart(acquisition, startup, preparation, startup.shutdownLimit) {
		return &LifecycleError{}
	}
	committed = true
	return nil
}

// acquireProtocol prepares immutable configuration and acquires DNS and replay owners.
func (l *Lifecycle) acquireProtocol(
	acquisition context.Context,
	startup *lifecycleStartup,
) (*config.RuntimePreparation, VerificationService, error) {
	preparation, err := l.state.deps.prepareRuntime(l.state.owner)
	if err != nil || preparation == nil || lifecycleContextFailed(acquisition) {
		return nil, nil, &LifecycleError{}
	}
	shutdownLimit, err := l.state.deps.shutdownTimeout(preparation)
	if err != nil || shutdownLimit != l.state.shutdownLimit {
		return nil, nil, &LifecycleError{}
	}
	startup.shutdownLimit = shutdownLimit
	telemetry, err := l.state.deps.newObservability(acquisition, preparation)
	if err != nil || telemetry == nil || lifecycleContextFailed(acquisition) {
		return nil, nil, &LifecycleError{}
	}
	startup.telemetry = telemetry
	if lifecycleContextFailed(acquisition) {
		return nil, nil, &LifecycleError{}
	}
	dnsParent, dnsStop := context.WithCancel(l.state.deps.newDetachedParent())
	startup.dnsStop = dnsStop
	verifier, err := l.state.deps.newDNSVerifier(dnsParent, preparation, startup.telemetry)
	if err != nil || nilInterface(verifier) || lifecycleContextFailed(acquisition) {
		return nil, nil, &LifecycleError{}
	}
	replay, err := l.state.deps.newReplayRuntime(
		acquisition,
		startup.rollback.context,
		preparation,
	)
	if !nilInterface(replay) {
		startup.replay = replay
	}
	if err != nil || nilInterface(replay) || lifecycleContextFailed(acquisition) {
		return nil, nil, &LifecycleError{}
	}
	if !sampleStartupAuthority(replay) || lifecycleContextFailed(acquisition) {
		return nil, nil, &LifecycleError{}
	}
	startup.authority = replay
	return preparation, verifier, nil
}

// assembleApplication constructs app services and optional replay revalidation.
func (l *Lifecycle) assembleApplication(
	acquisition context.Context,
	startup *lifecycleStartup,
	preparation *config.RuntimePreparation,
	verifier VerificationService,
) (*InboundProcessor, error) {
	processor, err := l.state.deps.newApplication(preparation, verifier, startup.replay)
	if err != nil || processor == nil || lifecycleContextFailed(acquisition) {
		return nil, &LifecycleError{}
	}
	processor.attachObservability(startup.telemetry)
	if preparation.Snapshot().Signing().Enabled() {
		publicKeys, ok := verifier.(dkim2.PublicKeyProvider)
		if !ok || nilInterface(publicKeys) {
			return nil, &LifecycleError{}
		}
		var (
			operation    *SigningService
			operationErr error
		)
		if preparation.Snapshot().Signing().Backend() == config.SigningFlatFile {
			operation, operationErr = NewSigningService(
				publicKeys,
				preparation.SigningStore(),
				preparation.Snapshot().Signing().AllowRecipientGroup(),
			)
		} else {
			startup.signing, operationErr = newNetworkSigningRuntime(
				acquisition, preparation, startup.telemetry,
			)
			if operationErr == nil && startup.signing != nil {
				operation, operationErr = NewDatasourceSigningService(
					publicKeys,
					startup.signing.runtime,
					preparation.Snapshot().Signing().AllowRecipientGroup(),
				)
				startup.authority = joinedAuthority{
					replay: startup.replay, signing: startup.signing,
				}
			}
		}
		if operationErr != nil || operation == nil {
			return nil, &LifecycleError{}
		}
		if preparation.Snapshot().Signing().Backend() == config.SigningFlatFile {
			if startErr := preparation.SigningStore().StartReload(
				preparation.Snapshot().Signing().ReloadInterval(),
			); startErr != nil {
				return nil, &LifecycleError{}
			}
		}
		startup.operation = operation
	}
	readiness, err := l.state.deps.newReadiness(startup.authority)
	if err != nil || readiness == nil {
		return nil, &LifecycleError{}
	}
	startup.readiness = readiness
	if !readiness.bindFatalGate(&l.state.fatalPending) ||
		lifecycleContextFailed(acquisition) {
		return nil, &LifecycleError{}
	}
	revalidator, err := l.state.deps.newRevalidator(preparation, startup.replay)
	if !nilInterface(revalidator) {
		startup.revalidator = revalidator
	}
	if err != nil || lifecycleContextFailed(acquisition) {
		return nil, &LifecycleError{}
	}
	return processor, nil
}

// bindTransport assembles and binds the HTTP owner without publishing readiness.
func (l *Lifecycle) bindTransport(
	acquisition context.Context,
	startup *lifecycleStartup,
	preparation *config.RuntimePreparation,
	processor *InboundProcessor,
) (HTTPRuntime, error) {
	requestParent, requestStop := context.WithCancel(l.state.deps.newDetachedParent())
	startup.requestStop = requestStop
	input, err := l.state.deps.newHTTPInput(
		requestParent,
		preparation,
		processor,
		startup.readiness,
		l,
		l,
		l,
	)
	input = input.withOperation(
		startup.operation,
		preparation.SignCapability(),
		preparation.ReviseCapability(),
		preparation.DSNSignCapability(),
	)
	input = input.withObservability(startup.telemetry)
	if err != nil || lifecycleContextFailed(acquisition) {
		return nil, &LifecycleError{}
	}
	assembly, err := invokeHTTPAssembly(l.state.factory, input)
	if err != nil || nilInterface(assembly) || lifecycleContextFailed(acquisition) {
		return nil, &LifecycleError{}
	}
	runtime, err := invokeHTTPBind(acquisition, assembly)
	if !nilInterface(runtime) {
		startup.http = runtime
	}
	if err != nil || nilInterface(runtime) || lifecycleContextFailed(acquisition) {
		return nil, &LifecycleError{}
	}
	return runtime, nil
}

// startProducers proves HTTP and optional revalidator goroutine ownership.
func (l *Lifecycle) startProducers(
	acquisition context.Context,
	startup *lifecycleStartup,
	runtime HTTPRuntime,
) error {
	if !startup.startServe(acquisition, l, runtime) || !invokeServing(runtime) ||
		lifecycleContextFailed(acquisition) {
		return &LifecycleError{}
	}
	if !startup.startRevalidator(acquisition, l) || !invokeServing(runtime) ||
		lifecycleContextFailed(acquisition) {
		return &LifecycleError{}
	}
	return nil
}

// beginStart reserves the one permitted startup attempt.
func (l *Lifecycle) beginStart() bool {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if l.state.phase != lifecycleNew {
		return false
	}
	l.state.phase = lifecycleStarting
	l.state.startupInProgress.Store(true)
	return true
}

// finalizeStart linearizes final authority proof, ownership transfer, activation, and readiness.
func (l *Lifecycle) finalizeStart(
	acquisition context.Context,
	startup *lifecycleStartup,
	preparation *config.RuntimePreparation,
	shutdownLimit time.Duration,
) bool {
	if !l.enterCommit(acquisition, startup) ||
		!l.commitStartup(acquisition, startup, preparation) ||
		!l.activateStartup(acquisition, startup) {
		return false
	}
	return l.publishStartup(acquisition, startup, shutdownLimit)
}

// enterCommit proves pre-transfer liveness and reserves the commit phase.
func (l *Lifecycle) enterCommit(
	acquisition context.Context,
	startup *lifecycleStartup,
) bool {
	if lifecycleContextFailed(acquisition) {
		return false
	}
	servingBeforeCommit := startup.serveLive.Load()
	authorityBeforeCommit := sampleStartupAuthority(startup.authority)
	servingAfterAuthority := startup.serveLive.Load()
	acquisitionLiveBeforeCommit := !lifecycleContextFailed(acquisition)
	l.state.mu.Lock()
	if l.state.phase != lifecycleStarting || !servingBeforeCommit ||
		!authorityBeforeCommit || !servingAfterAuthority ||
		!acquisitionLiveBeforeCommit ||
		l.state.fatalPending.Load() {
		l.transitionFatalLocked()
		l.state.mu.Unlock()
		return false
	}
	l.state.phase = lifecycleCommitting
	l.state.mu.Unlock()
	return true
}

// commitStartup transfers protected material and enters activation.
func (l *Lifecycle) commitStartup(
	acquisition context.Context,
	startup *lifecycleStartup,
	preparation *config.RuntimePreparation,
) bool {
	material, valid, err := invokeCommit(
		l.state.deps.commitRuntime,
		l.state.owner,
		preparation,
	)
	if valid && !nilInterface(material) {
		startup.material = material
	}
	acquisitionLiveAfterCommit := !lifecycleContextFailed(acquisition)
	authorityAfterCommit := sampleStartupAuthority(startup.authority)
	l.state.mu.Lock()
	if l.state.phase != lifecycleCommitting ||
		!valid || err != nil || nilInterface(material) ||
		!acquisitionLiveAfterCommit || !authorityAfterCommit ||
		l.state.fatalPending.Load() {
		l.transitionFatalLocked()
		l.state.mu.Unlock()
		return false
	}
	l.state.phase = lifecycleActivating
	l.state.mu.Unlock()
	return true
}

// activateStartup opens only producer gates backed by live committed owners.
func (l *Lifecycle) activateStartup(
	acquisition context.Context,
	startup *lifecycleStartup,
) bool {
	if !nilInterface(startup.revalidator) &&
		invokeRevalidatorActivate(startup.revalidator) != nil {
		l.transitionStartupFatal()
		return false
	}
	if lifecycleContextFailed(acquisition) {
		l.transitionStartupFatal()
		return false
	}
	if !startup.serveLive.Load() || !invokeServing(startup.http) ||
		(!nilInterface(startup.revalidator) &&
			(!startup.revalidatorLive.Load() ||
				!invokeRevalidatorRunning(startup.revalidator))) ||
		l.state.fatalPending.Load() {
		l.transitionStartupFatal()
		return false
	}
	if lifecycleContextFailed(acquisition) {
		l.transitionStartupFatal()
		return false
	}
	if !l.state.activationState.CompareAndSwap(
		uint32(lifecycleActivationInactive),
		uint32(lifecycleActivationArmed),
	) {
		l.transitionStartupFatal()
		return false
	}
	if err := invokeActivate(startup.http); err != nil {
		l.transitionStartupFatal()
		return false
	}
	if lifecycleContextFailed(acquisition) {
		l.transitionStartupFatal()
		return false
	}
	if lifecycleActivationState(l.state.activationState.Load()) != lifecycleActivationClaimed {
		l.transitionStartupFatal()
		return false
	}
	return true
}

// publishStartup linearizes terminal competition, ownership, and readiness.
func (l *Lifecycle) publishStartup(
	acquisition context.Context,
	startup *lifecycleStartup,
	shutdownLimit time.Duration,
) bool {
	servingForPublication := startup.serveLive.Load()
	revalidatorRunningForPublication := nilInterface(startup.revalidator) ||
		startup.revalidatorLive.Load()
	authorityForPublication := sampleStartupAuthority(startup.authority)
	l.state.deps.beforePublication()
	acquisitionLiveForPublication := !lifecycleContextFailed(acquisition)
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if l.state.phase != lifecycleActivating || !servingForPublication ||
		!revalidatorRunningForPublication || !authorityForPublication ||
		!acquisitionLiveForPublication ||
		l.state.fatalPending.Load() {
		l.transitionFatalLocked()
		return false
	}
	if !l.state.activationState.CompareAndSwap(
		uint32(lifecycleActivationClaimed),
		uint32(lifecycleActivationPublished),
	) {
		l.transitionFatalLocked()
		return false
	}
	l.state.readiness = startup.readiness
	l.state.telemetry = startup.telemetry
	l.state.replay = startup.replay
	l.state.signing = startup.signing
	l.state.revalidator = startup.revalidator
	l.state.revalidatorStop = startup.revalidatorStop
	l.state.revalidatorDone = startup.revalidatorDone
	l.state.dnsStop = startup.dnsStop
	l.state.requestStop = startup.requestStop
	l.state.http = startup.http
	l.state.serveDone = startup.serveDone
	l.state.material = startup.material
	l.state.shutdownLimit = shutdownLimit
	l.state.phase = lifecycleRunning
	if !startup.readiness.publishReady() {
		l.transitionFatalLocked()
		l.clearRuntimeLocked()
		return false
	}
	startup.telemetry.SetReady(true)
	l.finishStartupLocked()
	return true
}

// transitionStartupFatal records one failed finalization outside external callbacks.
func (l *Lifecycle) transitionStartupFatal() {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	l.transitionFatalLocked()
}

// finishStartupLocked publishes completion before releasing the startup guard.
func (l *Lifecycle) finishStartupLocked() {
	l.state.startDoneOnce.Do(func() { close(l.state.startDone) })
	l.state.startCancel = nil
	l.state.startupInProgress.Store(false)
}

// startServe starts one app-owned serve goroutine and classifies every return.
func (s *lifecycleStartup) startServe(
	acquisition context.Context,
	lifecycle *Lifecycle,
	runtime HTTPRuntime,
) bool {
	started, valid := invokeServeStarted(runtime)
	if !valid || started == nil {
		return false
	}
	done := make(chan struct{})
	s.serveDone = done
	s.serveLive.Store(true)
	go func() {
		defer close(done)
		defer s.serveLive.Store(false)
		defer containServeReturnFallback(lifecycle)
		_ = invokeServe(runtime)
	}()
	return waitLifecycleStarted(acquisition, started, done)
}

// startRevalidator starts one gated app-owned revalidation goroutine when configured.
func (s *lifecycleStartup) startRevalidator(
	acquisition context.Context,
	lifecycle *Lifecycle,
) bool {
	if nilInterface(s.revalidator) {
		return true
	}
	parent, cancel := context.WithCancel(s.deps.newDetachedParent())
	started, valid := invokeRevalidatorStarted(s.revalidator)
	if !valid || started == nil {
		cancel()
		return false
	}
	done := make(chan struct{})
	s.revalidatorStop = cancel
	s.revalidatorDone = done
	s.revalidatorLive.Store(true)
	go func() {
		defer close(done)
		defer s.revalidatorLive.Store(false)
		defer containServeReturnFallback(lifecycle)
		_ = invokeRevalidator(parent, s.revalidator, lifecycle)
	}()
	return waitLifecycleStarted(acquisition, started, done)
}

// NotifyServeReturn classifies one synchronous owned Serve return against stopping.
func (l *Lifecycle) NotifyServeReturn() {
	if l == nil || l.state == nil {
		return
	}
	if l.state.stopping.Load() {
		return
	}
	l.publishFatalPending()
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	switch l.state.phase {
	case lifecycleStarting, lifecycleCommitting, lifecycleActivating, lifecycleRunning:
		l.transitionFatalLocked()
	case lifecycleStoppingClean:
		l.state.phase = lifecycleStoppingFatal
		if l.state.readiness != nil {
			l.state.readiness.withdrawReady()
		}
	}
}

// notifyServeReturnFallback publishes only when the producer omitted terminal notification.
func (l *Lifecycle) notifyServeReturnFallback() {
	if l == nil || l.state == nil ||
		l.state.stopping.Load() || l.state.fatalPending.Load() {
		return
	}
	l.NotifyServeReturn()
}

// containServeReturnFallback prevents a fallback defect from skipping owner release.
func containServeReturnFallback(lifecycle *Lifecycle) {
	defer func() { _ = recover() }()
	lifecycle.notifyServeReturnFallback()
}

// NotifyFatal publishes one content-free fatal transition and shutdown request.
func (l *Lifecycle) NotifyFatal() {
	if l == nil || l.state == nil {
		return
	}
	l.publishFatalPending()
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	l.transitionFatalLocked()
}

// AllowHTTPActivation reports the one lock-free registration-gate authorization fact.
func (l *Lifecycle) AllowHTTPActivation() bool {
	if l == nil || l.state == nil || l.state.fatalPending.Load() ||
		!l.state.activationState.CompareAndSwap(
			uint32(lifecycleActivationArmed),
			uint32(lifecycleActivationClaimed),
		) {
		return false
	}
	if l.state.fatalPending.Load() {
		l.state.activationState.Store(uint32(lifecycleActivationTerminal))
		return false
	}
	return true
}

// transitionFatalLocked withdraws readiness and closes the exact-once shutdown signal.
func (l *Lifecycle) transitionFatalLocked() {
	l.publishFatalPending()
	switch l.state.phase {
	case lifecycleNew, lifecycleStarting, lifecycleCommitting, lifecycleActivating, lifecycleRunning:
		l.state.phase = lifecycleFatal
	case lifecycleStoppingClean:
		l.state.phase = lifecycleStoppingFatal
	case lifecycleStoppedClean:
		l.state.phase = lifecycleStoppedFatal
	}
	if l.state.readiness != nil {
		l.state.readiness.withdrawReady()
	}
	if l.state.telemetry != nil {
		l.state.telemetry.SetReady(false)
	}
	l.state.shutdownOnce.Do(func() { close(l.state.shutdown) })
}

// publishFatalPending terminalizes activation before exposing the fatal fact.
func (l *Lifecycle) publishFatalPending() {
	l.state.activationState.Store(uint32(lifecycleActivationTerminal))
	l.state.fatalPending.Store(true)
}

// markStartupFailed preserves a fatal non-ready terminal startup state.
func (l *Lifecycle) markStartupFailed() {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	l.transitionFatalLocked()
}

// Ready reports the instance-owned no-I/O readiness state.
func (l *Lifecycle) Ready() bool {
	if l == nil || l.state == nil {
		return false
	}
	l.state.mu.Lock()
	readiness := l.state.readiness
	l.state.mu.Unlock()
	return readiness != nil && readiness.Ready()
}

// ShutdownRequests returns the exact-once orderly-shutdown request signal.
func (l *Lifecycle) ShutdownRequests() <-chan struct{} {
	if l == nil || l.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return l.state.shutdown
}

// Stop withdraws admission and proves every joined owner before reverse teardown.
func (l *Lifecycle) Stop(caller context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return l.stop(caller)
}

// stop implements the exact-once stop election behind the public panic boundary.
func (l *Lifecycle) stop(caller context.Context) (resultErr error) {
	if l == nil || l.state == nil || nilInterface(caller) {
		return &LifecycleError{}
	}
	l.state.mu.Lock()
	shutdownLimit := l.state.shutdownLimit
	l.state.mu.Unlock()
	outerLimit, err := LifecycleStopTimeout(shutdownLimit)
	if err != nil {
		return &LifecycleError{}
	}
	outer, outerCancel := l.state.deps.withTimeout(caller, outerLimit)
	defer func() {
		defer func() { _ = recover() }()
		outerCancel()
	}()
	owner, wait, clean, startupCancel := l.beginStop()
	startupCancelFailed := startupCancel != nil &&
		!invokeCancelBounded(outer, startupCancel)
	if !owner {
		if wait == nil {
			if clean {
				return nil
			}
			return &LifecycleError{}
		}
		select {
		case <-wait:
		case <-outer.Done():
			select {
			case <-wait:
			default:
				return &LifecycleError{}
			}
		}
		if lifecycleContextFailed(outer) {
			select {
			case <-wait:
			default:
				return &LifecycleError{}
			}
		}
		l.state.mu.Lock()
		err := l.state.stopErr
		phase := l.state.phase
		l.state.mu.Unlock()
		if err == nil && phase != lifecycleStoppedClean {
			return &LifecycleError{}
		}
		if startupCancelFailed {
			return &LifecycleError{}
		}
		return err
	}

	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
		l.finishStop(resultErr)
		l.state.mu.Lock()
		resultErr = l.state.stopErr
		l.state.mu.Unlock()
	}()
	if !invokeRejectNewRequestsBounded(outer, l.state.http) {
		l.state.mu.Lock()
		l.state.stopAdmissionFailed = true
		l.transitionFatalLocked()
		l.state.mu.Unlock()
		resultErr = &LifecycleError{}
		return resultErr
	}
	resultErr = l.stopOwned(outer)
	return resultErr
}

// beginStop reserves exact-once stop ownership or returns the current owner join.
func (l *Lifecycle) beginStop() (
	owner bool,
	wait <-chan struct{},
	clean bool,
	startupCancel context.CancelFunc,
) {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if l.state.startupInProgress.Load() {
		l.transitionFatalLocked()
		cancel := l.state.startCancel
		l.state.startCancel = nil
		return false, l.state.startDone, false, cancel
	}
	switch l.state.phase {
	case lifecycleRunning:
		l.state.phase = lifecycleStoppingClean
		l.state.stopping.Store(true)
		if l.state.readiness != nil {
			l.state.readiness.beginStopping()
		}
		if l.state.telemetry != nil {
			l.state.telemetry.SetReady(false)
		}
		if l.state.fatalPending.Load() {
			l.state.phase = lifecycleStoppingFatal
		}
	case lifecycleFatal:
		l.state.phase = lifecycleStoppingFatal
		l.state.stopping.Store(true)
		if l.state.readiness != nil {
			l.state.readiness.beginStopping()
		}
		if l.state.telemetry != nil {
			l.state.telemetry.SetReady(false)
		}
	case lifecycleStoppingClean, lifecycleStoppingFatal:
		return false, l.state.stopDone, false, nil
	case lifecycleStarting, lifecycleCommitting, lifecycleActivating:
		l.transitionFatalLocked()
		return false, nil, false, nil
	case lifecycleStoppedClean:
		return false, nil, true, nil
	case lifecycleStoppedFatal:
		return false, nil, false, nil
	default:
		l.transitionFatalLocked()
		return false, nil, false, nil
	}
	return true, nil, false, nil
}

// stopOwned performs the exact ordered stop contract for the elected owner.
func (l *Lifecycle) stopOwned(outer context.Context) error {
	if l.state.stopAdmissionFailed {
		return &LifecycleError{}
	}
	shutdownLimit := l.state.shutdownLimit
	serveCtx, serveCancel := l.state.deps.withTimeout(outer, LifecycleServeJoinTimeout)
	serveJoined := closeListenerAndJoin(serveCtx, l.state.http, l.state.serveDone)
	serveCancel()
	if !serveJoined {
		if l.state.requestStop != nil {
			l.state.requestStop()
		}
		return &LifecycleError{}
	}

	shutdownCtx, shutdownCancel := l.state.deps.withTimeout(outer, shutdownLimit)
	shutdownOK := invokeShutdown(shutdownCtx, l.state.http) == nil
	shutdownCancel()
	failed := !shutdownOK
	forceCtx, forceCancel := l.state.deps.withTimeout(
		outer,
		LifecycleServeJoinTimeout,
	)
	defer forceCancel()
	handlersOK := shutdownOK && invokeHandlersQuiescent(l.state.http)
	if !shutdownOK || !handlersOK {
		failed = true
		if l.state.requestStop != nil {
			l.state.requestStop()
		}
		forceOK := invokeForceClose(forceCtx, l.state.http) == nil
		if forceOK {
			handlersOK = invokeWaitHandlers(forceCtx, l.state.http) == nil
		}
		if !forceOK || !handlersOK {
			return &LifecycleError{}
		}
	}
	if l.state.requestStop != nil {
		l.state.requestStop()
	}

	if l.state.revalidatorStop != nil {
		l.state.revalidatorStop()
	}
	revalidationCtx, revalidationCancel := l.state.deps.withTimeout(
		outer,
		LifecycleRevalidatorJoinTimeout,
	)
	revalidationJoined := waitLifecycleDone(revalidationCtx, l.state.revalidatorDone)
	revalidationCancel()
	if !revalidationJoined {
		return &LifecycleError{}
	}
	if l.state.dnsStop != nil {
		l.state.dnsStop()
	}

	finalCtx, finalCancel := l.state.deps.withTimeout(
		outer,
		LifecycleFinalCleanupTimeout,
	)
	defer finalCancel()
	if invokeReplayClose(finalCtx, l.state.replay) != nil {
		failed = true
	}
	if l.state.signing != nil && l.state.signing.Close(finalCtx) != nil {
		failed = true
	}
	if l.state.telemetry != nil && l.state.telemetry.Shutdown(finalCtx) != nil {
		failed = true
	}
	if invokeMaterialClose(finalCtx, l.state.material) != nil {
		failed = true
	}
	if failed {
		return &LifecycleError{}
	}
	return nil
}

// finishStop publishes one stable exact-once stop result.
func (l *Lifecycle) finishStop(result error) {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if result != nil || l.state.phase == lifecycleStoppingFatal {
		l.state.phase = lifecycleStoppedFatal
		l.state.stopErr = &LifecycleError{}
	} else {
		l.state.phase = lifecycleStoppedClean
		l.state.stopErr = nil
	}
	close(l.state.stopDone)
}

// clearRuntimeLocked removes an unpublished transfer while startup retains cleanup ownership.
func (l *Lifecycle) clearRuntimeLocked() {
	l.state.readiness = nil
	l.state.telemetry = nil
	l.state.replay = nil
	l.state.signing = nil
	l.state.revalidator = nil
	l.state.revalidatorStop = nil
	l.state.revalidatorDone = nil
	l.state.dnsStop = nil
	l.state.requestStop = nil
	l.state.http = nil
	l.state.serveDone = nil
	l.state.material = nil
}

// rollbackOwners releases partial startup owners in strict reverse order.
func (s *lifecycleStartup) rollbackOwners() error {
	if s == nil {
		return &LifecycleError{}
	}
	ctx := s.rollback.context()
	failed := false
	admissionClosed := true
	if !nilInterface(s.http) {
		admissionClosed = invokeRejectNewRequestsBounded(ctx, s.http)
	}
	if s.revalidatorStop != nil {
		s.revalidatorStop()
	}
	revalidatorJoined := waitLifecycleDone(ctx, s.revalidatorDone)
	if !admissionClosed || !revalidatorJoined {
		return &LifecycleError{}
	}
	if !nilInterface(s.http) {
		if !closeListenerAndJoin(ctx, s.http, s.serveDone) {
			if s.requestStop != nil {
				s.requestStop()
			}
			return &LifecycleError{}
		}
		shutdownCtx, shutdownCancel := s.deps.withTimeout(ctx, s.shutdownLimit)
		graceful := invokeShutdown(shutdownCtx, s.http) == nil
		shutdownCancel()
		forceCtx, forceCancel := s.deps.withTimeout(
			ctx,
			LifecycleServeJoinTimeout,
		)
		defer forceCancel()
		if graceful {
			graceful = invokeHandlersQuiescent(s.http)
		}
		if !graceful {
			if s.requestStop != nil {
				s.requestStop()
			}
			if invokeForceClose(forceCtx, s.http) != nil ||
				invokeWaitHandlers(forceCtx, s.http) != nil {
				return &LifecycleError{}
			}
		}
	}
	if s.requestStop != nil {
		s.requestStop()
	}
	if s.dnsStop != nil {
		s.dnsStop()
	}
	if !nilInterface(s.replay) {
		replayCtx, replayCancel := s.deps.withTimeout(
			ctx,
			LifecycleFinalCleanupTimeout,
		)
		if invokeReplayClose(replayCtx, s.replay) != nil {
			failed = true
		}
		replayCancel()
	}
	if s.signing != nil && s.signing.Close(ctx) != nil {
		failed = true
	}
	if s.telemetry != nil && s.telemetry.Shutdown(ctx) != nil {
		failed = true
	}
	if !nilInterface(s.material) {
		if invokeMaterialClose(ctx, s.material) != nil {
			failed = true
		}
	}
	if failed {
		return &LifecycleError{}
	}
	return nil
}

// sampleStartupAuthority contains hook-owned authority panics and accepts only true.
func sampleStartupAuthority(authority AuthorityReadiness) (ready bool) {
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return !nilInterface(authority) && authority.AuthorityReady()
}

// invokeHTTPAssembly contains hostile adapter assembly panics.
func invokeHTTPAssembly(
	factory HTTPFactory,
	input HTTPAssemblyInput,
) (assembly HTTPAssembly, resultErr error) {
	defer func() {
		if recover() != nil {
			assembly = nil
			resultErr = &LifecycleError{}
		}
	}()
	return factory.Assemble(input)
}

// invokeHTTPBind contains hostile adapter listener-binding panics.
func invokeHTTPBind(
	ctx context.Context,
	assembly HTTPAssembly,
) (runtime HTTPRuntime, resultErr error) {
	defer func() {
		if recover() != nil {
			runtime = nil
			resultErr = &LifecycleError{}
		}
	}()
	return assembly.Bind(ctx)
}

// invokeCommit contains protected-transfer panics outside lifecycle locks.
func invokeCommit(
	commit func(*config.Prebootstrap, *config.RuntimePreparation) (lifecycleMaterial, error),
	owner *config.Prebootstrap,
	preparation *config.RuntimePreparation,
) (material lifecycleMaterial, valid bool, resultErr error) {
	defer func() {
		if recover() != nil {
			material = nil
			resultErr = &LifecycleError{}
			valid = false
		}
	}()
	material, resultErr = commit(owner, preparation)
	return material, true, resultErr
}

// invokeActivate contains the adapter's impossible non-fallible activation panic.
func invokeActivate(runtime HTTPRuntime) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return runtime.Activate()
}

// invokeServeStarted contains hostile transport entry-proof access.
func invokeServeStarted(runtime HTTPRuntime) (started <-chan struct{}, valid bool) {
	defer func() {
		if recover() != nil {
			started = nil
			valid = false
		}
	}()
	return runtime.ServeStarted(), true
}

// invokeServing contains hostile transport liveness proof access.
func invokeServing(runtime HTTPRuntime) (serving bool) {
	defer func() {
		if recover() != nil {
			serving = false
		}
	}()
	return runtime.Serving()
}

// invokeServe contains an unexpected adapter panic as a normal fatal return.
func invokeServe(runtime HTTPRuntime) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return runtime.Serve()
}

// invokeRevalidator contains an unexpected periodic-loop panic as a fatal return.
func invokeRevalidator(
	ctx context.Context,
	revalidator lifecycleRevalidator,
	observer ServeReturnObserver,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return revalidator.RunObserved(ctx, observer)
}

// invokeRevalidatorStarted contains hostile revalidator entry-proof access.
func invokeRevalidatorStarted(
	revalidator lifecycleRevalidator,
) (started <-chan struct{}, valid bool) {
	defer func() {
		if recover() != nil {
			started = nil
			valid = false
		}
	}()
	return revalidator.Started(), true
}

// invokeRevalidatorActivate contains the exact-once post-commit gate release.
func invokeRevalidatorActivate(revalidator lifecycleRevalidator) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return revalidator.Activate()
}

// invokeRevalidatorRunning contains the producer-owned live-loop proof.
func invokeRevalidatorRunning(revalidator lifecycleRevalidator) (running bool) {
	defer func() {
		if recover() != nil {
			running = false
		}
	}()
	return revalidator.Running()
}

// invokeRejectNewRequests contains handler-gate closure panics.
func invokeRejectNewRequests(runtime HTTPRuntime) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	runtime.RejectNewRequests()
	return true
}

// invokeRejectNewRequestsBounded closes admission or reports the outer stop bound.
func invokeRejectNewRequestsBounded(ctx context.Context, runtime HTTPRuntime) bool {
	done := make(chan bool, 1)
	go func() {
		done <- invokeRejectNewRequests(runtime)
	}()
	select {
	case valid := <-done:
		return valid
	case <-ctx.Done():
		return false
	}
}

// invokeCancelBounded invokes one hostile-capable cancel function outside lifecycle locks.
func invokeCancelBounded(ctx context.Context, cancel context.CancelFunc) bool {
	done := make(chan bool, 1)
	go func() {
		valid := true
		defer func() {
			if recover() != nil {
				valid = false
			}
			done <- valid
		}()
		cancel()
	}()
	select {
	case valid := <-done:
		return valid
	case <-ctx.Done():
		select {
		case valid := <-done:
			return valid
		default:
			return false
		}
	}
}

// closeListenerAndJoin bounds listener closure and serve proof under one context.
func closeListenerAndJoin(
	ctx context.Context,
	runtime HTTPRuntime,
	serveDone <-chan struct{},
) bool {
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- invokeCloseListener(runtime)
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			return false
		}
	case <-ctx.Done():
		return false
	}
	return waitLifecycleDone(ctx, serveDone)
}

// invokeCloseListener contains listener-closure panics.
func invokeCloseListener(runtime HTTPRuntime) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return runtime.CloseListener()
}

// invokeShutdown bounds graceful shutdown and contains adapter panics.
func invokeShutdown(ctx context.Context, runtime HTTPRuntime) (resultErr error) {
	return invokeBoundedHTTPCall(ctx, func() error {
		return containShutdown(ctx, runtime)
	})
}

// containShutdown contains graceful-shutdown panics inside the owned worker.
func containShutdown(ctx context.Context, runtime HTTPRuntime) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return runtime.Shutdown(ctx)
}

// invokeForceClose bounds forced close under the caller-owned aggregate context.
func invokeForceClose(ctx context.Context, runtime HTTPRuntime) (resultErr error) {
	return invokeBoundedHTTPCall(ctx, func() error {
		return containForceClose(ctx, runtime)
	})
}

// containForceClose contains forced-close panics inside the owned worker.
func containForceClose(ctx context.Context, runtime HTTPRuntime) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return runtime.ForceClose(ctx)
}

// invokeWaitHandlers bounds handler join and contains adapter panics.
func invokeWaitHandlers(ctx context.Context, runtime HTTPRuntime) (resultErr error) {
	return invokeBoundedHTTPCall(ctx, func() error {
		return containWaitHandlers(ctx, runtime)
	})
}

// invokeHandlersQuiescent contains immediate handler-quiescence proof panics.
func invokeHandlersQuiescent(runtime HTTPRuntime) (quiescent bool) {
	defer func() {
		if recover() != nil {
			quiescent = false
		}
	}()
	return runtime.HandlersQuiescent()
}

// containWaitHandlers contains handler-join panics inside the owned worker.
func containWaitHandlers(ctx context.Context, runtime HTTPRuntime) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return runtime.WaitHandlers(ctx)
}

// invokeBoundedHTTPCall joins one adapter call or reports its context bound.
func invokeBoundedHTTPCall(ctx context.Context, call func() error) error {
	if lifecycleContextFailed(ctx) {
		return &LifecycleError{}
	}
	done := make(chan error, 1)
	go func() {
		done <- call()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return &LifecycleError{}
	}
}

// invokeReplayClose contains replay-owner cleanup panics.
func invokeReplayClose(ctx context.Context, replay lifecycleReplay) (resultErr error) {
	return invokeBoundedHTTPCall(ctx, func() error {
		return containReplayClose(ctx, replay)
	})
}

// containReplayClose contains replay-owner cleanup panics inside the owned worker.
func containReplayClose(ctx context.Context, replay lifecycleReplay) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return replay.Close(ctx)
}

// invokeMaterialClose bounds protected-runtime release and contains panics.
func invokeMaterialClose(ctx context.Context, material lifecycleMaterial) error {
	return invokeBoundedClose(ctx, material.Close)
}

// invokeBoundedClose runs one context-free release under a proven join bound.
func invokeBoundedClose(ctx context.Context, closeOwner func() error) error {
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- containLifecycleClose(closeOwner)
	}()
	<-started
	select {
	case err := <-done:
		return err
	default:
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		select {
		case err := <-done:
			return err
		default:
		}
		return &LifecycleError{}
	}
}

// containLifecycleClose converts a cleanup panic into one stable failure.
func containLifecycleClose(closeOwner func() error) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	return closeOwner()
}

// waitLifecycleDone proves one owned goroutine joined before its bound expires.
func waitLifecycleDone(ctx context.Context, done <-chan struct{}) bool {
	if done == nil {
		return true
	}
	select {
	case <-done:
		return true
	default:
	}
	select {
	case <-done:
		return true
	case <-ctx.Done():
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
}

// waitLifecycleStarted proves producer entry while rejecting an earlier terminal return.
func waitLifecycleStarted(
	ctx context.Context,
	started <-chan struct{},
	done <-chan struct{},
) bool {
	select {
	case <-done:
		return false
	case <-started:
		select {
		case <-done:
			return false
		default:
			return true
		}
	case <-ctx.Done():
		select {
		case <-started:
			select {
			case <-done:
				return false
			default:
				return true
			}
		default:
			return false
		}
	}
}

// lifecycleContextFailed contains hostile context implementations and reports termination.
func lifecycleContextFailed(ctx context.Context) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	if nilInterface(ctx) {
		return true
	}
	return ctx.Err() != nil
}
