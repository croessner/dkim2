package app

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

const (
	lifecycleAuthorityReadyStep = "authority-ready"
	lifecycleFiveSecondStep     = "timeout:5s"
	lifecycleShutdownStep       = "shutdown"
	lifecycleMaterialCloseStep  = "material-close"
	lifecycleForceCloseStep     = "force-close"
	lifecycleReplayCloseStep    = "replay-close"
	lifecycleRejectStep         = "reject"
)

// lifecycleOrder records one concurrency-safe orchestration trace.
type lifecycleOrder struct {
	mu    sync.Mutex
	steps []string
}

// add appends one observed lifecycle step.
func (o *lifecycleOrder) add(step string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.steps = append(o.steps, step)
}

// snapshot returns one isolated trace copy.
func (o *lifecycleOrder) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.steps...)
}

// lifecycleVerifierFake satisfies the construction-only verification seam.
type lifecycleVerifierFake struct{}

// Assess is unreachable in lifecycle orchestration tests.
func (lifecycleVerifierFake) Assess(context.Context, dkim2.VerifyRequest) (dkim2.VerificationAssessment, error) {
	return dkim2.VerificationAssessment{}, errors.New("unreachable")
}

// lifecycleReplayFake owns deterministic readiness and cleanup observations.
type lifecycleReplayFake struct {
	order        *lifecycleOrder
	ready        bool
	mu           sync.Mutex
	samples      []bool
	calls        int
	panicAt      int
	sampleHook   func(int)
	closeEntered chan struct{}
	closeBlock   <-chan struct{}
}

// Coordinate is unreachable in lifecycle orchestration tests.
func (*lifecycleReplayFake) Coordinate(context.Context, DomainResult) (ReplayOutcome, error) {
	return ReplayOutcome{}, errors.New("unreachable")
}

// AuthorityReady reports the configured no-I/O authority fact.
func (r *lifecycleReplayFake) AuthorityReady() bool {
	r.order.add(lifecycleAuthorityReadyStep)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.sampleHook != nil {
		r.sampleHook(r.calls)
	}
	if r.panicAt == r.calls {
		panic("private authority marker")
	}
	if len(r.samples) >= r.calls {
		return r.samples[r.calls-1]
	}
	return r.ready
}

// Close records replay cleanup.
func (r *lifecycleReplayFake) Close(context.Context) error {
	r.order.add(lifecycleReplayCloseStep)
	if r.closeEntered != nil {
		close(r.closeEntered)
	}
	if r.closeBlock != nil {
		<-r.closeBlock
	}
	return nil
}

// lifecycleMaterialFake records protected-runtime release.
type lifecycleMaterialFake struct {
	order *lifecycleOrder
}

// Close records protected-runtime release.
func (m *lifecycleMaterialFake) Close() error {
	m.order.add(lifecycleMaterialCloseStep)
	return nil
}

// lifecyclePanicServeObserver simulates one hostile synchronous observer.
type lifecyclePanicServeObserver struct{}

// NotifyServeReturn panics before publishing any producer terminal state.
func (*lifecyclePanicServeObserver) NotifyServeReturn() {
	panic("private serve observer marker")
}

// lifecycleRevalidatorFake blocks until its app-owned parent is canceled.
type lifecycleRevalidatorFake struct {
	order                 *lifecycleOrder
	started               chan struct{}
	activation            chan struct{}
	activeOnce            sync.Once
	running               atomic.Bool
	ignoreCancel          bool
	exitBlock             <-chan struct{}
	returnAfterActivation bool
	terminalEntered       chan struct{}
	terminalRelease       <-chan struct{}
	omitObserver          bool
	overrideObserver      ServeReturnObserver
}

// Started returns the producer-owned Run entry proof.
func (r *lifecycleRevalidatorFake) Started() <-chan struct{} { return r.started }

// Running reports whether the fake producer still owns Run.
func (r *lifecycleRevalidatorFake) Running() bool { return r.running.Load() }

// Activate releases the initialized fake after protected transfer.
func (r *lifecycleRevalidatorFake) Activate() error {
	r.order.add("revalidator-activate")
	r.activeOnce.Do(func() { close(r.activation) })
	return nil
}

// Run records activation and joins on cancellation.
func (r *lifecycleRevalidatorFake) Run(ctx context.Context) error {
	return r.run(ctx, nil)
}

// run executes the fake loop with producer-ordered terminal publication.
func (r *lifecycleRevalidatorFake) run(
	ctx context.Context,
	observer ServeReturnObserver,
) error {
	r.running.Store(true)
	defer r.running.Store(false)
	defer func() {
		if r.terminalEntered != nil {
			close(r.terminalEntered)
		}
		if r.terminalRelease != nil {
			<-r.terminalRelease
		}
		if !nilInterface(r.overrideObserver) {
			observer = r.overrideObserver
		}
		if !r.omitObserver && !nilInterface(observer) {
			observer.NotifyServeReturn()
		}
	}()
	r.order.add("revalidator-run")
	close(r.started)
	select {
	case <-r.activation:
	case <-ctx.Done():
		return ctx.Err()
	}
	if r.returnAfterActivation {
		return errors.New("private revalidator terminal marker")
	}
	if r.ignoreCancel {
		<-r.exitBlock
		r.order.add("revalidator-exit")
		return errors.New("private revalidator marker")
	}
	<-ctx.Done()
	r.order.add("revalidator-exit")
	return ctx.Err()
}

// RunObserved synchronously classifies the fake producer's physical return.
func (r *lifecycleRevalidatorFake) RunObserved(
	ctx context.Context,
	observer ServeReturnObserver,
) error {
	return r.run(ctx, observer)
}

// lifecycleHTTPRuntimeFake provides channel-controlled serve ownership.
type lifecycleHTTPRuntimeFake struct {
	order           *lifecycleOrder
	serve           chan struct{}
	serveOnce       sync.Once
	started         chan struct{}
	startedOnce     sync.Once
	earlyReturn     bool
	skipStart       bool
	serveReturn     ServeReturnObserver
	activation      ActivationAuthority
	terminated      atomic.Bool
	servingCalls    atomic.Int32
	servingHook     func(int)
	shutdownErr     error
	shutdownEntered chan struct{}
	shutdownBlock   <-chan struct{}
	forceErr        error
	waitErr         error
	notQuiescent    bool
	closeBlock      <-chan struct{}
	closeErr        error
	rejectPanic     bool
	rejectBlock     <-chan struct{}
	activateEntered chan struct{}
	activateRelease <-chan struct{}
	terminalEntered chan struct{}
	terminalRelease <-chan struct{}
	omitObserver    bool
}

// Activate records the non-fallible publication boundary.
func (r *lifecycleHTTPRuntimeFake) Activate() error {
	r.order.add("activate")
	if nilInterface(r.activation) || !r.activation.AllowHTTPActivation() {
		return errors.New("activation refused")
	}
	if r.activateEntered != nil {
		close(r.activateEntered)
	}
	if r.activateRelease != nil {
		<-r.activateRelease
	}
	return nil
}

// RejectNewRequests records the closed-first handler gate.
func (r *lifecycleHTTPRuntimeFake) RejectNewRequests() {
	r.order.add(lifecycleRejectStep)
	if r.rejectPanic {
		panic("private reject marker")
	}
	if r.rejectBlock != nil {
		<-r.rejectBlock
	}
}

// Serve blocks until listener closure unless configured to fail before transfer.
func (r *lifecycleHTTPRuntimeFake) Serve() error {
	defer r.terminated.Store(true)
	defer func() {
		if r.terminalEntered != nil {
			close(r.terminalEntered)
		}
		if r.terminalRelease != nil {
			<-r.terminalRelease
		}
		if !r.omitObserver {
			r.serveReturn.NotifyServeReturn()
		}
	}()
	if !r.skipStart {
		r.startedOnce.Do(func() { close(r.started) })
	}
	r.order.add("serve")
	if r.earlyReturn || r.skipStart {
		return errors.New("private serve marker")
	}
	<-r.serve
	r.order.add("serve-exit")
	return nil
}

// ServeStarted returns the producer-owned inner Serve entry proof.
func (r *lifecycleHTTPRuntimeFake) ServeStarted() <-chan struct{} { return r.started }

// Serving reports whether the fake inner Serve owner remains live.
func (r *lifecycleHTTPRuntimeFake) Serving() bool {
	call := int(r.servingCalls.Add(1))
	if r.servingHook != nil {
		r.servingHook(call)
	}
	select {
	case <-r.started:
		return !r.terminated.Load()
	default:
		return false
	}
}

// CloseListener releases the owned serve loop.
func (r *lifecycleHTTPRuntimeFake) CloseListener() error {
	r.order.add("listener-close")
	if r.closeBlock != nil {
		<-r.closeBlock
	}
	r.serveOnce.Do(func() { close(r.serve) })
	return r.closeErr
}

// Shutdown records graceful request shutdown.
func (r *lifecycleHTTPRuntimeFake) Shutdown(context.Context) error {
	r.order.add(lifecycleShutdownStep)
	if r.shutdownEntered != nil {
		close(r.shutdownEntered)
	}
	if r.shutdownBlock != nil {
		<-r.shutdownBlock
	}
	return r.shutdownErr
}

// HandlersQuiescent reports immediate graceful quiescence in the fake runtime.
func (r *lifecycleHTTPRuntimeFake) HandlersQuiescent() bool { return !r.notQuiescent }

// ForceClose records the bounded forced request path.
func (r *lifecycleHTTPRuntimeFake) ForceClose(context.Context) error {
	r.order.add(lifecycleForceCloseStep)
	return r.forceErr
}

// WaitHandlers records proof that no request handler remains.
func (r *lifecycleHTTPRuntimeFake) WaitHandlers(context.Context) error {
	r.order.add("handlers-joined")
	return r.waitErr
}

// lifecycleHTTPAssemblyFake returns one predetermined runtime owner.
type lifecycleHTTPAssemblyFake struct {
	order   *lifecycleOrder
	runtime HTTPRuntime
}

// Bind records the sole listener-acquisition step.
func (a *lifecycleHTTPAssemblyFake) Bind(context.Context) (HTTPRuntime, error) {
	a.order.add("bind")
	return a.runtime, nil
}

// lifecycleHTTPFactoryFake performs pure test assembly.
type lifecycleHTTPFactoryFake struct {
	order               *lifecycleOrder
	assembly            HTTPAssembly
	runtime             *lifecycleHTTPRuntimeFake
	baseContext         context.Context
	overrideServeReturn ServeReturnObserver
}

// Assemble records pure assembly and returns the configured assembly.
func (f *lifecycleHTTPFactoryFake) Assemble(input HTTPAssemblyInput) (HTTPAssembly, error) {
	f.order.add("assemble")
	if nilInterface(input.FatalNotifier()) {
		return nil, errors.New("missing notifier")
	}
	f.runtime.serveReturn = input.ServeReturnObserver()
	if !nilInterface(f.overrideServeReturn) {
		f.runtime.serveReturn = f.overrideServeReturn
	}
	f.runtime.activation = input.ActivationAuthority()
	f.baseContext = input.BaseContext()
	return f.assembly, nil
}

// lifecycleTestDependencies builds deterministic construction seams.
func lifecycleTestDependencies(
	order *lifecycleOrder,
	replay *lifecycleReplayFake,
	revalidator lifecycleRevalidator,
) lifecycleDependencies {
	return lifecycleDependencies{
		withTimeout: func(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
			order.add("timeout:" + duration.String())
			return context.WithCancel(parent)
		},
		newDetachedParent: func() context.Context {
			return context.Background()
		},
		initialShutdownTimeout: func(*config.Prebootstrap) (time.Duration, error) {
			return 7 * time.Second, nil
		},
		prepareRuntime: func(*config.Prebootstrap) (*config.RuntimePreparation, error) {
			order.add("prepare")
			return &config.RuntimePreparation{}, nil
		},
		newObservability: func(context.Context, *config.RuntimePreparation) (*observability.Runtime, error) {
			order.add("observability")
			return &observability.Runtime{}, nil
		},
		newDNSVerifier: func(
			context.Context,
			*config.RuntimePreparation,
			*observability.Runtime,
		) (VerificationService, error) {
			order.add("dns")
			return lifecycleVerifierFake{}, nil
		},
		newReplayRuntime: func(
			context.Context,
			replayRollbackFactory,
			*config.RuntimePreparation,
		) (lifecycleReplay, error) {
			order.add("replay")
			return replay, nil
		},
		newApplication: func(
			*config.RuntimePreparation,
			VerificationService,
			lifecycleReplay,
		) (*InboundProcessor, error) {
			order.add("application")
			return &InboundProcessor{}, nil
		},
		newReadiness: func(authority AuthorityReadiness) (*Readiness, error) {
			order.add("readiness")
			return NewReadiness(authority)
		},
		newRevalidator: func(
			*config.RuntimePreparation,
			lifecycleReplay,
		) (lifecycleRevalidator, error) {
			order.add("revalidator")
			return revalidator, nil
		},
		newHTTPInput: func(
			baseContext context.Context,
			_ *config.RuntimePreparation,
			_ *InboundProcessor,
			_ *Readiness,
			fatal FatalNotifier,
			serveReturn ServeReturnObserver,
			activation ActivationAuthority,
		) (HTTPAssemblyInput, error) {
			order.add("http-input")
			return HTTPAssemblyInput{
				fatal: fatal, serveReturn: serveReturn,
				activation: activation, baseContext: baseContext,
			}, nil
		},
		commitRuntime: func(
			*config.Prebootstrap,
			*config.RuntimePreparation,
		) (lifecycleMaterial, error) {
			order.add("commit")
			return &lifecycleMaterialFake{order: order}, nil
		},
		shutdownTimeout: func(*config.RuntimePreparation) (time.Duration, error) {
			return 7 * time.Second, nil
		},
		beforeStartCancelInstall: func() {},
		beforePublication:        func() {},
	}
}

// TestLifecycleContractDurations freezes the public Fx lifecycle budgets.
func TestLifecycleContractDurations(t *testing.T) {
	t.Parallel()
	if LifecycleStartTimeout != 115*time.Second ||
		LifecycleAcquisitionTimeout != 100*time.Second ||
		LifecycleRollbackTimeout != 10*time.Second ||
		LifecycleServeJoinTimeout != 5*time.Second ||
		LifecycleRevalidatorJoinTimeout != 30*time.Second ||
		LifecycleFinalCleanupTimeout != 5*time.Second {
		t.Fatal("lifecycle contract duration drift")
	}
	stop, err := LifecycleStopTimeout(7 * time.Second)
	if err != nil || stop != 57*time.Second {
		t.Fatal("dynamic outer stop contract drift")
	}
	if _, err := LifecycleStopTimeout(0); !IsLifecycleError(err) {
		t.Fatal("invalid shutdown timeout accepted")
	}
}

// TestLifecycleStartStopOrder freezes acquisition, publication, and reverse teardown order.
func TestLifecycleStartStopOrder(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	revalidator := &lifecycleRevalidatorFake{
		order: order, started: make(chan struct{}), activation: make(chan struct{}),
	}
	runtime := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	assembly := &lifecycleHTTPAssemblyFake{order: order, runtime: runtime}
	factory := &lifecycleHTTPFactoryFake{
		order: order, assembly: assembly, runtime: runtime,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, revalidator),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	<-revalidator.started
	if !lifecycle.Ready() {
		t.Fatal("successful transfer did not publish readiness")
	}
	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatalf("stop lifecycle: %v", err)
	}
	select {
	case <-factory.baseContext.Done():
	default:
		t.Fatal("clean Stop left request parent live")
	}
	want := []string{
		"timeout:1m55s", "timeout:1m40s", "prepare", "observability", "dns", "replay",
		lifecycleAuthorityReadyStep, "application", "readiness", "revalidator",
		"http-input", "assemble", "bind", "serve", "revalidator-run",
		lifecycleAuthorityReadyStep, "commit", lifecycleAuthorityReadyStep, "revalidator-activate", "activate",
		lifecycleAuthorityReadyStep, lifecycleAuthorityReadyStep, "timeout:57s", lifecycleRejectStep,
		lifecycleFiveSecondStep, "listener-close", "serve-exit", "timeout:7s",
		lifecycleShutdownStep, lifecycleFiveSecondStep, "timeout:30s", "revalidator-exit",
		lifecycleFiveSecondStep, lifecycleReplayCloseStep, lifecycleMaterialCloseStep,
	}
	if got := order.snapshot(); !equalLifecycleOrder(got, want) {
		t.Fatalf("unexpected lifecycle order\n got: %v\nwant: %v", got, want)
	}
	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatalf("repeated clean Stop: %v", err)
	}
}

// TestLifecycleEarlyServeExitPreventsCommitAndRollsBack freezes fatal linearization.
func TestLifecycleEarlyServeExitPreventsCommitAndRollsBack(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtime := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}), earlyReturn: true,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtime},
		runtime:  runtime,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("early serve exit returned %T, want stable lifecycle failure", err)
	}
	if lifecycle.Ready() {
		t.Fatal("early serve exit published readiness")
	}
	for _, forbidden := range []string{"commit", "activate"} {
		if containsLifecycleStep(order.snapshot(), forbidden) {
			t.Fatalf("early serve exit reached forbidden step %q", forbidden)
		}
	}
	select {
	case <-lifecycle.ShutdownRequests():
	default:
		t.Fatal("fatal serve exit did not request orderly shutdown")
	}
}

// TestLifecycleAuthorityGatesFailClosed freezes every hook-owned authority sample.
func TestLifecycleAuthorityGatesFailClosed(t *testing.T) {
	cases := []struct {
		name         string
		samples      []bool
		panicAt      int
		wantBind     bool
		wantCommit   bool
		wantActivate bool
	}{
		{name: "initial_false", samples: []bool{false}},
		{name: "initial_panic", panicAt: 1},
		{name: "precommit_false", samples: []bool{true, false}, wantBind: true},
		{name: "precommit_panic", samples: []bool{true}, panicAt: 2, wantBind: true},
		{
			name: "postcommit_false", samples: []bool{true, true, false},
			wantBind: true, wantCommit: true,
		},
		{
			name: "postcommit_panic", samples: []bool{true, true},
			panicAt: 3, wantBind: true, wantCommit: true,
		},
		{
			name: "prepublish_false", samples: []bool{true, true, true, false},
			wantBind: true, wantCommit: true, wantActivate: true,
		},
		{
			name: "prepublish_panic", samples: []bool{true, true, true},
			panicAt: 4, wantBind: true, wantCommit: true, wantActivate: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			order := &lifecycleOrder{}
			replay := &lifecycleReplayFake{
				order: order, ready: true, samples: testCase.samples, panicAt: testCase.panicAt,
			}
			runtime := &lifecycleHTTPRuntimeFake{
				order: order, serve: make(chan struct{}), started: make(chan struct{}),
			}
			factory := &lifecycleHTTPFactoryFake{
				order:    order,
				assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtime},
				runtime:  runtime,
			}
			lifecycle, err := newLifecycleWithDependencies(
				&config.Prebootstrap{},
				factory,
				lifecycleTestDependencies(order, replay, nil),
			)
			if err != nil {
				t.Fatalf("construct lifecycle: %v", err)
			}
			if err := lifecycle.Start(context.Background()); !IsLifecycleError(err) {
				t.Fatalf("authority failure returned %T", err)
			}
			if lifecycle.Ready() {
				t.Fatal("authority failure published readiness")
			}
			steps := order.snapshot()
			if got := containsLifecycleStep(steps, "bind"); got != testCase.wantBind {
				t.Fatalf("bind=%v, want %v: %v", got, testCase.wantBind, steps)
			}
			if got := containsLifecycleStep(steps, "commit"); got != testCase.wantCommit {
				t.Fatalf("commit=%v, want %v: %v", got, testCase.wantCommit, steps)
			}
			if got := containsLifecycleStep(steps, "activate"); got != testCase.wantActivate {
				t.Fatalf("activate=%v, want %v: %v", got, testCase.wantActivate, steps)
			}
			if testCase.wantCommit && !containsLifecycleStep(steps, lifecycleMaterialCloseStep) {
				t.Fatalf("committed authority failure leaked material: %v", steps)
			}
		})
	}
}

// TestLifecycleCancellationBeforeDNSPreventsNextStage freezes the post-timeout gate.
func TestLifecycleCancellationBeforeDNSPreventsNextStage(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order: order, assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime: runtimeHTTP,
	}
	deps, cancelAcquisition := cancellableLifecycleDependencies(order, replay, nil)
	originalShutdownTimeout := deps.shutdownTimeout
	deps.shutdownTimeout = func(
		preparation *config.RuntimePreparation,
	) (time.Duration, error) {
		timeout, err := originalShutdownTimeout(preparation)
		cancelAcquisition()
		return timeout, err
	}
	assertLifecycleCanceledBeforeStep(t, factory, deps, order, "dns")
}

// TestLifecycleCancellationAfterInitialAuthorityPreventsApplication freezes that gate.
func TestLifecycleCancellationAfterInitialAuthorityPreventsApplication(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order: order, assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime: runtimeHTTP,
	}
	deps, cancelAcquisition := cancellableLifecycleDependencies(order, replay, nil)
	replay.sampleHook = func(call int) {
		if call == 1 {
			cancelAcquisition()
		}
	}
	assertLifecycleCanceledBeforeStep(t, factory, deps, order, "application")
}

// TestLifecycleCancellationAfterServeProofPreventsRevalidatorRun freezes that gate.
func TestLifecycleCancellationAfterServeProofPreventsRevalidatorRun(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	revalidator := &lifecycleRevalidatorFake{
		order: order, started: make(chan struct{}), activation: make(chan struct{}),
	}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order: order, assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime: runtimeHTTP,
	}
	deps, cancelAcquisition := cancellableLifecycleDependencies(order, replay, revalidator)
	runtimeHTTP.servingHook = func(call int) {
		if call == 1 {
			cancelAcquisition()
		}
	}
	assertLifecycleCanceledBeforeStep(t, factory, deps, order, "revalidator-run")
}

// TestLifecycleCancellationBeforePublicationPreventsReadiness freezes the final gate.
func TestLifecycleCancellationBeforePublicationPreventsReadiness(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order: order, assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime: runtimeHTTP,
	}
	deps, cancelAcquisition := cancellableLifecycleDependencies(order, replay, nil)
	publicationEntered := make(chan struct{})
	publicationRelease := make(chan struct{})
	deps.beforePublication = func() {
		close(publicationEntered)
		<-publicationRelease
	}
	lifecycle, err := newLifecycleWithDependencies(&config.Prebootstrap{}, factory, deps)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- lifecycle.Start(context.Background()) }()
	<-publicationEntered
	cancelAcquisition()
	close(publicationRelease)
	if err := <-startResult; !IsLifecycleError(err) {
		t.Fatalf("canceled publication returned %T", err)
	}
	if lifecycle.Ready() {
		t.Fatal("canceled publication became ready")
	}
	if !containsLifecycleStep(order.snapshot(), lifecycleMaterialCloseStep) {
		t.Fatalf("canceled publication leaked transferred material: %v", order.snapshot())
	}
}

// cancellableLifecycleDependencies exposes only the acquisition cancel boundary.
func cancellableLifecycleDependencies(
	order *lifecycleOrder,
	replay *lifecycleReplayFake,
	revalidator lifecycleRevalidator,
) (lifecycleDependencies, context.CancelFunc) {
	deps := lifecycleTestDependencies(order, replay, revalidator)
	var acquisitionCancel context.CancelFunc
	originalWithTimeout := deps.withTimeout
	deps.withTimeout = func(
		parent context.Context,
		duration time.Duration,
	) (context.Context, context.CancelFunc) {
		ctx, cancel := originalWithTimeout(parent, duration)
		if duration == LifecycleAcquisitionTimeout {
			acquisitionCancel = cancel
		}
		return ctx, cancel
	}
	return deps, func() { acquisitionCancel() }
}

// assertLifecycleCanceledBeforeStep proves cancellation prevents the next stage.
func assertLifecycleCanceledBeforeStep(
	t *testing.T,
	factory HTTPFactory,
	deps lifecycleDependencies,
	order *lifecycleOrder,
	nextStep string,
) {
	t.Helper()
	lifecycle, err := newLifecycleWithDependencies(&config.Prebootstrap{}, factory, deps)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("canceled Start returned %T", err)
	}
	if containsLifecycleStep(order.snapshot(), nextStep) {
		t.Fatalf("canceled startup entered forbidden step %q: %v", nextStep, order.snapshot())
	}
}

// TestLifecycleProducerExitBeforeStartedFailsImmediately freezes done-versus-start arbitration.
func TestLifecycleProducerExitBeforeStartedFailsImmediately(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtime := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}), skipStart: true,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtime},
		runtime:  runtime,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("producer no-start returned %T", err)
	}
	steps := order.snapshot()
	if containsLifecycleStep(steps, "commit") ||
		containsLifecycleStep(steps, "activate") || lifecycle.Ready() {
		t.Fatalf("producer no-start crossed publication: %v", steps)
	}
}

// TestLifecycleForcedRecoveryPreservesFailureAndCompletesSafeTeardown freezes outcome taxonomy.
func TestLifecycleForcedRecoveryPreservesFailureAndCompletesSafeTeardown(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtime := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		shutdownErr: errors.New("private shutdown marker"),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtime},
		runtime:  runtime,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("forced recovery returned %T, want stable failure", err)
	}
	steps := order.snapshot()
	for _, required := range []string{
		lifecycleShutdownStep, lifecycleForceCloseStep, "handlers-joined",
		lifecycleReplayCloseStep,
		lifecycleMaterialCloseStep,
	} {
		if !containsLifecycleStep(steps, required) {
			t.Fatalf("forced recovery missed %q: %v", required, steps)
		}
	}
}

// TestLifecycleServeJoinFailureRetainsDependencies freezes the no-teardown safety rule.
func TestLifecycleServeJoinFailureRetainsDependencies(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	closeBlock := make(chan struct{})
	runtime := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		closeBlock: closeBlock,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtime},
		runtime:  runtime,
	}
	deps := lifecycleTestDependencies(order, replay, nil)
	var fiveSecondCalls atomic.Int32
	deps.withTimeout = func(
		parent context.Context,
		duration time.Duration,
	) (context.Context, context.CancelFunc) {
		order.add("timeout:" + duration.String())
		ctx, cancel := context.WithCancel(parent)
		if duration == LifecycleServeJoinTimeout &&
			fiveSecondCalls.Add(1) == 1 {
			cancel()
		}
		return ctx, cancel
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		deps,
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("serve nonjoin returned %T", err)
	}
	close(closeBlock)
	steps := order.snapshot()
	for _, forbidden := range []string{
		lifecycleShutdownStep, lifecycleForceCloseStep, lifecycleReplayCloseStep,
		lifecycleMaterialCloseStep,
	} {
		if containsLifecycleStep(steps, forbidden) {
			t.Fatalf("serve nonjoin tore down %q: %v", forbidden, steps)
		}
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("repeated failed Stop returned %T", err)
	}
}

// TestLifecycleRejectPanicCompletesStopOwner freezes exact-once waiter publication.
func TestLifecycleRejectPanicCompletesStopOwner(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtime := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		rejectPanic: true,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtime},
		runtime:  runtime,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("reject panic returned %T", err)
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("second Stop after reject panic returned %T", err)
	}
}

// TestLifecycleConcurrentStopCancelsAndJoinsStartup freezes startup-owner arbitration.
func TestLifecycleConcurrentStopCancelsAndJoinsStartup(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	deps := lifecycleTestDependencies(order, replay, nil)
	prepareEntered := make(chan struct{})
	prepareRelease := make(chan struct{})
	deps.prepareRuntime = func(*config.Prebootstrap) (*config.RuntimePreparation, error) {
		close(prepareEntered)
		<-prepareRelease
		return &config.RuntimePreparation{}, nil
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		deps,
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- lifecycle.Start(context.Background()) }()
	<-prepareEntered
	stopResult := make(chan error, 1)
	go func() { stopResult <- lifecycle.Stop(context.Background()) }()
	<-lifecycle.ShutdownRequests()
	select {
	case err := <-stopResult:
		t.Fatalf("Stop returned before startup rollback: %v", err)
	default:
	}
	close(prepareRelease)
	if err := <-startResult; !IsLifecycleError(err) {
		t.Fatalf("concurrent Start returned %T", err)
	}
	if err := <-stopResult; !IsLifecycleError(err) {
		t.Fatalf("concurrent Stop returned %T", err)
	}
	if containsLifecycleStep(order.snapshot(), "commit") {
		t.Fatalf("canceled startup committed: %v", order.snapshot())
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("repeated Stop after startup failure returned %T", err)
	}
}

// TestLifecycleStopBeforeCancelInstallationStillJoinsStartup freezes the early race.
func TestLifecycleStopBeforeCancelInstallationStillJoinsStartup(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order: order, assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime: runtimeHTTP,
	}
	deps := lifecycleTestDependencies(order, replay, nil)
	installEntered := make(chan struct{})
	installRelease := make(chan struct{})
	deps.beforeStartCancelInstall = func() {
		close(installEntered)
		<-installRelease
	}
	lifecycle, err := newLifecycleWithDependencies(&config.Prebootstrap{}, factory, deps)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- lifecycle.Start(context.Background()) }()
	<-installEntered
	stopResult := make(chan error, 1)
	go func() { stopResult <- lifecycle.Stop(context.Background()) }()
	<-lifecycle.ShutdownRequests()
	select {
	case err := <-stopResult:
		t.Fatalf("Stop returned before startup owner joined: %v", err)
	default:
	}
	close(installRelease)
	if err := <-startResult; !IsLifecycleError(err) {
		t.Fatalf("early-stop Start returned %T", err)
	}
	if err := <-stopResult; !IsLifecycleError(err) {
		t.Fatalf("early-stop Stop returned %T", err)
	}
}

// TestLifecycleFatalDuringCommitRetainsAndRollsBackTransferredMaterial freezes commit races.
func TestLifecycleFatalDuringCommitRetainsAndRollsBackTransferredMaterial(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	deps := lifecycleTestDependencies(order, replay, nil)
	commitEntered := make(chan struct{})
	commitRelease := make(chan struct{})
	deps.commitRuntime = func(
		*config.Prebootstrap,
		*config.RuntimePreparation,
	) (lifecycleMaterial, error) {
		order.add("commit")
		close(commitEntered)
		<-commitRelease
		return &lifecycleMaterialFake{order: order}, nil
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{}, factory, deps,
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- lifecycle.Start(context.Background()) }()
	<-commitEntered
	lifecycle.NotifyServeReturn()
	close(commitRelease)
	if err := <-result; !IsLifecycleError(err) {
		t.Fatalf("commit race returned %T", err)
	}
	steps := order.snapshot()
	if containsLifecycleStep(steps, "activate") || lifecycle.Ready() {
		t.Fatalf("commit race crossed activation: %v", steps)
	}
	if !containsLifecycleStep(steps, lifecycleMaterialCloseStep) {
		t.Fatalf("commit race leaked transferred material: %v", steps)
	}
}

// TestLifecycleFatalDuringHTTPActivateNeverPublishesReady freezes activation races.
func TestLifecycleFatalDuringHTTPActivateNeverPublishesReady(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	activateEntered := make(chan struct{})
	activateRelease := make(chan struct{})
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		activateEntered: activateEntered, activateRelease: activateRelease,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- lifecycle.Start(context.Background()) }()
	<-activateEntered
	lifecycle.NotifyServeReturn()
	close(activateRelease)
	if err := <-result; !IsLifecycleError(err) {
		t.Fatalf("activate race returned %T", err)
	}
	if lifecycle.Ready() {
		t.Fatal("activate race published readiness")
	}
	if !containsLifecycleStep(order.snapshot(), lifecycleMaterialCloseStep) {
		t.Fatalf("activate race leaked material: %v", order.snapshot())
	}
}

// TestLifecycleBlockedRejectDoesNotBlockReadinessOrFatalPublication freezes lock isolation.
func TestLifecycleBlockedRejectDoesNotBlockReadinessOrFatalPublication(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	rejectRelease := make(chan struct{})
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		rejectBlock: rejectRelease,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	stopResult := make(chan error, 1)
	go func() { stopResult <- lifecycle.Stop(context.Background()) }()
	for attempts := 0; attempts < 10_000; attempts++ {
		if containsLifecycleStep(order.snapshot(), lifecycleRejectStep) {
			break
		}
		if attempts == 9_999 {
			t.Fatal("Stop did not enter RejectNewRequests")
		}
		runtime.Gosched()
	}
	if lifecycle.Ready() {
		t.Fatal("stopping lifecycle remained ready")
	}
	fatalDone := make(chan struct{})
	go func() {
		lifecycle.NotifyFatal()
		close(fatalDone)
	}()
	for attempts := 0; attempts < 10_000; attempts++ {
		select {
		case <-fatalDone:
			attempts = 10_000
		default:
			if attempts == 9_999 {
				t.Fatal("blocked Reject held the lifecycle mutex")
			}
			runtime.Gosched()
		}
	}
	close(rejectRelease)
	if err := <-stopResult; !IsLifecycleError(err) {
		t.Fatalf("fatal blocked-reject Stop returned %T", err)
	}
}

// TestLifecycleHandlerNonjoinRetainsDependencies freezes forced-path safety.
func TestLifecycleHandlerNonjoinRetainsDependencies(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		notQuiescent: true, waitErr: errors.New("private handler marker"),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("handler nonjoin returned %T", err)
	}
	steps := order.snapshot()
	for _, required := range []string{lifecycleForceCloseStep, "handlers-joined"} {
		if !containsLifecycleStep(steps, required) {
			t.Fatalf("handler nonjoin missed %q: %v", required, steps)
		}
	}
	for _, forbidden := range []string{lifecycleReplayCloseStep, lifecycleMaterialCloseStep} {
		if containsLifecycleStep(steps, forbidden) {
			t.Fatalf("handler nonjoin tore down %q: %v", forbidden, steps)
		}
	}
}

// TestLifecycleRevalidatorNonjoinRetainsDependencies freezes audit-owner safety.
func TestLifecycleRevalidatorNonjoinRetainsDependencies(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	revalidatorRelease := make(chan struct{})
	revalidator := &lifecycleRevalidatorFake{
		order: order, started: make(chan struct{}), activation: make(chan struct{}),
		ignoreCancel: true, exitBlock: revalidatorRelease,
	}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	deps := lifecycleTestDependencies(order, replay, revalidator)
	deps.withTimeout = func(
		parent context.Context,
		duration time.Duration,
	) (context.Context, context.CancelFunc) {
		order.add("timeout:" + duration.String())
		ctx, cancel := context.WithCancel(parent)
		if duration == LifecycleRevalidatorJoinTimeout {
			cancel()
		}
		return ctx, cancel
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{}, factory, deps,
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
		t.Fatalf("revalidator nonjoin returned %T", err)
	}
	steps := order.snapshot()
	for _, forbidden := range []string{lifecycleReplayCloseStep, lifecycleMaterialCloseStep} {
		if containsLifecycleStep(steps, forbidden) {
			t.Fatalf("revalidator nonjoin tore down %q: %v", forbidden, steps)
		}
	}
	close(revalidatorRelease)
}

// TestLifecycleBlockedReplayCloseStillAttemptsMaterialRelease freezes final cleanup aggregation.
func TestLifecycleBlockedReplayCloseStillAttemptsMaterialRelease(t *testing.T) {
	order := &lifecycleOrder{}
	replayEntered := make(chan struct{})
	replayRelease := make(chan struct{})
	replay := &lifecycleReplayFake{
		order: order, ready: true, closeEntered: replayEntered, closeBlock: replayRelease,
	}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	deps := lifecycleTestDependencies(order, replay, nil)
	finalCancel := make(chan context.CancelFunc, 1)
	var fiveSecondCalls atomic.Int32
	deps.withTimeout = func(
		parent context.Context,
		duration time.Duration,
	) (context.Context, context.CancelFunc) {
		order.add("timeout:" + duration.String())
		ctx, cancel := context.WithCancel(parent)
		if duration == LifecycleFinalCleanupTimeout &&
			fiveSecondCalls.Add(1) == 3 {
			finalCancel <- cancel
		}
		return ctx, cancel
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{}, factory, deps,
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	stopResult := make(chan error, 1)
	go func() { stopResult <- lifecycle.Stop(context.Background()) }()
	<-replayEntered
	cancel := <-finalCancel
	cancel()
	if err := <-stopResult; !IsLifecycleError(err) {
		t.Fatalf("blocked replay Close returned %T", err)
	}
	if !containsLifecycleStep(order.snapshot(), lifecycleMaterialCloseStep) {
		t.Fatalf("blocked replay skipped material release: %v", order.snapshot())
	}
	close(replayRelease)
}

// TestLifecycleConcurrentStopHasOneOwnerAndOneResult freezes exact-once stop election.
func TestLifecycleConcurrentStopHasOneOwnerAndOneResult(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	shutdownEntered := make(chan struct{})
	shutdownRelease := make(chan struct{})
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
		shutdownEntered: shutdownEntered, shutdownBlock: shutdownRelease,
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{},
		factory,
		lifecycleTestDependencies(order, replay, nil),
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start lifecycle: %v", err)
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- lifecycle.Stop(context.Background()) }()
	<-shutdownEntered
	go func() { second <- lifecycle.Stop(context.Background()) }()
	close(shutdownRelease)
	if err := <-first; err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	steps := order.snapshot()
	for _, step := range []string{
		lifecycleRejectStep, "listener-close", lifecycleShutdownStep, lifecycleReplayCloseStep,
		lifecycleMaterialCloseStep,
	} {
		count := 0
		for _, observed := range steps {
			if observed == step {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s count=%d, want 1: %v", step, count, steps)
		}
	}
}

// TestLifecycleServeTerminalAndPublicationCASOrder freezes both linearization winners.
func TestLifecycleServeTerminalAndPublicationCASOrder(t *testing.T) {
	for _, publicationWins := range []bool{false, true} {
		name := "terminal_wins"
		if publicationWins {
			name = "publication_wins"
		}
		t.Run(name, func(t *testing.T) {
			order := &lifecycleOrder{}
			replay := &lifecycleReplayFake{order: order, ready: true}
			terminalEntered := make(chan struct{})
			terminalRelease := make(chan struct{})
			var publicationEntered chan struct{}
			var publicationRelease chan struct{}
			if !publicationWins {
				publicationEntered = make(chan struct{})
				publicationRelease = make(chan struct{})
			}
			runtimeHTTP := &lifecycleHTTPRuntimeFake{
				order: order, serve: make(chan struct{}), started: make(chan struct{}),
				earlyReturn: true, terminalEntered: terminalEntered,
				terminalRelease: terminalRelease,
			}
			factory := &lifecycleHTTPFactoryFake{
				order:    order,
				assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
				runtime:  runtimeHTTP,
			}
			deps := lifecycleTestDependencies(order, replay, nil)
			if !publicationWins {
				deps.beforePublication = func() {
					close(publicationEntered)
					<-publicationRelease
				}
			}
			lifecycle, err := newLifecycleWithDependencies(
				&config.Prebootstrap{},
				factory,
				deps,
			)
			if err != nil {
				t.Fatalf("construct lifecycle: %v", err)
			}
			startResult := make(chan error, 1)
			go func() { startResult <- lifecycle.Start(context.Background()) }()
			<-terminalEntered
			if publicationWins {
				if err := <-startResult; err != nil {
					t.Fatalf("publication winner Start: %v", err)
				}
				if !lifecycle.Ready() {
					t.Fatal("publication claim did not publish readiness")
				}
				close(terminalRelease)
				<-lifecycle.ShutdownRequests()
				if lifecycle.Ready() {
					t.Fatal("post-publication terminal return stayed ready")
				}
				if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
					t.Fatalf("fatal cleanup Stop returned %T", err)
				}
			} else {
				<-publicationEntered
				close(terminalRelease)
				<-lifecycle.ShutdownRequests()
				close(publicationRelease)
				if err := <-startResult; !IsLifecycleError(err) {
					t.Fatalf("terminal winner returned %T", err)
				}
				if lifecycle.Ready() {
					t.Fatal("terminal winner published readiness")
				}
			}
		})
	}
}

// TestLifecycleRevalidatorTerminalAndPublicationCASOrder freezes both audit-loop winners.
func TestLifecycleRevalidatorTerminalAndPublicationCASOrder(t *testing.T) {
	for _, publicationWins := range []bool{false, true} {
		name := "terminal_wins"
		if publicationWins {
			name = "publication_wins"
		}
		t.Run(name, func(t *testing.T) {
			order := &lifecycleOrder{}
			replay := &lifecycleReplayFake{order: order, ready: true}
			terminalEntered := make(chan struct{})
			terminalRelease := make(chan struct{})
			var publicationEntered chan struct{}
			var publicationRelease chan struct{}
			if !publicationWins {
				publicationEntered = make(chan struct{})
				publicationRelease = make(chan struct{})
			}
			revalidator := &lifecycleRevalidatorFake{
				order: order, started: make(chan struct{}), activation: make(chan struct{}),
				returnAfterActivation: true, terminalEntered: terminalEntered,
				terminalRelease: terminalRelease,
			}
			runtimeHTTP := &lifecycleHTTPRuntimeFake{
				order: order, serve: make(chan struct{}), started: make(chan struct{}),
			}
			factory := &lifecycleHTTPFactoryFake{
				order:    order,
				assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
				runtime:  runtimeHTTP,
			}
			deps := lifecycleTestDependencies(order, replay, revalidator)
			if !publicationWins {
				deps.beforePublication = func() {
					close(publicationEntered)
					<-publicationRelease
				}
			}
			lifecycle, err := newLifecycleWithDependencies(
				&config.Prebootstrap{},
				factory,
				deps,
			)
			if err != nil {
				t.Fatalf("construct lifecycle: %v", err)
			}
			startResult := make(chan error, 1)
			go func() { startResult <- lifecycle.Start(context.Background()) }()
			<-terminalEntered
			if publicationWins {
				if err := <-startResult; err != nil {
					t.Fatalf("publication winner Start: %v", err)
				}
				if !lifecycle.Ready() {
					t.Fatal("publication claim did not publish readiness")
				}
				close(terminalRelease)
				<-lifecycle.ShutdownRequests()
				if lifecycle.Ready() {
					t.Fatal("post-publication revalidator return stayed ready")
				}
				if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
					t.Fatalf("fatal cleanup Stop returned %T", err)
				}
			} else {
				<-publicationEntered
				close(terminalRelease)
				<-lifecycle.ShutdownRequests()
				close(publicationRelease)
				if err := <-startResult; !IsLifecycleError(err) {
					t.Fatalf("terminal winner returned %T", err)
				}
				if lifecycle.Ready() {
					t.Fatal("terminal revalidator winner published readiness")
				}
			}
		})
	}
}

// TestLifecycleServeObserverFallbackContainsOmissionAndPanic freezes defense-in-depth.
func TestLifecycleServeObserverFallbackContainsOmissionAndPanic(t *testing.T) {
	tests := []struct {
		name         string
		omitObserver bool
		observer     ServeReturnObserver
	}{
		{name: "omitted", omitObserver: true},
		{name: "panic", observer: &lifecyclePanicServeObserver{}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			order := &lifecycleOrder{}
			replay := &lifecycleReplayFake{order: order, ready: true}
			terminalEntered := make(chan struct{})
			runtimeHTTP := &lifecycleHTTPRuntimeFake{
				order: order, serve: make(chan struct{}), started: make(chan struct{}),
				earlyReturn: true, omitObserver: testCase.omitObserver,
				terminalEntered: terminalEntered,
			}
			factory := &lifecycleHTTPFactoryFake{
				order:               order,
				assembly:            &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
				runtime:             runtimeHTTP,
				overrideServeReturn: testCase.observer,
			}
			lifecycle, err := newLifecycleWithDependencies(
				&config.Prebootstrap{},
				factory,
				lifecycleTestDependencies(order, replay, nil),
			)
			if err != nil {
				t.Fatalf("construct lifecycle: %v", err)
			}
			startErr := lifecycle.Start(context.Background())
			if startErr != nil && !IsLifecycleError(startErr) {
				t.Fatalf("fallback returned %T", startErr)
			}
			<-terminalEntered
			<-lifecycle.ShutdownRequests()
			if startErr == nil {
				if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
					t.Fatalf("post-publication fallback Stop returned %T", err)
				}
			}
			if lifecycle.Ready() {
				t.Fatal("app fallback left readiness published")
			}
			if !runtimeHTTP.terminated.Load() {
				t.Fatal("app fallback left the transport terminal flag unpublished")
			}
		})
	}
}

// TestLifecycleRevalidatorObserverFallbackContainsOmissionAndPanic freezes defense-in-depth.
func TestLifecycleRevalidatorObserverFallbackContainsOmissionAndPanic(t *testing.T) {
	tests := []struct {
		name     string
		omit     bool
		observer ServeReturnObserver
	}{
		{name: "omitted", omit: true},
		{name: "panic", observer: &lifecyclePanicServeObserver{}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			order := &lifecycleOrder{}
			replay := &lifecycleReplayFake{order: order, ready: true}
			terminalEntered := make(chan struct{})
			revalidator := &lifecycleRevalidatorFake{
				order: order, started: make(chan struct{}), activation: make(chan struct{}),
				returnAfterActivation: true, omitObserver: testCase.omit,
				overrideObserver: testCase.observer, terminalEntered: terminalEntered,
			}
			runtimeHTTP := &lifecycleHTTPRuntimeFake{
				order: order, serve: make(chan struct{}), started: make(chan struct{}),
			}
			factory := &lifecycleHTTPFactoryFake{
				order:    order,
				assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
				runtime:  runtimeHTTP,
			}
			lifecycle, err := newLifecycleWithDependencies(
				&config.Prebootstrap{},
				factory,
				lifecycleTestDependencies(order, replay, revalidator),
			)
			if err != nil {
				t.Fatalf("construct lifecycle: %v", err)
			}
			startErr := lifecycle.Start(context.Background())
			if startErr != nil && !IsLifecycleError(startErr) {
				t.Fatalf("revalidator fallback returned %T", startErr)
			}
			<-terminalEntered
			<-lifecycle.ShutdownRequests()
			if startErr == nil {
				if err := lifecycle.Stop(context.Background()); !IsLifecycleError(err) {
					t.Fatalf("post-publication fallback Stop returned %T", err)
				}
			}
			if lifecycle.Ready() {
				t.Fatal("revalidator fallback left readiness published")
			}
			if revalidator.Running() {
				t.Fatal("revalidator fallback left producer live")
			}
		})
	}
}

// TestLifecycleStartupCancelPanicStillJoinsRollback freezes cancel-failure liveness.
func TestLifecycleStartupCancelPanicStillJoinsRollback(t *testing.T) {
	order := &lifecycleOrder{}
	replay := &lifecycleReplayFake{order: order, ready: true}
	runtimeHTTP := &lifecycleHTTPRuntimeFake{
		order: order, serve: make(chan struct{}), started: make(chan struct{}),
	}
	factory := &lifecycleHTTPFactoryFake{
		order:    order,
		assembly: &lifecycleHTTPAssemblyFake{order: order, runtime: runtimeHTTP},
		runtime:  runtimeHTTP,
	}
	deps := lifecycleTestDependencies(order, replay, nil)
	originalWithTimeout := deps.withTimeout
	cancelEntered := make(chan struct{})
	var cancelEnteredOnce sync.Once
	deps.withTimeout = func(
		parent context.Context,
		duration time.Duration,
	) (context.Context, context.CancelFunc) {
		ctx, cancel := originalWithTimeout(parent, duration)
		if duration != LifecycleAcquisitionTimeout {
			return ctx, cancel
		}
		return ctx, func() {
			cancelEnteredOnce.Do(func() { close(cancelEntered) })
			panic("private acquisition cancel marker")
		}
	}
	prepareEntered := make(chan struct{})
	prepareRelease := make(chan struct{})
	deps.prepareRuntime = func(*config.Prebootstrap) (*config.RuntimePreparation, error) {
		close(prepareEntered)
		<-prepareRelease
		return &config.RuntimePreparation{}, nil
	}
	lifecycle, err := newLifecycleWithDependencies(
		&config.Prebootstrap{}, factory, deps,
	)
	if err != nil {
		t.Fatalf("construct lifecycle: %v", err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- lifecycle.Start(context.Background()) }()
	<-prepareEntered
	stopResult := make(chan error, 1)
	go func() { stopResult <- lifecycle.Stop(context.Background()) }()
	<-cancelEntered
	select {
	case err := <-stopResult:
		t.Fatalf("Stop returned before rollback joined: %v", err)
	default:
	}
	close(prepareRelease)
	if err := <-startResult; !IsLifecycleError(err) {
		t.Fatalf("cancel-panic Start returned %T", err)
	}
	if err := <-stopResult; !IsLifecycleError(err) {
		t.Fatalf("cancel-panic Stop returned %T", err)
	}
}

// equalLifecycleOrder compares two exact orchestration traces.
func equalLifecycleOrder(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// containsLifecycleStep reports whether one exact step is present.
func containsLifecycleStep(steps []string, want string) bool {
	for _, step := range steps {
		if step == want {
			return true
		}
	}
	return false
}
