package app

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"go.uber.org/fx"
)

// ApplicationSignal is the content-free process exit class published by Fx.
type ApplicationSignal struct {
	Failed bool
}

// ManagedApplication exposes explicit framework startup, wait, and shutdown.
type ManagedApplication interface {
	Start(context.Context) error
	Wait() <-chan ApplicationSignal
	Stop(context.Context) error
}

// applicationLifecycle is the narrow Fx-to-daemon ownership boundary.
type applicationLifecycle interface {
	Start(context.Context) error
	Stop(context.Context) error
	ShutdownRequests() <-chan struct{}
}

// fxApplication owns one assembled Fx graph.
type fxApplication struct {
	app          *fx.App
	relayFailure <-chan struct{}
	waitStop     chan struct{}
	waitStopOnce sync.Once
}

// Start starts the graph through the caller's explicit bounded context.
func (a *fxApplication) Start(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	if a == nil || a.app == nil || nilInterface(ctx) {
		return &LifecycleError{}
	}
	if err := a.app.Start(ctx); err != nil {
		return &LifecycleError{}
	}
	return nil
}

// Wait returns one content-free framework shutdown signal.
func (a *fxApplication) Wait() <-chan ApplicationSignal {
	out := make(chan ApplicationSignal, 1)
	if a == nil || a.app == nil {
		out <- ApplicationSignal{Failed: true}
		close(out)
		return out
	}
	go relayFXSignal(a.app.Wait(), a.relayFailure, a.waitStop, out)
	return out
}

// Stop stops the graph through the caller's explicit bounded context.
func (a *fxApplication) Stop(ctx context.Context) (resultErr error) {
	defer func() {
		a.stopWaitRelay()
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	if a == nil || a.app == nil || nilInterface(ctx) {
		return &LifecycleError{}
	}
	if err := a.app.Stop(ctx); err != nil {
		return &LifecycleError{}
	}
	return nil
}

// stopWaitRelay releases any command waiter whose command context won first.
func (a *fxApplication) stopWaitRelay() {
	if a != nil && a.waitStop != nil {
		a.waitStopOnce.Do(func() { close(a.waitStop) })
	}
}

// relayFXSignal strips signal identity and fails closed on channel loss.
func relayFXSignal(
	source <-chan fx.ShutdownSignal,
	relayFailure <-chan struct{},
	waitStop <-chan struct{},
	target chan<- ApplicationSignal,
) {
	if source == nil || relayFailure == nil || waitStop == nil {
		target <- ApplicationSignal{Failed: true}
		close(target)
		return
	}
	select {
	case <-relayFailure:
		target <- ApplicationSignal{Failed: true}
		close(target)
		return
	default:
	}
	select {
	case <-waitStop:
		target <- ApplicationSignal{Failed: true}
		close(target)
		return
	default:
	}
	select {
	case <-relayFailure:
		target <- ApplicationSignal{Failed: true}
		close(target)
		return
	case <-waitStop:
		target <- ApplicationSignal{Failed: true}
		close(target)
		return
	case signal, ok := <-source:
		if !ok {
			target <- ApplicationSignal{Failed: true}
			close(target)
			return
		}
		select {
		case <-relayFailure:
			target <- ApplicationSignal{Failed: true}
			close(target)
			return
		default:
		}
		target <- ApplicationSignal{Failed: signal.ExitCode != 0}
		close(target)
	}
}

// shutdownRelayState publishes a stable terminal failure if Fx shutdown signaling fails.
type shutdownRelayState struct {
	failure chan struct{}
	once    sync.Once
}

// newShutdownRelayState constructs one instance-owned failure signal.
func newShutdownRelayState() *shutdownRelayState {
	return &shutdownRelayState{failure: make(chan struct{})}
}

// fail publishes relay failure exactly once.
func (s *shutdownRelayState) fail() {
	if s != nil {
		s.once.Do(func() { close(s.failure) })
	}
}

// lifecycleParameters binds the single bootstrap hook to pure dependencies.
type lifecycleParameters struct {
	fx.In

	Lifecycle  applicationLifecycle
	Shutdowner fx.Shutdowner
	Relay      *shutdownRelayState
}

// registerLifecycle installs the only daemon-owned Fx lifecycle hook.
func registerLifecycle(hooks fx.Lifecycle, params lifecycleParameters) error {
	if nilInterface(hooks) || nilInterface(params.Lifecycle) ||
		nilInterface(params.Shutdowner) || params.Relay == nil {
		return &LifecycleError{}
	}
	forwarder, err := newShutdownForwarder(
		params.Lifecycle.ShutdownRequests(),
		params.Shutdowner,
		params.Relay,
	)
	if err != nil {
		return &LifecycleError{}
	}
	hooks.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := params.Lifecycle.Start(ctx); err != nil {
				return &LifecycleError{}
			}
			forwarder.start()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			forwarder.beginStop()
			stopErr := params.Lifecycle.Stop(ctx)
			forwardErr := forwarder.join(ctx)
			if forwardErr != nil || stopErr != nil {
				return &LifecycleError{}
			}
			return nil
		},
	})
	return nil
}

// shutdownForwarder owns one joinable lifecycle-to-Fx fatal relay.
type shutdownForwarder struct {
	requests   <-chan struct{}
	shutdowner fx.Shutdowner
	relay      *shutdownRelayState
	stopSignal chan struct{}
	done       chan struct{}
	startOnce  sync.Once
	stopOnce   sync.Once
	stopped    atomic.Bool
}

// newShutdownForwarder constructs one dormant joinable relay.
func newShutdownForwarder(
	requests <-chan struct{},
	shutdowner fx.Shutdowner,
	relay *shutdownRelayState,
) (*shutdownForwarder, error) {
	if requests == nil || nilInterface(shutdowner) || relay == nil || relay.failure == nil {
		return nil, &LifecycleError{}
	}
	return &shutdownForwarder{
		requests: requests, shutdowner: shutdowner, relay: relay,
		stopSignal: make(chan struct{}), done: make(chan struct{}),
	}, nil
}

// start launches the relay exactly once after successful lifecycle startup.
func (f *shutdownForwarder) start() {
	f.startOnce.Do(func() {
		go f.run()
	})
}

// beginStop prevents a later fatal relay without waiting for its worker.
func (f *shutdownForwarder) beginStop() {
	if f == nil {
		return
	}
	f.stopOnce.Do(func() {
		f.stopped.Store(true)
		close(f.stopSignal)
	})
}

// join waits for the nonblocking Fx relay within the shared stop context.
func (f *shutdownForwarder) join(ctx context.Context) error {
	if f == nil || nilInterface(ctx) {
		return &LifecycleError{}
	}
	f.startOnce.Do(func() { close(f.done) })
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		select {
		case <-f.done:
			return nil
		default:
			return &LifecycleError{}
		}
	}
}

// stop prevents a later clean-stop race and joins the relay for focused callers.
func (f *shutdownForwarder) stop(ctx context.Context) error {
	f.beginStop()
	return f.join(ctx)
}

// run maps one pre-stop fatal lifecycle transition to exit status one.
func (f *shutdownForwarder) run() {
	defer func() {
		_ = recover()
		close(f.done)
	}()
	select {
	case <-f.stopSignal:
		return
	default:
	}
	select {
	case <-f.requests:
		if !f.stopped.Load() {
			f.relay.fail()
			_ = invokeFXShutdown(f.shutdowner)
		}
	case <-f.stopSignal:
	}
}

// invokeFXShutdown contains the concrete nonblocking Fx shutdown relay.
func invokeFXShutdown(shutdowner fx.Shutdowner) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &LifecycleError{}
		}
	}()
	if err := shutdowner.Shutdown(fx.ExitCode(1)); err != nil {
		return &LifecycleError{}
	}
	return nil
}

// provideApplicationLifecycle constructs the pure daemon lifecycle for Fx.
func provideApplicationLifecycle(
	owner *config.Prebootstrap,
	factory HTTPFactory,
) (applicationLifecycle, error) {
	return NewLifecycle(owner, factory)
}

// newFXApplication assembles one silent Fx graph with the exact outer bounds.
func newFXApplication(
	startTimeout time.Duration,
	stopTimeout time.Duration,
	options ...fx.Option,
) (*fxApplication, error) {
	relay := newShutdownRelayState()
	base := []fx.Option{
		fx.NopLogger,
		fx.StartTimeout(startTimeout),
		fx.StopTimeout(stopTimeout),
		fx.Supply(relay),
	}
	base = append(base, options...)
	base = append(base, fx.Invoke(registerLifecycle))
	fxApp := fx.New(base...)
	if fxApp.Err() != nil {
		return nil, &LifecycleError{}
	}
	return &fxApplication{
		app: fxApp, relayFailure: relay.failure, waitStop: make(chan struct{}),
	}, nil
}

// NewApplication constructs the pure Fx graph without acquiring runtime resources.
func NewApplication(
	owner *config.Prebootstrap,
	factory HTTPFactory,
	stopTimeout time.Duration,
) (ManagedApplication, error) {
	if owner == nil || nilInterface(factory) {
		return nil, &LifecycleError{}
	}
	expected, err := LifecycleStopTimeout(owner.Snapshot().Server().ShutdownTimeout())
	if err != nil || stopTimeout != expected {
		return nil, &LifecycleError{}
	}
	return newFXApplication(
		LifecycleStartTimeout,
		stopTimeout,
		fx.Supply(owner),
		fx.Provide(
			func() HTTPFactory { return factory },
			provideApplicationLifecycle,
		),
	)
}
