package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/fx"
)

// fxLifecycleFake records the real Fx hook boundary.
type fxLifecycleFake struct {
	mu           sync.Mutex
	startCalls   int
	stopCalls    int
	startError   error
	stopError    error
	closeOnStart bool
	shutdown     chan struct{}
	shutdownOnce sync.Once
}

// Start records one real Fx OnStart invocation.
func (l *fxLifecycleFake) Start(context.Context) error {
	l.mu.Lock()
	l.startCalls++
	startError := l.startError
	closeOnStart := l.closeOnStart
	l.mu.Unlock()
	if startError == nil && closeOnStart {
		l.shutdownOnce.Do(func() { close(l.shutdown) })
	}
	return startError
}

// Stop records one real Fx OnStop invocation.
func (l *fxLifecycleFake) Stop(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopCalls++
	return l.stopError
}

// ShutdownRequests returns the exact fake fatal transition signal.
func (l *fxLifecycleFake) ShutdownRequests() <-chan struct{} {
	return l.shutdown
}

// callCounts returns synchronized hook counts.
func (l *fxLifecycleFake) callCounts() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.startCalls, l.stopCalls
}

// fxShutdownerFake records, blocks, or panics at the private relay seam.
type fxShutdownerFake struct {
	mu        sync.Mutex
	calls     int
	panicNow  bool
	block     <-chan struct{}
	entered   chan struct{}
	enterOnce sync.Once
	exited    chan struct{}
	exitOnce  sync.Once
}

// fxLifecycleCollector captures the exact daemon-owned hook.
type fxLifecycleCollector struct {
	hooks []fx.Hook
}

// Append records one Fx lifecycle hook.
func (c *fxLifecycleCollector) Append(hook fx.Hook) {
	c.hooks = append(c.hooks, hook)
}

// Shutdown exercises one deterministic shutdown relay behavior.
func (s *fxShutdownerFake) Shutdown(...fx.ShutdownOption) error {
	s.mu.Lock()
	s.calls++
	panicNow := s.panicNow
	block := s.block
	entered := s.entered
	s.mu.Unlock()
	if entered != nil {
		s.enterOnce.Do(func() { close(entered) })
	}
	if panicNow {
		panic("private shutdowner marker")
	}
	if block != nil {
		<-block
	}
	if s.exited != nil {
		s.exitOnce.Do(func() { close(s.exited) })
	}
	return nil
}

// callCount returns the synchronized shutdown count.
func (s *fxShutdownerFake) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// newTestFXApplication constructs the actual Fx/registerLifecycle path.
func newTestFXApplication(
	t *testing.T,
	lifecycle applicationLifecycle,
	startTimeout time.Duration,
	stopTimeout time.Duration,
	options ...fx.Option,
) *fxApplication {
	t.Helper()
	options = append(
		options,
		fx.Provide(func() applicationLifecycle { return lifecycle }),
	)
	application, err := newFXApplication(startTimeout, stopTimeout, options...)
	if err != nil {
		t.Fatal("real Fx test graph failed pure construction")
	}
	return application
}

// TestFXApplicationFatalAndStartFailure proves one real hook and stable exit mapping.
func TestFXApplicationFatalAndStartFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		startError error
		fatal      bool
		wantStart  int
		wantStop   int
	}{
		{
			name:      "fatal after transfer",
			fatal:     true,
			wantStart: 1,
			wantStop:  1,
		},
		{
			name:       "on start failure",
			startError: errors.New("private start marker"),
			wantStart:  1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lifecycle := &fxLifecycleFake{
				startError:   test.startError,
				closeOnStart: test.fatal,
				shutdown:     make(chan struct{}),
			}
			stopTimeout := 51 * time.Second
			application := newTestFXApplication(
				t,
				lifecycle,
				LifecycleStartTimeout,
				stopTimeout,
			)
			if application.app.StartTimeout() != LifecycleStartTimeout {
				t.Fatalf("Fx start timeout = %s", application.app.StartTimeout())
			}
			if application.app.StopTimeout() != stopTimeout {
				t.Fatalf("Fx stop timeout = %s", application.app.StopTimeout())
			}
			if startCalls, stopCalls := lifecycle.callCounts(); startCalls != 0 || stopCalls != 0 {
				t.Fatal("pure Fx construction acquired lifecycle resources")
			}
			startContext, startCancel := context.WithTimeout(
				context.Background(),
				LifecycleStartTimeout,
			)
			startErr := application.Start(startContext)
			startCancel()
			if test.startError != nil {
				if !IsLifecycleError(startErr) {
					t.Fatal("real Fx OnStart failure was not stable")
				}
			} else {
				if startErr != nil {
					t.Fatal("real Fx fatal fixture failed startup")
				}
				select {
				case signal := <-application.Wait():
					if !signal.Failed {
						t.Fatal("fatal lifecycle request produced a clean signal")
					}
				case <-time.After(time.Second):
					t.Fatal("fatal lifecycle request was not forwarded")
				}
				stopContext, stopCancel := context.WithTimeout(context.Background(), stopTimeout)
				if err := application.Stop(stopContext); err != nil {
					t.Fatal("real Fx fatal fixture failed bounded stop")
				}
				stopCancel()
			}
			startCalls, stopCalls := lifecycle.callCounts()
			if startCalls != test.wantStart || stopCalls != test.wantStop {
				t.Fatalf(
					"real Fx hook calls = %d/%d, want %d/%d",
					startCalls,
					stopCalls,
					test.wantStart,
					test.wantStop,
				)
			}
		})
	}
}

// TestFXApplicationCleanSignalAndWatcherJoin proves clean Fx shutdown and no relay leak.
func TestFXApplicationCleanSignalAndWatcherJoin(t *testing.T) {
	t.Parallel()
	lifecycle := &fxLifecycleFake{shutdown: make(chan struct{})}
	var shutdowner fx.Shutdowner
	application := newTestFXApplication(
		t,
		lifecycle,
		LifecycleStartTimeout,
		170*time.Second,
		fx.Populate(&shutdowner),
	)
	startContext, startCancel := context.WithTimeout(context.Background(), time.Second)
	if err := application.Start(startContext); err != nil {
		t.Fatal("real Fx clean fixture failed startup")
	}
	startCancel()
	if err := shutdowner.Shutdown(); err != nil {
		t.Fatal("real Fx clean shutdown signal failed")
	}
	select {
	case signal := <-application.Wait():
		if signal.Failed {
			t.Fatal("clean Fx shutdown mapped to failure")
		}
	case <-time.After(time.Second):
		t.Fatal("clean Fx shutdown signal was not received")
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
	if err := application.Stop(stopContext); err != nil {
		t.Fatal("real Fx clean fixture failed stop")
	}
	stopCancel()
	close(lifecycle.shutdown)
	startCalls, stopCalls := lifecycle.callCounts()
	if startCalls != 1 || stopCalls != 1 {
		t.Fatalf("real Fx hook calls = %d/%d, want 1/1", startCalls, stopCalls)
	}
}

// TestFXApplicationStopReleasesOutstandingWait proves command cancellation cannot leak a waiter.
func TestFXApplicationStopReleasesOutstandingWait(t *testing.T) {
	t.Parallel()
	lifecycle := &fxLifecycleFake{shutdown: make(chan struct{})}
	application := newTestFXApplication(
		t,
		lifecycle,
		LifecycleStartTimeout,
		51*time.Second,
	)
	startContext, startCancel := context.WithTimeout(context.Background(), time.Second)
	if err := application.Start(startContext); err != nil {
		t.Fatal("real Fx cancellation fixture failed startup")
	}
	startCancel()
	wait := application.Wait()
	stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
	if err := application.Stop(stopContext); err != nil {
		t.Fatal("real Fx cancellation fixture failed stop")
	}
	stopCancel()
	select {
	case signal := <-wait:
		if !signal.Failed {
			t.Fatal("stop-completed waiter reported a clean external signal")
		}
	case <-time.After(time.Second):
		t.Fatal("Fx Stop stranded the outstanding Wait relay")
	}
	startCalls, stopCalls := lifecycle.callCounts()
	if startCalls != 1 || stopCalls != 1 {
		t.Fatalf("real Fx hook calls = %d/%d, want 1/1", startCalls, stopCalls)
	}
}

// TestFXApplicationRepeatedCancellationJoinsOwnedGoroutines proves bounded relay cleanup.
func TestFXApplicationRepeatedCancellationJoinsOwnedGoroutines(t *testing.T) {
	t.Parallel()
	for range 25 {
		lifecycle := &fxLifecycleFake{shutdown: make(chan struct{})}
		application := newTestFXApplication(
			t,
			lifecycle,
			LifecycleStartTimeout,
			51*time.Second,
		)
		startContext, startCancel := context.WithTimeout(context.Background(), time.Second)
		if err := application.Start(startContext); err != nil {
			startCancel()
			t.Fatal("repeated cancellation fixture failed startup")
		}
		startCancel()
		wait := application.Wait()
		stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
		if err := application.Stop(stopContext); err != nil {
			stopCancel()
			t.Fatal("repeated cancellation fixture failed stop")
		}
		stopCancel()
		select {
		case signal, ok := <-wait:
			if !ok || !signal.Failed {
				t.Fatal("owned Wait relay did not publish its terminal failure")
			}
		case <-time.After(time.Second):
			t.Fatal("owned Wait relay did not join")
		}
		if _, open := <-wait; open {
			t.Fatal("owned Wait relay output remained open")
		}
		startCalls, stopCalls := lifecycle.callCounts()
		if startCalls != 1 || stopCalls != 1 {
			t.Fatalf("real Fx hook calls = %d/%d, want 1/1", startCalls, stopCalls)
		}
	}
}

// TestShutdownForwarderFailsClosedAndBoundsHostileSeams covers invalid and hostile relays.
func TestShutdownForwarderFailsClosedAndBoundsHostileSeams(t *testing.T) {
	t.Parallel()
	var typedNil *fxShutdownerFake
	relay := newShutdownRelayState()
	if forwarder, err := newShutdownForwarder(nil, &fxShutdownerFake{}, relay); forwarder != nil ||
		!IsLifecycleError(err) {
		t.Fatal("nil request channel did not fail closed")
	}
	if forwarder, err := newShutdownForwarder(make(chan struct{}), typedNil, relay); forwarder != nil ||
		!IsLifecycleError(err) {
		t.Fatal("typed-nil shutdowner did not fail closed")
	}

	panicRequests := make(chan struct{})
	close(panicRequests)
	panicShutdowner := &fxShutdownerFake{panicNow: true}
	panicRelay := newShutdownRelayState()
	panicForwarder, err := newShutdownForwarder(panicRequests, panicShutdowner, panicRelay)
	if err != nil {
		t.Fatal("panic relay fixture construction failed")
	}
	panicForwarder.start()
	select {
	case <-panicForwarder.done:
	case <-time.After(time.Second):
		t.Fatal("shutdowner panic escaped or stranded relay")
	}
	select {
	case <-panicRelay.failure:
	default:
		t.Fatal("shutdowner panic did not publish terminal application failure")
	}

	block := make(chan struct{})
	entered := make(chan struct{})
	exited := make(chan struct{})
	blockRequests := make(chan struct{})
	close(blockRequests)
	blockForwarder, err := newShutdownForwarder(
		blockRequests,
		&fxShutdownerFake{block: block, entered: entered, exited: exited},
		newShutdownRelayState(),
	)
	if err != nil {
		t.Fatal("blocking relay fixture construction failed")
	}
	blockForwarder.start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("blocking shutdowner was not entered")
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := blockForwarder.stop(stopContext); !IsLifecycleError(err) {
		t.Fatal("blocking shutdowner did not respect the OnStop bound")
	}
	stopCancel()
	close(block)
	select {
	case <-blockForwarder.done:
	case <-time.After(time.Second):
		t.Fatal("released shutdowner relay did not join")
	}
}

// TestLifecycleHookStopsRuntimeBeforeJoiningBlockedRelay freezes stop ordering.
func TestLifecycleHookStopsRuntimeBeforeJoiningBlockedRelay(t *testing.T) {
	t.Parallel()
	requests := make(chan struct{})
	lifecycle := &fxLifecycleFake{shutdown: requests}
	block := make(chan struct{})
	entered := make(chan struct{})
	exited := make(chan struct{})
	shutdowner := &fxShutdownerFake{block: block, entered: entered, exited: exited}
	collector := &fxLifecycleCollector{}
	relay := newShutdownRelayState()
	if err := registerLifecycle(collector, lifecycleParameters{
		Lifecycle: lifecycle, Shutdowner: shutdowner, Relay: relay,
	}); err != nil {
		t.Fatal("hook registration failed")
	}
	if len(collector.hooks) != 1 {
		t.Fatalf("registered hooks = %d, want exactly 1", len(collector.hooks))
	}
	if err := collector.hooks[0].OnStart(context.Background()); err != nil {
		t.Fatal("hook startup failed")
	}
	close(requests)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("blocking shutdowner was not entered")
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- collector.hooks[0].OnStop(stopContext)
	}()
	deadline := time.After(10 * time.Millisecond)
	for {
		_, stopCalls := lifecycle.callCounts()
		if stopCalls == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("blocked relay delayed lifecycle stop entry")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := <-stopDone; !IsLifecycleError(err) {
		t.Fatal("blocked relay did not return one stable aggregate failure")
	}
	stopCancel()
	close(block)
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("released hook relay did not settle")
	}
}

// TestShutdownForwarderLinearizesFatalAgainstCleanStop freezes concurrent closure.
func TestShutdownForwarderLinearizesFatalAgainstCleanStop(t *testing.T) {
	t.Parallel()
	for range 100 {
		requests := make(chan struct{})
		shutdowner := &fxShutdownerFake{}
		forwarder, err := newShutdownForwarder(
			requests,
			shutdowner,
			newShutdownRelayState(),
		)
		if err != nil {
			t.Fatal("relay construction failed")
		}
		forwarder.start()
		stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			close(requests)
		}()
		go func() {
			defer group.Done()
			_ = forwarder.stop(stopContext)
		}()
		group.Wait()
		stopCancel()
		if shutdowner.callCount() > 1 {
			t.Fatal("one fatal transition was forwarded more than once")
		}
		select {
		case <-forwarder.done:
		default:
			t.Fatal("concurrent relay did not join")
		}
	}
}

// TestRelayFXSignalFailsClosed proves framework channel loss cannot look clean.
func TestRelayFXSignalFailsClosed(t *testing.T) {
	t.Parallel()
	for _, source := range []<-chan fx.ShutdownSignal{nil, closedFXSignalChannel()} {
		target := make(chan ApplicationSignal, 1)
		relayFailure := make(chan struct{})
		waitStop := make(chan struct{})
		relayFXSignal(source, relayFailure, waitStop, target)
		signal, ok := <-target
		if !ok || !signal.Failed {
			t.Fatalf("relayed signal = %#v/%t, want failure", signal, ok)
		}
		if _, open := <-target; open {
			t.Fatal("relay target remained open")
		}
	}
}

// TestRelayFXSignalGivesFailurePrecedence freezes the both-ready race.
func TestRelayFXSignalGivesFailurePrecedence(t *testing.T) {
	t.Parallel()
	for range 100 {
		source := make(chan fx.ShutdownSignal, 1)
		source <- fx.ShutdownSignal{ExitCode: 0}
		failure := make(chan struct{})
		close(failure)
		target := make(chan ApplicationSignal, 1)
		waitStop := make(chan struct{})
		relayFXSignal(source, failure, waitStop, target)
		if signal := <-target; !signal.Failed {
			t.Fatal("both-ready relay published a clean signal")
		}
	}
}

// closedFXSignalChannel returns one closed framework signal source.
func closedFXSignalChannel() <-chan fx.ShutdownSignal {
	source := make(chan fx.ShutdownSignal)
	close(source)
	return source
}

// TestFXConstructionFailureIsStable proves fx.New never exposes its raw graph cause.
func TestFXConstructionFailureIsStable(t *testing.T) {
	t.Parallel()
	application, err := newFXApplication(
		LifecycleStartTimeout,
		51*time.Second,
		fx.Invoke(func(string) {}),
	)
	if application != nil || !IsLifecycleError(err) {
		t.Fatal("invalid Fx graph did not return the stable lifecycle failure")
	}
}
