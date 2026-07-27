package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/testsupport"
)

const (
	productionPrivacyMarker = "production-private-marker"
	eventCapabilityLoad     = "capability.load"
	eventCapabilityClose    = "capability.close"
	eventHandlerNew         = "handler.new"
	eventHandlerClose       = "handler.close"
	eventAdmissionNew       = "admission.new"
	eventSocketNew          = "socket.new"
	eventSocketStart        = "socket.start"
	eventSocketClose        = "socket.close"
	eventSessionNew         = "session.new"
	eventTelemetryActivate  = "telemetry.activate"
	eventTelemetryMetrics   = "telemetry.metrics"
	eventTelemetryStop      = "telemetry.stop"
	eventTelemetryWithdraw  = "telemetry.withdraw"
)

// orderedEvents records lifecycle ordering without retaining protected data.
type orderedEvents struct {
	mu     sync.Mutex
	values []string
}

// add appends one closed event value.
func (e *orderedEvents) add(value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.values = append(e.values, value)
}

// snapshot returns one detached event sequence.
func (e *orderedEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.values...)
}

// orderedCapability records the final protected-owner release.
type orderedCapability struct {
	events *orderedEvents
}

// Close records one content-free cleanup event.
func (c *orderedCapability) Close() error {
	c.events.add(eventCapabilityClose)
	return nil
}

// orderedTelemetry records the central lifecycle boundary.
type orderedTelemetry struct {
	events       *orderedEvents
	withdrawOnce sync.Once
	refuseReady  bool
	activateErr  error
	metricsErr   error
	configErr    error
}

// Activate records quiescent observability acquisition.
func (t *orderedTelemetry) Activate() error {
	t.events.add(eventTelemetryActivate)
	return t.activateErr
}

// StartMetrics records post-socket listener activation.
func (t *orderedTelemetry) StartMetrics(context.Context) error {
	t.events.add(eventTelemetryMetrics)
	return t.metricsErr
}

// Stop records readiness withdrawal and observability release.
func (t *orderedTelemetry) Stop(context.Context) error {
	t.events.add(eventTelemetryStop)
	return nil
}

// WithdrawReadiness records the terminal not-ready transition.
func (t *orderedTelemetry) WithdrawReadiness() {
	t.withdrawOnce.Do(func() {
		t.events.add(eventTelemetryWithdraw)
	})
}

// RecordConfigAccepted records bounded configuration evidence.
func (t *orderedTelemetry) RecordConfigAccepted(string, bool) error {
	t.events.add("telemetry.config")
	return t.configErr
}

// RecordReady records and confirms the final readiness publication.
func (t *orderedTelemetry) RecordReady() bool {
	t.events.add("telemetry.ready")
	return !t.refuseReady
}

// RecordConnectionAdmission accepts one closed runtime fact.
func (*orderedTelemetry) RecordConnectionAdmission(string) {}

// RecordCallback accepts one closed runtime fact.
func (*orderedTelemetry) RecordCallback(string, string, string, time.Duration) {}

// RecordMessage accepts one closed runtime fact.
func (*orderedTelemetry) RecordMessage(
	string,
	string,
	string,
	string,
	time.Duration,
	uint64,
	uint64,
	bool,
) {
}

// RecordAction accepts one closed runtime fact.
func (*orderedTelemetry) RecordAction(string, string) {}

// orderedHandler records the generated-client owner release.
type orderedHandler struct {
	events     *orderedEvents
	closePanic bool
}

// Handle is an unused content-free application test seam.
func (*orderedHandler) Handle(context.Context, milter.Message) (milter.Result, error) {
	return milter.Result{}, &milter.Error{Class: milter.FailureInternal}
}

// Close records transport release and can exercise panic containment.
func (h *orderedHandler) Close() error {
	h.events.add(eventHandlerClose)
	if h.closePanic {
		panic(productionPrivacyMarker)
	}
	return nil
}

// orderedWorker is one isolated connection test seam.
type orderedWorker struct{}

// Serve is an unused connection worker implementation.
func (*orderedWorker) Serve(context.Context, io.ReadWriter) error { return nil }

// orderedSocket records listener lifecycle and optionally fails startup.
type orderedSocket struct {
	events       *orderedEvents
	factory      milter.ConnectionFactory
	ready        bool
	startError   error
	closePanic   bool
	unexpected   func()
	closeEntered chan struct{}
	closeRelease <-chan struct{}
}

// SetUnexpectedExitCallback retains one external readiness-withdrawal callback.
func (s *orderedSocket) SetUnexpectedExitCallback(callback func()) error {
	if callback == nil || s.unexpected != nil {
		return errApplication
	}
	s.unexpected = callback
	return nil
}

// Start constructs one session before publishing listener readiness.
func (s *orderedSocket) Start(ctx context.Context) error {
	s.events.add(eventSocketStart)
	if s.startError != nil {
		return s.startError
	}
	worker, err := s.factory(ctx)
	if err != nil || worker == nil {
		return errApplication
	}
	s.ready = true
	return nil
}

// Ready reports the injected listener state.
func (s *orderedSocket) Ready() bool { return s.ready }

// Close withdraws listener readiness before recording release.
func (s *orderedSocket) Close(context.Context) error {
	s.ready = false
	s.events.add(eventSocketClose)
	if s.closeEntered != nil {
		close(s.closeEntered)
	}
	if s.closeRelease != nil {
		<-s.closeRelease
	}
	if s.closePanic {
		panic(productionPrivacyMarker)
	}
	return nil
}

// orderedRuntimeDependencies creates deterministic production owners.
func orderedRuntimeDependencies(
	events *orderedEvents,
	socket **orderedSocket,
) runtimeDependencies {
	return runtimeDependencies{
		newHandler: func(config.Snapshot, *capabilityOwner) (operationHandler, error) {
			events.add(eventHandlerNew)
			return &orderedHandler{events: events}, nil
		},
		newAdmission: func(snapshot config.Snapshot) (*milter.Admission, error) {
			events.add(eventAdmissionNew)
			return milter.NewAdmission(
				snapshot.MaxConnections(),
				snapshot.MaxInFlightMessages(),
				snapshot.MaxBufferedBytes(),
			)
		},
		newSession: func(
			config.Snapshot,
			milter.Handler,
			*milter.Admission,
		) (milter.ConnectionWorker, error) {
			events.add(eventSessionNew)
			return &orderedWorker{}, nil
		},
		newSocket: func(
			_ config.Snapshot,
			_ *milter.Admission,
			factory milter.ConnectionFactory,
		) (socketLifecycle, error) {
			events.add(eventSocketNew)
			created := &orderedSocket{events: events, factory: factory}
			*socket = created
			return created, nil
		},
	}
}

// lifecycleTestRuntimeDependencies supplies inert process owners to legacy graph tests.
func lifecycleTestRuntimeDependencies() runtimeDependencies {
	events := &orderedEvents{}
	var socket *orderedSocket
	return orderedRuntimeDependencies(events, &socket)
}

// newOrderedRuntime constructs one runtime with a fake protected capability.
func newOrderedRuntime(
	t *testing.T,
	events *orderedEvents,
	telemetry lifecycleTelemetry,
	dependencies runtimeDependencies,
) *productionRuntime {
	t.Helper()
	owner, err := newCapabilityOwner(
		testSnapshot(t),
		func(string) (protectedCapability, error) {
			events.add(eventCapabilityLoad)
			return &orderedCapability{events: events}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newProductionRuntime(testSnapshot(t), owner, telemetry, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

// TestProductionRuntimeOrdersReadinessAndShutdown proves the complete owner graph.
func TestProductionRuntimeOrdersReadinessAndShutdown(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	runtime := newOrderedRuntime(
		t,
		events,
		&orderedTelemetry{events: events},
		orderedRuntimeDependencies(events, &socket),
	)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if socket == nil || !socket.Ready() {
		t.Fatal("listener was not live when startup completed")
	}
	if got, want := events.snapshot(), []string{
		eventCapabilityLoad,
		eventTelemetryActivate,
		eventHandlerNew,
		eventAdmissionNew,
		eventSocketNew,
		eventSocketStart,
		eventSessionNew,
		eventTelemetryMetrics,
		"telemetry.config",
		"telemetry.ready",
	}; !equalEventSequence(got, want) {
		t.Fatalf("startup events = %v, want %v", got, want)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := events.snapshot()[10:], []string{
		eventTelemetryWithdraw,
		eventSocketClose,
		eventHandlerClose,
		eventCapabilityClose,
		eventTelemetryStop,
	}; !equalEventSequence(got, want) {
		t.Fatalf("shutdown events = %v, want %v", got, want)
	}
}

// TestProductionRuntimeRollsBackRefusedReadiness proves false-ready fail-closed behavior.
func TestProductionRuntimeRollsBackRefusedReadiness(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	telemetry := &orderedTelemetry{events: events, refuseReady: true}
	runtime := newOrderedRuntime(
		t,
		events,
		telemetry,
		orderedRuntimeDependencies(events, &socket),
	)
	if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
		t.Fatalf("Start() error = %v", err)
	}
	got := strings.Join(events.snapshot(), ",")
	for _, required := range []string{
		"telemetry.ready", eventTelemetryWithdraw, eventSocketClose,
		eventHandlerClose, eventCapabilityClose, eventTelemetryStop,
	} {
		if !strings.Contains(got, required) {
			t.Fatalf("false-ready rollback events %q lack %q", got, required)
		}
	}
}

// TestProductionRuntimeRollsBackTelemetryStartupFailures proves every partial owner.
func TestProductionRuntimeRollsBackTelemetryStartupFailures(t *testing.T) {
	tests := []struct {
		name      string
		telemetry func(*orderedEvents) *orderedTelemetry
		want      []string
	}{
		{
			name: "activate",
			telemetry: func(events *orderedEvents) *orderedTelemetry {
				return &orderedTelemetry{events: events, activateErr: errApplication}
			},
			want: []string{
				eventCapabilityLoad, eventTelemetryActivate,
				eventCapabilityClose,
			},
		},
		{
			name: "metrics",
			telemetry: func(events *orderedEvents) *orderedTelemetry {
				return &orderedTelemetry{events: events, metricsErr: errApplication}
			},
			want: []string{
				eventCapabilityLoad, eventTelemetryActivate, eventHandlerNew, eventAdmissionNew,
				eventSocketNew, eventSocketStart, eventSessionNew, eventTelemetryMetrics,
				eventTelemetryWithdraw, eventSocketClose, eventHandlerClose,
				eventCapabilityClose, eventTelemetryStop,
			},
		},
		{
			name: "config evidence",
			telemetry: func(events *orderedEvents) *orderedTelemetry {
				return &orderedTelemetry{events: events, configErr: errApplication}
			},
			want: []string{
				eventCapabilityLoad, eventTelemetryActivate, eventHandlerNew, eventAdmissionNew,
				eventSocketNew, eventSocketStart, eventSessionNew, eventTelemetryMetrics,
				"telemetry.config", eventTelemetryWithdraw, eventSocketClose,
				eventHandlerClose, eventCapabilityClose, eventTelemetryStop,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := &orderedEvents{}
			var socket *orderedSocket
			runtime := newOrderedRuntime(
				t,
				events,
				test.telemetry(events),
				orderedRuntimeDependencies(events, &socket),
			)
			if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
				t.Fatalf("Start() error = %v", err)
			}
			if got := events.snapshot(); !equalEventSequence(got, test.want) {
				t.Fatalf("rollback events = %v, want %v", got, test.want)
			}
		})
	}
}

// TestProductionRuntimeOwnsAmbiguousConstructorResultsBeforeRollback closes every owner.
func TestProductionRuntimeOwnsAmbiguousConstructorResultsBeforeRollback(t *testing.T) {
	t.Run("handler", func(t *testing.T) {
		events := &orderedEvents{}
		var socket *orderedSocket
		dependencies := orderedRuntimeDependencies(events, &socket)
		dependencies.newHandler = func(
			config.Snapshot,
			*capabilityOwner,
		) (operationHandler, error) {
			events.add(eventHandlerNew)
			return &orderedHandler{events: events}, errApplication
		}
		runtime := newOrderedRuntime(
			t, events, &orderedTelemetry{events: events}, dependencies,
		)
		if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
			t.Fatal("ambiguous handler result was accepted")
		}
		if !containsEvent(events.snapshot(), eventHandlerClose) {
			t.Fatal("ambiguous handler result was not closed")
		}
	})
	t.Run("admission", func(t *testing.T) {
		events := &orderedEvents{}
		var socket *orderedSocket
		dependencies := orderedRuntimeDependencies(events, &socket)
		var admission *milter.Admission
		dependencies.newAdmission = func(config.Snapshot) (*milter.Admission, error) {
			events.add(eventAdmissionNew)
			var err error
			admission, err = milter.NewAdmission(1, 1, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			return admission, errApplication
		}
		runtime := newOrderedRuntime(
			t, events, &orderedTelemetry{events: events}, dependencies,
		)
		if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
			t.Fatal("ambiguous admission result was accepted")
		}
		if _, admitted := admission.AdmitConnection(); admitted {
			t.Fatal("ambiguous admission result was not stopped")
		}
	})
	t.Run("socket", func(t *testing.T) {
		events := &orderedEvents{}
		var socket *orderedSocket
		dependencies := orderedRuntimeDependencies(events, &socket)
		dependencies.newSocket = func(
			_ config.Snapshot,
			_ *milter.Admission,
			factory milter.ConnectionFactory,
		) (socketLifecycle, error) {
			events.add(eventSocketNew)
			socket = &orderedSocket{events: events, factory: factory}
			return socket, errApplication
		}
		runtime := newOrderedRuntime(
			t, events, &orderedTelemetry{events: events}, dependencies,
		)
		if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
			t.Fatal("ambiguous socket result was accepted")
		}
		if !containsEvent(events.snapshot(), eventSocketClose) {
			t.Fatal("ambiguous socket result was not closed")
		}
	})
}

// containsEvent reports whether one deterministic lifecycle event was recorded.
func containsEvent(events []string, want string) bool {
	for _, event := range events {
		if event == want {
			return true
		}
	}
	return false
}

// TestProductionRuntimeUnexpectedSocketExitWithdrawsReadiness proves liveness feedback.
func TestProductionRuntimeUnexpectedSocketExitWithdrawsReadiness(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	runtime := newOrderedRuntime(
		t,
		events,
		&orderedTelemetry{events: events},
		orderedRuntimeDependencies(events, &socket),
	)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if socket == nil || socket.unexpected == nil {
		t.Fatal("socket liveness callback was not installed")
	}
	socket.unexpected()
	if got := events.snapshot(); got[len(got)-1] != eventTelemetryWithdraw {
		t.Fatalf("unexpected socket exit left readiness published: %v", got)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestProductionRuntimeCoalescesConcurrentStop proves every caller joins cleanup.
func TestProductionRuntimeCoalescesConcurrentStop(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	runtime := newOrderedRuntime(
		t,
		events,
		&orderedTelemetry{events: events},
		orderedRuntimeDependencies(events, &socket),
	)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	socket.closeEntered = make(chan struct{})
	closeRelease := make(chan struct{})
	socket.closeRelease = closeRelease
	results := make(chan error, 2)
	go func() { results <- runtime.Stop(context.Background()) }()
	<-socket.closeEntered
	go func() { results <- runtime.Stop(context.Background()) }()
	select {
	case err := <-results:
		t.Fatalf("concurrent Stop returned before cleanup completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(closeRelease)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("coalesced Stop error = %v", err)
		}
	}
	count := 0
	for _, event := range events.snapshot() {
		if event == eventSocketClose {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("socket cleanup events = %d, want 1", count)
	}
}

// TestProductionRuntimeRollsBackFailedSocketStart proves reverse-order cleanup.
func TestProductionRuntimeRollsBackFailedSocketStart(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	dependencies := orderedRuntimeDependencies(events, &socket)
	originalNewSocket := dependencies.newSocket
	dependencies.newSocket = func(
		snapshot config.Snapshot,
		admission *milter.Admission,
		factory milter.ConnectionFactory,
	) (socketLifecycle, error) {
		created, err := originalNewSocket(snapshot, admission, factory)
		socket.startError = errors.New(productionPrivacyMarker)
		return created, err
	}
	runtime := newOrderedRuntime(
		t,
		events,
		&orderedTelemetry{events: events},
		dependencies,
	)
	if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
		t.Fatalf("Start() error = %v", err)
	}
	gotEvents := events.snapshot()
	wantEvents := []string{
		eventCapabilityLoad,
		eventTelemetryActivate,
		eventHandlerNew,
		eventAdmissionNew,
		eventSocketNew,
		eventSocketStart,
		eventTelemetryWithdraw, eventSocketClose, eventHandlerClose,
		eventCapabilityClose, eventTelemetryStop,
	}
	if !equalEventSequence(gotEvents, wantEvents) {
		t.Fatalf("rollback events = %v, want %v", gotEvents, wantEvents)
	}
	if strings.Contains(runtime.String(), productionPrivacyMarker) {
		t.Fatal("runtime formatting exposed a private startup error")
	}
	subjects := []any{
		runtime,
		*runtime,
		any(runtime),
		runtime.state,
		*runtime.state,
		runtime.state.guard,
		*runtime.state.guard,
		runtime.state.guard.graph,
		*runtime.state.guard.graph,
		struct{ Value any }{Value: runtime},
		struct{ Value productionRuntime }{Value: *runtime},
	}
	for _, subject := range subjects {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if formatted := fmt.Sprintf(format, subject); strings.Contains(
				formatted,
				productionPrivacyMarker,
			) || strings.Contains(formatted, "127.0.0.1:8080") {
				t.Fatalf("unsafe production runtime formatting: %q", formatted)
			}
		}
		if output, err := json.Marshal(subject); !errors.Is(err, errApplication) ||
			strings.Contains(string(output), productionPrivacyMarker) {
			t.Fatal("production runtime serialization did not fail closed")
		}
		if marshaler, ok := subject.(interface{ MarshalText() ([]byte, error) }); ok {
			if output, err := marshaler.MarshalText(); !errors.Is(err, errApplication) ||
				strings.Contains(string(output), productionPrivacyMarker) {
				t.Fatal("production runtime text serialization did not fail closed")
			}
		}
	}
}

// TestProductionRuntimeContainsStartupPanic proves reverse-order panic rollback.
func TestProductionRuntimeContainsStartupPanic(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	dependencies := orderedRuntimeDependencies(events, &socket)
	dependencies.newHandler = func(
		config.Snapshot,
		*capabilityOwner,
	) (operationHandler, error) {
		panic(productionPrivacyMarker)
	}
	runtime := newOrderedRuntime(
		t,
		events,
		&orderedTelemetry{events: events},
		dependencies,
	)
	if err := runtime.Start(context.Background()); !errors.Is(err, errApplication) {
		t.Fatalf("Start() error = %v", err)
	}
	got := strings.Join(events.snapshot(), ",")
	for _, required := range []string{
		eventTelemetryWithdraw, eventCapabilityClose, eventTelemetryStop,
	} {
		if !strings.Contains(got, required) {
			t.Fatalf("panic rollback events %q lack %q", got, required)
		}
	}
	if strings.Contains(got, productionPrivacyMarker) {
		t.Fatalf("panic rollback exposed private panic data: %q", got)
	}
}

// TestProductionRuntimeContainsCleanupPanicsAndContinues proves all owners release.
func TestProductionRuntimeContainsCleanupPanicsAndContinues(t *testing.T) {
	events := &orderedEvents{}
	var socket *orderedSocket
	dependencies := orderedRuntimeDependencies(events, &socket)
	runtime := newOrderedRuntime(
		t,
		events,
		&orderedTelemetry{events: events},
		dependencies,
	)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	socket.closePanic = true
	runtime.privateState().handler.(*orderedHandler).closePanic = true
	if err := runtime.Stop(context.Background()); !errors.Is(err, errApplication) {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := runtime.Stop(context.Background()); !errors.Is(err, errApplication) {
		t.Fatalf("second Stop() error = %v", err)
	}
	got := strings.Join(events.snapshot(), ",")
	if !strings.Contains(got, eventHandlerClose) ||
		!strings.Contains(got, eventCapabilityClose) ||
		strings.Contains(got, productionPrivacyMarker) {
		t.Fatalf("cleanup did not continue safely: %q", got)
	}
}

// TestDefaultRuntimeHandlerRequiresTypedCapability proves credential confinement.
func TestDefaultRuntimeHandlerRequiresTypedCapability(t *testing.T) {
	owner := &capabilityOwner{state: &capabilityOwnerState{
		guard: &capabilityOwnerGuard{
			mu: &sync.Mutex{}, capability: &orderedCapability{events: &orderedEvents{}},
		},
	}}
	if _, err := defaultRuntimeDependencies().newHandler(testSnapshot(t), owner); err == nil {
		t.Fatal("untyped capability reached the daemon handler")
	}
}

// TestDefaultRuntimeDependenciesConstructValidatedOwners proves concrete wiring seams.
func TestDefaultRuntimeDependenciesConstructValidatedOwners(t *testing.T) {
	snapshot, _ := productionTestSnapshot(t)
	capability, err := daemon.LoadCapability(snapshot.CapabilityFile())
	if err != nil {
		t.Fatal("typed capability construction failed")
	}
	owner := &capabilityOwner{state: &capabilityOwnerState{
		guard: &capabilityOwnerGuard{mu: &sync.Mutex{}, capability: capability},
	}}
	dependencies := defaultRuntimeDependencies()
	handler, err := dependencies.newHandler(snapshot, owner)
	if err != nil {
		t.Fatal("daemon handler construction failed")
	}
	admission, err := dependencies.newAdmission(snapshot)
	if err != nil {
		t.Fatal("admission construction failed")
	}
	worker, err := dependencies.newSession(snapshot, handler, admission)
	if err != nil || worker == nil {
		t.Fatal("session construction failed")
	}
	socket, err := dependencies.newSocket(
		snapshot,
		admission,
		func(context.Context) (milter.ConnectionWorker, error) {
			return worker, nil
		},
	)
	if err != nil {
		t.Fatal("socket construction failed")
	}
	if err := socket.Start(context.Background()); err != nil {
		t.Fatal("socket startup failed")
	}
	if !socket.Ready() {
		t.Fatal("socket startup returned before readiness")
	}
	if err := socket.Close(context.Background()); err != nil {
		t.Fatal("socket cleanup failed")
	}
	if err := handler.Close(); err != nil {
		t.Fatal("daemon handler cleanup failed")
	}
	if err := capability.Close(); err != nil {
		t.Fatal("typed capability cleanup failed")
	}
}

// equalEventSequence compares exact lifecycle ordering.
func equalEventSequence(left, right []string) bool {
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

// TestApplicationProductionGraphBindsAndCleansItsSocket exercises the real Fx path.
func TestApplicationProductionGraphBindsAndCleansItsSocket(t *testing.T) {
	snapshot, socketPath := productionTestSnapshot(t)
	var output bytes.Buffer
	application, err := New(snapshot, &output)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := application.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), productionPrivacyMarker) {
		t.Fatal("production lifecycle logs exposed private test data")
	}
	if socketPathExists(socketPath) {
		t.Fatal("owned socket remained after application shutdown")
	}
}

// productionTestSnapshot creates protected capability and socket parents.
func productionTestSnapshot(t *testing.T) (config.Snapshot, string) {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	socketParent := filepath.Join(root, "socket")
	if err := os.Mkdir(socketParent, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(socketParent, "dkim2.sock")
	capabilityParent := filepath.Join(root, "capability-"+productionPrivacyMarker)
	if err := os.Mkdir(capabilityParent, 0o700); err != nil {
		t.Fatal(err)
	}
	capabilityPath := filepath.Join(capabilityParent, "token")
	capability := make([]byte, 32)
	copy(capability, productionPrivacyMarker)
	if err := os.WriteFile(capabilityPath, capability, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(capabilityParent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(capabilityParent, 0o700)
	})
	clear(capability)
	document := `version: dkim2-milter-config-v1
server:
  socket: ` + socketPath + `
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: ` + capabilityPath + `
mode: inbound
`
	configPath := filepath.Join(root, "milter.yaml")
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, socketPath
}

// socketPathExists reports target existence without following it.
func socketPathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
