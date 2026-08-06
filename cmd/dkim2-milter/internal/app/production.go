package app

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/observability"
)

const (
	connectionIdleDeadline = 5 * time.Minute
	redactedRuntime        = "dkim2_milter_runtime{redacted}"
)

// lifecycleTelemetry is the central readiness and observability owner boundary.
type lifecycleTelemetry interface {
	Activate() error
	StartMetrics(context.Context) error
	WithdrawReadiness()
	Stop(context.Context) error
	RecordConfigAccepted(string, bool) error
	RecordReady() bool
	RecordConnectionAdmission(string)
	RecordCallback(string, string, string, time.Duration)
	RecordMessage(
		string, string, string, string, time.Duration, uint64, uint64, bool,
		milter.DomainObservation,
	)
	RecordAction(string, string)
}

// operationHandler owns the daemon client used by connection sessions.
type operationHandler interface {
	milter.Handler
	Close() error
}

// socketLifecycle owns the public Unix listener and its active workers.
type socketLifecycle interface {
	SetUnexpectedExitCallback(func()) error
	Start(context.Context) error
	Ready() bool
	Close(context.Context) error
}

// runtimeDependencies contains narrow construction seams for one process graph.
type runtimeDependencies struct {
	newHandler   func(config.Snapshot, *capabilityOwner) (operationHandler, error)
	newAdmission func(config.Snapshot) (*milter.Admission, error)
	newSession   func(config.Snapshot, milter.Handler, *milter.Admission) (milter.ConnectionWorker, error)
	newSocket    func(config.Snapshot, *milter.Admission, milter.ConnectionFactory) (socketLifecycle, error)
}

// productionRuntime owns the ordered process resources after configuration.
type productionRuntime struct {
	state *productionRuntimeState
}

// productionRuntimeState keeps copied holders opaque through one private guard.
type productionRuntimeState struct {
	guard *productionRuntimeGuard
}

// productionRuntimeGuard owns mutable lifecycle state and every live dependency.
type productionRuntimeGuard struct {
	mu             *sync.Mutex
	graph          *productionGraph
	telemetry      lifecycleTelemetry
	dependencies   runtimeDependencies
	handler        operationHandler
	admission      *milter.Admission
	socket         socketLifecycle
	starting       bool
	started        bool
	stopped        bool
	capabilityLive bool
	telemetryLive  bool
	stopDone       chan struct{}
	stopOnce       *sync.Once
	stopErr        error
}

// productionGraph confines configuration and the capability owner behind one opaque link.
type productionGraph struct {
	snapshot   config.Snapshot
	capability *capabilityOwner
}

// newProductionRuntime constructs an unstarted process resource owner.
func newProductionRuntime(
	snapshot config.Snapshot,
	capability *capabilityOwner,
	telemetry lifecycleTelemetry,
	dependencies runtimeDependencies,
) (*productionRuntime, error) {
	if capability == nil || telemetry == nil || !dependencies.valid() {
		return nil, errApplication
	}
	return &productionRuntime{state: &productionRuntimeState{guard: &productionRuntimeGuard{
		mu:        &sync.Mutex{},
		graph:     &productionGraph{snapshot: snapshot, capability: capability},
		telemetry: telemetry, dependencies: dependencies,
		stopDone: make(chan struct{}),
		stopOnce: &sync.Once{},
	},
	}}, nil
}

// defaultRuntimeDependencies connects validated configuration to concrete owners.
func defaultRuntimeDependencies() runtimeDependencies {
	return runtimeDependencies{
		newHandler: newDaemonHandler,
		newAdmission: func(snapshot config.Snapshot) (*milter.Admission, error) {
			return milter.NewAdmission(
				snapshot.MaxConnections(),
				snapshot.MaxInFlightMessages(),
				snapshot.MaxBufferedBytes(),
			)
		},
		newSession: newMilterSession,
		newSocket:  newMilterSocket,
	}
}

// valid rejects incomplete dependency graphs before Fx startup.
func (d runtimeDependencies) valid() bool {
	return d.newHandler != nil && d.newAdmission != nil &&
		d.newSession != nil && d.newSocket != nil
}

// newDaemonHandler creates the generated HTTP client from one typed capability.
func newDaemonHandler(
	snapshot config.Snapshot,
	owner *capabilityOwner,
) (operationHandler, error) {
	if owner == nil || owner.DaemonCapability() == nil {
		return nil, errApplication
	}
	handler, err := daemon.NewHandler(
		snapshot.DaemonEndpoint(),
		owner.DaemonCapability(),
		string(snapshot.Mode()),
		snapshot.Tenant(),
		snapshot.Domain(),
		snapshot.DomainSource(),
		snapshot.DSNDomain(),
		snapshot.AuthservID(),
	)
	if err != nil {
		return nil, errApplication
	}
	return handler, nil
}

// newMilterSession constructs isolated callback state for one accepted connection.
func newMilterSession(
	snapshot config.Snapshot,
	handler milter.Handler,
	admission *milter.Admission,
) (milter.ConnectionWorker, error) {
	session, err := milter.NewSession(
		handler,
		admission,
		milter.Limits{
			MessageBytes:     snapshot.MessageBytes(),
			HeaderBytes:      snapshot.HeaderBytes(),
			HeaderCount:      snapshot.HeaderCount(),
			HeaderFieldBytes: snapshot.HeaderFieldBytes(),
			RecipientCount:   snapshot.RecipientCount(),
		},
		snapshot.RequestTimeout(),
		milter.FailurePolicy{
			FailOpen:            snapshot.FailureMode() == config.FailureOpen,
			AllowRecipientGroup: snapshot.AllowRecipientGroup(),
		},
		string(snapshot.Mode()),
		snapshot.AuthservID(),
	)
	if err != nil {
		return nil, errApplication
	}
	return session, nil
}

// newMilterSocket creates the secure Unix runtime with a fixed idle bound.
func newMilterSocket(
	snapshot config.Snapshot,
	admission *milter.Admission,
	factory milter.ConnectionFactory,
) (socketLifecycle, error) {
	runtime, err := milter.NewSocketRuntime(
		milter.SocketRuntimeConfig{
			Path:               snapshot.Socket(),
			Mode:               snapshot.SocketMode(),
			ConnectionDeadline: connectionIdleDeadline,
			ShutdownTimeout:    snapshot.ShutdownTimeout(),
		},
		admission,
		factory,
	)
	if err != nil {
		return nil, errApplication
	}
	return runtime, nil
}

// Start acquires every resource and publishes readiness only after listeners live.
func (r *productionRuntime) Start(ctx context.Context) (resultErr error) {
	state := r.privateState()
	if state == nil {
		return errApplication
	}
	return state.start(ctx)
}

// privateState returns the mutable runtime guard only within this package.
func (r *productionRuntime) privateState() *productionRuntimeGuard {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.guard
}

// start acquires every resource within the private lifecycle state.
func (r *productionRuntimeGuard) start(ctx context.Context) (resultErr error) {
	if r == nil || ctx == nil {
		return errApplication
	}
	r.mu.Lock()
	if r.starting || r.started || r.stopped || !r.dependencies.valid() {
		r.mu.Unlock()
		return errApplication
	}
	r.starting = true
	r.mu.Unlock()
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
		if resultErr != nil {
			cleanupContext, cancel := context.WithTimeout(
				context.Background(),
				r.graph.snapshot.ShutdownTimeout(),
			)
			cleanupErr := r.release(cleanupContext)
			cancel()
			r.mu.Lock()
			r.starting = false
			r.stopped = true
			r.mu.Unlock()
			r.completeStop(cleanupErr)
			resultErr = errApplication
		}
	}()
	if err := r.graph.capability.Start(ctx); err != nil {
		return errApplication
	}
	r.capabilityLive = true
	if err := r.telemetry.Activate(); err != nil {
		return errApplication
	}
	r.telemetryLive = true
	handler, err := r.dependencies.newHandler(r.graph.snapshot, r.graph.capability)
	if handler != nil {
		r.handler = handler
	}
	if err != nil || handler == nil {
		return errApplication
	}
	admission, err := createObservedAdmission(
		r.graph.snapshot,
		r.dependencies,
		r.telemetry,
	)
	if admission != nil {
		r.admission = admission
	}
	if err != nil || admission == nil {
		return errApplication
	}
	factory := func(connectionContext context.Context) (milter.ConnectionWorker, error) {
		if connectionContext == nil {
			return nil, errApplication
		}
		worker, workerErr := r.dependencies.newSession(r.graph.snapshot, handler, admission)
		if workerErr != nil || worker == nil {
			return nil, errApplication
		}
		return worker, nil
	}
	socket, err := r.dependencies.newSocket(r.graph.snapshot, admission, factory)
	if socket != nil {
		r.socket = socket
	}
	if err != nil || socket == nil {
		return errApplication
	}
	if err := socket.SetUnexpectedExitCallback(func() {
		_ = withdrawLifecycleReadiness(r.telemetry)
	}); err != nil {
		return errApplication
	}
	if err := socket.Start(ctx); err != nil || !socket.Ready() {
		return errApplication
	}
	if err := activateRuntimeObservation(ctx, admission, r.telemetry); err != nil {
		return errApplication
	}
	if err := contextError(ctx); err != nil {
		return errApplication
	}
	if err := r.telemetry.RecordConfigAccepted(
		string(r.graph.snapshot.Mode()),
		r.graph.snapshot.FailureMode() == config.FailureOpen,
	); err != nil {
		return errApplication
	}
	if !r.telemetry.RecordReady() {
		return errApplication
	}
	r.mu.Lock()
	r.starting = false
	r.started = true
	r.mu.Unlock()
	return nil
}

// createObservedAdmission installs a dormant observer before socket binding.
func createObservedAdmission(
	snapshot config.Snapshot,
	dependencies runtimeDependencies,
	telemetry lifecycleTelemetry,
) (*milter.Admission, error) {
	if telemetry == nil || dependencies.newAdmission == nil {
		return nil, errApplication
	}
	admission, err := dependencies.newAdmission(snapshot)
	if err != nil || admission == nil {
		return admission, errApplication
	}
	if err := admission.SetObserver(telemetry); err != nil {
		admission.Stop()
		return nil, errApplication
	}
	return admission, nil
}

// activateRuntimeObservation starts delivery after quiescent socket binding.
func activateRuntimeObservation(
	ctx context.Context,
	admission *milter.Admission,
	telemetry lifecycleTelemetry,
) error {
	if ctx == nil || admission == nil || telemetry == nil {
		return errApplication
	}
	if err := admission.ActivateObserver(); err != nil {
		return errApplication
	}
	if err := telemetry.StartMetrics(ctx); err != nil {
		return errApplication
	}
	return nil
}

// Stop withdraws readiness before draining mail work and protected owners.
func (r *productionRuntime) Stop(ctx context.Context) error {
	state := r.privateState()
	if state == nil {
		return errApplication
	}
	return state.stop(ctx)
}

// stop withdraws readiness and drains resources within the private state.
func (r *productionRuntimeGuard) stop(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errApplication
	}
	r.mu.Lock()
	if r.stopped {
		done := r.stopDone
		r.mu.Unlock()
		return r.waitForStop(ctx, done)
	}
	if r.starting || !r.started {
		r.mu.Unlock()
		return errApplication
	}
	r.stopped = true
	r.started = false
	r.mu.Unlock()
	stopErr := r.release(ctx)
	r.completeStop(stopErr)
	if stopErr != nil {
		return errApplication
	}
	return nil
}

// completeStop publishes one immutable cleanup result to every stop caller.
func (r *productionRuntimeGuard) completeStop(stopErr error) {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		r.mu.Lock()
		if stopErr != nil {
			r.stopErr = errApplication
		}
		r.mu.Unlock()
		close(r.stopDone)
	})
}

// waitForStop joins an in-progress cleanup without extending the caller bound.
func (r *productionRuntimeGuard) waitForStop(ctx context.Context, done <-chan struct{}) error {
	if r == nil || ctx == nil || done == nil {
		return errApplication
	}
	select {
	case <-done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.stopErr
	default:
	}
	select {
	case <-done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.stopErr
	case <-ctx.Done():
		return errApplication
	}
}

// release cleans every acquired owner in security-sensitive reverse order.
func (r *productionRuntimeGuard) release(ctx context.Context) error {
	failed := false
	if r.telemetryLive {
		if err := withdrawLifecycleReadiness(r.telemetry); err != nil {
			failed = true
		}
	}
	if r.socket != nil {
		if err := closeSocketLifecycle(ctx, r.socket); err != nil {
			failed = true
		}
		r.socket = nil
	}
	if r.admission != nil {
		r.admission.Stop()
		if err := r.admission.CloseObserver(); err != nil {
			failed = true
		}
		if err := r.admission.WaitObserver(ctx); err != nil {
			failed = true
		}
	}
	r.admission = nil
	if r.handler != nil {
		if err := closeOperationHandler(r.handler); err != nil {
			failed = true
		}
		r.handler = nil
	}
	if r.capabilityLive && r.graph != nil && r.graph.capability != nil {
		if err := r.graph.capability.Stop(ctx); err != nil {
			failed = true
		}
		r.capabilityLive = false
	}
	if r.telemetryLive {
		if err := stopLifecycleTelemetry(ctx, r.telemetry); err != nil {
			failed = true
		}
		r.telemetryLive = false
	}
	if failed {
		return errApplication
	}
	return nil
}

// withdrawLifecycleReadiness contains readiness-publication seam panics.
func withdrawLifecycleReadiness(telemetry lifecycleTelemetry) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if telemetry == nil {
		return nil
	}
	telemetry.WithdrawReadiness()
	return nil
}

// stopLifecycleTelemetry contains logger and metrics shutdown panics.
func stopLifecycleTelemetry(ctx context.Context, telemetry lifecycleTelemetry) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if telemetry == nil {
		return nil
	}
	if err := telemetry.Stop(ctx); err != nil {
		return errApplication
	}
	return nil
}

// closeSocketLifecycle contains listener cleanup panics.
func closeSocketLifecycle(ctx context.Context, socket socketLifecycle) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if socket == nil {
		return nil
	}
	if err := socket.Close(ctx); err != nil {
		return errApplication
	}
	return nil
}

// closeOperationHandler contains generated-client cleanup panics.
func closeOperationHandler(handler operationHandler) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if handler == nil {
		return nil
	}
	if err := handler.Close(); err != nil {
		return errApplication
	}
	return nil
}

// String returns a content-free process-runtime diagnostic.
func (productionRuntime) String() string { return redactedRuntime }

// GoString returns a content-free process-runtime representation.
func (r productionRuntime) GoString() string { return r.String() }

// Format prevents formatter traversal into configuration or protected owners.
func (r productionRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects serialization of the process resource graph.
func (productionRuntime) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects process-graph text serialization.
func (productionRuntime) MarshalText() ([]byte, error) { return nil, errApplication }

// String returns a content-free private lifecycle-state diagnostic.
func (productionRuntimeState) String() string { return redactedRuntime }

// GoString returns a content-free private lifecycle-state representation.
func (r productionRuntimeState) GoString() string { return r.String() }

// Format prevents nested formatting from traversing live runtime dependencies.
func (r productionRuntimeState) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, r.String())
}

// MarshalJSON rejects private lifecycle-state serialization.
func (productionRuntimeState) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects private lifecycle-state text serialization.
func (productionRuntimeState) MarshalText() ([]byte, error) { return nil, errApplication }

// String returns a content-free private lifecycle-guard diagnostic.
func (productionRuntimeGuard) String() string { return redactedRuntime }

// GoString returns a content-free private lifecycle-guard representation.
func (r productionRuntimeGuard) GoString() string { return r.String() }

// Format prevents guard dereferencing from traversing live runtime dependencies.
func (r productionRuntimeGuard) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, r.String())
}

// MarshalJSON rejects private lifecycle-guard serialization.
func (productionRuntimeGuard) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects private lifecycle-guard text serialization.
func (productionRuntimeGuard) MarshalText() ([]byte, error) { return nil, errApplication }

// String returns a content-free configuration-and-capability graph diagnostic.
func (productionGraph) String() string { return redactedRuntime }

// GoString returns a content-free configuration-and-capability graph representation.
func (graph productionGraph) GoString() string { return graph.String() }

// Format prevents nested formatting from traversing configuration or capability state.
func (graph productionGraph) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, graph.String())
}

// MarshalJSON rejects internal production-graph serialization.
func (productionGraph) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects internal production-graph text serialization.
func (productionGraph) MarshalText() ([]byte, error) { return nil, errApplication }

var _ lifecycleTelemetry = (*observability.Runtime)(nil)
