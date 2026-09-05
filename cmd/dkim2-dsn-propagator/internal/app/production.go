package app

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/lmtp"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/observability"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/reinject"
)

const (
	connectionIdleDeadline = 5 * time.Minute
	redactedRuntime        = "dkim2_dsn_propagator_runtime{redacted}"
)

// lifecycleTelemetry is the central readiness and observability owner boundary.
type lifecycleTelemetry interface {
	transactionTelemetry
	Activate() error
	StartMetrics(context.Context) error
	WithdrawReadiness()
	Stop(context.Context) error
	RecordConfigAccepted(string) error
	RecordReady() bool
}

// receiverLifecycle owns the public LMTP listener and its active sessions.
type receiverLifecycle interface {
	Start(context.Context) error
	Ready() bool
	Close(context.Context) error
}

// runtimeDependencies contains narrow construction seams for one process graph.
type runtimeDependencies struct {
	newClient     func(config.Snapshot, *capabilityOwner) (propagationClient, error)
	newReinjector func(config.Snapshot) (reinjectionClient, error)
	newReceiver   func(config.Snapshot, lmtp.Handler) (receiverLifecycle, error)
}

// valid rejects incomplete dependency graphs before Fx startup.
func (d runtimeDependencies) valid() bool {
	return d.newClient != nil && d.newReinjector != nil && d.newReceiver != nil
}

// defaultRuntimeDependencies connects validated configuration to concrete owners.
func defaultRuntimeDependencies() runtimeDependencies {
	return runtimeDependencies{
		newClient:     newDaemonClient,
		newReinjector: newReinjectionClient,
		newReceiver:   newReceiver,
	}
}

// newDaemonClient creates the generated HTTP client from one typed capability.
func newDaemonClient(
	snapshot config.Snapshot,
	owner *capabilityOwner,
) (propagationClient, error) {
	if owner == nil || owner.DaemonCapability() == nil {
		return nil, errApplication
	}
	client, err := daemon.NewClient(
		snapshot.DaemonEndpoint(),
		owner.DaemonCapability(),
		snapshot.Tenant(),
		snapshot.ReportingMTA(),
		snapshot.RequestTimeout(),
		snapshot.CommitTimeout(),
		snapshot.MessageBytes(),
	)
	if err != nil {
		return nil, errApplication
	}
	return client, nil
}

// newReinjectionClient creates the confined SMTP submission client.
func newReinjectionClient(snapshot config.Snapshot) (reinjectionClient, error) {
	client, err := reinject.NewClient(
		snapshot.ReinjectionEndpoint(),
		snapshot.ReportingMTA(),
		reinject.Timeouts{
			Connect: snapshot.ConnectTimeout(),
			Command: snapshot.CommandTimeout(),
			Data:    snapshot.DataTimeout(),
		},
	)
	if err != nil {
		return nil, errApplication
	}
	return client, nil
}

// newReceiver creates the secure Unix LMTP runtime with a fixed idle bound.
func newReceiver(
	snapshot config.Snapshot,
	handler lmtp.Handler,
) (receiverLifecycle, error) {
	runtime, err := lmtp.NewRuntime(
		lmtp.RuntimeConfig{
			Path:               snapshot.Socket(),
			Mode:               snapshot.SocketMode(),
			MaxConnections:     snapshot.MaxConnections(),
			ConnectionDeadline: connectionIdleDeadline,
			ShutdownTimeout:    snapshot.ShutdownTimeout(),
			Limits: lmtp.Limits{
				MessageBytes: snapshot.MessageBytes(),
				GreetingName: snapshot.ReportingMTA(),
			},
		},
		handler,
	)
	if err != nil {
		return nil, errApplication
	}
	return runtime, nil
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
	client         propagationClient
	receiver       receiverLifecycle
	starting       bool
	started        bool
	stopped        bool
	capabilityLive bool
	telemetryLive  bool
	stopDone       chan struct{}
	stopOnce       *sync.Once
	stopErr        error
}

// productionGraph confines configuration and the capability owner behind one link.
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
		stopDone: make(chan struct{}), stopOnce: &sync.Once{},
	}}}, nil
}

// Start acquires every resource and publishes readiness only after the listener lives.
func (r *productionRuntime) Start(ctx context.Context) error {
	guard := r.privateState()
	if guard == nil {
		return errApplication
	}
	return guard.start(ctx)
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
				context.Background(), r.graph.snapshot.ShutdownTimeout(),
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
	client, err := r.dependencies.newClient(r.graph.snapshot, r.graph.capability)
	if client != nil {
		r.client = client
	}
	if err != nil || client == nil {
		return errApplication
	}
	reinjector, err := r.dependencies.newReinjector(r.graph.snapshot)
	if err != nil || reinjector == nil {
		return errApplication
	}
	handler, err := newPropagationHandler(
		client, reinjector, r.telemetry, r.graph.snapshot.PermanentFailureReply(),
	)
	if err != nil {
		return errApplication
	}
	receiver, err := r.dependencies.newReceiver(r.graph.snapshot, handler)
	if receiver != nil {
		r.receiver = receiver
	}
	if err != nil || receiver == nil {
		return errApplication
	}
	if err := receiver.Start(ctx); err != nil || !receiver.Ready() {
		return errApplication
	}
	if err := r.telemetry.StartMetrics(ctx); err != nil {
		return errApplication
	}
	if err := contextError(ctx); err != nil {
		return errApplication
	}
	if err := r.telemetry.RecordConfigAccepted(
		string(r.graph.snapshot.PermanentFailureReply()),
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

// Stop withdraws readiness before draining mail work and protected owners.
func (r *productionRuntime) Stop(ctx context.Context) error {
	guard := r.privateState()
	if guard == nil {
		return errApplication
	}
	return guard.stop(ctx)
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
	if r.receiver != nil {
		if err := closeReceiverLifecycle(ctx, r.receiver); err != nil {
			failed = true
		}
		r.receiver = nil
	}
	if r.client != nil {
		if err := closePropagationClient(r.client); err != nil {
			failed = true
		}
		r.client = nil
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

// closeReceiverLifecycle contains listener cleanup panics.
func closeReceiverLifecycle(ctx context.Context, receiver receiverLifecycle) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if receiver == nil {
		return nil
	}
	if err := receiver.Close(ctx); err != nil {
		return errApplication
	}
	return nil
}

// closePropagationClient contains generated-client cleanup panics.
func closePropagationClient(client propagationClient) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if client == nil {
		return nil
	}
	if err := client.Close(); err != nil {
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

// GoString returns a content-free configuration-and-capability representation.
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
