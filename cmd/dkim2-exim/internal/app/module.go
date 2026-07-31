// Package app owns Exim adapter runtime composition.
package app

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/evidence"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/inbound"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/observability"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/runtime"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

var errServe = errors.New("exim service unavailable")

// startupContext carries the sole bounded acquisition lifetime through Fx construction.
type startupContext struct{ context.Context }

// composedRuntime owns all resources that must start and stop as one service.
type composedRuntime struct {
	mu        sync.Mutex
	service   serviceOwner
	telemetry telemetryOwner
	store     *evidence.Store
	release   func()
	serveDone <-chan error
}

// serviceOwner is the narrow shutdown surface retained by the app owner.
type serviceOwner interface {
	DrainContext(context.Context) error
	RemoveSocket() error
}

// telemetryOwner is the narrow readiness and shutdown surface retained by the app owner.
type telemetryOwner interface {
	SetReady(bool)
	Stop(context.Context) error
	Terminal() <-chan struct{}
}

// failOpenGate prevents fail-open operation until its mandatory telemetry owner is ready.
type failOpenGate struct{ runtime *observability.Runtime }

// inboundObserver bridges the closed service vocabulary into telemetry.
type inboundObserver struct{ runtime *observability.Runtime }

// ObserveInbound records one content-free local-scan service outcome.
func (o inboundObserver) ObserveInbound(result string, failure string, admission string, failOpen bool) {
	if o.runtime == nil {
		return
	}
	o.runtime.Record(observability.Event{Hook: "local_scan", Operation: "process", Result: result, Failure: failure, Admission: admission, FailOpen: failOpen})
}

// RecordFailOpenContext records within the caller-owned mail decision deadline.
func (g *failOpenGate) RecordFailOpenContext(ctx context.Context) error {
	if g == nil || g.runtime == nil {
		return errServe
	}
	if err := g.runtime.RecordFailOpenContext(ctx); err != nil {
		return err
	}
	adapter.MarkFailOpen(ctx)
	return nil
}

// Module provides the Fx-owned inbound service lifecycle.
func Module() fx.Option { return fx.Provide(newComposedRuntime) }

// Serve loads one inbound snapshot and owns its complete listener lifetime.
func Serve(ctx context.Context, configPath string) (result error) {
	var application *fx.App
	defer func() {
		if application != nil {
			stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if stopErr := application.Stop(stop); stopErr != nil && result == nil {
				result = errServe
			}
			cancel()
		}
		if recover() != nil {
			result = errServe
		}
	}()
	if ctx == nil {
		return errServe
	}
	startup, cancelStart := context.WithTimeout(ctx, 15*time.Second)
	defer cancelStart()
	snapshot, err := config.LoadForOperation(configPath, config.OperationInbound)
	if err != nil || snapshot.ForOperation(config.OperationInbound) != nil {
		return errServe
	}
	var runtimeValue *composedRuntime
	application = fx.New(
		fx.Supply(snapshot),
		fx.Supply(startupContext{Context: startup}),
		Module(),
		fx.Populate(&runtimeValue),
		fx.RecoverFromPanics(),
		fx.WithLogger(func() fxevent.Logger { return fxevent.NopLogger }),
	)
	if err = application.Err(); err != nil || runtimeValue == nil {
		return errServe
	}
	err = application.Start(startup)
	if err != nil {
		return errServe
	}
	select {
	case <-ctx.Done():
		return nil
	case serveErr, open := <-runtimeValue.serveDone:
		if !open || serveErr != nil {
			return errServe
		}
		return errServe
	case <-runtimeValue.telemetry.Terminal():
		return errServe
	}
}

// newComposedRuntime validates all protected authority before the socket can bind.
func newComposedRuntime(lifecycle fx.Lifecycle, startup startupContext, snapshot config.Snapshot) (*composedRuntime, error) { //nolint:gocyclo // Acquisition and rollback remain visibly ordered in one owner.
	if lifecycle == nil || startup.Context == nil || startup.Err() != nil || snapshot.ForOperation(config.OperationInbound) != nil {
		return nil, errServe
	}
	capability, capabilityIdentity, err := securefile.ReadCapability(snapshot.CapabilityPath(config.OperationInbound))
	if err != nil || protectedAlias(snapshot.ConfigIdentity(), capabilityIdentity) {
		clear(capability)
		return nil, errServe
	}
	defer clear(capability)
	result := &composedRuntime{}
	closeResult := func() { result.close() }
	// Keep the optional publication dependency interface-nil while evidence is
	// disabled. A typed nil pointer would otherwise be callable through the
	// daemon interface and turn accepted mail into a closed resource failure.
	var publisher daemon.EvidencePublisher
	enabled, root, keyPath, retention, maxRecords, maxBytes := snapshot.Evidence()
	if enabled {
		reader, readerErr := evidence.NewReader(root, keyPath, snapshot.EvidenceReadinessPath(), time.Now)
		if readerErr != nil || reader.ConflictsProtectedIdentity(snapshot.ConfigIdentity()) || reader.ConflictsProtectedIdentity(capabilityIdentity) {
			if reader != nil {
				_ = reader.Close()
			}
			closeResult()
			return nil, errServe
		}
		_ = reader.Close()
		store, storeErr := evidence.NewStoreWithReadinessKeyPathContext(startup.Context, root, keyPath, snapshot.EvidenceReadinessPath(), time.Now, evidence.Limits{MaxRecords: maxRecords, MaxBytes: maxBytes}, snapshot.ConfigIdentity(), capabilityIdentity)
		if storeErr != nil {
			if store != nil {
				_ = store.Close()
			}
			closeResult()
			return nil, errServe
		}
		publisher, err = evidence.NewIncomingPublisher(store, retention)
		if err != nil {
			_ = store.Close()
			closeResult()
			return nil, errServe
		}
		result.store = store
	}
	client, releaseClient, err := runtime.NewProcessClient(snapshot.Endpoint(), snapshot.DaemonTimeout(), capability)
	clear(capability)
	if err != nil {
		closeResult()
		return nil, errServe
	}
	result.release = releaseClient
	allowlist, err := adapter.NewBuildAllowlist(snapshot.AllowedBuildIDs())
	if err != nil {
		closeResult()
		return nil, errServe
	}
	telemetry, err := observability.New(snapshot, os.Stderr)
	if err != nil {
		closeResult()
		return nil, errServe
	}
	result.telemetry = telemetry
	authEnabled, authservID := snapshot.InboundAuthentication()
	if !authEnabled {
		authservID = ""
	}
	mode := daemon.InboundTempfail
	var warning daemon.FailOpenWarning
	gate := &failOpenGate{runtime: telemetry}
	if snapshot.InboundFailure() == config.FailureOpen {
		mode, warning = daemon.InboundFailOpen, gate
	}
	processor, err := daemon.NewProcessorWithPolicy(client, authservID, inboundEvidencePublisher(enabled, publisher), mode, warning)
	if err != nil {
		closeResult()
		return nil, errServe
	}
	messageBytes, headerBytes, headerCount, headerFieldBytes, recipients := snapshot.Limits()
	service, err := inbound.NewService(inbound.ServiceConfig{Path: snapshot.InboundSocket(), Timeout: snapshot.InboundTimeout(), MaxConnections: snapshot.InboundConnections(), MaxInFlight: snapshot.InboundInFlight(), MaxBufferedBytes: snapshot.InboundBufferedBytes(), ReservationBytes: snapshot.InboundReservation(), Limits: ipc.RequestLimits{MessageBytes: int(messageBytes), HeaderBytes: int(headerBytes), HeaderCount: headerCount, HeaderFieldBytes: int(headerFieldBytes), RecipientCount: recipients}, PeerUID: snapshot.InboundPeerUID(), AllowIDs: allowlist, AuthservID: authservID, Observer: inboundObserver{runtime: telemetry}}, processor)
	if err != nil {
		closeResult()
		return nil, errServe
	}
	result.service = service
	lifecycle.Append(fx.Hook{
		OnStart: func(start context.Context) (startErr error) {
			defer func() {
				if recover() != nil {
					startErr = errServe
				}
				if startErr != nil {
					cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_ = result.shutdown(cleanup)
					cancel()
				}
			}()
			if err := service.Start(); err != nil {
				return errServe
			}
			if err := telemetry.StartMetrics(start); err != nil {
				return errServe
			}
			if snapshot.InboundFailure() == config.FailureOpen &&
				telemetry.RecordFailOpenStartup(start) != nil {
				return errServe
			}
			live, done, serveErr := service.ServeAsync(context.Background())
			if serveErr != nil {
				return errServe
			}
			select {
			case <-live:
			case terminal := <-done:
				if terminal != nil {
					return errServe
				}
				return errServe
			}
			result.serveDone = done
			telemetry.SetReady(true)
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return result.shutdown(ctx)
		},
	})
	return result, nil
}

// inboundEvidencePublisher preserves a genuinely nil interface when evidence is disabled.
func inboundEvidencePublisher(enabled bool, publisher daemon.EvidencePublisher) daemon.EvidencePublisher {
	if !enabled {
		return nil
	}
	return publisher
}

// close releases every non-listener authority in reverse allocation order.
func (r *composedRuntime) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store != nil {
		_ = r.store.Close()
		r.store = nil
	}
	if r.release != nil {
		r.release()
		r.release = nil
	}
}

// shutdown withdraws readiness and releases every owned runtime resource.
func (r *composedRuntime) shutdown(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errServe
	}
	if r.telemetry != nil {
		r.telemetry.SetReady(false)
	}
	var serviceErr, telemetryErr error
	if r.service != nil {
		serviceErr = r.service.DrainContext(ctx)
	}
	if serviceErr != nil {
		return errServe
	}
	if r.telemetry != nil {
		telemetryErr = r.telemetry.Stop(ctx)
	}
	r.close()
	var socketErr error
	if r.service != nil {
		socketErr = r.service.RemoveSocket()
	}
	if serviceErr != nil || telemetryErr != nil || socketErr != nil {
		return errServe
	}
	return nil
}

// protectedAlias rejects a shared protected child or final protected parent.
func protectedAlias(left securefile.Identity, right securefile.Identity) bool {
	return left.Equal(right) || left.SameParent(right)
}
