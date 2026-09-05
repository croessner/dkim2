package observability

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/config"
)

var errConfiguration = errors.New("observability configuration failure")

// Runtime owns one central logger and one process-local metric registry.
type Runtime struct {
	logger   *slog.Logger
	handler  *boundedJSONHandler
	registry *Registry
	metrics  *metricsServer

	started atomic.Uint64
	ready   atomic.Uint64
	stopped atomic.Uint64

	mu                 sync.Mutex
	active             bool
	readyPublished     bool
	readinessWithdrawn bool
	readyTerminal      bool
}

// Snapshot is one immutable, label-free lifecycle snapshot.
type Snapshot struct {
	Started uint64
	Ready   uint64
	Stopped uint64
}

// New constructs one bounded logger and one fresh process-local registry.
func New(snapshot config.Snapshot, output io.Writer) (*Runtime, error) {
	listenConfig := &net.ListenConfig{}
	return newRuntime(snapshot, output, listenConfig.Listen)
}

// newRuntime constructs one runtime through an injected listener seam.
func newRuntime(
	snapshot config.Snapshot,
	output io.Writer,
	listen metricsListen,
) (*Runtime, error) {
	if output == nil {
		return nil, errConfiguration
	}
	level, err := parseLevel(snapshot.LogLevel())
	if err != nil {
		return nil, err
	}
	registry := NewRegistry()
	if !registry.usable() {
		return nil, errConfiguration
	}
	handler := newBoundedJSONHandler(output, level)
	metrics, err := newMetricsServer(snapshot.MetricsEndpoint(), registry, listen)
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		logger: slog.New(handler), handler: handler,
		registry: registry, metrics: metrics,
	}
	if metrics != nil {
		metrics.onUnexpectedExit = runtime.recordMetricsExit
	}
	return runtime, nil
}

// parseLevel maps the closed configuration vocabulary to slog levels.
func parseLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, errConfiguration
	}
}

// Logger returns the process-local structured logger.
func (r *Runtime) Logger() *slog.Logger {
	if r == nil || r.logger == nil {
		return slog.New(discardHandler{})
	}
	return r.logger
}

// Registry returns the fresh metric registry owned by this runtime.
func (r *Runtime) Registry() *Registry {
	if r == nil {
		return nil
	}
	return r.registry
}

// Activate enables the central logger and registry without a listener.
func (r *Runtime) Activate() error {
	if r == nil {
		return errConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active || r.readinessWithdrawn || r.readyTerminal {
		return errConfiguration
	}
	if err := r.emit(
		slog.LevelInfo, eventLifecycleTransition, false,
		slog.String(keyOperation, "lifecycle"),
		slog.String(keyLifecycleState, "active"),
		slog.String(keyResultClass, valueSuccess),
	); err != nil {
		return errConfiguration
	}
	r.active = true
	r.started.Add(1)
	r.registry.recordLifecycle("active")
	return nil
}

// StartMetrics acquires the optional listener only after quiescent startup work.
func (r *Runtime) StartMetrics(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active || r.readinessWithdrawn || r.readyTerminal {
		return errConfiguration
	}
	if r.metrics == nil {
		return nil
	}
	if err := r.metrics.start(ctx); err != nil || !r.metrics.isRunning() {
		return errConfiguration
	}
	return nil
}

// RecordReady publishes readiness and reports whether ready is now true.
func (r *Runtime) RecordReady() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.readinessWithdrawn || r.readyTerminal || !r.active ||
		(r.metrics != nil && !r.metrics.isRunning()) {
		return false
	}
	if r.readyPublished {
		return true
	}
	if err := r.emit(
		slog.LevelInfo, eventReadinessTransition, false,
		slog.String(keyOperation, "readiness"),
		slog.Bool("ready", true),
		slog.String(keyResultClass, valueSuccess),
	); err != nil {
		return false
	}
	r.readyPublished = true
	r.ready.Add(1)
	r.registry.setReady(true)
	return true
}

// WithdrawReadiness terminally publishes not-ready without stopping telemetry.
func (r *Runtime) WithdrawReadiness() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.withdrawReadiness(valueSuccess)
}

// withdrawReadiness performs one serialized terminal readiness transition.
func (r *Runtime) withdrawReadiness(resultClass string) error {
	if r.readinessWithdrawn || r.readyTerminal {
		return nil
	}
	r.readinessWithdrawn = true
	r.readyPublished = false
	r.registry.setReady(false)
	return r.emit(
		readinessLogLevel(resultClass), eventReadinessTransition, false,
		slog.String(keyOperation, "readiness"),
		slog.Bool("ready", false),
		slog.String(keyResultClass, resultClass),
	)
}

// readinessLogLevel selects error only for an internal liveness loss.
func readinessLogLevel(resultClass string) slog.Level {
	if resultClass == valueInternal {
		return slog.LevelError
	}
	return slog.LevelInfo
}

// Stop withdraws readiness and releases optional telemetry resources once.
func (r *Runtime) Stop(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errConfiguration
	}
	r.mu.Lock()
	if r.readyTerminal {
		r.mu.Unlock()
		return nil
	}
	withdrawErr := r.withdrawReadiness(valueSuccess)
	r.readyTerminal = true
	r.active = false
	r.stopped.Add(1)
	r.registry.recordLifecycle("stopped")
	logErr := r.emit(
		slog.LevelInfo, eventLifecycleTransition, false,
		slog.String(keyOperation, "lifecycle"),
		slog.String(keyLifecycleState, "stopped"),
		slog.String(keyResultClass, valueSuccess),
	)
	r.mu.Unlock()
	var metricsErr error
	if r.metrics != nil {
		if err := r.metrics.stop(ctx); err != nil {
			metricsErr = errConfiguration
		}
	}
	if withdrawErr != nil || logErr != nil || metricsErr != nil {
		return errConfiguration
	}
	return nil
}

// RecordConfigAccepted records the redacted effective adapter policy.
func (r *Runtime) RecordConfigAccepted(permanentFailureReply string) error {
	if r == nil {
		return errConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active || r.readinessWithdrawn || r.readyTerminal {
		return errConfiguration
	}
	return r.emit(
		slog.LevelInfo, eventConfigAccepted, false,
		slog.String(keyPermanentReply, permanentFailureReply),
		slog.String(keyOperation, "config"),
		slog.String(keyResultClass, valueSuccess),
	)
}

// RecordTransaction records one completed transaction outcome and its reply.
func (r *Runtime) RecordTransaction(outcome, reply string) {
	if r == nil {
		return
	}
	r.registry.RecordTransaction(outcome)
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.emit(
		transactionLogLevel(outcome), eventTransactionCompleted, false,
		slog.String(keyTransactionOutcome, outcome),
		slog.String(keyReply, reply),
		slog.String(keyOperation, "transaction"),
		slog.String(keyResultClass, transactionResultClass(outcome)),
	)
}

// RecordReinjection records one completed re-injection attempt.
func (r *Runtime) RecordReinjection(outcome string) {
	if r == nil {
		return
	}
	r.registry.RecordReinjection(outcome)
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.emit(
		reinjectionLogLevel(outcome), eventReinjectionCompleted, false,
		slog.String(keyReinjectionOutcome, outcome),
		slog.String(keyOperation, "reinjection"),
		slog.String(keyResultClass, reinjectionResultClass(outcome)),
	)
}

// RecordCommit records one completed commit attempt.
func (r *Runtime) RecordCommit(outcome string) {
	if r == nil {
		return
	}
	r.registry.RecordCommit(outcome)
	level := slog.LevelInfo
	class := valueSuccess
	if outcome != CommitCommitted {
		level = slog.LevelWarn
		class = valueTemporary
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.emit(
		level, eventCommitCompleted, false,
		slog.String(keyCommitOutcome, outcome),
		slog.String(keyOperation, "commit"),
		slog.String(keyResultClass, class),
	)
}

// transactionResultClass maps one closed outcome to its closed result class.
func transactionResultClass(outcome string) string {
	switch outcome {
	case OutcomeAccepted:
		return valueSuccess
	case OutcomeDeferred:
		return valueTemporary
	case OutcomeContractFailure:
		return valueInternal
	default:
		return valueFailure
	}
}

// transactionLogLevel selects the severity of one closed transaction outcome.
func transactionLogLevel(outcome string) slog.Level {
	switch outcome {
	case OutcomeAccepted:
		return slog.LevelInfo
	case OutcomeContractFailure:
		return slog.LevelError
	case OutcomeDeferred:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// reinjectionResultClass maps one closed re-injection outcome to its class.
func reinjectionResultClass(outcome string) string {
	switch outcome {
	case ReinjectionAccepted:
		return valueSuccess
	case ReinjectionDeferred:
		return valueTemporary
	default:
		return valueFailure
	}
}

// reinjectionLogLevel selects the severity of one closed re-injection outcome.
func reinjectionLogLevel(outcome string) slog.Level {
	if outcome == ReinjectionAccepted {
		return slog.LevelInfo
	}
	return slog.LevelWarn
}

// emit writes one admitted event and optionally bypasses the configured threshold.
func (r *Runtime) emit(
	level slog.Level,
	eventID string,
	mandatory bool,
	attributes ...slog.Attr,
) error {
	if r == nil || r.handler == nil || !validLogLevel(level) {
		return errConfiguration
	}
	ctx := context.Background()
	if !mandatory && !r.handler.Enabled(ctx, level) {
		return nil
	}
	record := slog.NewRecord(time.Now(), level, eventID, 0)
	record.AddAttrs(attributes...)
	if err := r.handler.Handle(ctx, record); err != nil {
		return errConfiguration
	}
	return nil
}

// recordMetricsExit withdraws readiness after unexpected listener loss.
func (r *Runtime) recordMetricsExit() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.readyTerminal || !r.active {
		return
	}
	_ = r.withdrawReadiness(valueInternal)
}

// Metrics returns an immutable label-free lifecycle snapshot.
func (r *Runtime) Metrics() Snapshot {
	if r == nil {
		return Snapshot{}
	}
	return Snapshot{
		Started: r.started.Load(),
		Ready:   r.ready.Load(),
		Stopped: r.stopped.Load(),
	}
}

// Gather returns the deterministic capped Prometheus text representation.
func (r *Runtime) Gather() ([]byte, error) {
	if r == nil || r.registry == nil {
		return nil, errConfiguration
	}
	return r.registry.Gather()
}
