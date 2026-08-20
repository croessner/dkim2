package observability

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

// Runtime owns every concrete telemetry component for one daemon instance.
type Runtime struct {
	logger  *Logger
	tracing *TraceRuntime
	metrics *Metrics

	shutdownOnce sync.Once
	shutdownErr  error
	readiness    atomic.Uint32
	readinessMu  sync.Mutex
}

// NewRuntime constructs one instance-owned logger, tracer, and metrics registry.
func NewRuntime(
	ctx context.Context,
	settings config.ObservabilityConfig,
	destination io.Writer,
	material config.TracingStartupMaterial,
) (*Runtime, error) {
	if ctx == nil {
		return nil, errRejectedRecord
	}
	metrics, err := NewMetrics()
	if err != nil {
		return nil, errRejectedRecord
	}
	logger, err := newLogger(settings, destination, func(reason string) {
		metrics.ObservationDropped("log", reason)
	})
	if err != nil {
		return nil, errRejectedRecord
	}
	var tracing *TraceRuntime
	switch settings.Tracing().Exporter() {
	case config.TracingNone:
		tracing, err = newTraceRuntime(
			ctx,
			settings.Tracing(),
			nil,
			loggerTraceReporter(logger, metrics),
		)
	case config.TracingOTLPHTTP:
		err = material.UseRoots(func(rootsDER [][]byte) error {
			tracing, err = newTraceRuntime(
				ctx,
				settings.Tracing(),
				rootsDER,
				loggerTraceReporter(logger, metrics),
			)
			return err
		})
	default:
		err = errRejectedRecord
	}
	if err != nil || tracing == nil {
		return nil, errRejectedRecord
	}
	runtime := &Runtime{logger: logger, tracing: tracing, metrics: metrics}
	exporter := valueNone
	if settings.Tracing().Exporter() == config.TracingOTLPHTTP {
		exporter = "otlp_http"
	}
	runtime.Logger().Info(
		"config.accepted",
		slog.String("operation", "config"),
		slog.String("result", valueSuccess),
		slog.String("tracing_exporter", exporter),
	)
	runtime.logLifecycle("starting")
	return runtime, nil
}

// loggerTraceReporter projects only closed exporter failure classes.
func loggerTraceReporter(logger *Logger, metrics *Metrics) traceDropReporter {
	return func(reason, errorClass string) {
		if metrics != nil {
			metrics.ObservationDropped("trace", reason)
		}
		if logger == nil || reason == valueOverflow {
			return
		}
		if !slices.Contains(
			[]string{valueTimeout, valueTransport, "tls", "encoding", "shutdown", valueInternal},
			errorClass,
		) {
			errorClass = valueInternal
		}
		logger.Slog().Error(
			"telemetry.export.failed",
			slog.String("operation", "telemetry_export"),
			slog.String("result", valueInternal),
			slog.String("error_class", errorClass),
		)
	}
}

// Logger returns the central secret-safe slog facade.
func (r *Runtime) Logger() *slog.Logger {
	if r == nil || r.logger == nil {
		return slog.New(discardHandler{})
	}
	return r.logger.Slog()
}

// DebugEnabled reports whether one exact diagnostic module is enabled.
func (r *Runtime) DebugEnabled(module string) bool {
	return r != nil && r.logger != nil && r.logger.DebugEnabled(module)
}

// Metrics returns the instance-owned Prometheus registry facade.
func (r *Runtime) Metrics() *Metrics {
	if r == nil {
		return nil
	}
	return r.metrics
}

// ObserveDSNEvidence emits one closed terminal pre-policy evidence outcome.
func (r *Runtime) ObserveDSNEvidence(stage, result string) {
	if r == nil || r.metrics == nil || !closedMetricValue(keyEvidenceStage, stage) ||
		!closedMetricValue(keyResult, result) {
		return
	}
	r.metrics.DSNEvidenceCompleted(stage, result)
	r.Logger().Info(
		"dsn.evidence.completed",
		slog.String("operation", valueDSNSign),
		slog.String(keyEvidenceStage, stage),
		slog.String(keyResult, result),
	)
}

// Tracing returns the instance-owned OpenTelemetry facade.
func (r *Runtime) Tracing() *TraceRuntime {
	if r == nil {
		return nil
	}
	return r.tracing
}

// SetReady publishes one monotone readiness metric transition.
func (r *Runtime) SetReady(ready bool) {
	if r == nil || r.metrics == nil {
		return
	}
	r.readinessMu.Lock()
	defer r.readinessMu.Unlock()
	if ready {
		if !r.readiness.CompareAndSwap(0, 1) {
			return
		}
	} else if r.readiness.Swap(2) == 2 {
		return
	}
	r.metrics.SetReady(ready)
	r.Logger().Info(
		"readiness.transition",
		slog.String("operation", "readiness"),
		slog.String("result", valueSuccess),
		slog.Bool("ready", ready),
	)
	if ready {
		r.logLifecycle("active")
	} else {
		r.logLifecycle("stopping")
	}
}

// logLifecycle emits one closed instance lifecycle transition.
func (r *Runtime) logLifecycle(state string) {
	if r == nil {
		return
	}
	r.Logger().Info(
		"lifecycle.transition",
		slog.String("operation", "lifecycle"),
		slog.String("result", valueSuccess),
		slog.String("lifecycle_state", state),
	)
}

// Observe projects one validated library event into daemon-owned telemetry.
func (r *Runtime) Observe(ctx context.Context, event dkim2.ObservationEvent) {
	if r == nil || ctx == nil || !event.Valid() {
		if r != nil && r.metrics != nil {
			r.metrics.ObservationDropped("metric", "invalid")
		}
		return
	}
	switch event.Kind() {
	case dkim2.ObservationDNSLookupCompleted:
		r.observeDNS(ctx, event)
	case dkim2.ObservationVerifyCompleted:
		r.observeVerification(ctx, event)
	default:
		r.metrics.ObservationDropped("metric", "invalid")
	}
}

// observeDNS projects one closed DNS event without retaining query identity.
func (r *Runtime) observeDNS(ctx context.Context, event dkim2.ObservationEvent) {
	result := observationDNSResult(event.Result())
	cache := observationCacheResult(event.CacheResult())
	duration := observationDuration(event.DurationBucket())
	r.metrics.DNSCompleted(result, cache, duration)
	resultFact, _ := TextSpanFact("dkim2.result", observationResult(event.Result()))
	_, span := r.tracing.StartChild(ctx, "dkim2.dns.lookup", resultFact)
	outcome := SpanCompleted
	if event.Result() == dkim2.ObservationResultInternal {
		outcome = SpanInternalError
	}
	EndSpan(span, outcome)
	if r.DebugEnabled("dns") {
		r.Logger().Debug(
			"dns.lookup.completed",
			slog.String("operation", "dns_lookup"),
			slog.String("result", observationResult(event.Result())),
			slog.String("dns_result", result),
			slog.String("cache_result", cache),
		)
	}
}

// observeVerification records one authentic applicable verification and emits
// optional bounded message-shape diagnostics.
func (r *Runtime) observeVerification(ctx context.Context, event dkim2.ObservationEvent) {
	result := observationResult(event.Result())
	resultFact, _ := TextSpanFact("dkim2.result", result)
	_, span := r.tracing.StartChild(ctx, "dkim2.verify", resultFact)
	outcome := SpanCompleted
	if event.Result() == dkim2.ObservationResultInternal {
		outcome = SpanInternalError
	}
	EndSpan(span, outcome)
	if !r.DebugEnabled("message_shape") {
		return
	}
	r.Logger().Debug(
		"process.completed",
		slog.String("operation", "verify"),
		slog.String("result", result),
		slog.String("verdict", "neutral"),
		slog.String("message_size_bucket", observationMessageBucket(event.MessageSizeBucket())),
		slog.String("recipient_count_bucket", observationRecipientBucket(event.RecipientCountBucket())),
		slog.String("signature_count_bucket", observationCountBucket(event.SignatureCountBucket())),
		slog.String("chain_length_bucket", observationCountBucket(event.ChainLengthBucket())),
	)
}

// observationResult maps one library result into the daemon grammar.
func observationResult(value dkim2.ObservationResult) string {
	switch value {
	case dkim2.ObservationResultSuccess:
		return valueSuccess
	case dkim2.ObservationResultFailure:
		return valueFailure
	case dkim2.ObservationResultTemporary:
		return valueTemporary
	default:
		return valueInternal
	}
}

// observationDNSResult maps one library result into the DNS label grammar.
func observationDNSResult(value dkim2.ObservationResult) string {
	switch value {
	case dkim2.ObservationResultSuccess:
		return valueFound
	case dkim2.ObservationResultTemporary:
		return valueTemporary
	case dkim2.ObservationResultInternal:
		return valueInternal
	default:
		return valueInvalid
	}
}

// observationCacheResult maps one library cache fact into the daemon grammar.
func observationCacheResult(value dkim2.ObservationCacheResult) string {
	switch value {
	case dkim2.ObservationCacheHit:
		return valueHit
	case dkim2.ObservationCacheMiss:
		return valueMiss
	default:
		return valueNotUsed
	}
}

// observationDuration supplies one bounded representative for histogram projection.
func observationDuration(value dkim2.ObservationBucket) time.Duration {
	switch value {
	case dkim2.ObservationBucketSmall:
		return time.Millisecond
	case dkim2.ObservationBucketMedium:
		return 100 * time.Millisecond
	case dkim2.ObservationBucketLarge:
		return 5 * time.Second
	case dkim2.ObservationBucketOverflow:
		return 60 * time.Second
	default:
		return 0
	}
}

// observationMessageBucket maps one coarse library class into a closed log bucket.
func observationMessageBucket(value dkim2.ObservationBucket) string {
	switch value {
	case dkim2.ObservationBucketSmall:
		return "lt_1k"
	case dkim2.ObservationBucketMedium:
		return "lt_1m"
	case dkim2.ObservationBucketLarge:
		return "lt_10m"
	default:
		return "gte_10m"
	}
}

// observationRecipientBucket maps one coarse library class into a closed log bucket.
func observationRecipientBucket(value dkim2.ObservationBucket) string {
	switch value {
	case dkim2.ObservationBucketNone:
		return "0"
	case dkim2.ObservationBucketSmall:
		return "1"
	case dkim2.ObservationBucketMedium:
		return "2_10"
	case dkim2.ObservationBucketLarge:
		return "11_100"
	default:
		return "gte_1001"
	}
}

// observationCountBucket maps one coarse count class into a closed log bucket.
func observationCountBucket(value dkim2.ObservationBucket) string {
	switch value {
	case dkim2.ObservationBucketNone:
		return "0"
	case dkim2.ObservationBucketSmall:
		return "1"
	case dkim2.ObservationBucketMedium:
		return "2_4"
	case dkim2.ObservationBucketLarge:
		return "5_8"
	default:
		return valueGTE9
	}
}

// Shutdown flushes telemetry exactly once within the tracer's fixed budget.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nil
	}
	r.shutdownOnce.Do(func() {
		if r.tracing != nil {
			r.shutdownErr = r.tracing.Shutdown(ctx)
		}
		if r.shutdownErr == nil {
			r.logLifecycle("stopped")
		} else {
			r.Logger().Error(
				"telemetry.export.failed",
				slog.String("operation", "telemetry_export"),
				slog.String("result", valueInternal),
				slog.String("error_class", "shutdown"),
			)
		}
	})
	return r.shutdownErr
}
