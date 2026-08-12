// Package observability owns the Exim adapter's bounded local telemetry runtime.
//
//nolint:goconst,staticcheck // Closed telemetry vocabulary remains explicit at each authority boundary.
package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

var errTelemetry = errors.New("exim observability failure")

// Event contains only the closed low-cardinality telemetry vocabulary.
type Event struct {
	Hook      string
	Operation string
	Result    string
	Failure   string
	Admission string
	Ready     bool
	FailOpen  bool
}

// Runtime owns a JSON logger, fresh registry, optional metrics listener, and readiness state.
type Runtime struct {
	logger       *slog.Logger
	registry     *prometheus.Registry
	readiness    prometheus.Gauge
	events       *prometheus.CounterVec
	server       *http.Server
	listener     net.Listener
	queue        chan logRequest
	drainDone    chan struct{}
	terminalDone chan struct{}
	endpoint     string
	output       io.Writer
	mu           sync.Mutex
	started      bool
	ready        bool
	stopped      bool
	terminal     bool
}

// New creates one isolated telemetry runtime from safe validated configuration.
func New(snapshot config.Snapshot, output io.Writer) (*Runtime, error) {
	level, destination := snapshot.Logging()
	if destination == "none" {
		output = io.Discard
	}
	if output == nil || destination != "stderr" && destination != "none" {
		return nil, errTelemetry
	}
	parsed, err := parseLevel(level)
	if err != nil {
		return nil, errTelemetry
	}
	registry := prometheus.NewRegistry()
	readiness := prometheus.NewGauge(prometheus.GaugeOpts{Name: "dkim2_exim_readiness", Help: "Whether the Exim adapter may admit new work."})
	events := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dkim2_exim_events_total", Help: "Closed Exim adapter outcomes."}, []string{"hook", "operation", "result", "failure", "admission", "fail_open"})
	if registry.Register(readiness) != nil || registry.Register(events) != nil {
		return nil, errTelemetry
	}
	queue := make(chan logRequest, 64)
	drainDone := make(chan struct{})
	return &Runtime{logger: slog.New(&handler{queue: queue, level: parsed}), registry: registry, readiness: readiness, events: events, queue: queue, drainDone: drainDone, terminalDone: make(chan struct{}), endpoint: snapshot.MetricsEndpoint(), output: output}, nil
}

// StartMetrics starts the optional loopback metrics listener after service resources are quiescent.
func (r *Runtime) StartMetrics(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return errTelemetry
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.terminal || r.started {
		return errTelemetry
	}
	r.started = true
	go drain(r.output, r.queue, r.drainDone)
	if r.endpoint == "" {
		return nil
	}
	listener, err := net.Listen("tcp", r.endpoint)
	if err != nil {
		return errTelemetry
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", r.metrics)
	r.listener = listener
	r.server = &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second}
	server := r.server
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.failTerminal()
		}
	}()
	return nil
}

// SetReady publishes or withdraws process readiness through the sole registry owner.
func (r *Runtime) SetReady(value bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.terminal || value && !r.started || !value && !r.ready {
		return
	}
	r.ready = value
	if value {
		r.readiness.Set(1)
	} else {
		r.readiness.Set(0)
	}
}

// Terminal reports an unexpected owned observability runtime failure.
func (r *Runtime) Terminal() <-chan struct{} {
	if r == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return r.terminalDone
}

// Record emits one validated low-cardinality event without accepting arbitrary attributes.
func (r *Runtime) Record(event Event) {
	if r == nil || !validEvent(event) {
		return
	}
	defer func() { _ = recover() }()
	r.mu.Lock()
	if !r.started || r.stopped || r.terminal {
		r.mu.Unlock()
		return
	}
	event.Ready = r.ready && !r.stopped && !r.terminal
	r.mu.Unlock()
	r.events.WithLabelValues(event.Hook, event.Operation, event.Result, event.Failure, event.Admission, boolText(event.FailOpen)).Inc()
	r.logger.Log(context.Background(), slog.LevelInfo, "exim_adapter", slog.String("hook", event.Hook), slog.String("operation", event.Operation), slog.String("result", event.Result), slog.String("failure", event.Failure), slog.String("admission", event.Admission), slog.Bool("ready", event.Ready), slog.Bool("fail_open", event.FailOpen))
}

// RecordFailOpen records the mandatory operator warning before a fail-open response.
func (r *Runtime) RecordFailOpen() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.RecordFailOpenContext(ctx)
}

// RecordFailOpenContext records the mandatory warning within the mail decision deadline.
func (r *Runtime) RecordFailOpenContext(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return errTelemetry
	}
	event := Event{Hook: "local_scan", Operation: "process", Result: "success", Failure: "unavailable", Admission: "accepted", FailOpen: true}
	if !validEvent(event) {
		return errTelemetry
	}
	r.mu.Lock()
	stopped := r.stopped || r.terminal
	started := r.started
	ready := r.ready
	r.mu.Unlock()
	if stopped || !started {
		return errTelemetry
	}
	encoded, err := json.Marshal(logEntry{Level: "WARN", Event: "exim_adapter", Hook: event.Hook, Operation: event.Operation, Result: event.Result, Failure: event.Failure, Admission: event.Admission, Ready: ready, FailOpen: true})
	if err != nil {
		return errTelemetry
	}
	encoded = append(encoded, '\n')
	acknowledged := make(chan error, 1)
	if !enqueue(r.queue, logRequest{data: encoded, acknowledged: acknowledged}) {
		clear(encoded)
		return errTelemetry
	}
	select {
	case writeErr := <-acknowledged:
		if writeErr != nil {
			return errTelemetry
		}
		return nil
	case <-ctx.Done():
		return errTelemetry
	}
}

// RecordFailOpenStartup emits the mandatory warning before fail-open readiness.
func (r *Runtime) RecordFailOpenStartup(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return errTelemetry
	}
	r.mu.Lock()
	stopped := r.stopped || r.terminal || !r.started
	r.mu.Unlock()
	if stopped {
		return errTelemetry
	}
	encoded, err := json.Marshal(logEntry{
		Level: "WARN", Event: "exim_configuration", Hook: "startup",
		Operation: "process", Result: "success", Failure: "none",
		Admission: "accepted", FailOpen: true,
	})
	if err != nil {
		return errTelemetry
	}
	encoded = append(encoded, '\n')
	acknowledged := make(chan error, 1)
	if !enqueue(r.queue, logRequest{data: encoded, acknowledged: acknowledged}) {
		clear(encoded)
		return errTelemetry
	}
	select {
	case writeErr := <-acknowledged:
		if writeErr != nil {
			return errTelemetry
		}
		return nil
	case <-ctx.Done():
		return errTelemetry
	}
}

// Stop terminally withdraws readiness and releases optional metrics resources.
func (r *Runtime) Stop(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errTelemetry
	}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return nil
	}
	r.stopped = true
	r.ready = false
	r.readiness.Set(0)
	server := r.server
	listener := r.listener
	started := r.started
	r.mu.Unlock()
	failed := false
	if server != nil && server.Shutdown(ctx) != nil {
		failed = true
	}
	if listener != nil {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			failed = true
		}
	}
	if !started {
		return nil
	}
	close(r.queue)
	select {
	case <-r.drainDone:
	case <-ctx.Done():
		return errTelemetry
	}
	if failed {
		return errTelemetry
	}
	return nil
}

// failTerminal withdraws readiness permanently after an owned metrics failure.
func (r *Runtime) failTerminal() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminal {
		return
	}
	r.terminal = true
	r.ready = false
	r.readiness.Set(0)
	close(r.terminalDone)
}

// metrics writes deterministic bounded Prometheus output without creating a global handler.
func (r *Runtime) metrics(writer http.ResponseWriter, request *http.Request) {
	if r == nil || request.Method != http.MethodGet {
		http.NotFound(writer, request)
		return
	}
	families, err := r.registry.Gather()
	if err != nil {
		http.Error(writer, "", http.StatusServiceUnavailable)
		return
	}
	var output bytes.Buffer
	for _, family := range families {
		if _, err := expfmt.MetricFamilyToText(&output, family); err != nil || output.Len() > 256<<10 {
			http.Error(writer, "", http.StatusServiceUnavailable)
			return
		}
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = writer.Write(output.Bytes())
}

// handler admits only the exact attributes emitted by Record.
type handler struct {
	queue chan<- logRequest
	level slog.Level
}

// Enabled applies the configured bounded severity threshold.
func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return h != nil && level >= h.level
}

// Handle serializes only records from the closed adapter vocabulary.
func (h *handler) Handle(_ context.Context, record slog.Record) error {
	if h == nil || h.queue == nil || record.Message != "exim_adapter" {
		return errTelemetry
	}
	fields := map[string]any{}
	record.Attrs(func(attribute slog.Attr) bool {
		if _, duplicate := fields[attribute.Key]; duplicate {
			fields = nil
			return false
		}
		switch attribute.Key {
		case "hook", "operation", "result", "failure", "admission":
			if attribute.Value.Kind() != slog.KindString {
				fields = nil
				return false
			}
			fields[attribute.Key] = attribute.Value.String()
		case "ready", "fail_open":
			if attribute.Value.Kind() != slog.KindBool {
				fields = nil
				return false
			}
			fields[attribute.Key] = attribute.Value.Bool()
		default:
			fields = nil
			return false
		}
		return true
	})
	if fields == nil {
		return errTelemetry
	}
	entry := logEntry{Level: "INFO", Event: "exim_adapter", Hook: fields["hook"].(string), Operation: fields["operation"].(string), Result: fields["result"].(string), Failure: fields["failure"].(string), Admission: fields["admission"].(string), Ready: fields["ready"].(bool), FailOpen: fields["fail_open"].(bool)}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return errTelemetry
	}
	encoded = append(encoded, '\n')
	select {
	case h.queue <- logRequest{data: encoded}:
	default:
	}
	return nil
}

// logEntry is the only serialized telemetry shape.
type logEntry struct {
	Level     string `json:"level"`
	Event     string `json:"event"`
	Hook      string `json:"hook"`
	Operation string `json:"operation"`
	Result    string `json:"result"`
	Failure   string `json:"failure"`
	Admission string `json:"admission"`
	Ready     bool   `json:"ready"`
	FailOpen  bool   `json:"fail_open"`
}

// logRequest optionally acknowledges one mandatory sink write.
type logRequest struct {
	data         []byte
	acknowledged chan<- error
}

// drain contains sink blocking and panic outside mail-decision call paths.
func drain(output io.Writer, queue <-chan logRequest, done chan<- struct{}) {
	defer close(done)
	for request := range queue {
		writeErr := writeRecord(output, request.data)
		if request.acknowledged != nil {
			request.acknowledged <- writeErr
		}
	}
}

// enqueue contains a racing shutdown channel close without reporting false success.
func enqueue(queue chan<- logRequest, request logRequest) (accepted bool) {
	defer func() {
		if recover() != nil {
			accepted = false
		}
	}()
	select {
	case queue <- request:
		return true
	default:
		return false
	}
}

// writeRecord requires the complete bounded record to reach its sink.
func writeRecord(output io.Writer, value []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = errTelemetry
		}
	}()
	count, writeErr := output.Write(value)
	if writeErr != nil || count != len(value) {
		return errTelemetry
	}
	return nil
}

// WithAttrs rejects ambient attributes so callers cannot enrich telemetry with mail data.
func (h *handler) WithAttrs([]slog.Attr) slog.Handler { return discardHandler{} }

// WithGroup rejects ambient groups so callers cannot enrich telemetry with mail data.
func (h *handler) WithGroup(string) slog.Handler { return discardHandler{} }

// discardHandler contains rejected logger paths without affecting mail decisions.
type discardHandler struct{}

// Enabled suppresses all discarded records.
func (discardHandler) Enabled(context.Context, slog.Level) bool { return false }

// Handle silently contains rejected records.
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }

// WithAttrs keeps rejected records discarded.
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler { return discardHandler{} }

// WithGroup keeps rejected records discarded.
func (discardHandler) WithGroup(string) slog.Handler { return discardHandler{} }

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
	}
	return 0, errTelemetry
}

// validEvent rejects every raw or high-cardinality telemetry value.
func validEvent(event Event) bool {
	if event.Hook == "local_scan" && event.Operation != "process" ||
		event.Hook == "transport_filter" && event.Operation != "sign" && event.Operation != "revise" ||
		!oneOf(event.Hook, "local_scan", "transport_filter") ||
		!oneOf(event.Result, "success", "failure", "temporary") ||
		!oneOf(event.Failure, "none", "capacity", "contract", "fidelity", "internal", "timeout", "unavailable") ||
		!oneOf(event.Admission, "accepted", "connection_limit", "message_limit", "byte_limit", "stopping") {
		return false
	}
	return !event.FailOpen || event.Hook == "local_scan" && event.Operation == "process" && event.Result == "success" && event.Failure == "unavailable" && event.Admission == "accepted"
}

// oneOf checks one bounded vocabulary.
func oneOf(value string, accepted ...string) bool {
	return slices.Contains(accepted, value)
}

// boolText returns one stable metric label.
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
