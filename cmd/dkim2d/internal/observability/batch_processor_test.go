package observability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type controlledTraceExporter struct {
	started chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

// ExportSpans optionally blocks one batch and returns one hostile error.
func (e *controlledTraceExporter) ExportSpans(
	ctx context.Context,
	_ []sdktrace.ReadOnlySpan,
) error {
	e.once.Do(func() { close(e.started) })
	if e.release != nil {
		select {
		case <-e.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return e.err
}

// Shutdown performs no external work.
func (*controlledTraceExporter) Shutdown(context.Context) error { return nil }

// TestBoundedBatchProcessorCountsOverflowWithoutBlocking proves queue isolation.
func TestBoundedBatchProcessorCountsOverflowWithoutBlocking(t *testing.T) {
	exporter := &controlledTraceExporter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var mu sync.Mutex
	var reasons []string
	processor, err := newBoundedBatchProcessor(
		exporter,
		1,
		1,
		time.Hour,
		time.Second,
		func(reason, _ string) {
			mu.Lock()
			defer mu.Unlock()
			reasons = append(reasons, reason)
		},
	)
	if err != nil {
		t.Fatal("processor construction failed")
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(processor),
	)
	_, first := provider.Tracer("test").Start(context.Background(), "first")
	first.End()
	select {
	case <-exporter.started:
	case <-time.After(time.Second):
		t.Fatal("first export did not start")
	}
	for _, name := range []string{"queued", valueOverflow} {
		_, span := provider.Tracer("test").Start(context.Background(), name)
		span.End()
	}
	mu.Lock()
	got := append([]string(nil), reasons...)
	mu.Unlock()
	if len(got) != 1 || got[0] != valueOverflow {
		t.Fatalf("drop reasons = %v, want one overflow", got)
	}
	close(exporter.release)
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatal("processor shutdown failed")
	}
}

// TestBoundedBatchProcessorContainsRawExporterFailure proves errors stay classified.
func TestBoundedBatchProcessorContainsRawExporterFailure(t *testing.T) {
	exporter := &controlledTraceExporter{
		started: make(chan struct{}),
		err:     errors.New("private-endpoint-marker"),
	}
	var reason, errorClass string
	processor, err := newBoundedBatchProcessor(
		exporter,
		1,
		1,
		time.Hour,
		time.Second,
		func(gotReason, gotClass string) {
			reason, errorClass = gotReason, gotClass
		},
	)
	if err != nil {
		t.Fatal("processor construction failed")
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(processor),
	)
	_, span := provider.Tracer("test").Start(context.Background(), "failure")
	span.End()
	select {
	case <-exporter.started:
	case <-time.After(time.Second):
		t.Fatal("export did not start")
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatal("contained exporter error changed shutdown")
	}
	if reason != valueExport || errorClass != valueTransport {
		t.Fatalf("classification = %q/%q, want export/transport", reason, errorClass)
	}
}
