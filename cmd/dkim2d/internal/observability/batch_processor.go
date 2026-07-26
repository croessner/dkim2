package observability

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	traceQueueSize  = 2_048
	traceBatchSize  = 256
	traceBatchDelay = time.Second
)

type traceDropReporter func(reason, errorClass string)

type traceFlushRequest struct {
	ctx  context.Context
	done chan error
}

// boundedBatchProcessor exports sampled spans without using OTel global error state.
type boundedBatchProcessor struct {
	exporter     sdktrace.SpanExporter
	queue        chan sdktrace.ReadOnlySpan
	flush        chan traceFlushRequest
	stop         chan traceFlushRequest
	done         chan struct{}
	batchSize    int
	delay        time.Duration
	exportLimit  time.Duration
	report       traceDropReporter
	stopped      atomic.Bool
	shutdownOnce sync.Once
	shutdownErr  error
}

// newBoundedBatchProcessor starts one instance-owned nonblocking export queue.
func newBoundedBatchProcessor(
	exporter sdktrace.SpanExporter,
	queueSize int,
	batchSize int,
	delay time.Duration,
	exportLimit time.Duration,
	report traceDropReporter,
) (*boundedBatchProcessor, error) {
	if exporter == nil || queueSize <= 0 || batchSize <= 0 ||
		batchSize > queueSize || delay <= 0 || exportLimit <= 0 {
		return nil, errRejectedRecord
	}
	processor := &boundedBatchProcessor{
		exporter:    exporter,
		queue:       make(chan sdktrace.ReadOnlySpan, queueSize),
		flush:       make(chan traceFlushRequest),
		stop:        make(chan traceFlushRequest),
		done:        make(chan struct{}),
		batchSize:   batchSize,
		delay:       delay,
		exportLimit: exportLimit,
		report:      report,
	}
	go processor.run()
	return processor, nil
}

// OnStart intentionally records no mutable per-span state.
func (*boundedBatchProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

// OnEnd queues one sampled span without blocking protocol work.
func (p *boundedBatchProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	if p == nil || span == nil || p.stopped.Load() ||
		!span.SpanContext().IsSampled() {
		return
	}
	select {
	case p.queue <- span:
	default:
		notifyTraceDrop(p.report, valueOverflow, valueNone)
	}
}

// ForceFlush exports all spans accepted before the request.
func (p *boundedBatchProcessor) ForceFlush(ctx context.Context) error {
	if p == nil || ctx == nil || p.stopped.Load() {
		return nil
	}
	request := traceFlushRequest{ctx: ctx, done: make(chan error, 1)}
	select {
	case p.flush <- request:
	case <-ctx.Done():
		return errRejectedRecord
	case <-p.done:
		return nil
	}
	select {
	case err := <-request.done:
		return err
	case <-ctx.Done():
		return errRejectedRecord
	case <-p.done:
		return nil
	}
}

// Shutdown drains accepted spans and stops the exporter exactly once.
func (p *boundedBatchProcessor) Shutdown(ctx context.Context) error {
	if p == nil || ctx == nil {
		return nil
	}
	p.shutdownOnce.Do(func() {
		p.stopped.Store(true)
		request := traceFlushRequest{ctx: ctx, done: make(chan error, 1)}
		select {
		case p.stop <- request:
		case <-ctx.Done():
			p.shutdownErr = errRejectedRecord
			notifyTraceDrop(p.report, valueExport, "shutdown")
			return
		}
		select {
		case err := <-request.done:
			if err != nil {
				p.shutdownErr = errRejectedRecord
			}
		case <-ctx.Done():
			p.shutdownErr = errRejectedRecord
			notifyTraceDrop(p.report, valueExport, "shutdown")
			return
		}
		if p.shutdownErr == nil &&
			containedExporterShutdown(ctx, p.exporter) != nil {
			p.shutdownErr = errRejectedRecord
			notifyTraceDrop(p.report, valueExport, "shutdown")
		}
	})
	return p.shutdownErr
}

// run owns batching, timer state, and every exporter call.
func (p *boundedBatchProcessor) run() {
	defer close(p.done)
	timer := time.NewTimer(p.delay)
	defer timer.Stop()
	batch := make([]sdktrace.ReadOnlySpan, 0, p.batchSize)
	export := func(parent context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		spans := append([]sdktrace.ReadOnlySpan(nil), batch...)
		clear(batch)
		batch = batch[:0]
		return p.export(parent, spans)
	}
	for {
		select {
		case span := <-p.queue:
			batch = append(batch, span)
			if len(batch) == p.batchSize {
				_ = export(context.Background())
				resetTraceTimer(timer, p.delay)
			}
		case request := <-p.flush:
			p.drain(request.ctx, &batch)
			request.done <- export(request.ctx)
		case <-timer.C:
			_ = export(context.Background())
			timer.Reset(p.delay)
		case request := <-p.stop:
			p.drain(request.ctx, &batch)
			request.done <- export(request.ctx)
			return
		}
	}
}

// drain moves every currently accepted span into bounded export batches.
func (p *boundedBatchProcessor) drain(
	parent context.Context,
	batch *[]sdktrace.ReadOnlySpan,
) {
	for {
		select {
		case span := <-p.queue:
			*batch = append(*batch, span)
			if len(*batch) == p.batchSize {
				spans := append([]sdktrace.ReadOnlySpan(nil), (*batch)...)
				clear(*batch)
				*batch = (*batch)[:0]
				_ = p.export(parent, spans)
			}
		default:
			return
		}
	}
}

// export applies the fixed timeout and contains exporter errors and panics.
func (p *boundedBatchProcessor) export(
	parent context.Context,
	spans []sdktrace.ReadOnlySpan,
) (resultErr error) {
	if len(spans) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, p.exportLimit)
	defer cancel()
	defer func() {
		if recover() != nil {
			notifyTraceDrop(p.report, valuePanic, valueInternal)
			resultErr = nil
		}
	}()
	if err := p.exporter.ExportSpans(ctx, spans); err != nil {
		notifyTraceDrop(p.report, valueExport, classifyTraceExportError(ctx))
	}
	return nil
}

// containedExporterShutdown prevents exporter panics from crossing ownership.
func containedExporterShutdown(
	ctx context.Context,
	exporter sdktrace.SpanExporter,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRejectedRecord
		}
	}()
	return exporter.Shutdown(ctx)
}

// classifyTraceExportError reduces exporter failures without retaining errors.
func classifyTraceExportError(ctx context.Context) string {
	if ctx != nil && ctx.Err() != nil {
		return valueTimeout
	}
	return valueTransport
}

// notifyTraceDrop contains observation callback defects.
func notifyTraceDrop(reporter traceDropReporter, reason, errorClass string) {
	if reporter == nil {
		return
	}
	defer func() { _ = recover() }()
	reporter(reason, errorClass)
}

// resetTraceTimer safely restarts one worker-owned timer.
func resetTraceTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}
