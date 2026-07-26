package observability

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// FuzzSlogAdmission proves arbitrary keys and values cannot escape the bounded handler.
func FuzzSlogAdmission(f *testing.F) {
	f.Add("result", "success")
	f.Add("private-key", "private-marker")
	f.Fuzz(func(f *testing.T, key, value string) {
		var output bytes.Buffer
		handler := &boundedJSONHandler{
			destination: &output,
			level:       slog.LevelDebug,
			mu:          &sync.Mutex{},
		}
		record := slog.NewRecord(time.Unix(1, 0), slog.LevelInfo, "process.completed", 0)
		record.AddAttrs(slog.String(key, value))
		_ = handler.Handle(context.Background(), record)
		if output.Len() > maxLogRecordBytes {
			f.Fatal("log handler exceeded its record cap")
		}
	})
}

// FuzzMetricLabels proves arbitrary labels cannot create unbounded series.
func FuzzMetricLabels(f *testing.F) {
	f.Add("process", valueStatus2XX)
	f.Add("private-marker", "private-marker")
	f.Fuzz(func(f *testing.T, first, second string) {
		metrics, err := NewMetrics()
		if err != nil {
			f.Fatal("metrics construction failed")
		}
		metrics.HTTPStarted(first)
		metrics.HTTPCompleted(first, second, time.Millisecond)
		metrics.ProcessCompleted(first, second, first, second, time.Millisecond)
		metrics.PolicyCompleted(first, second, first)
		metrics.DNSCompleted(first, second, time.Millisecond)
		metrics.ReplayCompleted(first, second, time.Millisecond)
		metrics.ObservationDropped(first, second)
		output, gatherErr := metrics.Gather()
		if gatherErr != nil || len(output) > maxMetricsBytes {
			f.Fatal("bounded metrics gathering failed")
		}
	})
}

// FuzzOTLPProjection proves arbitrary attributes cannot enter span projection.
func FuzzOTLPProjection(f *testing.F) {
	f.Add("dkim2.result", "success", 200)
	f.Add("private-marker", "private-marker", -1)
	f.Fuzz(func(f *testing.T, key, value string, status int) {
		facts := make([]SpanFact, 0, 2)
		if fact, ok := TextSpanFact(key, value); ok {
			facts = append(facts, fact)
		}
		if fact, ok := HTTPStatusSpanFact(status); ok {
			facts = append(facts, fact)
		}
		if attributes, ok := spanAttributes(facts); !ok || len(attributes) > 2 {
			f.Fatal("span projection exceeded its bounded input")
		}
	})
}
