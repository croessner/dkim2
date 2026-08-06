package observability

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

// TestBoundedLoggerEmitsExactJSON proves deterministic keys and no source field.
func TestBoundedLoggerEmitsExactJSON(t *testing.T) {
	var output bytes.Buffer
	handler := &boundedJSONHandler{destination: &output, level: slog.LevelInfo, mu: &sync.Mutex{}}
	record := slog.NewRecord(time.Date(2026, 7, 26, 12, 0, 0, 123, time.FixedZone("x", 3600)), slog.LevelInfo, "config.accepted", 0)
	record.AddAttrs(
		slog.String("operation", "config"),
		slog.String("result", "success"),
		slog.String("tracing_exporter", "none"),
	)
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatal("valid record rejected")
	}
	expected := "{\"time\":\"2026-07-26T11:00:00.000000123Z\",\"level\":\"INFO\",\"msg\":\"config.accepted\",\"event_id\":\"config.accepted\",\"operation\":\"config\",\"result\":\"success\",\"tracing_exporter\":\"none\"}\n"
	if output.String() != expected || strings.Contains(output.String(), "source") {
		t.Fatal("bounded JSON representation changed")
	}
}

// TestBoundedLoggerAcceptsDSNSigningRoute freezes the dedicated delivery-status
// HTTP observation vocabulary.
func TestBoundedLoggerAcceptsDSNSigningRoute(t *testing.T) {
	var output bytes.Buffer
	handler := &boundedJSONHandler{destination: &output, level: slog.LevelInfo, mu: &sync.Mutex{}}
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "http.request.completed", 0)
	record.AddAttrs(
		slog.String("operation", valueDSNSign),
		slog.String("route", "/v1/dsn/sign"),
		slog.String("result", valueSuccess),
	)
	if err := handler.Handle(context.Background(), record); err != nil || output.Len() == 0 {
		t.Fatal("delivery-status HTTP observation was rejected")
	}
}

type hostileLogValuer struct{}

// LogValue injects a panic that admission must not evaluate.
func (hostileLogValuer) LogValue() slog.Value { panic("private-marker") }

// TestBoundedLoggerRejectsUnknownAndHostileValues proves arbitrary values never reach encoding.
func TestBoundedLoggerRejectsUnknownAndHostileValues(t *testing.T) {
	for _, attribute := range []slog.Attr{
		slog.String("unknown", "value"),
		slog.Any("result", hostileLogValuer{}),
		slog.Any("result", []byte("private-marker")),
		slog.Any("result", context.Canceled),
		slog.Group("result", slog.String("nested", "success")),
		slog.String("route", "/private/path"),
	} {
		var output bytes.Buffer
		handler := &boundedJSONHandler{destination: &output, level: slog.LevelDebug, mu: &sync.Mutex{}}
		record := slog.NewRecord(time.Now(), slog.LevelInfo, "process.completed", 0)
		record.AddAttrs(attribute)
		if err := handler.Handle(context.Background(), record); err == nil || output.Len() != 0 {
			t.Fatal("hostile or unknown value escaped admission")
		}
	}
}

// TestBoundedLoggerRejectsNoncanonicalLevels proves level text cannot widen the grammar.
func TestBoundedLoggerRejectsNoncanonicalLevels(t *testing.T) {
	var output bytes.Buffer
	handler := &boundedJSONHandler{
		destination: &output,
		level:       slog.LevelDebug,
		mu:          &sync.Mutex{},
	}
	record := slog.NewRecord(
		time.Now(),
		slog.Level(100),
		"lifecycle.transition",
		0,
	)
	record.AddAttrs(
		slog.String("operation", "lifecycle"),
		slog.String("lifecycle_state", "active"),
	)
	if err := handler.Handle(context.Background(), record); err == nil ||
		output.Len() != 0 {
		t.Fatal("noncanonical slog level escaped admission")
	}
}

type shortLogWriter struct{}

// Write simulates a destination that accepts only a strict prefix.
func (shortLogWriter) Write(value []byte) (int, error) {
	return max(0, len(value)-1), nil
}

// TestBoundedLoggerClassifiesShortWritesAsExportDrops proves destination defects stay bounded.
func TestBoundedLoggerClassifiesShortWritesAsExportDrops(t *testing.T) {
	var reasons []string
	handler := &boundedJSONHandler{
		destination: shortLogWriter{},
		level:       slog.LevelDebug,
		mu:          &sync.Mutex{},
		onDrop: func(reason string) {
			reasons = append(reasons, reason)
		},
	}
	record := slog.NewRecord(
		time.Now(),
		slog.LevelInfo,
		"lifecycle.transition",
		0,
	)
	record.AddAttrs(
		slog.String("operation", "lifecycle"),
		slog.String("lifecycle_state", "active"),
	)
	if err := handler.Handle(context.Background(), record); !errors.Is(err, errRejectedRecord) {
		t.Fatalf("short write error = %v, want bounded rejection", err)
	}
	if len(reasons) != 1 || reasons[0] != valueExport {
		t.Fatalf("drop reasons = %v, want export", reasons)
	}
}

// TestBoundedLoggerSerializesConcurrentWrites proves records cannot interleave.
func TestBoundedLoggerSerializesConcurrentWrites(t *testing.T) {
	var output lockedBuffer
	handler := &boundedJSONHandler{destination: &output, level: slog.LevelDebug, mu: &sync.Mutex{}}
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			record := slog.NewRecord(time.Now(), slog.LevelInfo, "lifecycle.transition", 0)
			record.AddAttrs(slog.String("operation", "lifecycle"), slog.String("lifecycle_state", "active"))
			if err := handler.Handle(context.Background(), record); err != nil {
				t.Error("concurrent record rejected")
			}
		}()
	}
	workers.Wait()
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 32 {
		t.Fatal("concurrent records interleaved or disappeared")
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

// Write appends one complete test record.
func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

// Bytes returns one independent output snapshot.
func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

// TestLoggerDoesNotMutateGlobal proves construction has no global slog side effect.
func TestLoggerDoesNotMutateGlobal(t *testing.T) {
	before := slog.Default()
	snapshot, err := config.Load([]byte(testObservabilityConfig), config.FlagValues{})
	if err != nil {
		t.Fatal("test config rejected")
	}
	logger, err := NewLogger(snapshot.Observability(), &bytes.Buffer{})
	if err != nil || logger == nil || slog.Default() != before {
		t.Fatal("logger construction changed global state")
	}
}

const testObservabilityConfig = `config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /secure/0123456789abcdef0123456789abcdef/capability
replay:
  backend: disabled
`
