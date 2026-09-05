package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureWriter records every admitted log record.
type captureWriter struct {
	mu    sync.Mutex
	lines []string
}

// Write records one complete admitted record.
func (w *captureWriter) Write(buffer []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, string(buffer))
	return len(buffer), nil
}

// records returns copies of every admitted record.
func (w *captureWriter) records() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.lines...)
}

// TestClosedEventAndAttributeGrammar proves only declared records are admitted.
func TestClosedEventAndAttributeGrammar(t *testing.T) {
	writer := &captureWriter{}
	handler := newBoundedJSONHandler(writer, slog.LevelDebug)
	admitted := slog.NewRecord(time.Now(), slog.LevelInfo, eventTransactionCompleted, 0)
	admitted.AddAttrs(
		slog.String(keyTransactionOutcome, OutcomeAccepted),
		slog.String(keyReply, ReplyAccepted),
		slog.String(keyOperation, "transaction"),
		slog.String(keyResultClass, valueSuccess),
	)
	if err := handler.Handle(context.Background(), admitted); err != nil {
		t.Fatalf("a declared record was refused: %v", err)
	}
	unknownEvent := slog.NewRecord(time.Now(), slog.LevelInfo, "mail.delivered", 0)
	if err := handler.Handle(context.Background(), unknownEvent); err == nil {
		t.Fatal("an undeclared event was admitted")
	}
	freeText := slog.NewRecord(time.Now(), slog.LevelInfo, eventTransactionCompleted, 0)
	freeText.AddAttrs(
		slog.String(keyTransactionOutcome, OutcomeAccepted),
		slog.String(keyReply, ReplyAccepted),
		slog.String(keyOperation, "transaction"),
		slog.String(keyResultClass, valueSuccess),
		slog.String("recipient", "victim@example.com"),
	)
	if err := handler.Handle(context.Background(), freeText); err == nil {
		t.Fatal("an undeclared attribute was admitted")
	}
	openValue := slog.NewRecord(time.Now(), slog.LevelInfo, eventTransactionCompleted, 0)
	openValue.AddAttrs(
		slog.String(keyTransactionOutcome, "mail.example"),
		slog.String(keyReply, ReplyAccepted),
		slog.String(keyOperation, "transaction"),
		slog.String(keyResultClass, valueSuccess),
	)
	if err := handler.Handle(context.Background(), openValue); err == nil {
		t.Fatal("an open outcome value was admitted")
	}
	if len(writer.records()) != 1 {
		t.Fatalf("records %v", writer.records())
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(writer.records()[0]), &document); err != nil {
		t.Fatal("the admitted record was not valid JSON")
	}
	if document["event_id"] != eventTransactionCompleted ||
		document[keyTransactionOutcome] != OutcomeAccepted {
		t.Fatalf("record shape drifted: %v", document)
	}
}

// TestGroupedLoggerFailsClosed proves derived group loggers cannot emit.
func TestGroupedLoggerFailsClosed(t *testing.T) {
	writer := &captureWriter{}
	handler := newBoundedJSONHandler(writer, slog.LevelDebug).WithGroup("mail")
	record := slog.NewRecord(time.Now(), slog.LevelInfo, eventCommitCompleted, 0)
	record.AddAttrs(
		slog.String(keyCommitOutcome, CommitCommitted),
		slog.String(keyOperation, "commit"),
		slog.String(keyResultClass, valueSuccess),
	)
	if err := handler.Handle(context.Background(), record); err == nil {
		t.Fatal("a grouped logger emitted a record")
	}
}

// TestRegistryClosedLabelSets proves only closed outcome values are counted.
func TestRegistryClosedLabelSets(t *testing.T) {
	registry := NewRegistry()
	registry.RecordTransaction(OutcomeAccepted)
	registry.RecordTransaction("victim@example.com")
	registry.RecordReinjection(ReinjectionDeferred)
	registry.RecordReinjection("mail.example")
	registry.RecordCommit(CommitCommitted)
	registry.RecordCommit("unknown")
	output, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	text := string(output)
	for _, expected := range []string{
		`dsn_propagator_transactions_total{outcome="accepted"} 1`,
		`dsn_propagator_reinjection_total{outcome="deferred"} 1`,
		`dsn_propagator_commit_total{outcome="committed"} 1`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %q", expected, text)
		}
	}
	for _, forbidden := range []string{"victim", "mail.example", "unknown"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("open label %q reached the registry", forbidden)
		}
	}
}

// TestMetricInventory freezes the exact adapter metric names.
func TestMetricInventory(t *testing.T) {
	registry := NewRegistry()
	registry.setReady(true)
	registry.recordLifecycle("active")
	registry.RecordTransaction(OutcomeDeferred)
	registry.RecordReinjection(ReinjectionFailed)
	registry.RecordCommit(CommitDeferred)
	output, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	text := string(output)
	for _, name := range []string{
		metricTransactions, metricReinjections, metricCommits,
		metricLifecycle, metricReadiness,
	} {
		if !strings.Contains(text, name) {
			t.Fatalf("metric %q is missing", name)
		}
	}
	for _, forbidden := range []string{"domain", "tenant", "recipient", "queue"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden label dimension %q exists", forbidden)
		}
	}
}
