//nolint:goconst // Exact telemetry vocabulary is repeated for independent assertions.
package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/config"
)

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("sink") }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type blockingWriter struct {
	started chan struct{}
	release chan struct{}
}

// Write blocks until the test releases the non-authoritative sink.
func (w *blockingWriter) Write(value []byte) (int, error) {
	select {
	case w.started <- struct{}{}:
	default:
	}
	<-w.release
	return len(value), nil
}

const serviceConfig = `version: dkim2-exim-config-v1
inbound:
  socket: /run/dkim2-exim/service.sock
  peer_uid: 100
  allowed_build_ids:
    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
daemon:
  endpoint: http://127.0.0.1:8080
  process_capability_file: /run/dkim2-exim/process.cap
`

// TestRuntimeRejectsUnboundedTelemetry proves raw values cannot become labels or logs.
func TestRuntimeRejectsUnboundedTelemetry(t *testing.T) {
	snapshot, err := config.Decode([]byte(serviceConfig))
	if err != nil {
		t.Fatal("configuration fixture rejected")
	}
	var output bytes.Buffer
	runtime, err := New(snapshot, &output)
	if err != nil {
		t.Fatal("telemetry construction failed")
	}
	if err := runtime.StartMetrics(context.Background()); err != nil {
		t.Fatal("telemetry activation failed")
	}
	runtime.Record(Event{Hook: "local_scan", Operation: "process", Result: "success", Failure: "none", Admission: "accepted"})
	stop, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Stop(stop); err != nil {
		t.Fatal("telemetry stop failed")
	}
	if output.Len() == 0 {
		t.Fatal("closed event was not logged")
	}
	before := output.Len()
	runtime.Record(Event{Hook: "local_scan", Operation: "process", Result: "raw-recipient@example.test", Failure: "none", Admission: "accepted"})
	if output.Len() != before {
		t.Fatal("unbounded event value was logged")
	}
}

// TestRuntimeActivationAndMandatoryWarnings proves allocation-only startup and exact schemas.
func TestRuntimeActivationAndMandatoryWarnings(t *testing.T) {
	snapshot, err := config.Decode([]byte(serviceConfig))
	if err != nil {
		t.Fatal("configuration fixture rejected")
	}
	var output bytes.Buffer
	runtime, err := New(snapshot, &output)
	if err != nil {
		t.Fatal("telemetry construction failed")
	}
	runtime.Record(Event{Hook: "local_scan", Operation: "process", Result: "success", Failure: "none", Admission: "accepted"})
	if output.Len() != 0 {
		t.Fatal("allocation-only runtime emitted before activation")
	}
	if err := runtime.StartMetrics(context.Background()); err != nil {
		t.Fatal("telemetry activation failed")
	}
	if err := runtime.RecordFailOpenStartup(context.Background()); err != nil {
		t.Fatal("startup warning failed")
	}
	if err := runtime.RecordFailOpenContext(context.Background()); err != nil {
		t.Fatal("mail fail-open warning failed")
	}
	stop, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Stop(stop); err != nil {
		t.Fatal("telemetry stop failed")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatal("mandatory warning count drifted")
	}
	for _, line := range lines {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil || entry["level"] != "WARN" {
			t.Fatal("mandatory warning schema drifted")
		}
	}
}

// TestRuntimeRejectsReadinessAndCanceledActivationBeforeStart proves lifecycle ownership.
func TestRuntimeRejectsReadinessAndCanceledActivationBeforeStart(t *testing.T) {
	snapshot, err := config.Decode([]byte(serviceConfig))
	if err != nil {
		t.Fatal("configuration fixture rejected")
	}
	runtime, err := New(snapshot, io.Discard)
	if err != nil {
		t.Fatal("telemetry construction failed")
	}
	runtime.SetReady(true)
	runtime.mu.Lock()
	ready := runtime.ready
	runtime.mu.Unlock()
	if ready {
		t.Fatal("readiness was published before activation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.StartMetrics(ctx); !errors.Is(err, errTelemetry) {
		t.Fatal("canceled activation context was accepted")
	}
	runtime.mu.Lock()
	started := runtime.started
	runtime.mu.Unlock()
	if started {
		t.Fatal("canceled activation mutated lifecycle state")
	}
}

// TestMandatorySinkFailureAndPanicStayClosed proves fail-open cannot outrun its warning.
func TestMandatorySinkFailureAndPanicStayClosed(t *testing.T) {
	snapshot, err := config.Decode([]byte(serviceConfig))
	if err != nil {
		t.Fatal("configuration fixture rejected")
	}
	for _, writer := range []io.Writer{failingWriter{}, panicWriter{}} {
		runtime, err := New(snapshot, writer)
		if err != nil || runtime.StartMetrics(context.Background()) != nil {
			t.Fatal("telemetry fixture failed")
		}
		if err := runtime.RecordFailOpenContext(context.Background()); !errors.Is(err, errTelemetry) {
			t.Fatal("mandatory sink anomaly did not fail closed")
		}
		stop, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = runtime.Stop(stop)
		cancel()
	}
}

// TestTerminalFailureWithdrawsReadinessAndSignalsOwner proves admission cannot outlive telemetry.
func TestTerminalFailureWithdrawsReadinessAndSignalsOwner(t *testing.T) {
	snapshot, err := config.Decode([]byte(serviceConfig))
	if err != nil {
		t.Fatal("configuration fixture rejected")
	}
	runtime, err := New(snapshot, io.Discard)
	if err != nil || runtime.StartMetrics(context.Background()) != nil {
		t.Fatal("telemetry fixture failed")
	}
	runtime.SetReady(true)
	runtime.failTerminal()
	select {
	case <-runtime.Terminal():
	default:
		t.Fatal("terminal failure did not notify owner")
	}
	runtime.mu.Lock()
	ready := runtime.ready
	runtime.mu.Unlock()
	if ready {
		t.Fatal("terminal failure left readiness true")
	}
	stop, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = runtime.Stop(stop)
}

// TestRecordOverflowAndStopRaceCannotBlockMail proves queue pressure and shutdown stay bounded.
func TestRecordOverflowAndStopRaceCannotBlockMail(t *testing.T) {
	snapshot, err := config.Decode([]byte(serviceConfig))
	if err != nil {
		t.Fatal("configuration fixture rejected")
	}
	writer := &blockingWriter{started: make(chan struct{}, 1), release: make(chan struct{})}
	runtime, err := New(snapshot, writer)
	if err != nil || runtime.StartMetrics(context.Background()) != nil {
		t.Fatal("telemetry fixture failed")
	}
	event := Event{Hook: "local_scan", Operation: "process", Result: "success", Failure: "none", Admission: "accepted"}
	runtime.Record(event)
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("blocking sink was not reached")
	}
	recordDone := make(chan struct{})
	go func() {
		defer close(recordDone)
		for range 2048 {
			runtime.Record(event)
		}
	}()
	select {
	case <-recordDone:
	case <-time.After(time.Second):
		t.Fatal("queue overflow blocked event recording")
	}
	stopContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := runtime.Stop(stopContext); !errors.Is(err, errTelemetry) {
		t.Fatal("blocked sink did not bound shutdown")
	}
	cancel()
	close(writer.release)
	select {
	case <-runtime.drainDone:
	case <-time.After(time.Second):
		t.Fatal("released sink did not finish shutdown drain")
	}
	runtime.Record(event)
}
