package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
)

// observabilitySnapshot loads one validated snapshot at the requested level.
func observabilitySnapshot(t *testing.T, level string) config.Snapshot {
	t.Helper()
	return observabilitySnapshotWithEndpoint(t, level, "")
}

// TestUnexpectedMetricsExitWithdrawsPublishedReadiness proves liveness tracking.
func TestUnexpectedMetricsExitWithdrawsPublishedReadiness(t *testing.T) {
	const authority = "127.0.0.1:9817"
	listener := newBlockingListener(authority)
	runtime, err := newRuntime(
		observabilitySnapshotWithEndpoint(t, "info", authority),
		&bytes.Buffer{},
		func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	)
	if err != nil || runtime.Activate() != nil ||
		runtime.StartMetrics(context.Background()) != nil {
		t.Fatal("metrics runtime did not start")
	}
	if !runtime.RecordReady() {
		t.Fatal("live metrics runtime did not publish readiness")
	}
	if err := listener.Close(); err != nil {
		t.Fatal("test listener close failed")
	}
	deadline := time.Now().Add(time.Second)
	for {
		exposition, gatherErr := runtime.Gather()
		if gatherErr != nil {
			t.Fatal("gather failed after listener loss")
		}
		if bytes.Contains(exposition, []byte(metricReadiness+" 0")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener loss did not withdraw readiness")
		}
		time.Sleep(time.Millisecond)
	}
	if runtime.RecordReady() {
		t.Fatal("readiness republished after metrics listener loss")
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal("runtime stop failed after listener loss")
	}
}

// TestWithdrawReadinessPrecedesFinalMetricsStopAndIsIdempotent proves shutdown ordering.
func TestWithdrawReadinessPrecedesFinalMetricsStopAndIsIdempotent(t *testing.T) {
	const authority = "127.0.0.1:9817"
	listener := newBlockingListener(authority)
	var output bytes.Buffer
	runtime, err := newRuntime(
		observabilitySnapshotWithEndpoint(t, "info", authority),
		&output,
		func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	)
	if err != nil || runtime.Activate() != nil ||
		runtime.StartMetrics(context.Background()) != nil {
		t.Fatal("metrics runtime did not start")
	}
	if !runtime.RecordReady() {
		t.Fatal("live runtime did not publish readiness")
	}
	if !runtime.RecordReady() {
		t.Fatal("live runtime did not preserve readiness")
	}
	runtime.WithdrawReadiness()
	runtime.WithdrawReadiness()
	if runtime.RecordReady() {
		t.Fatal("readiness republished after explicit withdrawal")
	}
	exposition, err := runtime.Gather()
	if err != nil || !bytes.Contains(exposition, []byte(metricReadiness+" 0")) {
		t.Fatal("readiness withdrawal did not immediately publish zero")
	}
	if listener.isClosed() {
		t.Fatal("readiness withdrawal prematurely stopped metrics serving")
	}
	if err := runtime.Stop(context.Background()); err != nil || !listener.isClosed() {
		t.Fatal("final stop did not release the metrics listener")
	}
	if bytes.Count(output.Bytes(), []byte(`"ready":false`)) != 1 {
		t.Fatal("idempotent withdrawal emitted duplicate readiness transitions")
	}
	if runtime.Metrics().Stopped != 1 {
		t.Fatal("final stop did not complete after readiness withdrawal")
	}
}

// TestConcurrentReadyAndWithdrawalEndsNotReady proves terminal race ordering.
func TestConcurrentReadyAndWithdrawalEndsNotReady(t *testing.T) {
	runtime, err := New(observabilitySnapshot(t, "info"), &bytes.Buffer{})
	if err != nil || runtime.Activate() != nil ||
		runtime.StartMetrics(context.Background()) != nil {
		t.Fatal("runtime did not start")
	}
	var workers sync.WaitGroup
	for range 64 {
		workers.Add(2)
		go func() {
			defer workers.Done()
			runtime.RecordReady()
		}()
		go func() {
			defer workers.Done()
			runtime.WithdrawReadiness()
		}()
	}
	workers.Wait()
	if runtime.RecordReady() {
		t.Fatal("withdrawn runtime published readiness")
	}
	exposition, gatherErr := runtime.Gather()
	if gatherErr != nil || !bytes.Contains(exposition, []byte(metricReadiness+" 0")) {
		t.Fatal("readiness rose after terminal withdrawal")
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal("runtime stop failed")
	}
}

// observabilitySnapshotWithEndpoint loads a snapshot with an optional listener.
func observabilitySnapshotWithEndpoint(
	t *testing.T,
	level string,
	endpoint string,
) config.Snapshot {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "milter.yaml")
	document := `version: dkim2-milter-config-v1
server:
  socket: /tmp/dkim2-milter.sock
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /tmp/dkim2-milter.cap
mode: inbound
observability:
  logging:
    level: ` + level + "\n"
	if endpoint != "" {
		document += "  metrics:\n    endpoint: " + endpoint + "\n"
	}
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// TestRuntimeOwnsOptionalMetricsListenerLifecycle proves endpoint configuration is live.
func TestRuntimeOwnsOptionalMetricsListenerLifecycle(t *testing.T) {
	const authority = "127.0.0.1:9817"
	listener := newBlockingListener(authority)
	var calls int
	runtime, err := newRuntime(
		observabilitySnapshotWithEndpoint(t, "info", authority),
		&bytes.Buffer{},
		func(context.Context, string, string) (net.Listener, error) {
			calls++
			return listener, nil
		},
	)
	if err != nil || calls != 0 {
		t.Fatal("metrics listener was acquired during construction")
	}
	if err := runtime.Activate(); err != nil || calls != 0 {
		t.Fatal("quiescent activation acquired a listener")
	}
	if err := runtime.StartMetrics(context.Background()); err != nil || calls != 1 {
		t.Fatal("metrics listener did not start with the runtime")
	}
	runtime.RecordReady()
	if runtime.Metrics().Ready != 1 {
		t.Fatal("live metrics listener did not permit readiness")
	}
	if err := runtime.Stop(context.Background()); err != nil || !listener.isClosed() {
		t.Fatal("metrics listener was not released during shutdown")
	}
}

// TestRuntimeContainsMetricsBindFailuresBeforeReadiness proves startup fail-closed.
func TestRuntimeContainsMetricsBindFailuresBeforeReadiness(t *testing.T) {
	const authority = "127.0.0.1:9817"
	runtime, err := newRuntime(
		observabilitySnapshotWithEndpoint(t, "info", authority),
		&bytes.Buffer{},
		func(context.Context, string, string) (net.Listener, error) {
			return nil, errors.New(privacyMarker)
		},
	)
	if err != nil {
		t.Fatal("listener acquisition occurred during construction")
	}
	if runtime.Activate() != nil {
		t.Fatal("quiescent runtime activation failed")
	}
	startErr := runtime.StartMetrics(context.Background())
	ready := runtime.RecordReady()
	if startErr == nil || strings.Contains(startErr.Error(), privacyMarker) ||
		ready || runtime.Metrics().Started != 1 || runtime.Metrics().Ready != 0 {
		t.Fatal("metrics bind failure did not fail closed content-free")
	}
}

// TestMetricsStartRollsBackPanickingListenerSeams proves post-bind containment.
func TestMetricsStartRollsBackPanickingListenerSeams(t *testing.T) {
	const authority = "127.0.0.1:9817"
	t.Run("address", func(t *testing.T) {
		listener := &panicAddressListener{}
		runtime, err := newRuntime(
			observabilitySnapshotWithEndpoint(t, "info", authority),
			&bytes.Buffer{},
			func(context.Context, string, string) (net.Listener, error) {
				return listener, nil
			},
		)
		if err != nil || runtime.Activate() != nil {
			t.Fatal("quiescent runtime activation failed")
		}
		if startErr := runtime.StartMetrics(context.Background()); startErr == nil ||
			!listener.closed {
			t.Fatal("panicking address seam did not close the bound listener")
		}
	})
	t.Run("listener factory", func(t *testing.T) {
		runtime, err := newRuntime(
			observabilitySnapshotWithEndpoint(t, "info", authority),
			&bytes.Buffer{},
			func(context.Context, string, string) (net.Listener, error) {
				panic(privacyMarker)
			},
		)
		if err != nil || runtime.Activate() != nil {
			t.Fatal("quiescent runtime activation failed")
		}
		if startErr := runtime.StartMetrics(context.Background()); startErr == nil ||
			strings.Contains(startErr.Error(), privacyMarker) {
			t.Fatal("panicking listener factory escaped the startup boundary")
		}
	})
	t.Run("rollback close", func(t *testing.T) {
		runtime, err := newRuntime(
			observabilitySnapshotWithEndpoint(t, "info", authority),
			&bytes.Buffer{},
			func(context.Context, string, string) (net.Listener, error) {
				return panicCloseListener{}, nil
			},
		)
		if err != nil || runtime.Activate() != nil {
			t.Fatal("quiescent runtime activation failed")
		}
		if startErr := runtime.StartMetrics(context.Background()); startErr == nil {
			t.Fatal("panicking rollback close escaped the startup boundary")
		}
	})
}

// TestRecordConfigAcceptedEmitsBoundedFailOpenWarning proves operator visibility.
func TestRecordConfigAcceptedEmitsBoundedFailOpenWarning(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil || runtime.Activate() != nil {
		t.Fatal("runtime construction failed")
	}
	if err := runtime.RecordConfigAccepted("originator", true); err != nil {
		t.Fatal("bounded fail-open warning failed")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"event_id":"`+eventConfigAccepted+`"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"fail_open":true`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"level":"WARN"`)) ||
		bytes.Contains(output.Bytes(), []byte(privacyMarker)) {
		t.Fatal("fail-open configuration warning was not bounded")
	}
}

// TestRecordConfigAcceptedAdmitsPostfixDSN proves the mode remains bounded.
func TestRecordConfigAcceptedAdmitsPostfixDSN(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil || runtime.Activate() != nil {
		t.Fatal("runtime construction failed")
	}
	if err := runtime.RecordConfigAccepted(valueModePostfixDSN, false); err != nil {
		t.Fatal("bounded Postfix DSN configuration fact failed")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"event_id":"`+eventConfigAccepted+`"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"mode":"`+valueModePostfixDSN+`"`)) ||
		bytes.Contains(output.Bytes(), []byte(privacyMarker)) {
		t.Fatal("Postfix DSN configuration fact was not bounded")
	}
}

// TestConfigRecordRejectsInvalidModeWithoutPublishing proves closed startup facts.
func TestConfigRecordRejectsInvalidModeWithoutPublishing(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil || runtime.Activate() != nil {
		t.Fatal("runtime activation failed")
	}
	before := output.Len()
	if recordErr := runtime.RecordConfigAccepted(privacyMarker, true); recordErr == nil ||
		output.Len() != before || bytes.Contains(output.Bytes(), []byte(privacyMarker)) {
		t.Fatal("invalid configuration fact reached the logger")
	}
}

// TestFailOpenWarningBypassesErrorThreshold proves mandatory operator visibility.
func TestFailOpenWarningBypassesErrorThreshold(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "error"), &output)
	if err != nil || runtime.Activate() != nil {
		t.Fatal("error-level runtime did not activate")
	}
	if output.Len() != 0 {
		t.Fatal("ordinary info lifecycle record bypassed the error threshold")
	}
	if err := runtime.RecordConfigAccepted("inbound", true); err != nil {
		t.Fatal("mandatory fail-open warning was rejected")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"level":"WARN"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"fail_open":true`)) {
		t.Fatal("mandatory fail-open warning was suppressed at error level")
	}
}

// TestConfigRecordReportsHostileWriterFailures proves startup can fail closed.
func TestConfigRecordReportsHostileWriterFailures(t *testing.T) {
	tests := []struct {
		name   string
		writer io.Writer
	}{
		{name: "error", writer: errorWriter{}},
		{name: "short", writer: shortWriter{}},
		{name: "panic", writer: panicWriter{}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			runtime, err := New(observabilitySnapshot(t, "error"), testCase.writer)
			if err != nil || runtime.Activate() != nil {
				t.Fatal("error-level runtime did not activate before mandatory output")
			}
			recordErr := runtime.RecordConfigAccepted("inbound", true)
			if recordErr == nil || strings.Contains(recordErr.Error(), privacyMarker) {
				t.Fatal("hostile mandatory output did not fail closed content-free")
			}
		})
	}
}

// TestReadinessRemainsLowWhenItsStartupOutputFails proves false-ready containment.
func TestReadinessRemainsLowWhenItsMandatoryOutputFails(t *testing.T) {
	output := &failAfterWriter{successfulWrites: 1}
	runtime, err := New(observabilitySnapshot(t, "info"), output)
	if err != nil || runtime.Activate() != nil {
		t.Fatal("runtime activation failed")
	}
	if runtime.RecordReady() {
		t.Fatal("runtime published readiness after its log output failed")
	}
	exposition, gatherErr := runtime.Gather()
	if gatherErr != nil || !bytes.Contains(exposition, []byte(metricReadiness+" 0")) {
		t.Fatal("failed readiness output raised the readiness gauge")
	}
}

// errorWriter returns a sensitive write failure for containment tests.
type errorWriter struct{}

// Write fails without accepting bytes.
func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New(privacyMarker)
}

// shortWriter reports an incomplete write without an error.
type shortWriter struct{}

// Write accepts fewer bytes than supplied.
func (shortWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	return len(value) - 1, nil
}

// failAfterWriter accepts a fixed number of complete records before failing.
type failAfterWriter struct {
	successfulWrites int
	writes           int
}

// Write admits the configured prefix and then returns a bounded error.
func (w *failAfterWriter) Write(value []byte) (int, error) {
	w.writes++
	if w.writes <= w.successfulWrites {
		return len(value), nil
	}
	return 0, errors.New(privacyMarker)
}

// blockingListener is a hermetic listener that blocks until closed.
type blockingListener struct {
	address fakeAddress
	closed  chan struct{}
	once    sync.Once
}

// newBlockingListener constructs one hermetic runtime listener.
func newBlockingListener(authority string) *blockingListener {
	return &blockingListener{
		address: fakeAddress(authority),
		closed:  make(chan struct{}),
	}
}

// Accept blocks until shutdown and then reports a content-free closure.
func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, errors.New("listener closed")
}

// Close releases every blocked accept exactly once.
func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr returns the exact configured listener authority.
func (l *blockingListener) Addr() net.Addr { return l.address }

// isClosed reports whether shutdown closed the listener.
func (l *blockingListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

// fakeAddress is one exact TCP listener address.
type fakeAddress string

// Network returns the fixed TCP network class.
func (fakeAddress) Network() string { return "tcp" }

// String returns the configured canonical authority.
func (a fakeAddress) String() string { return string(a) }

// panicAddressListener panics during bound-address validation.
type panicAddressListener struct {
	closed bool
}

// Accept is unreachable because address validation fails before serving.
func (*panicAddressListener) Accept() (net.Conn, error) {
	return nil, errors.New("unreachable")
}

// Close proves rollback released the bound listener.
func (l *panicAddressListener) Close() error {
	l.closed = true
	return nil
}

// Addr panics to exercise the post-bind startup boundary.
func (*panicAddressListener) Addr() net.Addr {
	panic(privacyMarker)
}

// panicCloseListener panics from both validation and rollback closure.
type panicCloseListener struct{}

// Accept is unreachable because address validation fails before serving.
func (panicCloseListener) Accept() (net.Conn, error) {
	return nil, errors.New("unreachable")
}

// Close panics to exercise nested rollback containment.
func (panicCloseListener) Close() error {
	panic(privacyMarker)
}

// Addr panics to enter the rollback path.
func (panicCloseListener) Addr() net.Addr {
	panic(privacyMarker)
}

// TestRuntimeLifecycleUsesCentralClosedProviders proves compatible lifecycle wiring.
func TestRuntimeLifecycleUsesCentralClosedProviders(t *testing.T) {
	var output bytes.Buffer
	runtime, err := New(observabilitySnapshot(t, "info"), &output)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	runtime.RecordStarted()
	if !runtime.RecordReady() {
		t.Fatal("started runtime did not publish readiness")
	}
	runtime.RecordStopped()
	if runtime.RecordReady() {
		t.Fatal("stopped runtime republished readiness")
	}
	runtime.RecordStopped()
	if metrics := runtime.Metrics(); metrics.Started != 1 ||
		metrics.Ready != 1 || metrics.Stopped != 1 {
		t.Fatalf("unexpected lifecycle snapshot: %#v", metrics)
	}
	exposition, err := runtime.Gather()
	if err != nil ||
		!bytes.Contains(exposition, []byte("dkim2_milter_readiness 0")) ||
		!bytes.Contains(exposition, []byte(`lifecycle_state="active"`)) ||
		!bytes.Contains(exposition, []byte(`lifecycle_state="stopped"`)) {
		t.Fatal("lifecycle metrics did not preserve terminal state")
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 4 {
		t.Fatalf("lifecycle emitted %d records, want 4", len(lines))
	}
	for _, line := range lines {
		var document map[string]any
		if json.Unmarshal(line, &document) != nil ||
			document["event_id"] == nil ||
			document["msg"] != document["event_id"] {
			t.Fatal("lifecycle did not emit the closed JSON envelope")
		}
	}
}

// TestRuntimeInstancesAndConcurrentLifecycleAreIsolated proves no global state exists.
func TestRuntimeInstancesAndConcurrentLifecycleAreIsolated(t *testing.T) {
	var firstOutput bytes.Buffer
	var secondOutput bytes.Buffer
	first, err := New(observabilitySnapshot(t, "info"), &firstOutput)
	if err != nil {
		t.Fatal("first runtime construction failed")
	}
	second, err := New(observabilitySnapshot(t, "info"), &secondOutput)
	if err != nil {
		t.Fatal("second runtime construction failed")
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			first.RecordStarted()
			first.RecordReady()
		}()
	}
	workers.Wait()
	second.RecordStopped()
	if first.Metrics().Started != 1 || first.Metrics().Ready != 1 ||
		second.Metrics().Started != 0 || second.Metrics().Stopped != 1 {
		t.Fatal("runtime instances shared process state")
	}
}

// TestRuntimeRejectsInvalidConstructionAndProvidesSafeNilAccess proves fail-closed edges.
func TestRuntimeRejectsInvalidConstructionAndProvidesSafeNilAccess(t *testing.T) {
	if _, err := New(observabilitySnapshot(t, "info"), nil); err == nil ||
		strings.Contains(err.Error(), "/") {
		t.Fatal("nil output was not rejected content-free")
	}
	var runtime *Runtime
	runtime.RecordStarted()
	if runtime.RecordReady() {
		t.Fatal("nil runtime reported readiness")
	}
	runtime.RecordStopped()
	if runtime.Logger() == nil || runtime.Registry() != nil ||
		runtime.Metrics() != (Snapshot{}) {
		t.Fatal("nil runtime access was not safe")
	}
	if _, err := runtime.Gather(); err == nil {
		t.Fatal("nil runtime gather was accepted")
	}
}
