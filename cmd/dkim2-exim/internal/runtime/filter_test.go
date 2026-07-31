package runtime

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/filter"
)

type faultResultSink struct {
	panicWrite bool
	closed     bool
}

// Write injects a non-authoritative result-sink panic or failure.
func (s *faultResultSink) Write([]byte) error {
	if s.panicWrite {
		panic("result sink panic")
	}
	return errRuntime
}

// Close records cleanup of the injected result sink.
func (s *faultResultSink) Close() error {
	s.closed = true
	return errRuntime
}

// TestProtectedRuntimeOwnersAreOpaque proves pointer and explicit-dereference formatting stays closed.
func TestProtectedRuntimeOwnersAreOpaque(t *testing.T) {
	const toxic = "toxic-capability-marker"
	capability := operationCapability{target: "http://127.0.0.1:8080/" + toxic}
	copy(capability.value[:], []byte(toxic))
	instance := &filterRuntime{
		config:     Config{Endpoint: "http://127.0.0.1:8080/" + toxic, Timeout: time.Second},
		capability: &capability,
	}
	sink := unixgramSink{}
	for _, value := range []any{capability, &capability, *instance, instance, instance.config, sink, &sink} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, toxic) || !strings.Contains(rendered, "redacted") {
				t.Fatal("protected runtime formatting escaped")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("protected runtime JSON serialization succeeded")
		}
		if text, ok := value.(encoding.TextMarshaler); ok {
			if _, err := text.MarshalText(); err == nil {
				t.Fatal("protected runtime text serialization succeeded")
			}
		}
	}
}

// TestNewFilterClientRejectsInvalidAuthority proves no client is built for a non-loopback route.
func TestNewFilterClientRejectsInvalidAuthority(t *testing.T) {
	capability := &operationCapability{target: "http://example.test/v1/sign"}
	capability.value[0] = 1
	if _, _, err := newFilterClient(
		Config{Endpoint: "http://example.test", Timeout: time.Second},
		capability,
	); err == nil {
		t.Fatal("non-loopback filter client accepted")
	}
}

// TestInterruptOwnedIOUsesChildDeadline proves blocked production descriptors cannot outlive timeout.
func TestInterruptOwnedIOUsesChildDeadline(t *testing.T) {
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("input pipe failed")
	}
	defer func() { _ = inputWriter.Close() }()
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal("output pipe failed")
	}
	defer func() { _ = outputReader.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	release := interruptOwnedIO(ctx, input, output)
	<-ctx.Done()
	release()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := input.Read(make([]byte, 1)); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child timeout did not close blocked input")
		}
	}
	if _, err := output.Write([]byte("x")); err == nil {
		t.Fatal("child timeout did not close blocked output")
	}
}

// TestResultSinkFailureCannotChangeMailDecision proves telemetry and cleanup are non-authoritative.
func TestResultSinkFailureCannotChangeMailDecision(t *testing.T) {
	for _, panicWrite := range []bool{false, true} {
		sink := &faultResultSink{panicWrite: panicWrite}
		instance := &filterRuntime{sink: sink}
		status := filter.ExitSuccess
		instance.emitResultSafely(adapter.FilterSign, &status)
		instance.closeSafely()
		if status != filter.ExitSuccess {
			t.Fatal("non-authoritative sink changed the mail decision")
		}
		if !sink.closed {
			t.Fatal("result sink was not closed after emission failure")
		}
	}
}

// TestFilterRequestContextCannotExtendWholeBudget proves acquisition time consumes the outer bound.
func TestFilterRequestContextCannotExtendWholeBudget(t *testing.T) {
	whole, cancelWhole := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelWhole()
	wholeDeadline, _ := whole.Deadline()
	time.Sleep(20 * time.Millisecond)
	request, cancelRequest := filterRequestContext(whole, wholeFilterTimeout)
	defer cancelRequest()
	requestDeadline, ok := request.Deadline()
	if !ok || !requestDeadline.Equal(wholeDeadline) {
		t.Fatal("configured request context extended the remaining whole-filter budget")
	}
}
