package app

import (
	"context"
	"errors"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/evidence"
)

type serviceStub struct {
	order    *[]string
	drainErr error
}

func (s *serviceStub) DrainContext(context.Context) error {
	*s.order = append(*s.order, "drain")
	return s.drainErr
}

func (s *serviceStub) RemoveSocket() error {
	*s.order = append(*s.order, "socket")
	return nil
}

type telemetryStub struct{ order *[]string }

func (t *telemetryStub) SetReady(value bool) {
	if !value {
		*t.order = append(*t.order, "not-ready")
	}
}
func (t *telemetryStub) Stop(context.Context) error {
	*t.order = append(*t.order, "telemetry")
	return nil
}
func (t *telemetryStub) Terminal() <-chan struct{} { return make(chan struct{}) }

// TestShutdownOrdersDependenciesBeforeSocketCleanup proves the durable finalization order.
func TestShutdownOrdersDependenciesBeforeSocketCleanup(t *testing.T) {
	order := []string{}
	runtime := &composedRuntime{
		service:   &serviceStub{order: &order},
		telemetry: &telemetryStub{order: &order},
		release:   func() { order = append(order, "client") },
	}
	if err := runtime.shutdown(context.Background()); err != nil {
		t.Fatal("clean shutdown failed")
	}
	want := []string{"not-ready", "drain", "telemetry", "client", "socket"}
	if len(order) != len(want) {
		t.Fatal("shutdown owner count drifted")
	}
	for index := range want {
		if order[index] != want[index] {
			t.Fatal("shutdown order drifted")
		}
	}
}

// TestShutdownPreservesDependenciesWhenDrainTimesOut proves workers cannot race closed owners.
func TestShutdownPreservesDependenciesWhenDrainTimesOut(t *testing.T) {
	order := []string{}
	released := false
	runtime := &composedRuntime{
		service:   &serviceStub{order: &order, drainErr: errors.New("timeout")},
		telemetry: &telemetryStub{order: &order},
		release:   func() { released = true },
	}
	if err := runtime.shutdown(context.Background()); err == nil {
		t.Fatal("timed-out drain reported success")
	}
	if released || len(order) != 2 || order[0] != "not-ready" || order[1] != "drain" {
		t.Fatal("shared dependencies were released before worker join")
	}
}

// TestServeRejectsNilContext proves startup cannot escape caller lifetime ownership.
func TestServeRejectsNilContext(t *testing.T) {
	if err := Serve(nil, "/protected/config"); err == nil { //nolint:staticcheck // Explicit nil is the contract case under test.
		t.Fatal("nil startup context accepted")
	}
}

// TestDisabledEvidencePublisherStaysNil proves composition erases typed nil evidence when disabled.
func TestDisabledEvidencePublisherStaysNil(t *testing.T) {
	var concrete *evidence.IncomingPublisher
	var publisher daemon.EvidencePublisher = concrete
	if inboundEvidencePublisher(false, publisher) != nil {
		t.Fatal("disabled evidence composition leaked a typed nil publisher")
	}
	if inboundEvidencePublisher(true, publisher) == nil {
		t.Fatal("enabled evidence composition discarded its publisher")
	}
}
