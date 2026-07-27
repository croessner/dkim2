package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/testsupport"
)

const appCapabilityPrivacyMarker = "private-capability-owner-marker"

// testCapability records protected ownership without retaining secret bytes.
type testCapability struct {
	mu         sync.Mutex
	closes     int
	closeError error
	panicClose bool
}

// Close records one idempotent ownership release.
func (c *testCapability) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	if c.panicClose {
		panic("private close marker")
	}
	if c.closeError != nil {
		return c.closeError
	}
	return nil
}

// TestCapabilityOwnerFormattingAndSerializationRemainRedacted proves path privacy.
func TestCapabilityOwnerFormattingAndSerializationRemainRedacted(t *testing.T) {
	owner := &capabilityOwner{state: &capabilityOwnerState{guard: &capabilityOwnerGuard{
		mu: &sync.Mutex{}, path: "/protected/" + appCapabilityPrivacyMarker,
	}}}
	subjects := []any{
		owner,
		*owner,
		any(owner),
		owner.state,
		*owner.state,
		owner.state.guard,
		*owner.state.guard,
		struct{ Value any }{Value: owner},
		struct{ Value capabilityOwner }{Value: *owner},
	}
	for _, subject := range subjects {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if formatted := fmt.Sprintf(format, subject); strings.Contains(
				formatted,
				appCapabilityPrivacyMarker,
			) {
				t.Fatalf("unsafe capability owner formatting: %q", formatted)
			}
		}
		if output, err := json.Marshal(subject); !errors.Is(err, errApplication) ||
			strings.Contains(string(output), appCapabilityPrivacyMarker) {
			t.Fatal("capability owner serialization did not fail closed")
		}
		if marshaler, ok := subject.(interface{ MarshalText() ([]byte, error) }); ok {
			if output, err := marshaler.MarshalText(); !errors.Is(err, errApplication) ||
				strings.Contains(string(output), appCapabilityPrivacyMarker) {
				t.Fatal("capability owner text serialization did not fail closed")
			}
		}
	}
}

// TestCapabilityOwnerContainsCloseErrorsAndPanics proves secret cleanup seams.
func TestCapabilityOwnerContainsCloseErrorsAndPanics(t *testing.T) {
	for _, capability := range []*testCapability{
		{closeError: errors.New("private close error")},
		{panicClose: true},
	} {
		owner := &capabilityOwner{state: &capabilityOwnerState{
			guard: &capabilityOwnerGuard{mu: &sync.Mutex{}, capability: capability},
		}}
		if err := owner.Stop(context.Background()); !errors.Is(err, errApplication) {
			t.Fatalf("Stop() error = %v", err)
		}
		if owner.Capability() != nil || capability.closeCount() != 1 {
			t.Fatal("failed Close retained ambiguous capability ownership")
		}
	}
}

// closeCount returns the synchronized release count.
func (c *testCapability) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// testSnapshot loads one real validated configuration for graph tests.
func testSnapshot(t *testing.T) config.Snapshot {
	t.Helper()
	return testSnapshotWithFailure(t, "tempfail")
}

// testSnapshotWithFailure loads one real config with an explicit failure policy.
func testSnapshotWithFailure(t *testing.T, failureMode string) config.Snapshot {
	t.Helper()
	directory := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(directory, "milter.yaml")
	document := `version: dkim2-milter-config-v1
server:
  socket: /tmp/dkim2-milter.sock
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /tmp/dkim2-milter.cap
mode: inbound
failure:
  mode: ` + failureMode + `
`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// TestApplicationEmitsBoundedFailOpenStartupEvidence proves operator visibility.
func TestApplicationEmitsBoundedFailOpenStartupEvidence(t *testing.T) {
	var output bytes.Buffer
	capability := &testCapability{}
	application, err := newWithCapabilityLoader(
		testSnapshotWithFailure(t, "fail_open"),
		&output,
		func(string) (protectedCapability, error) { return capability, nil },
		lifecycleTestRuntimeDependencies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := application.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	logs := output.String()
	if !strings.Contains(logs, `"event_id":"config.accepted"`) ||
		!strings.Contains(logs, `"fail_open":true`) ||
		!strings.Contains(logs, `"mode":"inbound"`) ||
		strings.Contains(logs, appCapabilityPrivacyMarker) {
		t.Fatalf("bounded fail-open startup evidence missing or unsafe: %s", logs)
	}
}

// TestApplicationLoadsAndClosesCapabilityInsideFxLifecycle proves protected ownership.
func TestApplicationLoadsAndClosesCapabilityInsideFxLifecycle(t *testing.T) {
	capability := &testCapability{}
	loadCalls := 0
	application, err := newWithCapabilityLoader(
		testSnapshot(t),
		&bytes.Buffer{},
		func(path string) (protectedCapability, error) {
			loadCalls++
			if path != "/tmp/dkim2-milter.cap" {
				t.Fatal("Fx received an unexpected capability path")
			}
			return capability, nil
		},
		lifecycleTestRuntimeDependencies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if loadCalls != 0 {
		t.Fatal("protected value was loaded before Fx startup")
	}
	if err := application.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if loadCalls != 1 {
		t.Fatalf("capability loads = %d, want 1", loadCalls)
	}
	if err := application.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if capability.closeCount() != 1 {
		t.Fatalf("capability closes = %d, want 1", capability.closeCount())
	}
}

// TestApplicationClosesAmbiguousCapabilityReturnedWithError proves fail-closed ownership.
func TestApplicationClosesAmbiguousCapabilityReturnedWithError(t *testing.T) {
	capability := &testCapability{}
	application, err := newWithCapabilityLoader(
		testSnapshot(t),
		&bytes.Buffer{},
		func(string) (protectedCapability, error) {
			return capability, errors.New("private capability marker")
		},
		lifecycleTestRuntimeDependencies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.Start(context.Background()); !errors.Is(err, errApplication) {
		t.Fatalf("Start() error = %v", err)
	}
	if capability.closeCount() != 1 {
		t.Fatalf("ambiguous capability closes = %d, want 1", capability.closeCount())
	}
}

// TestCapabilityOwnerClosesValueWhenContextExpiresDuringLoad proves cancellation cleanup.
func TestCapabilityOwnerClosesValueWhenContextExpiresDuringLoad(t *testing.T) {
	capability := &testCapability{}
	ctx, cancel := context.WithCancel(context.Background())
	owner, err := newCapabilityOwner(
		testSnapshot(t),
		func(string) (protectedCapability, error) {
			cancel()
			return capability, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Start(ctx); !errors.Is(err, errApplication) {
		t.Fatalf("Start() error = %v", err)
	}
	if capability.closeCount() != 1 || owner.Capability() != nil {
		t.Fatal("canceled loading retained protected capability ownership")
	}
}
