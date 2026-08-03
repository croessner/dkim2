//go:build datasourceintegration

package sqlsnapshot

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

type contentionStubTransaction struct {
	AdministrationTransaction
	connectionID uint64
}

// IntegrationConnectionID returns one synthetic physical connection identity.
func (t contentionStubTransaction) IntegrationConnectionID(context.Context) (uint64, error) {
	return t.connectionID, nil
}

// Rollback completes synthetic cleanup without an embedded transaction.
func (contentionStubTransaction) Rollback(context.Context) error { return nil }

// ReadLock completes one synthetic locked read.
func (contentionStubTransaction) ReadLock(context.Context, bool) (uint64, *string, error) {
	owner := testOperationOne
	return 1, &owner, nil
}

// ActivateCurrent completes one synthetic mutation.
func (contentionStubTransaction) ActivateCurrent(
	context.Context,
	CurrentPointerFence,
	CandidateRootFence,
) (int64, error) {
	return 1, nil
}

type contentionStubConnector struct {
	AdministrationConnector
	transaction AdministrationTransaction
}

// Begin returns one synthetic integration transaction.
func (c contentionStubConnector) Begin(context.Context, AdministrationMode) (AdministrationTransaction, error) {
	return c.transaction, nil
}

// TestActivationContentionGateIsBoundedAndIdempotent proves cancellation,
// release, and progress signals cannot leak goroutines or double-close channels.
func TestActivationContentionGateIsBoundedAndIdempotent(t *testing.T) {
	canceledGate := NewActivationContentionGate()
	canceledTransaction := &activationContentionTransaction{
		AdministrationTransaction: contentionStubTransaction{},
		gate:                      canceledGate, role: ActivationContentionHolder,
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := canceledTransaction.ActivateCurrent(
		canceled, CurrentPointerFence{}, CandidateRootFence{},
	); datasourceadmin.CodeOf(err) != datasourceadmin.CodeUnavailable {
		t.Fatal("canceled holder was not bounded")
	}
	waitForIntegrationContentionSignal(t, canceledGate.HolderBeforeMutation())

	releaseGate := NewActivationContentionGate()
	releaseTransaction := &activationContentionTransaction{
		AdministrationTransaction: contentionStubTransaction{},
		gate:                      releaseGate, role: ActivationContentionHolder,
	}
	result := make(chan error, 1)
	go func() {
		_, err := releaseTransaction.ActivateCurrent(
			t.Context(), CurrentPointerFence{}, CandidateRootFence{},
		)
		result <- err
	}()
	waitForIntegrationContentionSignal(t, releaseGate.HolderBeforeMutation())
	releaseGate.ReleaseHolder()
	releaseGate.ReleaseHolder()
	if err := waitForIntegrationContentionResult(t, result); err != nil {
		t.Fatal("released holder did not complete")
	}

	waiterGate := NewActivationContentionGate()
	waiterConnector := &activationContentionConnector{
		AdministrationConnector: contentionStubConnector{transaction: contentionStubTransaction{connectionID: 42}},
		gate:                    waiterGate, role: ActivationContentionWaiter,
	}
	waiter, err := waiterConnector.Begin(t.Context(), AdministrationActivation)
	if err != nil {
		t.Fatal("begin synthetic waiter")
	}
	waitForIntegrationContentionSignal(t, waiterGate.WaiterTransactionBegun())
	if _, _, err := waiter.ReadLock(t.Context(), true); err != nil {
		t.Fatal("read synthetic waiter lock")
	}
	waitForIntegrationContentionSignal(t, waiterGate.WaiterReadLockAttempt())
}

// TestActivationContentionGateRequiresPhysicalConnectionIDs proves the
// handshake cannot claim contention without both concrete transaction IDs.
func TestActivationContentionGateRequiresPhysicalConnectionIDs(t *testing.T) {
	gate := NewActivationContentionGate()
	holderConnector := &activationContentionConnector{
		AdministrationConnector: contentionStubConnector{
			transaction: contentionStubTransaction{connectionID: 41},
		},
		gate: gate, role: ActivationContentionHolder,
	}
	if _, err := holderConnector.Begin(t.Context(), AdministrationActivation); err != nil {
		t.Fatal("begin synthetic holder")
	}
	if id := waitForIntegrationConnectionID(t, gate.HolderConnectionID()); id != 41 {
		t.Fatal("holder physical connection identity was not preserved")
	}

	waiterConnector := &activationContentionConnector{
		AdministrationConnector: contentionStubConnector{
			transaction: contentionStubTransaction{connectionID: 42},
		},
		gate: gate, role: ActivationContentionWaiter,
	}
	if _, err := waiterConnector.Begin(t.Context(), AdministrationActivation); err != nil {
		t.Fatal("begin synthetic waiter")
	}
	if id := waitForIntegrationConnectionID(t, gate.WaiterConnectionID()); id != 42 {
		t.Fatal("waiter physical connection identity was not preserved")
	}

	missingID := &activationContentionConnector{
		AdministrationConnector: contentionStubConnector{transaction: struct{ AdministrationTransaction }{
			AdministrationTransaction: contentionStubTransaction{},
		}},
		gate: NewActivationContentionGate(), role: ActivationContentionHolder,
	}
	if _, err := missingID.Begin(t.Context(), AdministrationActivation); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("transaction without a physical connection identity was accepted")
	}
}

// waitForIntegrationContentionSignal bounds one unit-test handshake.
func waitForIntegrationContentionSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal("integration contention signal timed out")
	}
}

// waitForIntegrationContentionResult bounds one unit-test goroutine result.
func waitForIntegrationContentionResult(t *testing.T, result <-chan error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatal("integration contention result timed out")
		return ctx.Err()
	}
}

// waitForIntegrationConnectionID bounds one physical-ID handshake.
func waitForIntegrationConnectionID(t *testing.T, ids <-chan uint64) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case id := <-ids:
		return id
	case <-ctx.Done():
		t.Fatal("integration connection identity timed out")
		return 0
	}
}
