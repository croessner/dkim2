//go:build datasourceintegration

package sqlsnapshot

import (
	"context"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// ActivationContentionRole selects one closed integration-only contender role.
type ActivationContentionRole uint8

const (
	// ActivationContentionHolder pauses after readback and before mutation.
	ActivationContentionHolder ActivationContentionRole = iota + 1
	// ActivationContentionWaiter reports transaction and locked-read progress.
	ActivationContentionWaiter
)

// ActivationContentionGate coordinates deterministic real-backend contention.
type ActivationContentionGate struct {
	holderBeforeMutation chan struct{}
	holderRelease        chan struct{}
	waiterBegun          chan struct{}
	waiterReadLock       chan struct{}
	holderConnectionID   chan uint64
	waiterConnectionID   chan uint64
	holderBeforeOnce     sync.Once
	holderReleaseOnce    sync.Once
	waiterBegunOnce      sync.Once
	waiterReadLockOnce   sync.Once
}

// NewActivationContentionGate constructs one isolated integration handshake.
func NewActivationContentionGate() *ActivationContentionGate {
	return &ActivationContentionGate{
		holderBeforeMutation: make(chan struct{}),
		holderRelease:        make(chan struct{}),
		waiterBegun:          make(chan struct{}),
		waiterReadLock:       make(chan struct{}),
		holderConnectionID:   make(chan uint64, 1),
		waiterConnectionID:   make(chan uint64, 1),
	}
}

// HolderConnectionID reports the holder's exact physical transaction identity.
func (g *ActivationContentionGate) HolderConnectionID() <-chan uint64 {
	if g == nil {
		return nil
	}
	return g.holderConnectionID
}

// WaiterConnectionID reports the waiter's exact physical transaction identity.
func (g *ActivationContentionGate) WaiterConnectionID() <-chan uint64 {
	if g == nil {
		return nil
	}
	return g.waiterConnectionID
}

// HolderBeforeMutation reports that all reads completed before mutation entry.
func (g *ActivationContentionGate) HolderBeforeMutation() <-chan struct{} {
	if g == nil {
		return nil
	}
	return g.holderBeforeMutation
}

// WaiterTransactionBegun reports successful creation of the independent transaction.
func (g *ActivationContentionGate) WaiterTransactionBegun() <-chan struct{} {
	if g == nil {
		return nil
	}
	return g.waiterBegun
}

// WaiterReadLockAttempt reports entry into the waiter's physical lock read.
func (g *ActivationContentionGate) WaiterReadLockAttempt() <-chan struct{} {
	if g == nil {
		return nil
	}
	return g.waiterReadLock
}

// ReleaseHolder allows the paused transaction to mutate and commit once.
func (g *ActivationContentionGate) ReleaseHolder() {
	if g != nil {
		g.holderReleaseOnce.Do(func() { close(g.holderRelease) })
	}
}

// DecorateActivationContention installs one integration-only activator wrapper.
func DecorateActivationContention(
	administrator *Administrator,
	gate *ActivationContentionGate,
	role ActivationContentionRole,
) error {
	if administrator == nil || administrator.activator == nil || gate == nil ||
		role != ActivationContentionHolder && role != ActivationContentionWaiter {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	administrator.activator = &activationContentionConnector{
		AdministrationConnector: administrator.activator,
		gate:                    gate,
		role:                    role,
	}
	return nil
}

type activationContentionConnector struct {
	AdministrationConnector
	gate *ActivationContentionGate
	role ActivationContentionRole
}

type activationConnectionIDProvider interface {
	IntegrationConnectionID(context.Context) (uint64, error)
}

// Begin decorates one successfully opened activation transaction.
func (c *activationContentionConnector) Begin(
	ctx context.Context,
	mode AdministrationMode,
) (AdministrationTransaction, error) {
	transaction, err := c.AdministrationConnector.Begin(ctx, mode)
	if err != nil {
		return nil, err
	}
	if mode != AdministrationActivation {
		return transaction, nil
	}
	provider, ok := transaction.(activationConnectionIDProvider)
	if !ok {
		_ = transaction.Rollback(ctx)
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	connectionID, err := provider.IntegrationConnectionID(ctx)
	if err != nil || connectionID == 0 {
		_ = transaction.Rollback(ctx)
		if err != nil {
			return nil, err
		}
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if c.role == ActivationContentionHolder {
		c.gate.holderConnectionID <- connectionID
	} else {
		c.gate.waiterConnectionID <- connectionID
	}
	if c.role == ActivationContentionWaiter {
		c.gate.waiterBegunOnce.Do(func() { close(c.gate.waiterBegun) })
	}
	return &activationContentionTransaction{
		AdministrationTransaction: transaction,
		gate:                      c.gate,
		role:                      c.role,
	}, nil
}

type activationContentionTransaction struct {
	AdministrationTransaction
	gate *ActivationContentionGate
	role ActivationContentionRole
}

// ReadLock signals the waiter's exact locked-read attempt before delegation.
func (t *activationContentionTransaction) ReadLock(
	ctx context.Context,
	locked bool,
) (uint64, *string, error) {
	if t.role == ActivationContentionWaiter && locked {
		t.gate.waiterReadLockOnce.Do(func() { close(t.gate.waiterReadLock) })
	}
	return t.AdministrationTransaction.ReadLock(ctx, locked)
}

// ActivateCurrent pauses the holder after complete readback and before mutation.
func (t *activationContentionTransaction) ActivateCurrent(
	ctx context.Context,
	current CurrentPointerFence,
	candidate CandidateRootFence,
) (int64, error) {
	if t.role == ActivationContentionHolder {
		t.gate.holderBeforeOnce.Do(func() { close(t.gate.holderBeforeMutation) })
		select {
		case <-t.gate.holderRelease:
		case <-ctx.Done():
			return 0, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
	}
	return t.AdministrationTransaction.ActivateCurrent(ctx, current, candidate)
}
