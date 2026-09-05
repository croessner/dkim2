package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

const propagationReplayRedacted = "dkim2d_propagation_replay"

// PropagationReplayService is the narrow two-phase propagation replay seam.
// ReservePropagation derives the propagation coordinate of one verified
// received notification under the distinct propagation frame and reserves
// it; CommitPropagation moves a reserved coordinate to committed. The key is
// returned so that the caller can bind an opaque commit token to it without
// retaining any storage-key byte.
type PropagationReplayService interface {
	ReservePropagation(context.Context, dkim2.VerifyResult) (dkim2.ReplayPropagationReservation, dkim2.ReplayKey, error)
	CommitPropagation(context.Context, dkim2.ReplayKey) (dkim2.ReplayPropagationCommit, error)
}

// propagationKeyDeriver is the narrow propagation-frame derivation seam.
type propagationKeyDeriver interface {
	DerivePropagation(context.Context, dkim2.ReplayIdentity) (dkim2.ReplayKey, error)
}

// PropagationReplayCoordinator applies the propagation replay contract over
// the same deriver, retention, and store as the process route while keeping
// the coordinate under the distinct propagation frame, so that a preceding
// process call on the same notification never blocks its first propagation.
type PropagationReplayCoordinator struct {
	state *propagationReplayState
}

// propagationReplayState retains only the selected closed dependencies.
type propagationReplayState struct {
	disabled  bool
	deriver   propagationKeyDeriver
	store     dkim2.ReplayPropagationStore
	retention dkim2.ReplayRetention
	lease     dkim2.ReplayLease
}

// NewDisabledPropagationReplayCoordinator constructs the explicit no-storage
// propagation policy: every reservation and commit is reported disabled.
func NewDisabledPropagationReplayCoordinator() *PropagationReplayCoordinator {
	return &PropagationReplayCoordinator{state: &propagationReplayState{disabled: true}}
}

// NewPropagationReplayCoordinator constructs one enabled propagation replay
// policy over a provider-neutral propagation store.
func NewPropagationReplayCoordinator(
	deriver *dkim2.ReplayDeriver,
	store dkim2.ReplayPropagationStore,
	retention dkim2.ReplayRetention,
	lease dkim2.ReplayLease,
) (*PropagationReplayCoordinator, error) {
	if deriver == nil {
		return nil, &ReplayCoordinatorError{}
	}
	return newPropagationReplayCoordinator(deriver, store, retention, lease)
}

// newPropagationReplayCoordinator constructs an enabled coordinator through narrow seams.
func newPropagationReplayCoordinator(
	deriver propagationKeyDeriver,
	store dkim2.ReplayPropagationStore,
	retention dkim2.ReplayRetention,
	lease dkim2.ReplayLease,
) (*PropagationReplayCoordinator, error) {
	if nilInterface(deriver) || nilInterface(store) || !retention.Valid() || !lease.Valid() {
		return nil, &ReplayCoordinatorError{}
	}
	return &PropagationReplayCoordinator{state: &propagationReplayState{
		deriver: deriver, store: store, retention: retention, lease: lease,
	}}, nil
}

// ReservePropagation derives exactly one propagation coordinate from the
// notification's own authenticated identity and reserves it. Every ambiguous
// identity, derivation, or store outcome is returned as an error so that the
// route fails closed as a temporary condition.
func (c *PropagationReplayCoordinator) ReservePropagation(
	ctx context.Context,
	verification dkim2.VerifyResult,
) (dkim2.ReplayPropagationReservation, dkim2.ReplayKey, error) {
	if c == nil || c.state == nil {
		return 0, dkim2.ReplayKey{}, &ReplayCoordinatorError{}
	}
	if err := replayContextError(ctx); err != nil {
		return 0, dkim2.ReplayKey{}, err
	}
	if c.state.disabled {
		return dkim2.ReplayPropagationReservationDisabled, dkim2.ReplayKey{}, nil
	}
	key, err := c.deriveKey(ctx, verification)
	if err != nil {
		return 0, dkim2.ReplayKey{}, err
	}
	reservation, err := c.state.store.ReservePropagation(ctx, key, c.state.retention, c.state.lease)
	if contextErr := replayContextError(ctx); contextErr != nil {
		return 0, dkim2.ReplayKey{}, contextErr
	}
	if err != nil || !reservation.Known() || reservation == dkim2.ReplayPropagationReservationDisabled {
		return 0, dkim2.ReplayKey{}, &ReplayCoordinatorError{}
	}
	return reservation, key, nil
}

// CommitPropagation moves one reserved coordinate to committed.
func (c *PropagationReplayCoordinator) CommitPropagation(
	ctx context.Context,
	key dkim2.ReplayKey,
) (dkim2.ReplayPropagationCommit, error) {
	if c == nil || c.state == nil {
		return 0, &ReplayCoordinatorError{}
	}
	if err := replayContextError(ctx); err != nil {
		return 0, err
	}
	if c.state.disabled {
		return dkim2.ReplayPropagationCommitDisabled, nil
	}
	if !key.Valid() {
		return 0, &ReplayCoordinatorError{}
	}
	commit, err := c.state.store.CommitPropagation(ctx, key)
	if contextErr := replayContextError(ctx); contextErr != nil {
		return 0, contextErr
	}
	if err != nil || !commit.Known() || commit == dkim2.ReplayPropagationCommitDisabled {
		return 0, &ReplayCoordinatorError{}
	}
	return commit, nil
}

// deriveKey projects the notification's single message-wide identity under
// the propagation frame. A notification is a fresh single-instance message,
// so exactly one identity is admitted.
func (c *PropagationReplayCoordinator) deriveKey(
	ctx context.Context,
	verification dkim2.VerifyResult,
) (dkim2.ReplayKey, error) {
	identities, err := dkim2.ReplayIdentities(verification)
	if err != nil || !identities.Valid() || identities.Len() != 1 {
		return dkim2.ReplayKey{}, &ReplayCoordinatorError{}
	}
	identity, err := identities.Identity(0)
	if err != nil || !identity.Valid() {
		return dkim2.ReplayKey{}, &ReplayCoordinatorError{}
	}
	key, err := c.state.deriver.DerivePropagation(ctx, identity)
	if contextErr := replayContextError(ctx); contextErr != nil {
		return dkim2.ReplayKey{}, contextErr
	}
	if err != nil || !key.Valid() {
		return dkim2.ReplayKey{}, &ReplayCoordinatorError{}
	}
	return key, nil
}

// String returns a content-free coordinator representation.
func (*PropagationReplayCoordinator) String() string { return propagationReplayRedacted }

// GoString returns a content-free coordinator representation.
func (*PropagationReplayCoordinator) GoString() string { return propagationReplayRedacted }

// Format prevents formatting from traversing replay dependencies.
func (*PropagationReplayCoordinator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationReplayRedacted)
}

// PropagationReplay returns the runtime's propagation replay policy over its
// own backend: the disabled backend reports disabled outcomes, and every
// enabled backend must implement the two-phase propagation contract, which
// the memory and Valkey providers do. A backend without that contract is
// refused so that the propagation route is never composed over a store that
// cannot hold a pending record.
func (r *ReplayRuntime) PropagationReplay(lease time.Duration) (PropagationReplayService, error) {
	if r == nil || r.state == nil || nilInterface(r.state.store) {
		return nil, &ReplayRuntimeError{}
	}
	if r.state.backend == config.ReplayDisabled {
		return NewDisabledPropagationReplayCoordinator(), nil
	}
	store, ok := r.state.store.(dkim2.ReplayPropagationStore)
	if !ok || nilInterface(store) || r.state.deriver == nil {
		return nil, &ReplayRuntimeError{}
	}
	validLease, err := dkim2.NewReplayLease(lease)
	if err != nil {
		return nil, &ReplayRuntimeError{}
	}
	coordinator, err := NewPropagationReplayCoordinator(r.state.deriver, store, r.state.retention, validLease)
	if err != nil {
		return nil, &ReplayRuntimeError{}
	}
	return coordinator, nil
}
