package replay

import (
	"context"
	"fmt"
	"io"
)

const disabledStoreRedactedText = "replay_disabled_store"

// DisabledStore is an explicit no-storage replay provider.
type DisabledStore struct {
	state *disabledStoreState
}

// disabledStoreState owns lifecycle state behind one format-safe handle.
type disabledStoreState struct {
	gate *lifecycleGate
}

// NewDisabledStore constructs one explicit disabled replay provider.
func NewDisabledStore() *DisabledStore {
	return &DisabledStore{state: &disabledStoreState{gate: newLifecycleGate(StoreDisabled)}}
}

// CheckAndRemember returns disabled without inspecting key or retention.
func (s *DisabledStore) CheckAndRemember(
	ctx context.Context,
	_ Key,
	_ Retention,
) (Check, error) {
	if err := s.disabledAdmission(ctx); err != nil {
		return 0, err
	}
	return CheckDisabled, nil
}

// ReservePropagation returns disabled without inspecting key, retention, or lease.
func (s *DisabledStore) ReservePropagation(ctx context.Context, _ Key, _ Retention, _ Lease) (PropagationReservation, error) {
	if err := s.disabledAdmission(ctx); err != nil {
		return 0, err
	}
	return PropagationReservationDisabled, nil
}

// CommitPropagation returns disabled without inspecting the key.
func (s *DisabledStore) CommitPropagation(ctx context.Context, _ Key) (PropagationCommit, error) {
	if err := s.disabledAdmission(ctx); err != nil {
		return 0, err
	}
	return PropagationCommitDisabled, nil
}

// disabledAdmission applies the context and lifecycle rules shared by every disabled operation.
func (s *DisabledStore) disabledAdmission(ctx context.Context) error {
	if err := PreflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.state == nil || s.state.gate == nil {
		return NewError(ErrorCodeMisconfigured)
	}
	switch s.state.gate.State() {
	case StoreDisabled:
		return nil
	case StoreClosing, StoreClosed:
		return NewError(ErrorCodeClosed)
	default:
		return NewError(ErrorCodeInternalInvariant)
	}
}

// State returns one bounded lock-free lifecycle snapshot.
func (s *DisabledStore) State() StoreState {
	if s == nil || s.state == nil || s.state.gate == nil {
		return 0
	}
	return s.state.gate.State()
}

// Close atomically closes the disabled provider and is idempotent.
func (s *DisabledStore) Close(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if err := PreflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.state == nil || s.state.gate == nil {
		return NewError(ErrorCodeMisconfigured)
	}
	drained, err := s.state.gate.beginClose()
	if err != nil {
		return err
	}
	if err := waitForDrain(ctx, drained); err != nil {
		return err
	}
	return s.state.gate.publishClosed()
}

// String returns a constant representation without lifecycle detail.
func (DisabledStore) String() string { return disabledStoreRedactedText }

// GoString returns a constant representation without lifecycle detail.
func (DisabledStore) GoString() string { return disabledStoreRedactedText }

// Format prevents every formatting verb from exposing provider state.
func (DisabledStore) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, disabledStoreRedactedText)
}

// MarshalText rejects serialization of disabled-provider state.
func (DisabledStore) MarshalText() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// MarshalJSON rejects serialization of disabled-provider state.
func (DisabledStore) MarshalJSON() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}
