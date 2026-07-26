package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app/outcome"
)

const (
	replayCoordinatorErrorText = "dkim2d replay coordination failure"
	replayCoordinatorRedacted  = "dkim2d_replay_coordinator"
	replayOutcomeRedacted      = "dkim2d_replay_outcome"
)

// ReplayResultClass is the transport-neutral replay aggregate vocabulary.
type ReplayResultClass = outcome.ReplayClass

const (
	// ReplayResultNotChecked means the verification and policy gate skipped replay.
	ReplayResultNotChecked = outcome.ReplayNotChecked
	// ReplayResultDisabled means explicit local configuration disabled replay.
	ReplayResultDisabled = outcome.ReplayDisabled
	// ReplayResultFirstSeen means every authenticated identity was newly retained.
	ReplayResultFirstSeen = outcome.ReplayFirstSeen
	// ReplayResultReplayed means at least one authenticated identity already existed.
	ReplayResultReplayed = outcome.ReplayReplayed
	// ReplayResultIndeterminate means replay storage cannot be classified safely.
	ReplayResultIndeterminate = outcome.ReplayIndeterminate
)

// FinalDisposition is the transport-neutral final daemon disposition.
type FinalDisposition = outcome.FinalDisposition

const (
	// FinalDispositionAccept permits normal continuation.
	FinalDispositionAccept = outcome.DispositionAccept
	// FinalDispositionReject reports permanent local rejection.
	FinalDispositionReject = outcome.DispositionReject
	// FinalDispositionTempfail requests a retryable deferral.
	FinalDispositionTempfail = outcome.DispositionTempfail
	// FinalDispositionContinue withholds a terminal daemon decision.
	FinalDispositionContinue = outcome.DispositionContinue
)

// ReplayCoordinatorError reports one content-free construction or coordination failure.
type ReplayCoordinatorError struct{}

// Error returns a constant content-free replay diagnostic.
func (*ReplayCoordinatorError) Error() string { return replayCoordinatorErrorText }

// Is recognizes the bounded replay-coordinator error type.
func (*ReplayCoordinatorError) Is(target error) bool {
	_, ok := target.(*ReplayCoordinatorError)
	return ok
}

// replayKeyDeriver is the narrow opaque-key derivation seam.
type replayKeyDeriver interface {
	Derive(context.Context, dkim2.ReplayIdentity) (dkim2.ReplayKey, error)
}

// ReplayCoordinator owns the immutable local replay policy and provider boundary.
type ReplayCoordinator struct {
	state *replayCoordinatorState
}

// replayCoordinatorState retains only the selected closed backend dependencies.
type replayCoordinatorState struct {
	disabled  bool
	deriver   replayKeyDeriver
	store     dkim2.ReplayStore
	retention dkim2.ReplayRetention
}

// ReplayOutcome is one immutable replay aggregate and final daemon disposition.
type ReplayOutcome struct {
	state *replayOutcomeState
}

// replayOutcomeState owns the bounded coordination result.
type replayOutcomeState struct {
	class            ReplayResultClass
	disposition      FinalDisposition
	possibleMutation bool
}

// NewDisabledReplayCoordinator constructs an explicit no-derivation replay policy.
func NewDisabledReplayCoordinator() *ReplayCoordinator {
	return &ReplayCoordinator{state: &replayCoordinatorState{disabled: true}}
}

// NewEnabledReplayCoordinator constructs one provider-neutral enabled replay policy.
func NewEnabledReplayCoordinator(
	deriver *dkim2.ReplayDeriver,
	store dkim2.ReplayStore,
	retention dkim2.ReplayRetention,
) (*ReplayCoordinator, error) {
	return newEnabledReplayCoordinator(deriver, store, retention)
}

// newEnabledReplayCoordinator constructs an enabled coordinator through narrow testable seams.
func newEnabledReplayCoordinator(
	deriver replayKeyDeriver,
	store dkim2.ReplayStore,
	retention dkim2.ReplayRetention,
) (*ReplayCoordinator, error) {
	if nilInterface(deriver) || nilInterface(store) || !retention.Valid() {
		return nil, &ReplayCoordinatorError{}
	}
	return &ReplayCoordinator{state: &replayCoordinatorState{
		deriver: deriver, store: store, retention: retention,
	}}, nil
}

// Coordinate applies the exact replay gate, deterministic batch, and disposition matrix.
func (c *ReplayCoordinator) Coordinate(ctx context.Context, domain DomainResult) (ReplayOutcome, error) {
	if c == nil || c.state == nil || nilInterface(ctx) || !domain.valid() {
		return ReplayOutcome{}, &ReplayCoordinatorError{}
	}
	if err := replayContextError(ctx); err != nil {
		return ReplayOutcome{}, err
	}
	verification, verificationErr := domain.Verification()
	policy, policyErr := domain.Policy()
	if verificationErr != nil || policyErr != nil ||
		policy.VerificationState() != verification.State() || !policy.Verdict().Known() {
		return ReplayOutcome{}, &ReplayCoordinatorError{}
	}

	if verification.State() != dkim2.ResultStatePASS || policy.Verdict() != dkim2.PolicyVerdictAccept {
		disposition, ok := dispositionForPolicy(policy.Verdict())
		if !ok {
			return ReplayOutcome{}, &ReplayCoordinatorError{}
		}
		if err := replayContextError(ctx); err != nil {
			return ReplayOutcome{}, err
		}
		return newReplayOutcome(ReplayResultNotChecked, disposition, false), nil
	}
	if c.state.disabled {
		if err := replayContextError(ctx); err != nil {
			return ReplayOutcome{}, err
		}
		return newReplayOutcome(ReplayResultDisabled, FinalDispositionAccept, false), nil
	}
	if nilInterface(c.state.deriver) || nilInterface(c.state.store) || !c.state.retention.Valid() {
		return ReplayOutcome{}, &ReplayCoordinatorError{}
	}

	return c.coordinateEnabled(ctx, verification)
}

// coordinateEnabled derives every key before sequentially mutating the selected store.
func (c *ReplayCoordinator) coordinateEnabled(
	ctx context.Context,
	verification dkim2.VerifyResult,
) (ReplayOutcome, error) {
	if err := replayContextError(ctx); err != nil {
		return ReplayOutcome{}, err
	}
	identities, identityErr := dkim2.ReplayIdentities(verification)
	if err := replayContextError(ctx); err != nil {
		return ReplayOutcome{}, err
	}
	if identityErr != nil || !identities.Valid() || identities.Len() == 0 {
		return indeterminateReplayOutcome(false), nil
	}

	keys := make([]dkim2.ReplayKey, identities.Len())
	for index := range identities.Len() {
		if err := replayContextError(ctx); err != nil {
			return ReplayOutcome{}, err
		}
		identity, err := identities.Identity(index)
		if contextErr := replayContextError(ctx); contextErr != nil {
			return ReplayOutcome{}, contextErr
		}
		if err != nil || !identity.Valid() {
			return indeterminateReplayOutcome(false), nil
		}
		key, err := c.state.deriver.Derive(ctx, identity)
		if contextErr := replayContextError(ctx); contextErr != nil {
			return ReplayOutcome{}, contextErr
		}
		if err != nil || !key.Valid() {
			return indeterminateReplayOutcome(false), nil
		}
		keys[index] = key
	}
	if err := replayContextError(ctx); err != nil {
		return ReplayOutcome{}, err
	}

	possibleMutation := false
	indeterminate := false
	replayed := false
	for _, key := range keys {
		if err := replayContextError(ctx); err != nil {
			return interruptedReplayOutcome(possibleMutation, err)
		}
		check, err := c.state.store.CheckAndRemember(ctx, key, c.state.retention)
		contextErr := replayContextError(ctx)
		classification := classifyReplayCheck(check, err, contextErr)
		possibleMutation = possibleMutation || classification.possibleMutation
		indeterminate = indeterminate || classification.indeterminate
		replayed = replayed || classification.replayed

		if contextErr != nil {
			return interruptedReplayOutcome(possibleMutation, contextErr)
		}
		if classification.stop {
			return indeterminateReplayOutcome(possibleMutation), nil
		}
	}

	switch {
	case indeterminate:
		return indeterminateReplayOutcome(possibleMutation), nil
	case replayed:
		return newReplayOutcome(ReplayResultReplayed, FinalDispositionReject, possibleMutation), nil
	default:
		return newReplayOutcome(ReplayResultFirstSeen, FinalDispositionAccept, possibleMutation), nil
	}
}

// replayCheckClassification records only bounded mutation and aggregate facts.
type replayCheckClassification struct {
	possibleMutation bool
	indeterminate    bool
	replayed         bool
	stop             bool
}

// classifyReplayCheck validates one closed store pair without retaining raw errors.
func classifyReplayCheck(
	check dkim2.ReplayCheck,
	err error,
	contextErr error,
) replayCheckClassification {
	if err == nil {
		switch check {
		case dkim2.ReplayCheckFirstSeen:
			return replayCheckClassification{possibleMutation: true}
		case dkim2.ReplayCheckReplayed:
			return replayCheckClassification{replayed: true}
		default:
			return replayCheckClassification{possibleMutation: true, indeterminate: true}
		}
	}
	if !dkim2.IsReplayError(err) {
		return replayCheckClassification{possibleMutation: true, indeterminate: true}
	}
	code := dkim2.ReplayErrorCodeOf(err)
	if check != 0 {
		return replayCheckClassification{
			possibleMutation: true,
			indeterminate:    true,
			stop: code == dkim2.ReplayErrorCancelled ||
				code == dkim2.ReplayErrorDeadlineExceeded,
		}
	}
	switch code {
	case dkim2.ReplayErrorCancelled, dkim2.ReplayErrorDeadlineExceeded:
		if code == dkim2.ReplayErrorCancelled && contextErr == context.Canceled ||
			code == dkim2.ReplayErrorDeadlineExceeded && contextErr == context.DeadlineExceeded {
			return replayCheckClassification{stop: true}
		}
		return replayCheckClassification{possibleMutation: true, indeterminate: true, stop: true}
	case dkim2.ReplayErrorLimitExceeded, dkim2.ReplayErrorUnavailable, dkim2.ReplayErrorClosed:
		return replayCheckClassification{indeterminate: true}
	case dkim2.ReplayErrorInvalidRequest, dkim2.ReplayErrorMisconfigured,
		dkim2.ReplayErrorIndeterminate, dkim2.ReplayErrorInconsistent,
		dkim2.ReplayErrorInternalInvariant:
		return replayCheckClassification{possibleMutation: true, indeterminate: true}
	default:
		return replayCheckClassification{possibleMutation: true, indeterminate: true}
	}
}

// interruptedReplayOutcome applies transport precedence before possible mutation.
func interruptedReplayOutcome(possibleMutation bool, err error) (ReplayOutcome, error) {
	if possibleMutation {
		return indeterminateReplayOutcome(true), nil
	}
	return ReplayOutcome{}, err
}

// indeterminateReplayOutcome constructs the exact retryable closed failure result.
func indeterminateReplayOutcome(possibleMutation bool) ReplayOutcome {
	return newReplayOutcome(ReplayResultIndeterminate, FinalDispositionTempfail, possibleMutation)
}

// newReplayOutcome constructs one coherent closed replay result.
func newReplayOutcome(
	class ReplayResultClass,
	disposition FinalDisposition,
	possibleMutation bool,
) ReplayOutcome {
	return ReplayOutcome{state: &replayOutcomeState{
		class: class, disposition: disposition, possibleMutation: possibleMutation,
	}}
}

// dispositionForPolicy maps one closed policy verdict without changing policy truth.
func dispositionForPolicy(verdict dkim2.PolicyVerdict) (FinalDisposition, bool) {
	switch verdict {
	case dkim2.PolicyVerdictAccept:
		return FinalDispositionAccept, true
	case dkim2.PolicyVerdictReject:
		return FinalDispositionReject, true
	case dkim2.PolicyVerdictTempfail:
		return FinalDispositionTempfail, true
	case dkim2.PolicyVerdictContinue:
		return FinalDispositionContinue, true
	default:
		return 0, false
	}
}

// Valid reports whether the outcome is one coherent matrix member.
func (o ReplayOutcome) Valid() bool {
	if o.state == nil || !o.state.class.Known() || !o.state.disposition.Known() {
		return false
	}
	switch o.state.class {
	case ReplayResultNotChecked:
		return !o.state.possibleMutation
	case ReplayResultDisabled:
		return o.state.disposition == FinalDispositionAccept && !o.state.possibleMutation
	case ReplayResultFirstSeen:
		return o.state.disposition == FinalDispositionAccept && o.state.possibleMutation
	case ReplayResultReplayed:
		return o.state.disposition == FinalDispositionReject
	case ReplayResultIndeterminate:
		return o.state.disposition == FinalDispositionTempfail
	default:
		return false
	}
}

// Class returns the privacy-minimal replay aggregate.
func (o ReplayOutcome) Class() ReplayResultClass {
	if !o.Valid() {
		return 0
	}
	return o.state.class
}

// Disposition returns the final daemon disposition.
func (o ReplayOutcome) Disposition() FinalDisposition {
	if !o.Valid() {
		return 0
	}
	return o.state.disposition
}

// possibleStoreMutation reports whether any store mutation may have occurred.
func (o ReplayOutcome) possibleStoreMutation() bool {
	return o.Valid() && o.state.possibleMutation
}

// String returns a content-free replay-coordinator representation.
func (ReplayCoordinator) String() string { return replayCoordinatorRedacted }

// GoString returns a content-free replay-coordinator representation.
func (ReplayCoordinator) GoString() string { return replayCoordinatorRedacted }

// Format prevents formatting from traversing replay dependencies.
func (ReplayCoordinator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayCoordinatorRedacted)
}

// MarshalJSON rejects serialization of retained replay dependencies.
func (ReplayCoordinator) MarshalJSON() ([]byte, error) {
	return nil, &ReplayCoordinatorError{}
}

// MarshalText rejects diagnostic serialization of replay dependencies.
func (ReplayCoordinator) MarshalText() ([]byte, error) {
	return nil, &ReplayCoordinatorError{}
}

// String returns a content-free replay-outcome representation.
func (ReplayOutcome) String() string { return replayOutcomeRedacted }

// GoString returns a content-free replay-outcome representation.
func (ReplayOutcome) GoString() string { return replayOutcomeRedacted }

// Format prevents formatting from traversing replay outcome state.
func (ReplayOutcome) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayOutcomeRedacted)
}

// MarshalJSON rejects serialization outside the package-owned response mapper.
func (ReplayOutcome) MarshalJSON() ([]byte, error) {
	return nil, &ReplayCoordinatorError{}
}

// MarshalText rejects diagnostic serialization of replay outcome state.
func (ReplayOutcome) MarshalText() ([]byte, error) {
	return nil, &ReplayCoordinatorError{}
}

// IsReplayCoordinatorError reports whether an error is a bounded coordination failure.
func IsReplayCoordinatorError(err error) bool {
	return errors.Is(err, &ReplayCoordinatorError{})
}

// replayContextError returns only exact terminal context identity or a bounded contract failure.
func replayContextError(ctx context.Context) error {
	valid, terminal := boundedContextState(ctx)
	if !valid {
		return &ReplayCoordinatorError{}
	}
	return terminal
}

// boundedContextState contains hostile context implementations at one app boundary.
func boundedContextState(ctx context.Context) (valid bool, terminal error) {
	defer func() {
		if recover() != nil {
			valid = false
			terminal = nil
		}
	}()
	if nilInterface(ctx) {
		return false, nil
	}
	switch err := ctx.Err(); err {
	case nil:
		deadline, present := ctx.Deadline()
		if present && !time.Now().Before(deadline) {
			return true, context.DeadlineExceeded
		}
		return true, nil
	case context.Canceled:
		return true, context.Canceled
	case context.DeadlineExceeded:
		return true, context.DeadlineExceeded
	default:
		return false, nil
	}
}
