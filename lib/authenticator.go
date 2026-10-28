package dkim2

import (
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/niliface"
)

// AuthenticationReason identifies the authoritative Draft-08 result reason.
type AuthenticationReason = ReasonCode

const (
	// AuthenticationReasonDuplicateMessageWithoutExploded reports an unexpected
	// replay. It is a local delivery-policy rejection (Draft-08 Section 15.1);
	// the underlying VerifyResult still reports the DKIM2 validity PASS.
	AuthenticationReasonDuplicateMessageWithoutExploded ReasonCode = "duplicate_message_without_exploded"
	// AuthenticationReasonReplayIndeterminate reports unavailable or ambiguous replay storage.
	AuthenticationReasonReplayIndeterminate ReasonCode = "replay_indeterminate"
	// AuthenticationReasonReplayEvidenceUnavailable reports a missing
	// authenticated m=1 hash declaration identity.
	AuthenticationReasonReplayEvidenceUnavailable ReasonCode = "replay_evidence_unavailable"
)

// AuthenticationReplayClass identifies one final replay classification.
type AuthenticationReplayClass string

const (
	// AuthenticationReplayNotChecked means replay is inapplicable before final PASS.
	AuthenticationReplayNotChecked AuthenticationReplayClass = "not_checked"
	// AuthenticationReplayNotEligible means the message passed but only the
	// originator's i=1 signature authenticated it, so no intermediary re-sent
	// it and Draft-08 Section 15.1 replay counting does not apply.
	AuthenticationReplayNotEligible AuthenticationReplayClass = "not_eligible"
	// AuthenticationReplayDisabled means the explicit no-store mode accepted the message.
	AuthenticationReplayDisabled AuthenticationReplayClass = "disabled"
	// AuthenticationReplayFirstSeen means the message-wide identity was inserted once.
	AuthenticationReplayFirstSeen AuthenticationReplayClass = "first_seen"
	// AuthenticationReplayExploded means authenticated fanout permits repeated delivery.
	AuthenticationReplayExploded AuthenticationReplayClass = "exploded"
	// AuthenticationReplayReplayed means an unexpected duplicate was observed.
	AuthenticationReplayReplayed AuthenticationReplayClass = "replayed"
	// AuthenticationReplayIndeterminate means storage could not provide a final answer.
	AuthenticationReplayIndeterminate AuthenticationReplayClass = "indeterminate"
)

// Known reports whether the class belongs to the closed Draft-08 vocabulary.
func (c AuthenticationReplayClass) Known() bool {
	switch c {
	case AuthenticationReplayNotChecked, AuthenticationReplayNotEligible, AuthenticationReplayDisabled, AuthenticationReplayFirstSeen, AuthenticationReplayExploded, AuthenticationReplayReplayed, AuthenticationReplayIndeterminate:
		return true
	default:
		return false
	}
}

// AuthenticationResult is one sealed final stateful Draft-08 result. It layers
// local replay delivery policy over the stateless DKIM2 validity result, which
// Verification returns unchanged.
type AuthenticationResult struct{ state *authenticationResultState }

type authenticationResultState struct {
	verification VerifyResult
	state        ResultState
	reason       AuthenticationReason
	replay       AuthenticationReplayClass
}

// Valid reports whether cryptographic evidence and the final replay state are coherent.
func (r AuthenticationResult) Valid() bool {
	if r.state == nil || !r.state.verification.Valid() || !r.state.state.Known() || !r.state.replay.Known() {
		return false
	}
	if r.state.replay == AuthenticationReplayReplayed {
		return r.state.state == ResultStateFAIL && r.state.reason == AuthenticationReasonDuplicateMessageWithoutExploded
	}
	if r.state.replay == AuthenticationReplayIndeterminate {
		return r.state.state == ResultStateTEMPERROR && (r.state.reason == AuthenticationReasonReplayIndeterminate || r.state.reason == AuthenticationReasonReplayEvidenceUnavailable)
	}
	return r.state.state == r.state.verification.State() && r.state.reason == r.state.verification.PrimaryReason()
}

// Verification returns immutable message-local cryptographic evidence.
func (r AuthenticationResult) Verification() VerifyResult {
	if !r.Valid() {
		return VerifyResult{}
	}
	return r.state.verification
}

// State returns the authoritative final authentication state.
func (r AuthenticationResult) State() ResultState {
	if !r.Valid() {
		return ""
	}
	return r.state.state
}

// PrimaryReason returns the replay-owned reason, or none after final PASS.
func (r AuthenticationResult) PrimaryReason() AuthenticationReason {
	if !r.Valid() {
		return ""
	}
	return r.state.reason
}

// ReplayClass returns the final bounded replay classification.
func (r AuthenticationResult) ReplayClass() AuthenticationReplayClass {
	if !r.Valid() {
		return ""
	}
	return r.state.replay
}

// String returns a content-free final-result representation.
func (AuthenticationResult) String() string { return "dkim2.AuthenticationResult{redacted}" }

// GoString returns a content-free final-result representation.
func (AuthenticationResult) GoString() string { return "dkim2.AuthenticationResult{redacted}" }

// Format prevents formatting from traversing verification or replay facts.
func (AuthenticationResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2.AuthenticationResult{redacted}")
}

// Authenticator owns verification and the mandatory stateful replay decision.
type Authenticator struct {
	verifier  *Verifier
	store     ReplayStore
	deriver   *ReplayDeriver
	retention ReplayRetention
	disabled  bool
	counting  ReplayCountingPolicy
}

// ReplayCountingPolicy is the local delivery policy that decides which
// authenticated messages replay detection counts (Draft-08 Section 15.1). It
// is the single owner of that decision for every replay path. The zero value
// is the default: only messages re-sent by an intermediary are counted.
type ReplayCountingPolicy struct{ direct bool }

// DirectDeliveryReplayCountingPolicy also counts direct deliveries that carry
// only the originator's i=1 signature.
func DirectDeliveryReplayCountingPolicy() ReplayCountingPolicy {
	return ReplayCountingPolicy{direct: true}
}

// CountsDirectDeliveries reports whether i=1-only messages are counted.
func (p ReplayCountingPolicy) CountsDirectDeliveries() bool { return p.direct }

// Counts reports whether replay detection counts the message of a valid
// identity set under this policy.
func (p ReplayCountingPolicy) Counts(identities ReplayIdentitySet) bool {
	return identities.Eligible() || p.direct && identities.Valid()
}

// AuthenticatorOption configures optional local replay delivery policy.
type AuthenticatorOption func(*Authenticator)

// WithDirectDeliveryReplayCounting makes local replay policy count messages
// authenticated only by the originator's i=1 signature. Draft-08 Section 15.1
// leaves replay counting to local delivery policy and does not count such
// direct deliveries by default; a receiver that acts on every accepted
// message, such as a reflector, may count them so an identical direct
// delivery is reported as a replay. The constructors enforce that it is used
// only with an enabled replay store.
func WithDirectDeliveryReplayCounting() AuthenticatorOption {
	return func(a *Authenticator) { a.counting = DirectDeliveryReplayCountingPolicy() }
}

// NewAuthenticator constructs one enabled fail-closed Draft-08 authenticator.
func NewAuthenticator(verifier *Verifier, store ReplayStore, deriver *ReplayDeriver, retention ReplayRetention, options ...AuthenticatorOption) (*Authenticator, error) {
	if verifier == nil || verifier.state == nil || niliface.IsNil(store) || deriver == nil || !retention.Valid() {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	if managed, ok := store.(ManagedReplayStore); ok && managed.State() == ReplayStoreDisabled {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	authenticator := &Authenticator{verifier: verifier, store: store, deriver: deriver, retention: retention}
	for _, option := range options {
		if option == nil {
			return nil, newAPIError(APIErrorCodeInvalidOption)
		}
		option(authenticator)
	}
	return authenticator, nil
}

// NewDisabledAuthenticator constructs the sole explicit no-store authentication
// mode. Replay options require a store, so any option fails closed.
func NewDisabledAuthenticator(verifier *Verifier, options ...AuthenticatorOption) (*Authenticator, error) {
	if verifier == nil || verifier.state == nil || len(options) != 0 {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	return &Authenticator{verifier: verifier, disabled: true}, nil
}

// Authenticate performs message-local verification then one message-wide replay mutation.
func (a *Authenticator) Authenticate(ctx context.Context, request VerifyRequest) (AuthenticationResult, error) {
	if a == nil || a.verifier == nil || ctx == nil {
		return AuthenticationResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	verification, err := a.verifier.Verify(ctx, request)
	if err != nil {
		return AuthenticationResult{}, err
	}
	return a.AuthenticateVerified(ctx, verification)
}

// AuthenticateVerified coordinates replay for immutable evidence already produced by the owned verifier.
func (a *Authenticator) AuthenticateVerified(ctx context.Context, verification VerifyResult) (AuthenticationResult, error) {
	if a == nil || a.verifier == nil || ctx == nil || !verification.Valid() {
		return AuthenticationResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	if verification.State() != ResultStatePASS {
		return newAuthenticationResult(verification, verification.State(), verification.PrimaryReason(), AuthenticationReplayNotChecked), nil
	}
	if a.disabled {
		return newAuthenticationResult(verification, ResultStatePASS, ReasonNone, AuthenticationReplayDisabled), nil
	}
	identities, identityErr := ReplayIdentities(verification)
	if identityErr != nil || !identities.Valid() || identities.Len() != 1 {
		return newAuthenticationResult(verification, ResultStateTEMPERROR, AuthenticationReasonReplayEvidenceUnavailable, AuthenticationReplayIndeterminate), nil
	}
	if !a.counting.Counts(identities) {
		return newAuthenticationResult(verification, ResultStatePASS, ReasonNone, AuthenticationReplayNotEligible), nil
	}
	identity, identityErr := identities.Identity(0)
	if identityErr != nil {
		return newAuthenticationResult(verification, ResultStateTEMPERROR, AuthenticationReasonReplayEvidenceUnavailable, AuthenticationReplayIndeterminate), nil
	}
	key, deriveErr := a.deriver.Derive(ctx, identity)
	if deriveErr != nil {
		return newAuthenticationResult(verification, ResultStateTEMPERROR, AuthenticationReasonReplayIndeterminate, AuthenticationReplayIndeterminate), nil
	}
	check, storeErr := a.store.CheckAndRemember(ctx, key, a.retention)
	if ctx.Err() != nil {
		return newAuthenticationResult(verification, ResultStateTEMPERROR, AuthenticationReasonReplayIndeterminate, AuthenticationReplayIndeterminate), nil
	}
	if storeErr != nil || check == ReplayCheckDisabled || check != ReplayCheckFirstSeen && check != ReplayCheckReplayed {
		return newAuthenticationResult(verification, ResultStateTEMPERROR, AuthenticationReasonReplayIndeterminate, AuthenticationReplayIndeterminate), nil
	}
	_, policyErr := EvaluatePolicy(verification, WithPolicyMode(PolicyModeStrict))
	effectiveExploded := policyErr == nil && identities.Exploded()
	if effectiveExploded {
		return newAuthenticationResult(verification, ResultStatePASS, ReasonNone, AuthenticationReplayExploded), nil
	}
	if check == ReplayCheckReplayed {
		return newAuthenticationResult(verification, ResultStateFAIL, AuthenticationReasonDuplicateMessageWithoutExploded, AuthenticationReplayReplayed), nil
	}
	return newAuthenticationResult(verification, ResultStatePASS, ReasonNone, AuthenticationReplayFirstSeen), nil
}

// newAuthenticationResult seals one internally composed final state.
func newAuthenticationResult(verification VerifyResult, state ResultState, reason AuthenticationReason, replay AuthenticationReplayClass) AuthenticationResult {
	result := AuthenticationResult{state: &authenticationResultState{verification: verification, state: state, reason: reason, replay: replay}}
	if !result.Valid() {
		return AuthenticationResult{}
	}
	return result
}
