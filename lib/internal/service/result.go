package service

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/policy"
)

// Target identifies the current signature and instance numbers.
type Target struct{ Sequence, Instance uint64 }

// CheckFact records one bounded check and reason.
type CheckFact struct {
	Class  CheckClass
	Reason Reason
}

// SignatureSetFact records one bounded signature-set outcome.
type SignatureSetFact struct {
	Algorithm Algorithm
	Status    SignatureStatus
	Reason    Reason
	Selector  string
	KeyPolicy KeyPolicyMetadata
}

// Result is an immutable internal current-verification outcome.
type Result struct {
	draft                 string
	state                 State
	scope                 Scope
	historicalContent     HistoricalState
	historicalSignatures  HistoricalState
	custody               Custody
	target                Target
	primaryReason         Reason
	checks                []CheckFact
	signatures            []SignatureSetFact
	policyProjection      policy.Projection
	replayProjection      ReplayProjection
	hasReplayProjection   bool
	verifierProjection    VerifierProjection
	hasVerifierProjection bool
}

// newResult constructs an immutable populated service result.
func newResult(state State, custody Custody, target Target, reason Reason, checks []CheckFact, signatures []SignatureSetFact) Result {
	if !resultDataValid(state, custody, reason, checks, signatures) {
		return internalContractResult(target)
	}
	return Result{
		draft: DraftIdentifier, state: state, scope: ScopeCurrent,
		historicalContent: HistoricalNotEvaluated, historicalSignatures: HistoricalNotEvaluated,
		custody: custody, target: target, primaryReason: reason,
		checks: slices.Clone(checks), signatures: slices.Clone(signatures),
	}
}

// resultDataValid enforces closed vocabularies and impossible-state invariants.
func resultDataValid(state State, custody Custody, reason Reason, checks []CheckFact, signatures []SignatureSetFact) bool {
	if !state.Known() || !custody.Known() || !reason.Known() {
		return false
	}
	if state == StatePASS && (custody == CustodyNotEvaluated || custody == CustodyTerminalNDRequiresOOB || reason != ReasonNone) {
		return false
	}
	for _, fact := range checks {
		if !fact.Class.Known() || !fact.Reason.Known() {
			return false
		}
	}
	for _, fact := range signatures {
		if !fact.Algorithm.Known() || !fact.Status.Known() || !fact.Reason.Known() || !fact.KeyPolicy.Valid() || !serviceResultKeyPolicyCoherent(fact) {
			return false
		}
		if (fact.Status == SignatureFAIL) != (fact.Selector != "") || len(fact.Selector) > 253 {
			return false
		}
	}
	return true
}

// serviceResultKeyPolicyCoherent restricts DNS metadata to unique-record result reasons.
func serviceResultKeyPolicyCoherent(fact SignatureSetFact) bool {
	if fact.KeyPolicy == (KeyPolicyMetadata{}) {
		return true
	}
	switch fact.Reason {
	case ReasonNone, ReasonSignatureMismatch, ReasonInvalidKey, ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch:
		return true
	default:
		return false
	}
}

// internalContractResult returns a bounded fail-closed invariant result.
func internalContractResult(target Target) Result {
	result := Result{
		draft: DraftIdentifier, state: StatePERMERROR, scope: ScopeCurrent,
		historicalContent: HistoricalNotEvaluated, historicalSignatures: HistoricalNotEvaluated,
		custody: CustodyNotEvaluated, target: target, primaryReason: ReasonInternalContract,
		checks: []CheckFact{{Class: CheckInternalContract, Reason: ReasonInternalContract}},
	}
	if target == (Target{}) {
		projection, _ := policy.NewUnavailableProjection(policy.PreTargetInternalContract)
		result.policyProjection = projection
	}
	return result
}

// withPolicyProjection attaches an independently cloned coherent projection.
func (r Result) withPolicyProjection(projection policy.Projection) Result {
	if !projection.Valid() {
		return r
	}
	r.policyProjection = projection.Clone()
	return r
}

// withAuthenticatedHistory seals successful all-hop coverage.
func (r Result) withAuthenticatedHistory(content HistoricalState, projection policy.Projection) Result {
	if r.state != StatePASS || !content.Known() || content == HistoricalNotEvaluated || !projection.Valid() {
		return internalContractResult(r.target)
	}
	r.scope = ScopeChain
	r.historicalContent = content
	r.historicalSignatures = HistoricalComplete
	r.policyProjection = projection.Clone()
	return r
}

// withAuthenticatedOrigin upgrades an m=1 current proof without a second key lookup.
func (r Result) withAuthenticatedOrigin() Result {
	if r.state != StatePASS || r.target.Sequence != 1 || r.target.Instance != 1 || !r.policyProjection.Valid() {
		return internalContractResult(r.target)
	}
	r.scope = ScopeChain
	r.historicalContent = HistoricalComplete
	r.historicalSignatures = HistoricalComplete
	return r
}

// Draft returns the exact active behavior baseline.
func (r Result) Draft() string { return r.draft }

// State returns one of the four service states.
func (r Result) State() State { return r.state }

// Scope returns the authenticated verification scope.
func (r Result) Scope() Scope { return r.scope }

// HistoricalContent returns historical content coverage.
func (r Result) HistoricalContent() HistoricalState { return r.historicalContent }

// HistoricalSignatures returns historical cryptographic coverage.
func (r Result) HistoricalSignatures() HistoricalState { return r.historicalSignatures }

// Custody returns structural next-domain coverage.
func (r Result) Custody() Custody { return r.custody }

// Target returns bounded target identifiers.
func (r Result) Target() Target { return r.target }

// PrimaryReason returns the highest-precedence bounded reason.
func (r Result) PrimaryReason() Reason { return r.primaryReason }

// Checks returns immutable bounded check facts.
func (r Result) Checks() []CheckFact { return slices.Clone(r.checks) }

// SignatureSets returns immutable bounded signature-set facts.
func (r Result) SignatureSets() []SignatureSetFact { return slices.Clone(r.signatures) }

// PolicyProjection returns an independent internal facade-transfer clone.
func (r Result) PolicyProjection() policy.Projection { return r.policyProjection.Clone() }

// withReplayProjection attaches one independently cloned coherent replay projection.
func (r Result) withReplayProjection(projection ReplayProjection) Result {
	if !projection.Valid() || r.state != StatePASS {
		return r
	}
	r.replayProjection = projection.clone()
	r.hasReplayProjection = true
	return r
}

// ReplayProjection returns one independent sealed replay projection when present.
func (r Result) ReplayProjection() (ReplayProjection, bool) {
	if !r.hasReplayProjection || !r.replayProjection.Valid() || r.state != StatePASS {
		return ReplayProjection{}, false
	}
	return r.replayProjection.clone(), true
}

// withVerifierProjection attaches one independently cloned complete verifier projection.
func (r Result) withVerifierProjection(projection VerifierProjection) Result {
	if !projection.Valid() || r.state != StatePASS || r.scope != ScopeChain {
		return r
	}
	r.verifierProjection = projection.clone()
	r.hasVerifierProjection = true
	return r
}

// VerifierProjection returns one independent sealed projection when present.
func (r Result) VerifierProjection() (VerifierProjection, bool) {
	if !r.hasVerifierProjection || !r.verifierProjection.Valid() || r.state != StatePASS || r.scope != ScopeChain {
		return VerifierProjection{}, false
	}
	return r.verifierProjection.clone(), true
}

// String returns a constant representation without private service facts.
func (Result) String() string { return "service.Result{redacted}" }

// GoString returns a constant representation without private service facts.
func (Result) GoString() string { return "service.Result{redacted}" }

// Format prevents formatting from traversing private service facts.
func (Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "service.Result{redacted}")
}
