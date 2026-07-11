package service

import (
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
	KeyPolicy KeyPolicyMetadata
}

// Result is an immutable internal current-verification outcome.
type Result struct {
	draft                string
	state                State
	scope                Scope
	historicalContent    HistoricalState
	historicalSignatures HistoricalState
	custody              Custody
	target               Target
	primaryReason        Reason
	checks               []CheckFact
	signatures           []SignatureSetFact
	policyProjection     policy.Projection
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

// Draft returns the exact active behavior baseline.
func (r Result) Draft() string { return r.draft }

// State returns one of the four service states.
func (r Result) State() State { return r.state }

// Scope returns the current-only verification scope.
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
