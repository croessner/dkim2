package service

import (
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/policy"
)

// TestNewResultRejectsUnknownAndImpossibleFacts verifies fail-closed result ownership.
func TestNewResultRejectsUnknownAndImpossibleFacts(t *testing.T) {
	tests := []struct {
		name       string
		state      State
		custody    Custody
		reason     Reason
		checks     []CheckFact
		signatures []SignatureSetFact
	}{
		{name: "unknown state", state: State("future"), custody: CustodyNotPresent, reason: ReasonNone},
		{name: "unknown custody", state: StatePERMERROR, custody: Custody("future"), reason: ReasonInternalContract},
		{name: "pass without custody evaluation", state: StatePASS, custody: CustodyNotEvaluated, reason: ReasonNone},
		{name: "pass with terminal custody", state: StatePASS, custody: CustodyTerminalNDRequiresOOB, reason: ReasonNone},
		{name: "unknown reason", state: StatePERMERROR, custody: CustodyNotEvaluated, reason: Reason("raw-secret")},
		{name: "unknown check", state: StatePERMERROR, custody: CustodyNotEvaluated, reason: ReasonInternalContract, checks: []CheckFact{{Class: CheckClass("raw-secret"), Reason: ReasonInternalContract}}},
		{name: "unknown signature", state: StatePERMERROR, custody: CustodyNotPresent, reason: ReasonInternalContract, signatures: []SignatureSetFact{{Algorithm: Algorithm("raw-secret"), Status: SignaturePASS, Reason: ReasonNone}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := newResult(tt.state, tt.custody, Target{}, tt.reason, tt.checks, tt.signatures)
			if result.State() != StatePERMERROR || result.Custody() != CustodyNotEvaluated || result.PrimaryReason() != ReasonInternalContract {
				t.Fatalf("result = %q/%q/%q", result.State(), result.Custody(), result.PrimaryReason())
			}
		})
	}
}

// TestServiceErrorRejectsUnknownDiagnosticTokens verifies errors never echo arbitrary codes.
func TestServiceErrorRejectsUnknownDiagnosticTokens(t *testing.T) {
	err := newError(ErrorCode("RAW-SECRET-CODE"))
	if strings.Contains(err.Error(), "RAW-SECRET-CODE") || err.Code() != "" {
		t.Fatalf("unknown error code escaped: %q/%q", err.Error(), err.Code())
	}
}

// TestAuthenticatedOriginCompletesPolicyProjection reproduces the one-hop projection split.
func TestAuthenticatedOriginCompletesPolicyProjection(t *testing.T) {
	signatureFact, err := policy.NewSignatureFact(policy.SetAlgorithmRSA, policy.SetStatusPass, policy.SetReasonNone)
	if err != nil {
		t.Fatalf("policy.NewSignatureFact() error = %v", err)
	}
	hop, err := policy.NewAuthenticatedHopFact(1, policy.TransitionOrigin, false, false, false)
	if err != nil {
		t.Fatalf("policy.NewAuthenticatedHopFact() error = %v", err)
	}
	projection, err := policy.NewSelectedProjection(policy.ProtocolPASS, policy.VerificationReasonNone, 1, []policy.HopFact{hop}, []policy.SignatureFact{signatureFact}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("policy.NewSelectedProjection() error = %v", err)
	}
	current := newResult(StatePASS, CustodyNotPresent, Target{Sequence: 1, Instance: 1}, ReasonNone, []CheckFact{{Class: CheckSignature, Reason: ReasonNone}}, []SignatureSetFact{{Algorithm: AlgorithmRSASHA256, Status: SignaturePASS, Reason: ReasonNone}}).withPolicyProjection(projection)

	result := current.withAuthenticatedOrigin()
	completed := result.PolicyProjection()
	if result.Scope() != ScopeChain || result.HistoricalContent() != HistoricalComplete || result.HistoricalSignatures() != HistoricalComplete ||
		!completed.Valid() || completed.HistoryCoverage() != policy.HistoryComplete {
		t.Fatalf("completed origin = scope=%q content=%q signatures=%q projection=%#v", result.Scope(), result.HistoricalContent(), result.HistoricalSignatures(), completed)
	}
	if hops, facts := completed.Hops(), completed.SignatureFacts(); len(hops) != 1 || len(facts) != 1 || hops[0].Sequence() != 1 ||
		hops[0].Transition() != policy.TransitionOrigin || facts[0] != signatureFact {
		t.Fatalf("completed facts = hops=%#v signatures=%#v", hops, facts)
	}
	evaluator, err := policy.NewEvaluator(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("policy.NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.EvaluateProjection(completed)
	if err != nil || !decision.Valid() || decision.Verdict() == policy.VerdictReject {
		t.Fatalf("origin decision = verdict=%q primary=%q error=%v", decision.Verdict(), decision.PrimaryReason(), err)
	}
	for _, finding := range decision.Findings() {
		if _, sequenced := finding.Sequence(); sequenced {
			t.Fatalf("flagless origin produced hop finding %q", finding.Reason())
		}
	}
}

// TestAuthenticatedOriginPreservesSignedFlags verifies the upgrade cannot replace authenticated hop facts.
func TestAuthenticatedOriginPreservesSignedFlags(t *testing.T) {
	signatureFact, err := policy.NewSignatureFact(policy.SetAlgorithmEd25519, policy.SetStatusPass, policy.SetReasonNone)
	if err != nil {
		t.Fatalf("policy.NewSignatureFact() error = %v", err)
	}
	hop, err := policy.NewAuthenticatedHopFact(1, policy.TransitionOrigin, true, true, true)
	if err != nil {
		t.Fatalf("policy.NewAuthenticatedHopFact() error = %v", err)
	}
	projection, err := policy.NewSelectedProjection(policy.ProtocolPASS, policy.VerificationReasonNone, 1, []policy.HopFact{hop}, []policy.SignatureFact{signatureFact}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("policy.NewSelectedProjection() error = %v", err)
	}
	current := newResult(StatePASS, CustodyNotPresent, Target{Sequence: 1, Instance: 1}, ReasonNone, []CheckFact{{Class: CheckSignature, Reason: ReasonNone}}, []SignatureSetFact{{Algorithm: AlgorithmEd25519SHA256, Status: SignaturePASS, Reason: ReasonNone}}).withPolicyProjection(projection)

	completed := current.withAuthenticatedOrigin().PolicyProjection()
	hops := completed.Hops()
	if len(hops) != 1 || !hops[0].Feedback() || !hops[0].FeedHere() || !hops[0].Exploded() || len(completed.SignatureFacts()) != 1 {
		t.Fatalf("completed origin lost authenticated facts: projection=%#v hops=%#v", completed, hops)
	}
}

// TestAuthenticatedOriginRejectsIneligibleResults verifies the completion boundary remains fail closed.
func TestAuthenticatedOriginRejectsIneligibleResults(t *testing.T) {
	for _, current := range []Result{
		newResult(StateFAIL, CustodyNotPresent, Target{Sequence: 1, Instance: 1}, ReasonSignatureMismatch, []CheckFact{{Class: CheckSignature, Reason: ReasonSignatureMismatch}}, nil),
		newResult(StatePASS, CustodyNotPresent, Target{Sequence: 2, Instance: 1}, ReasonNone, []CheckFact{{Class: CheckSignature, Reason: ReasonNone}}, nil),
		newResult(StatePASS, CustodyNotPresent, Target{Sequence: 1, Instance: 2}, ReasonNone, []CheckFact{{Class: CheckSignature, Reason: ReasonNone}}, nil),
	} {
		result := current.withAuthenticatedOrigin()
		if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonInternalContract || result.Scope() != ScopeCurrent {
			t.Fatalf("ineligible origin completion = %q/%q/%q", result.State(), result.PrimaryReason(), result.Scope())
		}
	}
}
