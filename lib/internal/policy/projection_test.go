package policy

import (
	"math"
	"testing"
)

// TestSelectedProjectionAuthenticatesOnlyPassingCurrentFlags verifies current provenance.
func TestSelectedProjectionAuthenticatesOnlyPassingCurrentFlags(t *testing.T) {
	hop, err := NewAuthenticatedHopFact(2, TransitionNotEvaluated, true, true, true, true, true)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	set := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, true, false)
	for _, tt := range []struct {
		protocol ProtocolClass
		reason   VerificationReason
		wantHops int
		facts    []SignatureFact
	}{
		{protocol: ProtocolPASS, reason: VerificationReasonNone, wantHops: 1, facts: []SignatureFact{set}},
		{protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, facts: []SignatureFact{set}},
		{protocol: ProtocolPERMERROR, reason: VerificationReasonInternalContract, facts: []SignatureFact{set}},
		{protocol: ProtocolTEMPERROR, reason: VerificationReasonProviderTemporary, facts: []SignatureFact{mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusTemperror, SetReasonProviderTemporary, false, false)}},
	} {
		hops := []HopFact(nil)
		if tt.protocol == ProtocolPASS {
			hops = []HopFact{hop}
		}
		projection, err := NewSelectedProjection(tt.protocol, tt.reason, 2, hops, tt.facts, DefaultLimits())
		if err != nil || !projection.Valid() || projection.Form() != TargetSelected || projection.TargetSequence() != 2 || len(projection.Hops()) != tt.wantHops {
			t.Fatalf("projection %q = %#v error=%v", tt.protocol, projection, err)
		}
		if len(projection.SignatureFacts()) != 1 {
			t.Fatal("selected projection lost complete signature facts")
		}
	}
	if projection, err := NewSelectedProjection(ProtocolFAIL, VerificationReasonHashMismatch, 2, []HopFact{hop}, []SignatureFact{set}, DefaultLimits()); !IsErrorCode(err, ErrorInternalContract) || !projection.IsZero() {
		t.Fatalf("non-PASS authenticated projection = %#v error=%v", projection, err)
	}
	for _, tt := range []struct {
		name       string
		protocol   ProtocolClass
		reason     VerificationReason
		target     uint64
		hops       []HopFact
		signatures []SignatureFact
	}{
		{name: "PASS missing hop", protocol: ProtocolPASS, reason: VerificationReasonNone, target: 2, signatures: []SignatureFact{set}},
		{name: "zero selected target", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, signatures: []SignatureFact{set}},
		{name: "selected missing signature facts", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, target: 2},
		{name: "unknown protocol", protocol: "future", reason: VerificationReasonNone, target: 2, signatures: []SignatureFact{set}},
		{name: "mismatched PASS hop", protocol: ProtocolPASS, reason: VerificationReasonNone, target: 1, hops: []HopFact{hop}, signatures: []SignatureFact{set}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if projection, projectionErr := NewSelectedProjection(tt.protocol, tt.reason, tt.target, tt.hops, tt.signatures, DefaultLimits()); !IsErrorCode(projectionErr, ErrorInternalContract) || !projection.IsZero() {
				t.Fatalf("invalid selected = %#v error=%v", projection, projectionErr)
			}
		})
	}
}

// TestCompleteOriginHistoryPreservesCurrentEvidence verifies the one-hop completion invariant.
func TestCompleteOriginHistoryPreservesCurrentEvidence(t *testing.T) {
	hop := mustProjectionHop(t, 1, TransitionOrigin)
	set := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, true, true)
	current, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 1, []HopFact{hop}, []SignatureFact{set}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}

	completed, err := current.CompleteOriginHistory(DefaultLimits())
	if err != nil || !completed.Valid() || completed.HistoryCoverage() != HistoryComplete || len(completed.Hops()) != 1 || len(completed.SignatureFacts()) != 1 ||
		!completed.SignatureFacts()[0].TestingDeclared() || !completed.SignatureFacts()[0].StrictIdentityDeclared() {
		t.Fatalf("CompleteOriginHistory() = %#v error=%v", completed, err)
	}
	if current.HistoryCoverage() != HistoryNotEvaluated {
		t.Fatalf("current projection mutated to %q", current.HistoryCoverage())
	}
}

// TestCompleteOriginHistoryRejectsIneligibleProjections verifies fail-closed completion.
func TestCompleteOriginHistoryRejectsIneligibleProjections(t *testing.T) {
	pass := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	for _, test := range []struct {
		name    string
		target  uint64
		history HistoryCoverage
		hops    []HopFact
	}{
		{name: "non-origin target", target: 2, history: HistoryNotEvaluated, hops: []HopFact{mustProjectionHop(t, 2, TransitionNotEvaluated)}},
		{name: "already complete", target: 1, history: HistoryComplete, hops: []HopFact{mustProjectionHop(t, 1, TransitionOrigin)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var current Projection
			var err error
			if test.history == HistoryNotEvaluated {
				current, err = NewSelectedProjection(ProtocolPASS, VerificationReasonNone, test.target, test.hops, []SignatureFact{pass}, DefaultLimits())
			} else {
				current, err = NewHistoricalProjection(test.target, test.history, test.hops, DefaultLimits())
			}
			if err != nil {
				t.Fatalf("fixture error = %v", err)
			}
			if completed, completionErr := current.CompleteOriginHistory(DefaultLimits()); !IsErrorCode(completionErr, ErrorInternalContract) || !completed.IsZero() {
				t.Fatalf("completion = %#v error=%v", completed, completionErr)
			}
		})
	}
}

// TestRevisionFailureProjectionSeparatesCurrentTestingFactsFromInheritedFailure locks fail-closed history provenance.
func TestRevisionFailureProjectionSeparatesCurrentTestingFactsFromInheritedFailure(t *testing.T) {
	hop := mustProjectionHop(t, 2, TransitionNotEvaluated)
	pass := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, true, false)
	current, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 2, []HopFact{hop}, []SignatureFact{pass}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := NewRevisionFailureProjection(ProtocolFAIL, VerificationReasonSignatureMismatch, current, DefaultLimits())
	if err != nil || !projection.Valid() || projection.Form() != TargetSelected || projection.TargetSequence() != 2 || len(projection.Hops()) != 0 || len(projection.SignatureFacts()) != 1 {
		t.Fatalf("NewRevisionFailureProjection() = %#v error=%v", projection, err)
	}
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if err != nil || decision.Verdict() != VerdictReject || decision.DNSTestingEffective() || !decisionHasReason(decision, ReasonDNSTestingIneligible) {
		t.Fatalf("EvaluateProjection() = %#v error=%v", decision, err)
	}
	if forged, forgeErr := NewRevisionFailureProjection(ProtocolPASS, VerificationReasonNone, current, DefaultLimits()); !IsErrorCode(forgeErr, ErrorInternalContract) || !forged.IsZero() {
		t.Fatalf("PASS revision failure = %#v error=%v", forged, forgeErr)
	}
	if forged, forgeErr := NewRevisionFailureProjection(ProtocolFAIL, VerificationReasonHashMismatch, Projection{}, DefaultLimits()); !IsErrorCode(forgeErr, ErrorInternalContract) || !forged.IsZero() {
		t.Fatalf("zero current projection = %#v error=%v", forged, forgeErr)
	}
}

// TestRevisionFailureProjectionAllowsOnlyServiceOutcomePairs locks the exact service-to-policy history-failure seam.
func TestRevisionFailureProjectionAllowsOnlyServiceOutcomePairs(t *testing.T) {
	hop := mustProjectionHop(t, 2, TransitionNotEvaluated)
	pass := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	current, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 2, []HopFact{hop}, []SignatureFact{pass}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	allowed := []struct {
		protocol ProtocolClass
		reason   VerificationReason
	}{
		{ProtocolFAIL, VerificationReasonHashMismatch},
		{ProtocolFAIL, VerificationReasonSignatureMismatch},
		{ProtocolPERMERROR, VerificationReasonUnsupportedAlgorithm},
		{ProtocolTEMPERROR, VerificationReasonProviderTemporary},
		{ProtocolPERMERROR, VerificationReasonProviderPermanent},
		{ProtocolPERMERROR, VerificationReasonProviderContract},
		{ProtocolPERMERROR, VerificationReasonLimitExceeded},
		{ProtocolPERMERROR, VerificationReasonOutOfBandRequired},
		{ProtocolPERMERROR, VerificationReasonInvalidRecipeJSON},
		{ProtocolPERMERROR, VerificationReasonMalformedProtocol},
		{ProtocolPERMERROR, VerificationReasonInternalContract},
	}
	for _, test := range allowed {
		projection, projectionErr := NewRevisionFailureProjection(test.protocol, test.reason, current, DefaultLimits())
		if projectionErr != nil || !projection.Valid() || projection.Protocol() != test.protocol || projection.VerificationReason() != test.reason {
			t.Errorf("allowed %q/%q = %#v error=%v", test.protocol, test.reason, projection, projectionErr)
		}
	}
	rejected := []struct {
		protocol ProtocolClass
		reason   VerificationReason
	}{
		{ProtocolPERMERROR, VerificationReasonMissingKey},
		{ProtocolPERMERROR, VerificationReasonDuplicateSelector},
		{ProtocolPERMERROR, VerificationReasonTimestampInvalid},
		{ProtocolPERMERROR, VerificationReason("future")},
		{ProtocolFAIL, VerificationReasonProviderTemporary},
		{ProtocolPASS, VerificationReasonNone},
	}
	for _, test := range rejected {
		projection, projectionErr := NewRevisionFailureProjection(test.protocol, test.reason, current, DefaultLimits())
		if !IsErrorCode(projectionErr, ErrorInternalContract) || !projection.IsZero() {
			t.Errorf("rejected %q/%q = %#v error=%v", test.protocol, test.reason, projection, projectionErr)
		}
	}
	forged := current
	forged.protocol = ProtocolPERMERROR
	forged.verificationReason = VerificationReasonMissingKey
	forged.history = HistoryNotEvaluated
	forged.hops = nil
	forged.revisionFailure = true
	if forged.Valid() {
		t.Fatal("directly forged disallowed revision-failure pair is valid")
	}
}

// decisionHasReason reports whether one sealed decision carries the requested bounded reason.
func decisionHasReason(decision Decision, reason PolicyReason) bool {
	for _, finding := range decision.Findings() {
		if finding.Reason() == reason {
			return true
		}
	}
	return false
}

// TestProjectionCopiesStorage verifies immutable fact ownership.
func TestProjectionCopiesStorage(t *testing.T) {
	hop, _ := NewAuthenticatedHopFact(1, TransitionOrigin, true, false, false, false, false)
	facts := []SignatureFact{mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPass, SetReasonNone, false, false)}
	projection, err := NewSelectedProjection(ProtocolPASS, VerificationReasonNone, 1, []HopFact{hop}, facts, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	facts[0] = SignatureFact{}
	hops := projection.Hops()
	sets := projection.SignatureFacts()
	hops[0] = HopFact{}
	sets[0] = SignatureFact{}
	if !projection.Hops()[0].Valid() || !projection.SignatureFacts()[0].Valid() || !projection.Valid() {
		t.Fatal("projection exposed mutable storage")
	}
}

// TestUnavailableProjectionAllowsOnlyExactPreTargetReasons verifies the closed zero-target form.
func TestUnavailableProjectionAllowsOnlyExactPreTargetReasons(t *testing.T) {
	for _, reason := range []PreTargetReason{
		PreTargetLimitExceeded, PreTargetMalformedMessage, PreTargetMalformedProtocol,
		PreTargetMissingProtocol, PreTargetSequenceInvalid, PreTargetInternalContract,
	} {
		projection, err := NewUnavailableProjection(reason)
		if err != nil || !projection.Valid() || projection.Form() != TargetUnavailable || projection.TargetSequence() != 0 || len(projection.Hops()) != 0 || len(projection.SignatureFacts()) != 0 {
			t.Fatalf("unavailable %q = %#v error=%v", reason, projection, err)
		}
	}
	if projection, err := NewUnavailableProjection(PreTargetReason("future")); !IsErrorCode(err, ErrorInvalidInput) || !projection.IsZero() {
		t.Fatalf("unknown unavailable = %#v error=%v", projection, err)
	}
	corrupt, _ := NewUnavailableProjection(PreTargetInternalContract)
	corrupt.verificationReason = VerificationReasonInternalContract
	if corrupt.Valid() {
		t.Fatal("target-unavailable accepted selected verification reason")
	}
}

// TestHistoricalProjectionEnforcesCoverageAndBounds verifies safe contiguous history validation.
func TestHistoricalProjectionEnforcesCoverageAndBounds(t *testing.T) {
	complete := []HopFact{
		mustProjectionHop(t, 1, TransitionOrigin),
		mustProjectionHop(t, 2, TransitionUnchanged),
	}
	projection, err := newHistoricalProjection(2, HistoryComplete, complete, DefaultLimits())
	if err != nil || !projection.Valid() {
		t.Fatalf("complete projection = %#v error=%v", projection, err)
	}
	for _, tt := range []struct {
		name     string
		target   uint64
		coverage HistoryCoverage
		hops     []HopFact
	}{
		{name: "gap claimed complete", target: 3, coverage: HistoryComplete, hops: []HopFact{complete[0], mustProjectionHop(t, 3, TransitionUnchanged)}},
		{name: "wrong terminal", target: 3, coverage: HistoryComplete, hops: complete},
		{name: "misplaced origin", target: 2, coverage: HistoryComplete, hops: []HopFact{complete[0], mustProjectionHop(t, 2, TransitionOrigin)}},
		{name: "zero target", coverage: HistoryComplete, hops: []HopFact{complete[0]}},
		{name: "duplicate", target: 2, coverage: HistoryIndeterminate, hops: []HopFact{complete[0], complete[0]}},
		{name: "descending", target: 2, coverage: HistoryIndeterminate, hops: []HopFact{complete[1], complete[0]}},
		{name: "first one not origin", target: 2, coverage: HistoryIndeterminate, hops: []HopFact{mustProjectionHop(t, 1, TransitionUnchanged)}},
		{name: "complete not evaluated", target: 2, coverage: HistoryComplete, hops: []HopFact{complete[0], mustProjectionHop(t, 2, TransitionNotEvaluated)}},
		{name: "extreme target", target: math.MaxUint64, coverage: HistoryComplete, hops: complete},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if projection, err := newHistoricalProjection(tt.target, tt.coverage, tt.hops, DefaultLimits()); !IsErrorCode(err, ErrorInternalContract) || !projection.IsZero() {
				t.Fatalf("invalid history = %#v error=%v", projection, err)
			}
		})
	}
	partial, err := newHistoricalProjection(3, HistoryIndeterminate, []HopFact{complete[0], complete[1]}, DefaultLimits())
	if err != nil || !partial.Valid() || partial.HistoryCoverage() != HistoryIndeterminate {
		t.Fatalf("partial projection = %#v error=%v", partial, err)
	}
	sparse, err := newHistoricalProjection(3, HistoryIndeterminate, []HopFact{mustProjectionHop(t, 2, TransitionUnchanged)}, DefaultLimits())
	if err != nil || !sparse.Valid() {
		t.Fatalf("sparse authenticated transition = %#v error=%v", sparse, err)
	}
	tooMany := make([]HopFact, 129)
	for index := range tooMany {
		tooMany[index] = mustProjectionHop(t, uint64(index+1), transitionForTestIndex(index))
	}
	if projection, err := newHistoricalProjection(129, HistoryComplete, tooMany, DefaultLimits()); !IsErrorCode(err, ErrorLimitExceeded) || !projection.IsZero() {
		t.Fatalf("over-limit history = %#v error=%v", projection, err)
	}
	narrow := DefaultLimits()
	narrow.MaxAuthenticatedHops = 2
	if projection, err := newHistoricalProjection(2, HistoryComplete, complete, narrow); err != nil || !projection.Valid() {
		t.Fatalf("exact narrow history = %#v error=%v", projection, err)
	}
	three := append(append([]HopFact(nil), complete...), mustProjectionHop(t, 3, TransitionUnchanged))
	if projection, err := newHistoricalProjection(3, HistoryComplete, three, narrow); !IsErrorCode(err, ErrorLimitExceeded) || !projection.IsZero() {
		t.Fatalf("over narrow history = %#v error=%v", projection, err)
	}
}

// TestSelectedProjectionEnforcesCompleteSignatureFactHardBound verifies exact and one-over counts.
func TestSelectedProjectionEnforcesCompleteSignatureFactHardBound(t *testing.T) {
	fact := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPermerror, SetReasonMissingKey, false, false)
	exact := make([]SignatureFact, 16)
	for index := range exact {
		exact[index] = fact
	}
	if projection, err := NewSelectedProjection(ProtocolPERMERROR, VerificationReasonMissingKey, 1, nil, exact, DefaultLimits()); err != nil || !projection.Valid() || len(projection.SignatureFacts()) != 16 {
		t.Fatalf("exact signature facts = %#v error=%v", projection, err)
	}
	over := append(append([]SignatureFact(nil), exact...), fact)
	if projection, err := NewSelectedProjection(ProtocolPERMERROR, VerificationReasonMissingKey, 1, nil, over, DefaultLimits()); !IsErrorCode(err, ErrorInternalContract) || !projection.IsZero() {
		t.Fatalf("over signature facts = %#v error=%v", projection, err)
	}
}

// TestPermanentProjectionRequiresACompatibleOutcomeDriver rejects forged aggregate reasons over unrelated set facts.
func TestPermanentProjectionRequiresACompatibleOutcomeDriver(t *testing.T) {
	pass := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	fail := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusFail, SetReasonSignatureMismatch, false, false)
	missing := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPermerror, SetReasonMissingKey, false, false)
	provider := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPermerror, SetReasonProviderPermanent, false, false)
	ignored := mustProjectionSignatureFact(t, SetAlgorithmUnknown, SetStatusIgnored, SetReasonUnsupportedAlgorithm, false, false)
	invalid := []struct {
		name   string
		reason VerificationReason
		facts  []SignatureFact
	}{
		{"missing over pass", VerificationReasonMissingKey, []SignatureFact{pass}},
		{"missing over fail", VerificationReasonMissingKey, []SignatureFact{fail}},
		{"missing over provider", VerificationReasonMissingKey, []SignatureFact{provider}},
		{"provider over pass", VerificationReasonProviderPermanent, []SignatureFact{pass}},
		{"provider over missing", VerificationReasonProviderPermanent, []SignatureFact{missing}},
		{"timestamp over missing", VerificationReasonTimestampInvalid, []SignatureFact{missing}},
		{"envelope over provider", VerificationReasonEnvelopeMismatch, []SignatureFact{provider}},
		{"alignment over missing", VerificationReasonDomainAlignmentMismatch, []SignatureFact{missing}},
		{"next domain over provider", VerificationReasonNextDomainMismatch, []SignatureFact{provider}},
		{"out of band over missing", VerificationReasonOutOfBandRequired, []SignatureFact{missing}},
		{"pre-target malformed message", VerificationReasonMalformedMessage, []SignatureFact{pass}},
		{"pre-target malformed protocol", VerificationReasonMalformedProtocol, []SignatureFact{pass}},
		{"pre-target missing protocol", VerificationReasonMissingProtocol, []SignatureFact{pass}},
		{"pre-target sequence invalid", VerificationReasonSequenceInvalid, []SignatureFact{pass}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			projection, err := NewSelectedProjection(ProtocolPERMERROR, test.reason, 1, nil, test.facts, DefaultLimits())
			if !IsErrorCode(err, ErrorInternalContract) || !projection.IsZero() {
				t.Fatalf("forged permanent projection = %#v error=%v", projection, err)
			}
		})
	}
	valid := []struct {
		reason VerificationReason
		facts  []SignatureFact
	}{
		{VerificationReasonMissingKey, []SignatureFact{pass, missing}},
		{VerificationReasonMissingKey, []SignatureFact{pass, missing, ignored}},
		{VerificationReasonProviderPermanent, []SignatureFact{provider}},
		{VerificationReasonUnsupportedAlgorithm, []SignatureFact{ignored}},
		{VerificationReasonUnsupportedAlgorithm, []SignatureFact{pass}},
		{VerificationReasonUnsupportedAlgorithm, []SignatureFact{pass, missing}},
		{VerificationReasonTimestampInvalid, []SignatureFact{pass}},
		{VerificationReasonTimestampInvalid, []SignatureFact{pass, ignored}},
		{VerificationReasonLimitExceeded, []SignatureFact{pass}},
	}
	for _, test := range valid {
		projection, err := NewSelectedProjection(ProtocolPERMERROR, test.reason, 1, nil, test.facts, DefaultLimits())
		if err != nil || !projection.Valid() {
			t.Fatalf("valid permanent projection %q = %#v error=%v", test.reason, projection, err)
		}
	}
}

// TestSignatureFactStatusReasonAlgorithmMatrix verifies every closed coherence row.
func TestSignatureFactStatusReasonAlgorithmMatrix(t *testing.T) {
	valid := []struct {
		algorithm SetAlgorithm
		status    SetStatus
		reason    SetReason
	}{
		{SetAlgorithmRSA, SetStatusPass, SetReasonNone},
		{SetAlgorithmEd25519, SetStatusFail, SetReasonSignatureMismatch},
		{SetAlgorithmUnknown, SetStatusIgnored, SetReasonUnsupportedAlgorithm},
		{SetAlgorithmRSA, SetStatusTemperror, SetReasonProviderTemporary},
	}
	for _, reason := range []SetReason{
		SetReasonMissingKey, SetReasonInvalidKey, SetReasonAmbiguousKey,
		SetReasonRevokedKey, SetReasonUnsupportedKeyType, SetReasonKeyAlgorithmMismatch,
		SetReasonProviderPermanent, SetReasonProviderContract, SetReasonInternalContract,
	} {
		valid = append(valid, struct {
			algorithm SetAlgorithm
			status    SetStatus
			reason    SetReason
		}{SetAlgorithmRSA, SetStatusPermerror, reason})
	}
	for _, row := range valid {
		if fact, err := NewSignatureFact(row.algorithm, row.status, row.reason, false, false); err != nil || !fact.Valid() {
			t.Fatalf("valid row %q/%q/%q = %#v error=%v", row.algorithm, row.status, row.reason, fact, err)
		}
	}
	invalid := []struct {
		algorithm SetAlgorithm
		status    SetStatus
		reason    SetReason
		testing   bool
	}{
		{SetAlgorithmUnknown, SetStatusPass, SetReasonNone, false},
		{SetAlgorithmRSA, SetStatusPass, SetReasonSignatureMismatch, false},
		{SetAlgorithmUnknown, SetStatusFail, SetReasonSignatureMismatch, false},
		{SetAlgorithmRSA, SetStatusIgnored, SetReasonUnsupportedAlgorithm, false},
		{SetAlgorithmRSA, SetStatusTemperror, SetReasonProviderTemporary, true},
		{SetAlgorithmRSA, SetStatusPermerror, SetReasonMissingKey, true},
		{SetAlgorithmUnknown, SetStatusPermerror, SetReasonMissingKey, false},
		{SetAlgorithmRSA, SetStatusPermerror, SetReasonProviderTemporary, false},
		{SetAlgorithmRSA, SetStatusPermerror, SetReasonUnsupportedAlgorithm, false},
		{SetAlgorithm("future"), SetStatusPermerror, SetReasonInternalContract, false},
	}
	for _, row := range invalid {
		if fact, err := NewSignatureFact(row.algorithm, row.status, row.reason, row.testing, false); err == nil || fact.Valid() {
			t.Fatalf("invalid row %q/%q/%q = %#v error=%v", row.algorithm, row.status, row.reason, fact, err)
		}
	}
}

// TestCurrentProjectionBindsProtocolToSignatureOutcomes verifies aggregate coherence.
func TestCurrentProjectionBindsProtocolToSignatureOutcomes(t *testing.T) {
	pass := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, false)
	fail := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusFail, SetReasonSignatureMismatch, false, false)
	temporary := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusTemperror, SetReasonProviderTemporary, false, false)
	permanent := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPermerror, SetReasonMissingKey, false, false)
	hop := mustProjectionHop(t, 1, TransitionOrigin)
	for _, tt := range []struct {
		name     string
		protocol ProtocolClass
		reason   VerificationReason
		hops     []HopFact
		facts    []SignatureFact
	}{
		{name: "PASS with failure", protocol: ProtocolPASS, reason: VerificationReasonNone, hops: []HopFact{hop}, facts: []SignatureFact{pass, fail}},
		{name: "PASS with permanent", protocol: ProtocolPASS, reason: VerificationReasonNone, hops: []HopFact{hop}, facts: []SignatureFact{pass, permanent}},
		{name: "TEMPERROR with pass only", protocol: ProtocolTEMPERROR, reason: VerificationReasonProviderTemporary, facts: []SignatureFact{pass}},
		{name: "TEMPERROR with permanent", protocol: ProtocolTEMPERROR, reason: VerificationReasonProviderTemporary, facts: []SignatureFact{temporary, permanent}},
		{name: "FAIL with temporary", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, facts: []SignatureFact{pass, temporary}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if projection, err := NewSelectedProjection(tt.protocol, tt.reason, 1, tt.hops, tt.facts, DefaultLimits()); !IsErrorCode(err, ErrorInternalContract) || !projection.IsZero() {
				t.Fatalf("incoherent projection = %#v error=%v", projection, err)
			}
		})
	}
}

// mustProjectionSignatureFact constructs one coherent test set fact.
func mustProjectionSignatureFact(t *testing.T, algorithm SetAlgorithm, status SetStatus, reason SetReason, testing, strict bool) SignatureFact {
	t.Helper()
	fact, err := NewSignatureFact(algorithm, status, reason, testing, strict)
	if err != nil {
		t.Fatalf("NewSignatureFact() error = %v", err)
	}
	return fact
}

// mustProjectionHop constructs one coherent synthetic authenticated hop.
func mustProjectionHop(t *testing.T, sequence uint64, transition TransitionState) HopFact {
	t.Helper()
	hop, err := NewAuthenticatedHopFact(sequence, transition, false, false, false, false, false)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	return hop
}

// transitionForTestIndex returns origin only for the first synthetic hop.
func transitionForTestIndex(index int) TransitionState {
	if index == 0 {
		return TransitionOrigin
	}
	return TransitionUnchanged
}
