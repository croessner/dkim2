package policy

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// FuzzSealedPolicyEvaluation exercises closed policy dimensions without constructing raw message state.
func FuzzSealedPolicyEvaluation(f *testing.F) {
	for mode := range 3 {
		for protocol := range 4 {
			f.Add(mode, protocol, 0, 0, uint8(0), 0, 1, 128, uint64(1))
			f.Add(mode, protocol, 0, protocol%8, uint8(31), protocol%4, 2, 1, uint64(2))
		}
	}
	for transition := range 8 {
		f.Add(0, 0, 0, transition, uint8(31), 0, 2, 128, uint64(2))
		f.Add(0, 0, 0, transition, uint8(31), 1, 2, 127, uint64(2))
	}
	for dns := range 14 {
		f.Add(dns%3, dns%4, 0, 0, uint8(1<<uint(dns%5)), dns, 1, 128, uint64(1))
	}
	for mode := range 3 {
		for _, dns := range []int{1, 4, 5, 6, 8, 9, 10, 11, 12} {
			f.Add(mode, 2, 0, 0, uint8(0), dns, 1, 127, uint64(1))
		}
	}
	for unavailable := range 6 {
		f.Add(unavailable%3, 2, 1, unavailable, uint8(0), unavailable%4, 0, 128, uint64(0))
	}
	f.Add(0, 0, 0, 1, uint8(31), 1, 128, 128, ^uint64(0))
	f.Add(0, 0, 0, 1, uint8(31), 1, 127, 127, uint64(128))
	f.Add(2, 3, 0, 7, uint8(16), 3, 129, 129, uint64(0))

	f.Fuzz(func(t *testing.T, modeSeed, protocolSeed, formSeed, transitionSeed int, flags uint8, dnsSeed, hopSeed, findingSeed int, targetSeed uint64) {
		runSealedPolicyFuzzCase(t, modeSeed, protocolSeed, formSeed, transitionSeed, flags, dnsSeed, hopSeed, findingSeed, targetSeed)
	})
}

// runSealedPolicyFuzzCase constructs twice, evaluates twice, and delegates closed property checks.
func runSealedPolicyFuzzCase(t *testing.T, modeSeed, protocolSeed, formSeed, transitionSeed int, flags uint8, dnsSeed, hopSeed, findingSeed int, targetSeed uint64) {
	t.Helper()
	limits := DefaultLimits()
	limits.MaxFindings = boundedFuzzLimit(findingSeed, hardMaxFindings)
	mode := []Mode{ModeStrict, ModePermissive, ModeTesting}[boundedFuzzIndex(modeSeed, 3)]
	evaluator, err := NewEvaluator(Config{Mode: mode, Limits: limits})
	if err != nil {
		t.Fatalf("known fuzz config failed: %v", err)
	}
	projection, constructionErr := fuzzPolicyProjection(protocolSeed, formSeed, transitionSeed, flags, dnsSeed, hopSeed, targetSeed)
	projectionAgain, constructionErrAgain := fuzzPolicyProjection(protocolSeed, formSeed, transitionSeed, flags, dnsSeed, hopSeed, targetSeed)
	if fmt.Sprint(constructionErr) != fmt.Sprint(constructionErrAgain) || !reflect.DeepEqual(projection, projectionAgain) {
		t.Fatal("projection construction was nondeterministic")
	}
	if constructionErr != nil {
		if !projection.IsZero() || !projectionAgain.IsZero() {
			t.Fatal("invalid construction returned partial projection")
		}
		return
	}
	beforeHops, beforeSignatures := projection.Hops(), projection.SignatureFacts()
	decision, evaluateErr := evaluator.EvaluateProjection(projection)
	decisionAgain, evaluateErrAgain := evaluator.EvaluateProjection(projection)
	if !reflect.DeepEqual(policyFuzzSnapshot(decision, evaluateErr), policyFuzzSnapshot(decisionAgain, evaluateErrAgain)) {
		t.Fatal("policy evaluation was nondeterministic")
	}
	if !reflect.DeepEqual(beforeHops, projection.Hops()) || !reflect.DeepEqual(beforeSignatures, projection.SignatureFacts()) {
		t.Fatal("policy evaluation mutated sealed projection")
	}
	assertSealedPolicyFuzzOutcome(t, projection, decision, evaluateErr, limits)
}

// assertSealedPolicyFuzzOutcome validates error disjointness, bounds, history, and DNS treatment.
func assertSealedPolicyFuzzOutcome(t *testing.T, projection Projection, decision Decision, evaluateErr error, limits Limits) {
	t.Helper()
	if evaluateErr != nil {
		if !decision.IsZero() {
			t.Fatal("policy error returned a partial decision")
		}
		var policyErr *Error
		if !errors.As(evaluateErr, &policyErr) || !policyErr.Code().Known() || len(evaluateErr.Error()) > 96 {
			t.Fatalf("policy error escaped closed contract: %v", evaluateErr)
		}
		return
	}
	if !decision.Valid() || len(decision.Actions()) != 1 || len(decision.Findings()) > limits.MaxFindings || len(decision.Findings()) > hardMaxFindings {
		t.Fatalf("successful decision violated bounds: %#v", decision)
	}
	if projection.HistoryCoverage() != HistoryComplete && (decision.DoNotModifyCompliance() == ComplianceHonored || decision.DoNotModifyCompliance() == ComplianceViolated || decision.DoNotExplodeCompliance() == ComplianceHonored || decision.DoNotExplodeCompliance() == ComplianceViolated) {
		t.Fatal("incomplete history produced false honor or violation")
	}
	if decision.DNSTestingEffective() != fuzzDNSTestingShouldBeEffective(projection) {
		t.Fatal("DNS testing treatment disagreed with exact eligibility")
	}
	if decision.DNSTestingEffective() && projection.Protocol() == ProtocolPASS {
		assertTestingPassSuppressesFuzzFlags(t, decision)
	}
}

// assertTestingPassSuppressesFuzzFlags rejects feedback, compliance, and sequenced findings.
func assertTestingPassSuppressesFuzzFlags(t *testing.T, decision Decision) {
	t.Helper()
	intent := decision.FeedbackIntent()
	if intent.Requested() || intent.RelayRequired() || decision.DoNotModifyCompliance() != ComplianceNotEvaluated || decision.DoNotExplodeCompliance() != ComplianceNotEvaluated {
		t.Fatal("testing PASS retained authenticated flag effects")
	}
	for _, finding := range decision.Findings() {
		if _, sequenced := finding.Sequence(); sequenced {
			t.Fatal("testing PASS emitted hop-derived finding")
		}
	}
}

// fuzzPolicyProjection builds one bounded selected, historical, unavailable, or rejected projection.
func fuzzPolicyProjection(protocolSeed, formSeed, transitionSeed int, flags uint8, dnsSeed, hopSeed int, targetSeed uint64) (Projection, error) {
	if boundedFuzzIndex(formSeed, 2) == 1 {
		reasons := []PreTargetReason{PreTargetLimitExceeded, PreTargetMalformedMessage, PreTargetMalformedProtocol, PreTargetMissingProtocol, PreTargetSequenceInvalid, PreTargetInternalContract}
		return NewUnavailableProjection(reasons[boundedFuzzIndex(transitionSeed, len(reasons))])
	}
	protocol := []ProtocolClass{ProtocolPASS, ProtocolFAIL, ProtocolPERMERROR, ProtocolTEMPERROR}[boundedFuzzIndex(protocolSeed, 4)]
	target := targetSeed
	if target == 0 {
		target = uint64(boundedFuzzLimit(hopSeed, hardMaxAuthenticatedHops))
	}
	transition := []TransitionState{TransitionOrigin, TransitionUnchanged, TransitionBodyChanged, TransitionHeadersChanged, TransitionBodyAndHeadersChanged, TransitionHeaderAdditionOnly, TransitionIndeterminate, TransitionNotEvaluated}[boundedFuzzIndex(transitionSeed, 8)]
	if protocol == ProtocolPASS && transition != TransitionOrigin {
		count := boundedFuzzLimit(hopSeed, hardMaxAuthenticatedHops)
		hops := fuzzHistoricalHops(count, transition, flags)
		if targetSeed != ^uint64(0) {
			target = uint64(count)
		}
		coverage := []HistoryCoverage{HistoryComplete, HistoryIndeterminate, HistoryNotEvaluated}[boundedFuzzIndex(dnsSeed, 3)]
		return newHistoricalProjection(target, coverage, hops, DefaultLimits())
	}
	hops := []HopFact(nil)
	if protocol == ProtocolPASS {
		hop, err := NewAuthenticatedHopFact(target, TransitionOrigin, flags&1 != 0, flags&2 != 0, flags&4 != 0, flags&8 != 0, flags&16 != 0)
		if err != nil {
			return Projection{}, err
		}
		hops = []HopFact{hop}
	}
	reason, facts, err := fuzzSignatureFacts(protocol, dnsSeed)
	if err != nil {
		return Projection{}, err
	}
	return NewSelectedProjection(protocol, reason, target, hops, facts, DefaultLimits())
}

// fuzzHistoricalHops builds bounded ascending facts while allowing invalid terminal targets to exercise rejection.
func fuzzHistoricalHops(count int, transition TransitionState, flags uint8) []HopFact {
	hops := make([]HopFact, 0, count)
	for index := 1; index <= count; index++ {
		state := transition
		if index == 1 {
			state = TransitionOrigin
		}
		hop, err := NewAuthenticatedHopFact(uint64(index), state, flags&1 != 0, flags&2 != 0, flags&4 != 0, flags&8 != 0, flags&16 != 0)
		if err != nil {
			return nil
		}
		hops = append(hops, hop)
	}
	return hops
}

// fuzzSignatureFacts returns a coherent aggregate reason and pre-retention fact set for one DNS class.
func fuzzSignatureFacts(protocol ProtocolClass, dnsSeed int) (VerificationReason, []SignatureFact, error) {
	dnsClass := boundedFuzzIndex(dnsSeed, 14)
	testing := dnsClass == 1 || dnsClass == 2 || dnsClass == 4 || dnsClass == 5 || dnsClass == 6 || dnsClass >= 8 && dnsClass <= 12
	plainSecond := dnsClass == 2
	newFact := func(algorithm SetAlgorithm, status SetStatus, reason SetReason, declared bool) (SignatureFact, error) {
		return NewSignatureFact(algorithm, status, reason, declared, false)
	}
	var reason VerificationReason
	var first SignatureFact
	var err error
	switch protocol {
	case ProtocolPASS:
		reason = VerificationReasonNone
		first, err = newFact(SetAlgorithmRSA, SetStatusPass, SetReasonNone, testing)
	case ProtocolFAIL:
		if dnsClass == 4 || dnsClass == 5 {
			reason = VerificationReasonHashMismatch
			first, err = newFact(SetAlgorithmRSA, SetStatusPass, SetReasonNone, testing)
		} else {
			reason = VerificationReasonSignatureMismatch
			first, err = newFact(SetAlgorithmRSA, SetStatusFail, SetReasonSignatureMismatch, testing)
		}
	case ProtocolPERMERROR:
		switch dnsClass {
		case 1, 2:
			reason = VerificationReasonInvalidKey
			first, err = newFact(SetAlgorithmRSA, SetStatusPermerror, SetReasonInvalidKey, testing)
		case 4:
			reason = VerificationReasonRevokedKey
			first, err = newFact(SetAlgorithmRSA, SetStatusPermerror, SetReasonRevokedKey, true)
		case 5:
			reason = VerificationReasonUnsupportedKeyType
			first, err = newFact(SetAlgorithmRSA, SetStatusPermerror, SetReasonUnsupportedKeyType, true)
		case 6:
			reason = VerificationReasonKeyAlgorithmMismatch
			first, err = newFact(SetAlgorithmRSA, SetStatusPermerror, SetReasonKeyAlgorithmMismatch, true)
		case 8, 9, 10, 11, 12:
			reason = []VerificationReason{VerificationReasonTimestampInvalid, VerificationReasonEnvelopeMismatch, VerificationReasonDomainAlignmentMismatch, VerificationReasonNextDomainMismatch, VerificationReasonOutOfBandRequired}[dnsClass-8]
			first, err = newFact(SetAlgorithmRSA, SetStatusPass, SetReasonNone, true)
		default:
			reason = VerificationReasonMissingKey
			first, err = newFact(SetAlgorithmRSA, SetStatusPermerror, SetReasonMissingKey, false)
		}
	case ProtocolTEMPERROR:
		reason = VerificationReasonProviderTemporary
		first, err = newFact(SetAlgorithmRSA, SetStatusTemperror, SetReasonProviderTemporary, false)
	}
	if err != nil {
		return "", nil, err
	}
	facts := []SignatureFact{first}
	if plainSecond {
		second, secondErr := newFact(SetAlgorithmEd25519, SetStatusPass, SetReasonNone, false)
		if secondErr != nil {
			return "", nil, secondErr
		}
		facts = append(facts, second)
	}
	if dnsClass == 3 || dnsClass == 7 {
		declared, declaredErr := newFact(SetAlgorithmEd25519, SetStatusPass, SetReasonNone, true)
		if declaredErr != nil {
			return "", nil, declaredErr
		}
		facts = append(facts, declared)
	}
	return reason, facts, nil
}

// fuzzDNSTestingShouldBeEffective independently states the exact effective subset over a valid projection.
func fuzzDNSTestingShouldBeEffective(projection Projection) bool {
	if projection.Form() != TargetSelected {
		return false
	}
	facts := projection.SignatureFacts()
	supported := 0
	permanent := false
	for _, fact := range facts {
		if fact.Algorithm() == SetAlgorithmUnknown || fact.Status() == SetStatusIgnored {
			continue
		}
		supported++
		if !fact.TestingDeclared() {
			return false
		}
		switch projection.Protocol() {
		case ProtocolPASS:
			if fact.Status() != SetStatusPass || fact.Reason() != SetReasonNone {
				return false
			}
		case ProtocolFAIL:
			if projection.VerificationReason() == VerificationReasonHashMismatch && (fact.Status() != SetStatusPass || fact.Reason() != SetReasonNone) {
				return false
			}
			if projection.VerificationReason() == VerificationReasonSignatureMismatch && !fuzzPassingOrSignatureFailure(fact) {
				return false
			}
		case ProtocolPERMERROR:
			if fact.Status() == SetStatusPass && fact.Reason() == SetReasonNone {
				continue
			}
			if fact.Status() != SetStatusPermerror || !fuzzEligiblePermanentReason(VerificationReason(fact.Reason())) {
				return false
			}
			permanent = true
		default:
			return false
		}
	}
	if supported == 0 {
		return false
	}
	switch projection.Protocol() {
	case ProtocolPASS:
		return projection.VerificationReason() == VerificationReasonNone
	case ProtocolFAIL:
		return projection.VerificationReason() == VerificationReasonHashMismatch || projection.VerificationReason() == VerificationReasonSignatureMismatch
	case ProtocolPERMERROR:
		return fuzzPostKeyPermanentReason(projection.VerificationReason()) && !permanent || permanent && fuzzEligiblePermanentReason(projection.VerificationReason())
	default:
		return false
	}
}

// fuzzPassingOrSignatureFailure states the two eligible signature-mismatch set rows.
func fuzzPassingOrSignatureFailure(fact SignatureFact) bool {
	return fact.Status() == SetStatusPass && fact.Reason() == SetReasonNone || fact.Status() == SetStatusFail && fact.Reason() == SetReasonSignatureMismatch
}

// fuzzEligiblePermanentReason states the four DNS testing-eligible permanent reasons independently.
func fuzzEligiblePermanentReason(reason VerificationReason) bool {
	return reason == VerificationReasonInvalidKey || reason == VerificationReasonRevokedKey || reason == VerificationReasonUnsupportedKeyType || reason == VerificationReasonKeyAlgorithmMismatch
}

// fuzzPostKeyPermanentReason independently states the five eligible post-key failures.
func fuzzPostKeyPermanentReason(reason VerificationReason) bool {
	return reason == VerificationReasonTimestampInvalid || reason == VerificationReasonEnvelopeMismatch || reason == VerificationReasonDomainAlignmentMismatch || reason == VerificationReasonNextDomainMismatch || reason == VerificationReasonOutOfBandRequired
}

// boundedFuzzIndex maps arbitrary signed fuzz input into a nonnegative closed index.
func boundedFuzzIndex(value, size int) int {
	if value < 0 {
		value = max(-value, 0)
	}
	return value % size
}

// boundedFuzzLimit maps arbitrary input to an exact 1..maximum bound.
func boundedFuzzLimit(value, maximum int) int { return boundedFuzzIndex(value, maximum) + 1 }

// policyFuzzSnapshot captures only closed deterministic decision and error output.
func policyFuzzSnapshot(decision Decision, err error) any {
	if err != nil {
		var policyErr *Error
		if errors.As(err, &policyErr) {
			return []any{policyErr.Code(), policyErr.LimitName(), policyErr.ConfiguredLimit(), policyErr.ObservedCount(), err.Error()}
		}
		return []any{"unknown_error", err.Error()}
	}
	return []any{decision.Protocol(), decision.Mode(), decision.Verdict(), decision.PrimaryReason(), decision.DoNotModifyCompliance(), decision.DoNotExplodeCompliance(), decision.FeedbackIntent(), decision.DNSTestingEffective(), decision.Findings(), decision.Actions()}
}
