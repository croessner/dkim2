package policy

import (
	"slices"
	"testing"
)

// TestDNSTestingEligibleRows verifies PASS, FAIL, and permanent treatment.
func TestDNSTestingEligibleRows(t *testing.T) {
	passTesting := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, true, false)
	failTesting := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusFail, SetReasonSignatureMismatch, true, false)
	tests := []struct {
		name     string
		protocol ProtocolClass
		reason   VerificationReason
		facts    []SignatureFact
		dns      PolicyReason
	}{
		{name: "PASS testing", protocol: ProtocolPASS, reason: VerificationReasonNone, facts: []SignatureFact{passTesting}, dns: ReasonDNSTestingEffective},
		{name: "FAIL signature", protocol: ProtocolFAIL, reason: VerificationReasonSignatureMismatch, facts: []SignatureFact{failTesting, passTesting}, dns: ReasonDNSTestingEffective},
		{name: "FAIL hash", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, facts: []SignatureFact{passTesting}, dns: ReasonDNSTestingEffective},
	}
	for _, reason := range []VerificationReason{VerificationReasonInvalidKey, VerificationReasonRevokedKey, VerificationReasonUnsupportedKeyType, VerificationReasonKeyAlgorithmMismatch} {
		tests = append(tests, struct {
			name     string
			protocol ProtocolClass
			reason   VerificationReason
			facts    []SignatureFact
			dns      PolicyReason
		}{name: string(reason), protocol: ProtocolPERMERROR, reason: reason, facts: []SignatureFact{mustEligiblePermanentFact(t, reason, true)}, dns: ReasonDNSTestingEffective})
	}
	for _, reason := range []VerificationReason{VerificationReasonTimestampInvalid, VerificationReasonEnvelopeMismatch, VerificationReasonDomainAlignmentMismatch, VerificationReasonNextDomainMismatch, VerificationReasonOutOfBandRequired} {
		tests = append(tests, struct {
			name     string
			protocol ProtocolClass
			reason   VerificationReason
			facts    []SignatureFact
			dns      PolicyReason
		}{name: string(reason), protocol: ProtocolPERMERROR, reason: reason, facts: []SignatureFact{passTesting}, dns: ReasonDNSTestingEffective})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projection := mustDNSProjection(t, tt.protocol, tt.reason, tt.facts)
			for _, mode := range []Mode{ModeStrict, ModePermissive, ModeTesting} {
				decision := mustEvaluateCompliance(t, mode, projection, DefaultLimits())
				if decision.Protocol() != tt.protocol || !slices.Equal(dnsFindingReasons(decision), []PolicyReason{tt.dns}) {
					t.Fatalf("mode %q decision = %#v", mode, decision)
				}
				if tt.dns == ReasonDNSTestingEffective {
					if decision.Verdict() != VerdictContinue || decision.PrimaryReason() != ReasonDNSTestingEffective || mode == ModePermissive && hasFindingReason(decision, ReasonPermissiveOverride) {
						t.Fatalf("effective mode %q decision = %#v", mode, decision)
					}
				}
			}
		})
	}
}

// TestDNSTestingMixedPermanentReasonsUseServicePrimaryOrder verifies deterministic aggregation.
func TestDNSTestingMixedPermanentReasonsUseServicePrimaryOrder(t *testing.T) {
	facts := []SignatureFact{
		mustEligiblePermanentFact(t, VerificationReasonInvalidKey, true),
		mustEligiblePermanentFact(t, VerificationReasonRevokedKey, true),
		mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPass, SetReasonNone, true, false),
	}
	projection := mustDNSProjection(t, ProtocolPERMERROR, VerificationReasonRevokedKey, facts)
	decision := mustEvaluateCompliance(t, ModeStrict, projection, DefaultLimits())
	if decision.PrimaryReason() != ReasonDNSTestingEffective || decision.Verdict() != VerdictContinue {
		t.Fatalf("mixed permanent decision = %#v", decision)
	}
	if corrupt, err := NewSelectedProjection(ProtocolPERMERROR, VerificationReasonInvalidKey, 1, nil, facts, DefaultLimits()); !IsErrorCode(err, ErrorInternalContract) || !corrupt.IsZero() {
		t.Fatalf("wrong permanent primary = %#v error=%v", corrupt, err)
	}
}

// TestDNSTestingIneligibleAndMixedRowsRemainBasePolicy verifies restrictive exclusions.
func TestDNSTestingIneligibleAndMixedRowsRemainBasePolicy(t *testing.T) {
	passTesting := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, true, false)
	passPlain := mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPass, SetReasonNone, false, false)
	temp := mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusTemperror, SetReasonProviderTemporary, false, false)
	missing := mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPermerror, SetReasonMissingKey, false, false)
	ambiguous := mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPermerror, SetReasonAmbiguousKey, false, false)
	providerPermanent := mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPermerror, SetReasonProviderPermanent, false, false)
	providerContract := mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPermerror, SetReasonProviderContract, false, false)
	ignored := mustProjectionSignatureFact(t, SetAlgorithmUnknown, SetStatusIgnored, SetReasonUnsupportedAlgorithm, false, false)
	tests := []struct {
		name     string
		protocol ProtocolClass
		reason   VerificationReason
		facts    []SignatureFact
		dns      PolicyReason
		verdict  Verdict
		primary  PolicyReason
	}{
		{name: "mixed declarations", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, facts: []SignatureFact{passTesting, passPlain}, dns: ReasonDNSTestingMixed, verdict: VerdictReject, primary: ReasonProtocolFail},
		{name: "temporary always ineligible", protocol: ProtocolTEMPERROR, reason: VerificationReasonProviderTemporary, facts: []SignatureFact{passTesting, temp}, dns: ReasonDNSTestingIneligible, verdict: VerdictTempfail, primary: ReasonProtocolTemperror},
		{name: "missing key ineligible", protocol: ProtocolPERMERROR, reason: VerificationReasonMissingKey, facts: []SignatureFact{passTesting, missing}, dns: ReasonDNSTestingIneligible, verdict: VerdictReject, primary: ReasonProtocolPermerror},
		{name: "ambiguous key ineligible", protocol: ProtocolPERMERROR, reason: VerificationReasonAmbiguousKey, facts: []SignatureFact{passTesting, ambiguous}, dns: ReasonDNSTestingIneligible, verdict: VerdictReject, primary: ReasonProtocolPermerror},
		{name: "provider permanent ineligible", protocol: ProtocolPERMERROR, reason: VerificationReasonProviderPermanent, facts: []SignatureFact{passTesting, providerPermanent}, dns: ReasonDNSTestingIneligible, verdict: VerdictReject, primary: ReasonProtocolPermerror},
		{name: "provider contract ineligible", protocol: ProtocolPERMERROR, reason: VerificationReasonProviderContract, facts: []SignatureFact{passTesting, providerContract}, dns: ReasonDNSTestingIneligible, verdict: VerdictReject, primary: ReasonProtocolPermerror},
		{name: "ignored only no declaration", protocol: ProtocolPERMERROR, reason: VerificationReasonUnsupportedAlgorithm, facts: []SignatureFact{ignored}, verdict: VerdictReject, primary: ReasonProtocolPermerror},
		{name: "all false no declaration", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, facts: []SignatureFact{passPlain}, verdict: VerdictReject, primary: ReasonProtocolFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustEvaluateCompliance(t, ModeStrict, mustDNSProjection(t, tt.protocol, tt.reason, tt.facts), DefaultLimits())
			wantDNS := []PolicyReason(nil)
			if tt.dns != "" {
				wantDNS = []PolicyReason{tt.dns}
			}
			if !slices.Equal(dnsFindingReasons(decision), wantDNS) || decision.PrimaryReason() != tt.primary || decision.Verdict() != tt.verdict || decision.Protocol() != tt.protocol {
				t.Fatalf("ineligible decision = %#v", decision)
			}
		})
	}
}

// TestDNSTestingIgnoresStrictIdentityOnlyMetadata verifies t=s is not t=y.
func TestDNSTestingIgnoresStrictIdentityOnlyMetadata(t *testing.T) {
	fact := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, false, true)
	decision := mustEvaluateCompliance(t, ModeStrict, mustDNSProjection(t, ProtocolPASS, VerificationReasonNone, []SignatureFact{fact}), DefaultLimits())
	if len(dnsFindingReasons(decision)) != 0 || decision.DNSTestingEffective() {
		t.Fatalf("strict-identity-only decision = %#v", decision)
	}
}

// TestProjectionRejectsAggregateReasonAndSetIncoherence verifies no DNS exception.
func TestProjectionRejectsAggregateReasonAndSetIncoherence(t *testing.T) {
	pass := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPass, SetReasonNone, true, false)
	fail := mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusFail, SetReasonSignatureMismatch, true, false)
	permanent := mustEligiblePermanentFact(t, VerificationReasonInvalidKey, true)
	hop := mustComplianceHop(t, 1, TransitionOrigin, false, false, false)
	tests := []struct {
		name     string
		protocol ProtocolClass
		reason   VerificationReason
		hops     []HopFact
		facts    []SignatureFact
	}{
		{name: "PASS non-none reason", protocol: ProtocolPASS, reason: VerificationReasonHashMismatch, hops: []HopFact{hop}, facts: []SignatureFact{pass}},
		{name: "PASS non-pass set", protocol: ProtocolPASS, reason: VerificationReasonNone, hops: []HopFact{hop}, facts: []SignatureFact{fail}},
		{name: "signature mismatch without fail set", protocol: ProtocolFAIL, reason: VerificationReasonSignatureMismatch, facts: []SignatureFact{pass}},
		{name: "hash mismatch with fail set", protocol: ProtocolFAIL, reason: VerificationReasonHashMismatch, facts: []SignatureFact{pass, fail}},
		{name: "eligible permanent without driving set", protocol: ProtocolPERMERROR, reason: VerificationReasonInvalidKey, facts: []SignatureFact{pass}},
		{name: "zero selected facts", protocol: ProtocolPERMERROR, reason: VerificationReasonInternalContract},
		{name: "eligible permanent wrong driving set", protocol: ProtocolPERMERROR, reason: VerificationReasonRevokedKey, facts: []SignatureFact{permanent}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projection, err := NewSelectedProjection(tt.protocol, tt.reason, 1, tt.hops, tt.facts, DefaultLimits())
			if !IsErrorCode(err, ErrorInternalContract) || !projection.IsZero() {
				t.Fatalf("incoherent projection = %#v error=%v", projection, err)
			}
		})
	}
}

// TestDNSTestingFindingOrderAndLimit verifies mode-before-DNS ordering and pre-count.
func TestDNSTestingFindingOrderAndLimit(t *testing.T) {
	projection := mustDNSProjection(t, ProtocolFAIL, VerificationReasonSignatureMismatch, []SignatureFact{
		mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusFail, SetReasonSignatureMismatch, true, false),
	})
	config := DefaultConfig()
	config.Mode = ModeTesting
	config.Limits.MaxFindings = 3
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if err != nil || !slices.Equal(findingReasons(decision.Findings()), []PolicyReason{ReasonProtocolFail, ReasonTestingModeObserve, ReasonDNSTestingEffective}) {
		t.Fatalf("ordered DNS decision = %#v error=%v", decision, err)
	}
	config.Limits.MaxFindings = 2
	evaluator, _ = NewEvaluator(config)
	decision, err = evaluator.EvaluateProjection(projection)
	if !IsErrorCode(err, ErrorLimitExceeded) || !decision.IsZero() {
		t.Fatalf("DNS limit decision = %#v error=%v", decision, err)
	}
}

// mustDNSProjection constructs one current selected projection with exact top-level reason.
func mustDNSProjection(t *testing.T, protocol ProtocolClass, reason VerificationReason, facts []SignatureFact) Projection {
	t.Helper()
	var hops []HopFact
	if protocol == ProtocolPASS {
		hops = []HopFact{mustComplianceHop(t, 1, TransitionOrigin, false, false, false)}
	}
	projection, err := NewSelectedProjection(protocol, reason, 1, hops, facts, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	return projection
}

// mustEligiblePermanentFact constructs one testing-eligible permanent set fact.
func mustEligiblePermanentFact(t *testing.T, reason VerificationReason, testing bool) SignatureFact {
	t.Helper()
	setReason := SetReason(reason)
	return mustProjectionSignatureFact(t, SetAlgorithmRSA, SetStatusPermerror, setReason, testing, false)
}

// dnsFindingReasons returns the exact DNS-class finding set.
func dnsFindingReasons(decision Decision) []PolicyReason {
	result := make([]PolicyReason, 0, 1)
	for _, finding := range decision.Findings() {
		switch finding.Reason() {
		case ReasonDNSTestingEffective, ReasonDNSTestingMixed, ReasonDNSTestingIneligible:
			result = append(result, finding.Reason())
		}
	}
	return result
}
