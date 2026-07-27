package httpjson

import (
	"math"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const futureMappingValue = "future"
const selectedRSAPassVector = "rsa_pass"

type scalarMappingCase[Input comparable, Output comparable] struct {
	input Input
	want  Output
}

// TestVerificationScalarMappings proves every reachable verification value maps explicitly.
func TestVerificationScalarMappings(t *testing.T) {
	assertScalarMapping(t, "verification state", mapVerificationState, []scalarMappingCase[dkim2.ResultState, generated.VerificationState]{
		{dkim2.ResultStatePASS, generated.PASS},
		{dkim2.ResultStateFAIL, generated.FAIL},
		{dkim2.ResultStatePERMERROR, generated.PERMERROR},
		{dkim2.ResultStateTEMPERROR, generated.TEMPERROR},
	})
	assertScalarMapping(t, "verification scope", mapVerificationScope, []scalarMappingCase[dkim2.VerificationScope, generated.VerificationResultScope]{
		{dkim2.VerificationScopeCurrent, generated.Current},
	})
	assertScalarMapping(t, "historical state", mapHistoricalState, []scalarMappingCase[dkim2.HistoricalState, generated.VerificationResultHistoricalContent]{
		{dkim2.HistoricalStateNotEvaluated, generated.VerificationResultHistoricalContentNotEvaluated},
	})
	assertScalarMapping(t, "historical signatures", mapHistoricalSignatures, []scalarMappingCase[dkim2.HistoricalState, generated.VerificationResultHistoricalSignatures]{
		{dkim2.HistoricalStateNotEvaluated, generated.VerificationResultHistoricalSignaturesNotEvaluated},
	})
	assertScalarMapping(t, "custody structure", mapCustodyStructure, []scalarMappingCase[dkim2.CustodyStructure, generated.VerificationResultCustodyStructure]{
		{dkim2.CustodyStructureNotEvaluated, generated.VerificationResultCustodyStructureNotEvaluated},
		{dkim2.CustodyStructureNotPresent, generated.VerificationResultCustodyStructureNotPresent},
		{dkim2.CustodyStructureNDLinksEvaluated, generated.VerificationResultCustodyStructureNdLinksEvaluated},
		{dkim2.CustodyStructureTerminalNDRequiresOOB, generated.VerificationResultCustodyStructureTerminalNdRequiresOob},
	})
	assertScalarMapping(t, "check class", mapCheckClass, []scalarMappingCase[dkim2.CheckClass, generated.VerificationCheckClass]{
		{dkim2.CheckClassMessage, generated.VerificationCheckClassMessage},
		{dkim2.CheckClassProtocol, generated.VerificationCheckClassProtocol},
		{dkim2.CheckClassBodyHash, generated.VerificationCheckClassBodyHash},
		{dkim2.CheckClassHeaderHash, generated.VerificationCheckClassHeaderHash},
		{dkim2.CheckClassSignature, generated.VerificationCheckClassSignature},
		{dkim2.CheckClassKey, generated.VerificationCheckClassKey},
		{dkim2.CheckClassTimestamp, generated.VerificationCheckClassTimestamp},
		{dkim2.CheckClassEnvelope, generated.VerificationCheckClassEnvelope},
		{dkim2.CheckClassDomainAlignment, generated.VerificationCheckClassDomainAlignment},
		{dkim2.CheckClassNextDomain, generated.VerificationCheckClassNextDomain},
		{dkim2.CheckClassProvider, generated.VerificationCheckClassProvider},
		{dkim2.CheckClassInternalContract, generated.VerificationCheckClassInternalContract},
	})
	assertScalarMapping(t, "algorithm", mapAlgorithm, []scalarMappingCase[dkim2.Algorithm, generated.SignatureSetResultAlgorithm]{
		{dkim2.AlgorithmRSASHA256, generated.RsaSha256},
		{dkim2.AlgorithmEd25519SHA256, generated.Ed25519Sha256},
		{dkim2.AlgorithmUnknown, generated.Unknown},
	})
	assertScalarMapping(t, "signature status", mapSignatureStatus, []scalarMappingCase[dkim2.SignatureStatus, generated.SignatureSetResultStatus]{
		{dkim2.SignatureStatusPASS, generated.SignatureSetResultStatusPass},
		{dkim2.SignatureStatusFAIL, generated.SignatureSetResultStatusFail},
		{dkim2.SignatureStatusPERMERROR, generated.SignatureSetResultStatusPermerror},
		{dkim2.SignatureStatusTEMPERROR, generated.SignatureSetResultStatusTemperror},
		{dkim2.SignatureStatusIgnored, generated.SignatureSetResultStatusIgnored},
	})
}

// TestProcessReportActionsAreDaemonOwned proves the daemon constructs the
// exact accepted RFC 8601 field while non-accepting outcomes remain inert.
func TestProcessReportActionsAreDaemonOwned(t *testing.T) {
	actions, err := mapProcessReportActions(
		generated.PASS,
		generated.DispositionAccept,
		"mx.example.test",
	)
	if err != nil || len(actions) != 1 ||
		actions[0].Type != generated.AddHeader ||
		actions[0].Name != generated.AuthenticationResults ||
		actions[0].Value != "mx.example.test; dkim2=pass" {
		t.Fatalf("accepted report actions = %#v/%v", actions, err)
	}
	actions, err = mapProcessReportActions(
		generated.TEMPERROR,
		generated.DispositionTempfail,
		"mx.example.test",
	)
	if err != nil || len(actions) != 0 {
		t.Fatalf("non-accepting report actions = %#v/%v", actions, err)
	}
	if _, err = mapProcessReportActions(
		generated.PASS,
		generated.DispositionAccept,
		"bad..example",
	); !IsMappingError(err, MappingInternalContract) {
		t.Fatalf("invalid reporting authority error = %v", err)
	}
}

// TestVerificationReasonMappingExcludesErrorOnlyValue proves REST never serializes public programmer misuse.
func TestVerificationReasonMappingExcludesErrorOnlyValue(t *testing.T) {
	assertScalarMapping(t, "verification reason", mapVerificationReason, []scalarMappingCase[dkim2.ReasonCode, generated.VerificationReason]{
		{dkim2.ReasonNone, generated.VerificationReasonNone},
		{dkim2.ReasonLimitExceeded, generated.VerificationReasonLimitExceeded},
		{dkim2.ReasonMalformedMessage, generated.VerificationReasonMalformedMessage},
		{dkim2.ReasonMalformedProtocol, generated.VerificationReasonMalformedProtocol},
		{dkim2.ReasonMissingProtocol, generated.VerificationReasonMissingProtocol},
		{dkim2.ReasonSequenceInvalid, generated.VerificationReasonSequenceInvalid},
		{dkim2.ReasonUnsupportedAlgorithm, generated.VerificationReasonUnsupportedAlgorithm},
		{dkim2.ReasonHashMismatch, generated.VerificationReasonHashMismatch},
		{dkim2.ReasonSignatureMismatch, generated.VerificationReasonSignatureMismatch},
		{dkim2.ReasonMissingKey, generated.VerificationReasonMissingKey},
		{dkim2.ReasonInvalidKey, generated.VerificationReasonInvalidKey},
		{dkim2.ReasonAmbiguousKey, generated.VerificationReasonAmbiguousKey},
		{dkim2.ReasonRevokedKey, generated.VerificationReasonRevokedKey},
		{dkim2.ReasonUnsupportedKeyType, generated.VerificationReasonUnsupportedKeyType},
		{dkim2.ReasonKeyAlgorithmMismatch, generated.VerificationReasonKeyAlgorithmMismatch},
		{dkim2.ReasonProviderTemporary, generated.VerificationReasonProviderTemporary},
		{dkim2.ReasonProviderPermanent, generated.VerificationReasonProviderPermanent},
		{dkim2.ReasonProviderContract, generated.VerificationReasonProviderContract},
		{dkim2.ReasonTimestampInvalid, generated.VerificationReasonTimestampInvalid},
		{dkim2.ReasonEnvelopeMismatch, generated.VerificationReasonEnvelopeMismatch},
		{dkim2.ReasonDomainAlignmentMismatch, generated.VerificationReasonDomainAlignmentMismatch},
		{dkim2.ReasonNextDomainMismatch, generated.VerificationReasonNextDomainMismatch},
		{dkim2.ReasonOutOfBandRequired, generated.VerificationReasonOutOfBandRequired},
		{dkim2.ReasonInternalContract, generated.VerificationReasonInternalContract},
	})

	if _, ok := mapVerificationReason(dkim2.ReasonInvalidRequest); ok {
		t.Fatal("error-only invalid_request mapped to REST")
	}
}

// TestPolicyScalarMappings proves the exact current-only policy vocabulary maps explicitly.
func TestPolicyScalarMappings(t *testing.T) {
	assertScalarMapping(t, "policy mode", mapPolicyMode, []scalarMappingCase[dkim2.PolicyMode, generated.PolicyResultMode]{
		{dkim2.PolicyModeStrict, generated.Strict},
		{dkim2.PolicyModePermissive, generated.Permissive},
		{dkim2.PolicyModeTesting, generated.Testing},
	})
	assertScalarMapping(t, "policy verdict", mapPolicyVerdict, []scalarMappingCase[dkim2.PolicyVerdict, generated.PolicyResultVerdict]{
		{dkim2.PolicyVerdictAccept, generated.PolicyResultVerdictAccept},
		{dkim2.PolicyVerdictReject, generated.PolicyResultVerdictReject},
		{dkim2.PolicyVerdictTempfail, generated.PolicyResultVerdictTempfail},
		{dkim2.PolicyVerdictContinue, generated.PolicyResultVerdictContinue},
	})
	assertScalarMapping(t, "disposition", mapDisposition, []scalarMappingCase[FinalDisposition, generated.Disposition]{
		{FinalDispositionAccept, generated.DispositionAccept},
		{FinalDispositionReject, generated.DispositionReject},
		{FinalDispositionTempfail, generated.DispositionTempfail},
		{FinalDispositionContinue, generated.DispositionContinue},
	})
	assertScalarMapping(t, "policy finding severity", mapPolicyFindingSeverity, []scalarMappingCase[dkim2.PolicyFindingSeverity, generated.PolicyFindingSeverity]{
		{dkim2.PolicySeverityInfo, generated.Info},
		{dkim2.PolicySeverityWarning, generated.Warning},
		{dkim2.PolicySeverityPermanent, generated.Permanent},
		{dkim2.PolicySeverityTemporary, generated.Temporary},
	})
}

// TestPolicyReasonMappingExcludesUnreachableHistory proves the wire inventory is narrower than the public engine.
func TestPolicyReasonMappingExcludesUnreachableHistory(t *testing.T) {
	assertScalarMapping(t, "policy reason", mapPolicyReason, []scalarMappingCase[dkim2.PolicyReason, generated.PolicyReason]{
		{dkim2.PolicyReasonProtocolPass, generated.ProtocolPass},
		{dkim2.PolicyReasonProtocolFail, generated.ProtocolFail},
		{dkim2.PolicyReasonProtocolPermerror, generated.ProtocolPermerror},
		{dkim2.PolicyReasonProtocolTemperror, generated.ProtocolTemperror},
		{dkim2.PolicyReasonPermissiveOverride, generated.PermissiveOverride},
		{dkim2.PolicyReasonTestingModeObserve, generated.TestingModeObserve},
		{dkim2.PolicyReasonDNSTestingEffective, generated.DnsTestingEffective},
		{dkim2.PolicyReasonDNSTestingMixed, generated.DnsTestingMixed},
		{dkim2.PolicyReasonDNSTestingIneligible, generated.DnsTestingIneligible},
		{dkim2.PolicyReasonDoNotModifyNotEvaluated, generated.DonotmodifyNotEvaluated},
		{dkim2.PolicyReasonDoNotExplodeNotEvaluated, generated.DonotexplodeNotEvaluated},
		{dkim2.PolicyReasonFeedbackRequested, generated.FeedbackRequested},
		{dkim2.PolicyReasonFeedbackRelaySelected, generated.FeedbackRelaySelected},
		{dkim2.PolicyReasonFeedHereInert, generated.FeedhereInert},
		{dkim2.PolicyReasonExplodedReported, generated.ExplodedReported},
	})

	rejected := []dkim2.PolicyReason{
		dkim2.PolicyReasonInvalidInput,
		dkim2.PolicyReasonLimitExceeded,
		dkim2.PolicyReasonInternalContract,
		dkim2.PolicyReasonDoNotModifyHonored,
		dkim2.PolicyReasonDoNotModifyViolated,
		dkim2.PolicyReasonDoNotModifyIndeterminate,
		dkim2.PolicyReasonDoNotExplodeViolated,
		dkim2.PolicyReasonDoNotExplodeIndeterminate,
	}
	for _, reason := range rejected {
		if _, ok := mapPolicyReason(reason); ok {
			t.Fatalf("unreachable policy reason %q mapped to REST", reason)
		}
	}
}

// TestCurrentOnlySingletonMappingsRejectHistoricalClaims proves current-only output cannot overstate history.
func TestCurrentOnlySingletonMappingsRejectHistoricalClaims(t *testing.T) {
	if got, ok := mapDoNotModify(dkim2.PolicyComplianceNotEvaluated); !ok || got != generated.PolicyResultDoNotModifyNotEvaluated {
		t.Fatalf("mapDoNotModify(not_evaluated) = %q/%t", got, ok)
	}
	if got, ok := mapDoNotExplode(dkim2.PolicyComplianceNotEvaluated); !ok || got != generated.PolicyResultDoNotExplodeNotEvaluated {
		t.Fatalf("mapDoNotExplode(not_evaluated) = %q/%t", got, ok)
	}
	if got, ok := mapPolicyHistoryCoverage(dkim2.PolicyHistoryNotEvaluated); !ok || got != generated.PolicyFeedbackHistoryCoverageNotEvaluated {
		t.Fatalf("mapPolicyHistoryCoverage(not_evaluated) = %q/%t", got, ok)
	}

	for _, value := range []dkim2.PolicyCompliance{
		dkim2.PolicyComplianceNotRequested,
		dkim2.PolicyComplianceHonored,
		dkim2.PolicyComplianceViolated,
		dkim2.PolicyComplianceIndeterminate,
	} {
		if _, ok := mapDoNotModify(value); ok {
			t.Fatalf("historical modification compliance %q mapped", value)
		}
		if _, ok := mapDoNotExplode(value); ok {
			t.Fatalf("historical explosion compliance %q mapped", value)
		}
	}
	for _, value := range []dkim2.PolicyHistoryCoverage{
		dkim2.PolicyHistoryComplete,
		dkim2.PolicyHistoryIndeterminate,
	} {
		if _, ok := mapPolicyHistoryCoverage(value); ok {
			t.Fatalf("historical feedback coverage %q mapped", value)
		}
	}
	if got, ok := mapStrictIdentityApplicable(false); !ok || got != generated.False {
		t.Fatalf("mapStrictIdentityApplicable(false) = %t/%t", got, ok)
	}
	if _, ok := mapStrictIdentityApplicable(true); ok {
		t.Fatal("impossible strict-identity applicability mapped")
	}
}

// TestCanonicalUint64MappingRejectsZero proves target and sequence strings stay exact.
func TestCanonicalUint64MappingRejectsZero(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
		ok    bool
	}{
		{input: 0, ok: false},
		{input: 1, want: "1", ok: true},
		{input: 10, want: "10", ok: true},
		{input: math.MaxInt64, want: "9223372036854775807", ok: true},
		{input: uint64(math.MaxInt64) + 1, want: "9223372036854775808", ok: true},
		{input: math.MaxUint64, want: "18446744073709551615", ok: true},
	}
	for _, testCase := range tests {
		got, ok := mapCanonicalUint64(testCase.input)
		if ok != testCase.ok || got != testCase.want {
			t.Fatalf("mapCanonicalUint64(%d) = %q/%t, want %q/%t", testCase.input, got, ok, testCase.want, testCase.ok)
		}
	}
}

// TestScalarMappingsRejectZeroAndFutureValues proves no mapper relies on string casts.
func TestScalarMappingsRejectZeroAndFutureValues(t *testing.T) {
	rejectScalarMapping(t, "verification state", mapVerificationState, []dkim2.ResultState{"", futureMappingValue})
	rejectScalarMapping(t, "verification scope", mapVerificationScope, []dkim2.VerificationScope{"", futureMappingValue})
	rejectScalarMapping(t, "historical state", mapHistoricalState, []dkim2.HistoricalState{"", futureMappingValue})
	rejectScalarMapping(t, "historical signatures", mapHistoricalSignatures, []dkim2.HistoricalState{"", futureMappingValue})
	rejectScalarMapping(t, "custody structure", mapCustodyStructure, []dkim2.CustodyStructure{"", futureMappingValue})
	rejectScalarMapping(t, "verification reason", mapVerificationReason, []dkim2.ReasonCode{"", futureMappingValue, dkim2.ReasonInvalidRequest})
	rejectScalarMapping(t, "check class", mapCheckClass, []dkim2.CheckClass{"", futureMappingValue})
	rejectScalarMapping(t, "algorithm", mapAlgorithm, []dkim2.Algorithm{"", futureMappingValue})
	rejectScalarMapping(t, "signature status", mapSignatureStatus, []dkim2.SignatureStatus{"", futureMappingValue})
	rejectScalarMapping(t, "policy mode", mapPolicyMode, []dkim2.PolicyMode{"", futureMappingValue})
	rejectScalarMapping(t, "policy verdict", mapPolicyVerdict, []dkim2.PolicyVerdict{"", futureMappingValue})
	rejectScalarMapping(t, "disposition", mapDisposition, []FinalDisposition{0, 255})
	rejectScalarMapping(t, "policy reason", mapPolicyReason, []dkim2.PolicyReason{"", futureMappingValue, dkim2.PolicyReasonInvalidInput})
	rejectScalarMapping(t, "policy finding severity", mapPolicyFindingSeverity, []dkim2.PolicyFindingSeverity{"", futureMappingValue})
}

// assertScalarMapping checks a complete explicit input/output inventory.
func assertScalarMapping[Input comparable, Output comparable](
	t *testing.T,
	name string,
	mapper func(Input) (Output, bool),
	cases []scalarMappingCase[Input, Output],
) {
	t.Helper()
	for _, testCase := range cases {
		got, ok := mapper(testCase.input)
		if !ok || got != testCase.want {
			t.Fatalf("%s mapper(%v) = %v/%t, want %v/true", name, testCase.input, got, ok, testCase.want)
		}
	}
}

// rejectScalarMapping checks fail-closed behavior for zero and synthetic future values.
func rejectScalarMapping[Input comparable, Output comparable](
	t *testing.T,
	name string,
	mapper func(Input) (Output, bool),
	values []Input,
) {
	t.Helper()
	for _, value := range values {
		if got, ok := mapper(value); ok {
			t.Fatalf("%s mapper(%v) unexpectedly returned %v", name, value, got)
		}
	}
}
