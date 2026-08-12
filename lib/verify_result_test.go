package dkim2

import "testing"

// TestPublicVerificationVocabulariesAreClosed proves public result tokens are exact and fail closed on zero or unknown values.
func TestPublicVerificationVocabulariesAreClosed(t *testing.T) {
	testKnownStrings(t, "result state", []knownString{
		{string(ResultStatePASS), ResultStatePASS.Known()},
		{string(ResultStateFAIL), ResultStateFAIL.Known()},
		{string(ResultStatePERMERROR), ResultStatePERMERROR.Known()},
		{string(ResultStateTEMPERROR), ResultStateTEMPERROR.Known()},
	}, func(value string) bool { return ResultState(value).Known() })

	testKnownStrings(t, "scope", []knownString{{string(VerificationScopeCurrent), VerificationScopeCurrent.Known()}, {string(VerificationScopeChain), VerificationScopeChain.Known()}}, func(value string) bool {
		return VerificationScope(value).Known()
	})
	testKnownStrings(t, "historical state", []knownString{{string(HistoricalStateNotEvaluated), HistoricalStateNotEvaluated.Known()}, {string(HistoricalStateComplete), HistoricalStateComplete.Known()}, {string(HistoricalStatePartial), HistoricalStatePartial.Known()}}, func(value string) bool {
		return HistoricalState(value).Known()
	})
	testKnownStrings(t, "custody structure", []knownString{
		{string(CustodyStructureNotEvaluated), CustodyStructureNotEvaluated.Known()},
		{string(CustodyStructureNotPresent), CustodyStructureNotPresent.Known()},
		{string(CustodyStructureNDLinksEvaluated), CustodyStructureNDLinksEvaluated.Known()},
		{string(CustodyStructureTerminalNDRequiresOOB), CustodyStructureTerminalNDRequiresOOB.Known()},
	}, func(value string) bool { return CustodyStructure(value).Known() })

	checks := []CheckClass{
		CheckClassMessage, CheckClassProtocol, CheckClassBodyHash,
		CheckClassHeaderHash, CheckClassSignature, CheckClassKey,
		CheckClassTimestamp, CheckClassEnvelope, CheckClassDomainAlignment,
		CheckClassNextDomain, CheckClassProvider, CheckClassInternalContract,
	}
	for _, check := range checks {
		if !check.Known() {
			t.Fatalf("check class %q is not known", check)
		}
	}
	if CheckClass("").Known() || CheckClass("future").Known() {
		t.Fatal("zero or unknown check class was accepted")
	}

	reasons := []ReasonCode{
		ReasonNone, ReasonInvalidRequest, ReasonLimitExceeded,
		ReasonMalformedMessage, ReasonMalformedProtocol, ReasonMissingProtocol,
		ReasonSequenceInvalid, ReasonUnsupportedAlgorithm, ReasonHashMismatch,
		ReasonSignatureMismatch, ReasonMissingKey, ReasonInvalidKey,
		ReasonAmbiguousKey, ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch, ReasonProviderTemporary, ReasonProviderPermanent,
		ReasonProviderContract, ReasonTimestampInvalid, ReasonEnvelopeMismatch,
		ReasonDomainAlignmentMismatch, ReasonNextDomainMismatch,
		ReasonOutOfBandRequired, ReasonInternalContract,
	}
	for _, reason := range reasons {
		if !reason.Known() {
			t.Fatalf("reason code %q is not known", reason)
		}
	}
	if ReasonCode("").Known() || ReasonCode("future").Known() {
		t.Fatal("zero or unknown reason code was accepted")
	}

	statuses := []SignatureStatus{
		SignatureStatusPASS, SignatureStatusFAIL, SignatureStatusPERMERROR,
		SignatureStatusTEMPERROR, SignatureStatusIgnored,
	}
	for _, status := range statuses {
		if !status.Known() {
			t.Fatalf("signature status %q is not known", status)
		}
	}
	if SignatureStatus("").Known() || SignatureStatus("future").Known() {
		t.Fatal("zero or unknown signature status was accepted")
	}
}

// TestVerifyResultAccessorsAreImmutable proves returned fact slices cannot mutate result-owned state.
func TestVerifyResultAccessorsAreImmutable(t *testing.T) {
	checks := []CheckFact{
		newCheckFact(CheckClassBodyHash, ReasonNone),
		newCheckFact(CheckClassSignature, ReasonNone),
	}
	signatures := []SignatureSetFact{
		newSignatureSetFact(AlgorithmRSASHA256, SignatureStatusPASS, ReasonNone),
	}
	result := newVerifyResult(verifyResultData{
		state:                ResultStatePASS,
		scope:                VerificationScopeCurrent,
		historicalContent:    HistoricalStateNotEvaluated,
		historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure:     CustodyStructureNotPresent,
		target:               newVerificationTarget(2, 3),
		primaryReason:        ReasonNone,
		checks:               checks,
		signatures:           signatures,
	})

	checks[0] = CheckFact{}
	signatures[0] = SignatureSetFact{}
	gotChecks := result.Checks()
	gotSignatures := result.SignatureSets()
	gotChecks[1] = CheckFact{}
	gotSignatures[0] = SignatureSetFact{}

	if got := result.Checks(); len(got) != 2 || got[0].Class() != CheckClassBodyHash || got[1].Class() != CheckClassSignature {
		t.Fatalf("Checks() exposed result storage: %#v", got)
	}
	if got := result.SignatureSets(); len(got) != 1 || got[0].Algorithm() != AlgorithmRSASHA256 || got[0].Status() != SignatureStatusPASS {
		t.Fatalf("SignatureSets() exposed result storage: %#v", got)
	}
	if result.Draft() != DraftIdentifier || result.State() != ResultStatePASS || result.Scope() != VerificationScopeCurrent {
		t.Fatal("result identity or current scope is incorrect")
	}
	if result.HistoricalContent() != HistoricalStateNotEvaluated || result.HistoricalSignatures() != HistoricalStateNotEvaluated {
		t.Fatal("result overstates historical coverage")
	}
	if result.CustodyStructure() != CustodyStructureNotPresent {
		t.Fatal("result custody structure is incorrect")
	}
	if result.Target().Sequence() != 2 || result.Target().Instance() != 3 {
		t.Fatal("result target is incorrect")
	}
}

// TestVerifyResultZeroValueCannotPass proves the zero result is detectably incomplete and never successful.
func TestVerifyResultZeroValueCannotPass(t *testing.T) {
	var result VerifyResult
	if result.State().Known() || result.State() == ResultStatePASS {
		t.Fatal("zero result became a known success state")
	}
	if result.Draft() != "" || result.Scope().Known() || result.HistoricalContent().Known() || result.CustodyStructure().Known() {
		t.Fatal("zero result claims verification coverage")
	}
	if result.Checks() != nil || result.SignatureSets() != nil {
		t.Fatal("zero result unexpectedly contains facts")
	}
}

// TestVerifyResultRejectsMetadataWithoutUniqueKey verifies public invariant ownership.
func TestVerifyResultRejectsMetadataWithoutUniqueKey(t *testing.T) {
	result := newVerifyResult(verifyResultData{
		state: ResultStatePERMERROR, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotPresent, primaryReason: ReasonMissingKey,
		signatures: []SignatureSetFact{newSignatureSetFact(AlgorithmRSASHA256, SignatureStatusPERMERROR, ReasonMissingKey, newKeyPolicyMetadata(true, false))},
	})
	if result.PrimaryReason() != ReasonInternalContract {
		t.Fatalf("PrimaryReason() = %q", result.PrimaryReason())
	}
}

// TestVerifyResultRejectsImpossibleCustodyPass proves indeterminate and terminal custody cannot pass.
func TestVerifyResultRejectsImpossibleCustodyPass(t *testing.T) {
	for _, custody := range []CustodyStructure{
		CustodyStructureNotEvaluated,
		CustodyStructureTerminalNDRequiresOOB,
	} {
		result := newVerifyResult(verifyResultData{
			state:                ResultStatePASS,
			scope:                VerificationScopeCurrent,
			historicalContent:    HistoricalStateNotEvaluated,
			historicalSignatures: HistoricalStateNotEvaluated,
			custodyStructure:     custody,
			primaryReason:        ReasonNone,
		})
		if result.State() != ResultStatePERMERROR ||
			result.CustodyStructure() != CustodyStructureNotEvaluated {
			t.Fatalf("invalid custody PASS did not fail closed: state=%q custody=%q", result.State(), result.CustodyStructure())
		}
		checks := result.Checks()
		if len(checks) != 1 || checks[0].Class() != CheckClassInternalContract || checks[0].Reason() != ReasonInternalContract {
			t.Fatal("invalid custody PASS omitted bounded internal-contract evidence")
		}
	}
}

type knownString struct {
	value string
	known bool
}

// testKnownStrings verifies an exact vocabulary and rejects zero and synthetic future values.
func testKnownStrings(t *testing.T, name string, values []knownString, known func(string) bool) {
	t.Helper()
	for _, value := range values {
		if !value.known {
			t.Fatalf("%s %q is not known", name, value.value)
		}
	}
	if known("") || known("future") {
		t.Fatalf("zero or unknown %s was accepted", name)
	}
}
