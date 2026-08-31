package httpjson

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

// TestMappingSnapshotsFormatWithoutIdentifiers proves private source-bound views cannot leak sequences.
func TestMappingSnapshotsFormatWithoutIdentifiers(t *testing.T) {
	verification := verificationSnapshot{state: &verificationSnapshotState{
		targetSequence: math.MaxUint64,
		targetInstance: math.MaxUint64 - 1,
	}}
	policy := policySnapshot{state: &policySnapshotState{
		feedbackRelaySequence: math.MaxUint64,
		findings:              []policyFindingSnapshot{{sequence: math.MaxUint64 - 1, hasSequence: true}},
	}}
	values := []any{verification, &verification, policy, &policy, []verificationSnapshot{verification}, []policySnapshot{policy}}
	var formatted strings.Builder
	for _, value := range values {
		fmt.Fprintf(&formatted, "%s %q %v %+v %#v %x %p\n", value, value, value, value, value, value, value)
	}
	text := formatted.String()
	if strings.Contains(text, "18446744073709551615") ||
		strings.Contains(text, "18446744073709551614") ||
		!strings.Contains(text, mappingSnapshotRedacted) {
		t.Fatal("mapping snapshot formatting was not content-free")
	}
}

type unusedPublicKeyProvider struct{}

// LookupPublicKey fails the test contract if a missing-protocol fixture reaches DNS.
func (unusedPublicKeyProvider) LookupPublicKey(context.Context, dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	return dkim2.PublicKeyResult{}, dkim2.NewPermanentProviderError()
}

// TestVerificationSnapshotMapsOneAuthenticCurrentResult proves the private view remains bound to its sealed source.
func TestVerificationSnapshotMapsOneAuthenticCurrentResult(t *testing.T) {
	result, _ := currentMissingProtocolResult(t)
	snapshot := captureVerification(result)
	mapped, err := mapVerificationSnapshot(snapshot)
	if err != nil {
		t.Fatalf("authentic verification snapshot was rejected: %v", err)
	}
	if mapped.State != generated.PERMERROR ||
		mapped.PrimaryReason != generated.VerificationReasonMissingProtocol ||
		mapped.Scope != generated.Current ||
		mapped.HistoricalContent != generated.VerificationResultHistoricalContentNotEvaluated ||
		mapped.HistoricalSignatures != generated.VerificationResultHistoricalSignaturesNotEvaluated ||
		mapped.Target != nil ||
		len(mapped.Checks) == 0 ||
		len(mapped.Checks) != result.CheckCount() ||
		len(mapped.SignatureSets) != result.SignatureSetCount() {
		t.Fatal("mapped verification shape is incoherent")
	}
}

// TestVerificationSnapshotRejectsEveryForgedAggregateField proves mapper data cannot diverge from its sealed source.
func TestVerificationSnapshotRejectsEveryForgedAggregateField(t *testing.T) {
	result, _ := currentMissingProtocolResult(t)
	base := captureVerification(result)
	if _, err := mapVerificationSnapshot(verificationSnapshot{}); err == nil {
		t.Fatal("nil-state verification snapshot mapped")
	}

	tests := []struct {
		name   string
		mutate func(*verificationSnapshot)
	}{
		{name: "zero source", mutate: func(value *verificationSnapshot) { value.state.source = dkim2.VerifyResult{} }},
		{name: testDraftName, mutate: func(value *verificationSnapshot) { value.state.draft = futureMappingValue }},
		{name: "state", mutate: func(value *verificationSnapshot) { value.state.state = dkim2.ResultStatePASS }},
		{name: "scope", mutate: func(value *verificationSnapshot) { value.state.scope = dkim2.VerificationScope(futureMappingValue) }},
		{name: "historical content", mutate: func(value *verificationSnapshot) {
			value.state.historicalContent = dkim2.HistoricalState(futureMappingValue)
		}},
		{name: "historical signatures", mutate: func(value *verificationSnapshot) {
			value.state.historicalSignatures = dkim2.HistoricalState(futureMappingValue)
		}},
		{name: "custody", mutate: func(value *verificationSnapshot) {
			if value.state.custody == dkim2.CustodyStructureNotEvaluated {
				value.state.custody = dkim2.CustodyStructureNotPresent
			} else {
				value.state.custody = dkim2.CustodyStructureNotEvaluated
			}
		}},
		{name: "primary reason", mutate: func(value *verificationSnapshot) { value.state.primaryReason = dkim2.ReasonInvalidRequest }},
		{name: "half target sequence", mutate: func(value *verificationSnapshot) { value.state.targetSequence = 1 }},
		{name: "half target instance", mutate: func(value *verificationSnapshot) { value.state.targetInstance = 1 }},
		{name: "empty checks", mutate: func(value *verificationSnapshot) { value.state.checks = nil }},
		{name: "check class", mutate: func(value *verificationSnapshot) {
			value.state.checks[0].class = dkim2.CheckClass("future")
		}},
		{name: "check reason", mutate: func(value *verificationSnapshot) {
			value.state.checks[0].reason = dkim2.ReasonInvalidRequest
		}},
		{name: "check count", mutate: func(value *verificationSnapshot) { value.state.checkCount++ }},
		{name: "signature count", mutate: func(value *verificationSnapshot) { value.state.signatureCount++ }},
		{name: "extra signature", mutate: func(value *verificationSnapshot) {
			value.state.signatures = append(value.state.signatures, signatureSetSnapshot{})
		}},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			forged := cloneVerificationSnapshot(base)
			testCase.mutate(&forged)
			if _, err := mapVerificationSnapshot(forged); err == nil {
				t.Fatal("forged verification snapshot mapped")
			}
		})
	}
}

// TestPolicySnapshotMapsOneAuthenticCurrentDecision proves current-only policy output remains source-bound.
func TestPolicySnapshotMapsOneAuthenticCurrentDecision(t *testing.T) {
	result, decision := currentMissingProtocolResult(t)
	snapshot := capturePolicy(decision)
	mapped, err := mapPolicySnapshot(snapshot, result.State())
	if err != nil {
		t.Fatalf("authentic policy snapshot was rejected: %v", err)
	}
	if mapped.Mode != generated.Strict ||
		mapped.Verdict != generated.PolicyResultVerdictReject ||
		mapped.PrimaryReason != generated.ProtocolPermerror ||
		mapped.DoNotModify != generated.PolicyResultDoNotModifyNotEvaluated ||
		mapped.DoNotExplode != generated.PolicyResultDoNotExplodeNotEvaluated ||
		mapped.Feedback.HistoryCoverage != generated.PolicyFeedbackHistoryCoverageNotEvaluated ||
		len(mapped.Findings) == 0 {
		t.Fatal("mapped policy shape is incoherent")
	}
}

// TestPolicySnapshotRejectsEveryForgedAggregateField proves redundant policy facts cannot disagree.
func TestPolicySnapshotRejectsEveryForgedAggregateField(t *testing.T) {
	result, decision := currentMissingProtocolResult(t)
	base := capturePolicy(decision)
	if _, err := mapPolicySnapshot(policySnapshot{}, result.State()); err == nil {
		t.Fatal("nil-state policy snapshot mapped")
	}

	tests := []struct {
		name   string
		mutate func(*policySnapshot)
	}{
		{name: "zero source", mutate: func(value *policySnapshot) { value.state.source = dkim2.PolicyDecision{} }},
		{name: "verification state", mutate: func(value *policySnapshot) { value.state.verificationState = dkim2.ResultStatePASS }},
		{name: "mode", mutate: func(value *policySnapshot) { value.state.mode = dkim2.PolicyModePermissive }},
		{name: "verdict", mutate: func(value *policySnapshot) { value.state.verdict = dkim2.PolicyVerdictAccept }},
		{name: "primary reason", mutate: func(value *policySnapshot) { value.state.primaryReason = dkim2.PolicyReasonInternalContract }},
		{name: "modify compliance", mutate: func(value *policySnapshot) { value.state.doNotModify = dkim2.PolicyComplianceHonored }},
		{name: "explode compliance", mutate: func(value *policySnapshot) { value.state.doNotExplode = dkim2.PolicyComplianceViolated }},
		{name: "feedback requested", mutate: func(value *policySnapshot) { value.state.feedbackRequested = !value.state.feedbackRequested }},
		{name: "feedback relay required", mutate: func(value *policySnapshot) {
			value.state.feedbackRelayRequired = !value.state.feedbackRelayRequired
		}},
		{name: "feedback relay sequence", mutate: func(value *policySnapshot) { value.state.feedbackRelaySequence = 1 }},
		{name: "feedback history", mutate: func(value *policySnapshot) {
			value.state.feedbackHistory = dkim2.PolicyHistoryComplete
		}},
		{name: "DNS testing", mutate: func(value *policySnapshot) { value.state.dnsTestingEffective = !value.state.dnsTestingEffective }},
		{name: "empty findings", mutate: func(value *policySnapshot) { value.state.findings = nil }},
		{name: "extra finding", mutate: func(value *policySnapshot) {
			value.state.findings = append(value.state.findings, policyFindingSnapshot{})
		}},
		{name: "finding reason", mutate: func(value *policySnapshot) {
			value.state.findings[0].reason = dkim2.PolicyReasonInternalContract
		}},
		{name: "finding severity", mutate: func(value *policySnapshot) {
			value.state.findings[0].severity = dkim2.PolicyFindingSeverity("future")
		}},
		{name: "finding sequence", mutate: func(value *policySnapshot) { value.state.findings[0].sequence++ }},
		{name: "finding sequence presence", mutate: func(value *policySnapshot) {
			value.state.findings[0].hasSequence = !value.state.findings[0].hasSequence
		}},
		{name: "finding validity", mutate: func(value *policySnapshot) { value.state.findings[0].valid = false }},
		{name: "invalid action", mutate: func(value *policySnapshot) { value.state.actionValid = false }},
		{name: "action kind", mutate: func(value *policySnapshot) { value.state.actionKind = dkim2.PolicyActionAccept }},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			forged := clonePolicySnapshot(base)
			testCase.mutate(&forged)
			if _, err := mapPolicySnapshot(forged, result.State()); err == nil {
				t.Fatal("forged policy snapshot mapped")
			}
		})
	}

	if _, err := mapPolicySnapshot(base, dkim2.ResultStatePASS); err == nil {
		t.Fatal("policy snapshot mapped against a different verification state")
	}
}

// TestMapDomainResultFailureIsAtomic proves either invalid aggregate returns no partial DTO.
func TestMapDomainResultFailureIsAtomic(t *testing.T) {
	result, decision := currentMissingProtocolResult(t)
	tests := []struct {
		name     string
		result   dkim2.VerifyResult
		decision dkim2.PolicyDecision
	}{
		{name: "zero verification", result: dkim2.VerifyResult{}, decision: decision},
		{name: "zero policy", result: result, decision: dkim2.PolicyDecision{}},
		{name: "both zero"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			projection, err := MapDomainResult(testCase.result, testCase.decision)
			if err == nil || !IsMappingError(err, MappingInternalContract) {
				t.Fatalf("MapDomainResult() error = %v", err)
			}
			verification, policy, valid := projection.domainValues()
			if valid ||
				!reflect.DeepEqual(verification, generated.VerificationResult{}) ||
				!reflect.DeepEqual(policy, generated.PolicyResult{}) {
				t.Fatal("MapDomainResult() returned a partial projection")
			}
		})
	}
}

// TestDomainProjectionDeepClonesEveryMutableDTOField proves extraction cannot mutate retained output.
func TestDomainProjectionDeepClonesEveryMutableDTOField(t *testing.T) {
	maximum := generated.CanonicalUint64("18446744073709551615")
	target := generated.VerificationTarget{Sequence: maximum, Instance: maximum}
	findingSequence := maximum
	relaySequence := maximum
	projection := DomainProjection{state: &domainProjectionState{
		verification: generated.VerificationResult{
			Checks:        []generated.VerificationCheck{{Class: generated.VerificationCheckClassMessage, Reason: generated.VerificationReasonNone}},
			SignatureSets: []generated.SignatureSetResult{{Algorithm: generated.RsaSha256}},
			Target:        &target,
		},
		policy: generated.PolicyResult{
			Findings: []generated.PolicyFinding{{Reason: generated.ProtocolPass, Sequence: &findingSequence}},
			Feedback: generated.PolicyFeedback{RelaySequence: &relaySequence},
		},
	}}

	firstVerification, firstPolicy, ok := projection.domainValues()
	if !ok {
		t.Fatal("valid projection did not expose package-owned values")
	}
	firstVerification.Checks[0] = generated.VerificationCheck{}
	firstVerification.SignatureSets[0] = generated.SignatureSetResult{}
	*firstVerification.Target = generated.VerificationTarget{}
	*firstPolicy.Findings[0].Sequence = generated.CanonicalUint64("1")
	firstPolicy.Findings[0] = generated.PolicyFinding{}
	*firstPolicy.Feedback.RelaySequence = generated.CanonicalUint64("1")

	secondVerification, secondPolicy, ok := projection.domainValues()
	if !ok || len(secondVerification.Checks) != 1 || len(secondVerification.SignatureSets) != 1 ||
		secondVerification.Target == nil || secondVerification.Target.Sequence != maximum ||
		len(secondPolicy.Findings) != 1 || secondPolicy.Findings[0].Sequence == nil ||
		*secondPolicy.Findings[0].Sequence != maximum || secondPolicy.Feedback.RelaySequence == nil ||
		*secondPolicy.Feedback.RelaySequence != maximum {
		t.Fatal("caller mutation changed retained projection state")
	}
}

// TestDomainProjectionFormattingAndSerializationAreContentFree proves the DTO owner is opaque.
func TestDomainProjectionFormattingAndSerializationAreContentFree(t *testing.T) {
	maximum := generated.CanonicalUint64("18446744073709551615")
	projection := DomainProjection{state: &domainProjectionState{
		verification: generated.VerificationResult{
			Target: &generated.VerificationTarget{Sequence: maximum, Instance: maximum},
		},
		policy: generated.PolicyResult{
			Findings: []generated.PolicyFinding{{Sequence: &maximum}},
			Feedback: generated.PolicyFeedback{RelaySequence: &maximum},
		},
	}}
	values := []any{
		projection, &projection, any(projection),
		[]DomainProjection{projection}, map[DomainProjection]bool{projection: true},
	}
	var formatted strings.Builder
	for _, value := range values {
		fmt.Fprintf(&formatted, "%s|%q|%v|%+v|%#v|%x|%p\n", value, value, value, value, value, value, value)
	}
	if strings.Contains(formatted.String(), "18446744073709551615") ||
		strings.Contains(strings.ToLower(formatted.String()), "ffffffffffffffff") ||
		!strings.Contains(formatted.String(), domainProjectionRedacted) {
		t.Fatal("domain projection formatting exposed response identifiers")
	}
	if encoded, err := json.Marshal(projection); err == nil || len(encoded) != 0 {
		t.Fatal("domain projection allowed direct JSON serialization")
	}
	if encoded, err := projection.MarshalText(); err == nil || len(encoded) != 0 {
		t.Fatal("domain projection allowed direct text serialization")
	}
}

type selectedGoldenCorpus struct {
	Draft       string `json:"draft"`
	RSAModulus  string `json:"rsa_modulus_base64"`
	RSAExponent int    `json:"rsa_exponent"`
	Vectors     map[string]struct {
		Raw     string   `json:"raw_base64"`
		Reverse string   `json:"reverse_path_base64"`
		Forward []string `json:"forward_paths_base64"`
	} `json:"vectors"`
}

// loadSelectedGoldenCorpus loads the shared authenticated response fixture.
func loadSelectedGoldenCorpus(t *testing.T) selectedGoldenCorpus {
	t.Helper()

	corpusBytes, err := os.ReadFile("../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/public-golden.json")
	if err != nil {
		t.Fatal("golden verification corpus unavailable")
	}

	var corpus selectedGoldenCorpus
	if json.Unmarshal(corpusBytes, &corpus) != nil || corpus.Draft != dkim2.DraftIdentifier {
		t.Fatal("golden verification corpus was invalid")
	}

	return corpus
}

// selectedGoldenRSAKey constructs the public key bound to the shared corpus.
func selectedGoldenRSAKey(t *testing.T, corpus selectedGoldenCorpus) *rsa.PublicKey {
	t.Helper()

	modulus := decodeSelectedGolden(t, corpus.RSAModulus)

	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: corpus.RSAExponent}
}

type fixedTXTTransport struct {
	payload []byte
}

// LookupTXT returns one deterministic DNS key record.
func (t fixedTXTTransport) LookupTXT(context.Context, string) (dkim2.TXTLookupResult, error) {
	return dkim2.NewFoundTXTLookupResult([][]byte{t.payload}, time.Minute, dkim2.DNSSECStatusUnavailable)
}

type selectedProviderOutcome uint8

const (
	selectedProviderFound selectedProviderOutcome = iota
	selectedProviderMissing
	selectedProviderTemporary
)

type selectedMatrixProvider struct {
	key     *rsa.PublicKey
	outcome selectedProviderOutcome
}

type selectedMatrixCase struct {
	name       string
	vector     string
	outcome    selectedProviderOutcome
	state      dkim2.ResultState
	reason     dkim2.ReasonCode
	strict     dkim2.PolicyReason
	permissive dkim2.PolicyReason
}

// LookupPublicKey returns one closed matrix outcome.
func (p selectedMatrixProvider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	switch p.outcome {
	case selectedProviderFound:
		return dkim2.FoundRSAPublicKey(p.key), nil
	case selectedProviderMissing:
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	case selectedProviderTemporary:
		return dkim2.PublicKeyResult{}, dkim2.NewTemporaryProviderError()
	default:
		return dkim2.PublicKeyResult{}, dkim2.NewPermanentProviderError()
	}
}

// TestMapDomainResultMapsAuthenticSelectedSignatureAndKeyPolicy proves end-to-end selected output.
func TestMapDomainResultMapsAuthenticSelectedSignatureAndKeyPolicy(t *testing.T) {
	corpus := loadSelectedGoldenCorpus(t)
	vector, ok := corpus.Vectors["rsa_pass"]
	if !ok {
		t.Fatal("golden RSA PASS vector unavailable")
	}
	keyDER := x509.MarshalPKCS1PublicKey(selectedGoldenRSAKey(t, corpus))
	record := []byte("p=" + base64.StdEncoding.EncodeToString(keyDER) + "; t=y:s")
	provider, err := dkim2.NewDNSPublicKeyProvider(fixedTXTTransport{payload: record})
	if err != nil {
		t.Fatal("DNS provider construction failed")
	}
	verifier, err := dkim2.NewVerifier(provider, dkim2.WithVerificationClock(func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}))
	if err != nil {
		t.Fatal("verifier construction failed")
	}
	forward := make([][]byte, len(vector.Forward))
	for index, value := range vector.Forward {
		forward[index] = decodeSelectedGolden(t, value)
	}
	result, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(
		decodeSelectedGolden(t, vector.Raw),
		decodeSelectedGolden(t, vector.Reverse),
		forward,
	))
	if err != nil || !result.Valid() || result.State() != dkim2.ResultStatePASS {
		t.Fatal("authentic selected verification did not pass")
	}
	decision, err := dkim2.EvaluatePolicy(result, dkim2.WithPolicyMode(dkim2.PolicyModeStrict))
	if err != nil || !decision.Valid() {
		t.Fatal("authentic selected policy decision failed")
	}
	projection, err := MapDomainResult(result, decision)
	if err != nil {
		t.Fatal("authentic selected result did not map")
	}
	verification, _, ok := projection.domainValues()
	if !ok || verification.Target == nil || verification.Target.Sequence != generated.CanonicalUint64("1") ||
		verification.Target.Instance != generated.CanonicalUint64("1") ||
		len(verification.SignatureSets) != 1 ||
		verification.SignatureSets[0].Algorithm != generated.RsaSha256 ||
		verification.SignatureSets[0].Status != generated.SignatureSetResultStatusPass ||
		verification.SignatureSets[0].Reason != generated.VerificationReasonNone ||
		!verification.SignatureSets[0].KeyPolicy.TestingDeclared ||
		!verification.SignatureSets[0].KeyPolicy.StrictIdentityDeclared ||
		bool(verification.SignatureSets[0].KeyPolicy.StrictIdentityApplicable) {
		t.Fatal("selected signature or DNS key policy was not mapped exactly")
	}
}

// TestMapDomainResultAuthenticFourStatePolicyMatrix proves combined result and policy gates accept every legal cell.
func TestMapDomainResultAuthenticFourStatePolicyMatrix(t *testing.T) {
	corpus := loadSelectedGoldenCorpus(t)
	key := selectedGoldenRSAKey(t, corpus)
	states := []selectedMatrixCase{
		{name: authenticationResultPass, vector: selectedRSAPassVector, outcome: selectedProviderFound, state: dkim2.ResultStatePASS, reason: dkim2.ReasonNone, strict: dkim2.PolicyReasonProtocolPass, permissive: dkim2.PolicyReasonProtocolPass},
		{name: authenticationResultFail, vector: "body_mismatch", outcome: selectedProviderFound, state: dkim2.ResultStateFAIL, reason: dkim2.ReasonHashMismatch, strict: dkim2.PolicyReasonProtocolFail, permissive: dkim2.PolicyReasonPermissiveOverride},
		{name: authenticationResultPermerror, vector: selectedRSAPassVector, outcome: selectedProviderMissing, state: dkim2.ResultStatePERMERROR, reason: dkim2.ReasonMissingKey, strict: dkim2.PolicyReasonProtocolPermerror, permissive: dkim2.PolicyReasonPermissiveOverride},
		{name: authenticationResultTemperror, vector: selectedRSAPassVector, outcome: selectedProviderTemporary, state: dkim2.ResultStateTEMPERROR, reason: dkim2.ReasonProviderTemporary, strict: dkim2.PolicyReasonProtocolTemperror, permissive: dkim2.PolicyReasonProtocolTemperror},
	}
	modes := []dkim2.PolicyMode{dkim2.PolicyModeStrict, dkim2.PolicyModePermissive, dkim2.PolicyModeTesting}
	for _, stateCase := range states {
		result := authenticSelectedMatrixResult(t, corpus, key, stateCase)
		for _, mode := range modes {
			t.Run(stateCase.name+"/"+string(mode), func(t *testing.T) {
				assertAuthenticMappedCell(t, result, stateCase, mode)
			})
		}
	}
}

// authenticSelectedMatrixResult obtains one library-owned selected verification state.
func authenticSelectedMatrixResult(t *testing.T, corpus selectedGoldenCorpus, key *rsa.PublicKey, testCase selectedMatrixCase) dkim2.VerifyResult {
	t.Helper()
	vector, ok := corpus.Vectors[testCase.vector]
	if !ok {
		t.Fatal("required matrix vector unavailable")
	}
	forward := make([][]byte, len(vector.Forward))
	for index, value := range vector.Forward {
		forward[index] = decodeSelectedGolden(t, value)
	}
	verifier, err := dkim2.NewVerifier(
		selectedMatrixProvider{key: key, outcome: testCase.outcome},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatal("matrix verifier construction failed")
	}
	result, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(
		decodeSelectedGolden(t, vector.Raw), decodeSelectedGolden(t, vector.Reverse), forward,
	))
	if err != nil || !result.Valid() || result.State() != testCase.state ||
		result.PrimaryReason() != testCase.reason || result.Target().Sequence() != 1 {
		t.Fatal("authentic selected matrix verification was incoherent")
	}
	return result
}

// assertAuthenticMappedCell verifies one policy-mode projection exactly.
func assertAuthenticMappedCell(t *testing.T, result dkim2.VerifyResult, testCase selectedMatrixCase, mode dkim2.PolicyMode) {
	t.Helper()
	decision, err := dkim2.EvaluatePolicy(result, dkim2.WithPolicyMode(mode))
	if err != nil || !decision.Valid() || decision.PrimaryReason() != expectedMatrixPolicyReason(testCase, mode) {
		t.Fatal("authentic matrix policy decision failed")
	}
	projection, err := MapDomainResult(result, decision)
	if err != nil {
		t.Fatal("authentic matrix cell did not map")
	}
	verification, policyResult, valid := projection.domainValues()
	wantState, _ := mapVerificationState(testCase.state)
	wantReason, _ := mapVerificationReason(testCase.reason)
	wantMode, _ := mapPolicyMode(mode)
	wantVerdict, _ := mapPolicyVerdict(decision.Verdict())
	wantPolicyReason, _ := mapPolicyReason(decision.PrimaryReason())
	wantCustody, _ := mapCustodyStructure(result.CustodyStructure())
	wantScope, _ := mapVerificationScope(result.Scope())
	wantContent, _ := mapHistoricalContent(result.HistoricalContent())
	wantSignatures, _ := mapHistoricalSignatures(result.HistoricalSignatures())
	if !valid || verification.State != wantState || verification.PrimaryReason != wantReason ||
		verification.Scope != wantScope ||
		verification.HistoricalContent != wantContent ||
		verification.HistoricalSignatures != wantSignatures ||
		verification.CustodyStructure != wantCustody ||
		verification.Target == nil || verification.Target.Sequence != generated.CanonicalUint64("1") ||
		verification.Target.Instance != generated.CanonicalUint64("1") ||
		len(verification.Checks) != result.CheckCount() ||
		len(verification.SignatureSets) != result.SignatureSetCount() ||
		policyResult.Mode != wantMode || policyResult.Verdict != wantVerdict ||
		policyResult.PrimaryReason != wantPolicyReason ||
		policyResult.DoNotModify != generated.PolicyResultDoNotModifyNotEvaluated ||
		policyResult.DoNotExplode != generated.PolicyResultDoNotExplodeNotEvaluated {
		t.Fatal("authentic matrix cell mapped incorrect state or policy")
	}
}

// expectedMatrixPolicyReason returns the exact mode-specific reason for one verification state.
func expectedMatrixPolicyReason(testCase selectedMatrixCase, mode dkim2.PolicyMode) dkim2.PolicyReason {
	switch mode {
	case dkim2.PolicyModeStrict:
		return testCase.strict
	case dkim2.PolicyModePermissive:
		return testCase.permissive
	case dkim2.PolicyModeTesting:
		return dkim2.PolicyReasonTestingModeObserve
	default:
		return ""
	}
}

// decodeSelectedGolden decodes one frozen vector field.
func decodeSelectedGolden(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal("golden vector base64 was invalid")
	}
	return decoded
}

// currentMissingProtocolResult returns one authentic zero-target current result and its strict decision.
func currentMissingProtocolResult(t testing.TB) (dkim2.VerifyResult, dkim2.PolicyDecision) {
	t.Helper()
	verifier, err := dkim2.NewVerifier(unusedPublicKeyProvider{})
	if err != nil {
		t.Fatal(err)
	}
	request := dkim2.NewVerifyRequest(
		[]byte("From: sender@example.test\r\nTo: recipient@example.test\r\n\r\nbody\r\n"),
		[]byte("<sender@example.test>"),
		[][]byte{[]byte("<recipient@example.test>")},
	)
	result, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid() || result.State() != dkim2.ResultStatePERMERROR ||
		result.PrimaryReason() != dkim2.ReasonMissingProtocol ||
		result.Target().Sequence() != 0 || result.Target().Instance() != 0 {
		t.Fatalf("unexpected verification fixture: draft=%q state=%q reason=%q scope=%q history=%q/%q custody=%q target=%d/%d checks=%d signatures=%d valid=%t",
			result.Draft(), result.State(), result.PrimaryReason(), result.Scope(), result.HistoricalContent(),
			result.HistoricalSignatures(), result.CustodyStructure(), result.Target().Sequence(), result.Target().Instance(),
			result.CheckCount(), result.SignatureSetCount(), result.Valid())
	}
	decision, err := dkim2.EvaluatePolicy(result, dkim2.WithPolicyMode(dkim2.PolicyModeStrict))
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Valid() {
		t.Fatal("policy fixture is invalid")
	}
	return result, decision
}

// FuzzResponseSnapshotMappers proves arbitrary private-view corruption cannot panic or escape closed DTOs.
func FuzzResponseSnapshotMappers(f *testing.F) {
	result, decision := currentMissingProtocolResult(f)
	verificationSeed := captureVerification(result)
	policySeed := capturePolicy(decision)
	for _, seed := range []struct {
		mode  uint8
		value uint64
	}{
		{0, 0}, {1, 1}, {2, math.MaxUint64}, {3, 17}, {4, 255}, {5, 65_537},
	} {
		f.Add(seed.mode, seed.value)
	}
	f.Fuzz(func(t *testing.T, mode uint8, value uint64) {
		verification := cloneVerificationSnapshot(verificationSeed)
		policyView := clonePolicySnapshot(policySeed)
		switch mode % 8 {
		case 0:
			verification.state.targetSequence = value
		case 1:
			verification.state.targetInstance = value
		case 2:
			verification.state.checkCount = int(value)
		case 3:
			verification.state.signatureCount = int(value)
		case 4:
			policyView.state.feedbackRelaySequence = value
		case 5:
			policyView.state.actionKind = dkim2.PolicyActionKind(fmt.Sprint(value))
		case 6:
			policyView.state.primaryReason = dkim2.PolicyReason(fmt.Sprint(value))
		case 7:
			policyView.state.findings[0].sequence = value
		}
		mappedVerification, verificationErr := mapVerificationSnapshot(verification)
		if verificationErr != nil {
			if !IsMappingError(verificationErr, MappingInternalContract) ||
				!reflect.DeepEqual(mappedVerification, generated.VerificationResult{}) {
				t.Fatal("verification mapper failure was not atomic and classified")
			}
		} else {
			if _, known := mapVerificationState(dkim2.ResultState(mappedVerification.State)); !known {
				t.Fatal("verification mapper emitted an open value")
			}
		}
		mappedPolicy, policyErr := mapPolicySnapshot(policyView, result.State())
		if policyErr != nil {
			if !IsMappingError(policyErr, MappingInternalContract) ||
				!reflect.DeepEqual(mappedPolicy, generated.PolicyResult{}) {
				t.Fatal("policy mapper failure was not atomic and classified")
			}
		} else if mappedPolicy.Mode == "" || mappedPolicy.Verdict == "" || mappedPolicy.PrimaryReason == "" {
			t.Fatal("policy mapper emitted an incomplete value")
		}
	})
}

// cloneVerificationSnapshot detaches mapper-owned slices before a forged-view mutation.
func cloneVerificationSnapshot(input verificationSnapshot) verificationSnapshot {
	state := *input.state
	state.checks = append([]verificationCheckSnapshot(nil), input.state.checks...)
	state.signatures = append([]signatureSetSnapshot(nil), input.state.signatures...)
	input.state = &state
	return input
}

// clonePolicySnapshot detaches mapper-owned slices before a forged-view mutation.
func clonePolicySnapshot(input policySnapshot) policySnapshot {
	state := *input.state
	state.findings = append([]policyFindingSnapshot(nil), input.state.findings...)
	input.state = &state
	return input
}
