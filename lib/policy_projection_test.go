package dkim2

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/service"
)

// TestFacadeTransfersAndClonesSealedPolicyProjection verifies the service-to-root seam.
func TestFacadeTransfersAndClonesSealedPolicyProjection(t *testing.T) {
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	projection := result.sealedPolicyProjection()
	if !projection.Valid() || projection.Form() != policy.TargetSelected || projection.TargetSequence() != result.Target().Sequence() || len(projection.Hops()) != 0 || len(projection.SignatureFacts()) != 1 {
		t.Fatalf("facade projection = %#v", projection)
	}
	facts := projection.SignatureFacts()
	facts[0] = policy.SignatureFact{}
	copyResult := result
	if !result.sealedPolicyProjection().Valid() || !copyResult.sealedPolicyProjection().Valid() || !result.sealedPolicyProjection().SignatureFacts()[0].Valid() {
		t.Fatal("facade projection exposed mutable storage")
	}
}

// TestMalformedHistoriedMessageFailsClosedAcrossServiceAndFacade locks the authenticated-chain boundary.
func TestMalformedHistoriedMessageFailsClosedAcrossServiceAndFacade(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicHistoriedMessage(t, timestamp)
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	coordinator := serviceVerifierForTest(t, verifier)
	serviceResult, err := coordinator.Verify(context.Background(), service.NewRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || serviceResult.State() != service.StatePERMERROR || serviceResult.PrimaryReason() != service.ReasonInvalidRecipeJSON || serviceResult.Target().Instance != 2 {
		t.Fatalf("service historied result = %q/%q target=%#v error=%v", serviceResult.State(), serviceResult.PrimaryReason(), serviceResult.Target(), err)
	}
	serviceProjection := serviceResult.PolicyProjection()
	if !serviceProjection.Valid() || serviceProjection.Form() != policy.TargetSelected || serviceProjection.TargetSequence() != 1 || serviceProjection.VerificationReason() != policy.VerificationReasonInvalidRecipeJSON {
		t.Fatalf("service historied projection = %#v", serviceProjection)
	}
	publicResult, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || publicResult.State() != ResultStatePERMERROR || publicResult.PrimaryReason() != ReasonInvalidRecipeJSON || publicResult.Target().Instance() != 2 {
		t.Fatalf("facade historied result = %q/%q target=%#v error=%v", publicResult.State(), publicResult.PrimaryReason(), publicResult.Target(), err)
	}
	decision, err := EvaluatePolicy(publicResult)
	if err != nil || decision.VerificationState() != ResultStatePERMERROR || decision.Verdict() != PolicyVerdictReject || decision.PrimaryReason() != PolicyReasonProtocolPermerror {
		t.Fatalf("historied policy decision = %q/%q/%q error=%v", decision.VerificationState(), decision.Verdict(), decision.PrimaryReason(), err)
	}
}

// TestDraft05MalformedFieldsRemainTargetUnavailableAcrossPublicPolicy proves parser failures keep exact fail-closed authority.
func TestDraft05MalformedFieldsRemainTargetUnavailableAcrossPublicPolicy(t *testing.T) {
	base := string(publicProviderFixture(t))
	hashStart := strings.Index(base, "h=")
	signatureStart := strings.Index(base, "s=")
	if hashStart < 0 || signatureStart < 0 {
		t.Fatal("public fixture lacks h= or s=")
	}
	hashEnd := strings.Index(base[hashStart:], ";")
	signatureEnd := strings.Index(base[signatureStart:], ";")
	if hashEnd < 0 || signatureEnd < 0 {
		t.Fatal("public fixture has unterminated h= or s=")
	}
	hashValue := base[hashStart+2 : hashStart+hashEnd]
	signatureValue := base[signatureStart+2 : signatureStart+signatureEnd]
	parts := strings.SplitN(signatureValue, ":", 3)
	if len(parts) != 3 {
		t.Fatal("public fixture signature set is malformed")
	}
	many := make([]string, 3)
	for index := range many {
		many[index] = "selector-" + strconv.Itoa(index+1) + ".test:" + parts[1] + ":" + parts[2]
	}
	tests := []struct {
		name      string
		raw       string
		reason    ReasonCode
		service   service.Reason
		preTarget policy.PreTargetReason
	}{
		{"duplicate hash", strings.Replace(base, "h="+hashValue, "h="+hashValue+","+hashValue, 1), ReasonDuplicateHashAlgorithm, service.ReasonDuplicateHashAlgorithm, policy.PreTargetDuplicateHashAlgorithm},
		{"duplicate selector", strings.Replace(base, "s="+signatureValue, "s="+signatureValue+","+signatureValue, 1), ReasonDuplicateSelector, service.ReasonDuplicateSelector, policy.PreTargetDuplicateSelector},
		{"too many signatures", strings.Replace(base, "s="+signatureValue, "s="+strings.Join(many, ","), 1), ReasonTooManySignatures, service.ReasonTooManySignatures, policy.PreTargetTooManySignatures},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerCalls := 0
			verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
				providerCalls++
				return MissingPublicKey(AlgorithmRSASHA256), nil
			}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
			if err != nil {
				t.Fatal(err)
			}
			coordinator := serviceVerifierForTest(t, verifier)
			serviceResult, serviceErr := coordinator.Verify(context.Background(), service.NewRequest([]byte(test.raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			serviceProjection := serviceResult.PolicyProjection()
			if serviceErr != nil || serviceResult.State() != service.StatePERMERROR || serviceResult.PrimaryReason() != test.service || serviceResult.Target() != (service.Target{}) || !serviceProjection.Valid() || serviceProjection.Form() != policy.TargetUnavailable || serviceProjection.PreTargetReason() != test.preTarget {
				t.Fatalf("service = %q/%q target=%#v projection=%#v error=%v", serviceResult.State(), serviceResult.PrimaryReason(), serviceResult.Target(), serviceProjection, serviceErr)
			}
			publicResult, publicErr := verifier.Verify(context.Background(), NewVerifyRequest([]byte(test.raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			decision, policyErr := EvaluatePolicy(publicResult)
			if publicErr != nil || policyErr != nil || providerCalls != 0 || publicResult.State() != ResultStatePERMERROR || publicResult.PrimaryReason() != test.reason || publicResult.Target() != (VerificationTarget{}) || decision.VerificationState() != ResultStatePERMERROR || decision.Verdict() != PolicyVerdictReject {
				t.Fatalf("public = %q/%q target=%#v decision=%q/%q calls=%d errors=%v/%v", publicResult.State(), publicResult.PrimaryReason(), publicResult.Target(), decision.VerificationState(), decision.Verdict(), providerCalls, publicErr, policyErr)
			}
		})
	}
}

// TestFacadeZerosMismatchedSelectedReasonWithoutRewritingVerification verifies exact provenance.
func TestFacadeZerosMismatchedSelectedReasonWithoutRewritingVerification(t *testing.T) {
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	coordinator := serviceVerifierForTest(t, verifier)
	serviceResult, err := coordinator.Verify(context.Background(), service.NewRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("service Verify() error = %v", err)
	}
	original := serviceResult.PolicyProjection()
	ambiguous, err := policy.NewSignatureFact(policy.SetAlgorithmRSA, policy.SetStatusPermerror, policy.SetReasonAmbiguousKey, false, false)
	if err != nil {
		t.Fatalf("NewSignatureFact(ambiguous) error = %v", err)
	}
	wrong, err := policy.NewSelectedProjection(original.Protocol(), policy.VerificationReasonAmbiguousKey, original.TargetSequence(), nil, []policy.SignatureFact{ambiguous}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection(wrong) error = %v", err)
	}
	public := adaptServiceResultWithProjection(serviceResult, wrong)
	if public.State() != ResultStatePERMERROR || public.PrimaryReason() != ReasonMissingKey || !public.sealedPolicyProjection().IsZero() {
		t.Fatalf("mismatched selected reason = %q/%q/%#v", public.State(), public.PrimaryReason(), public.sealedPolicyProjection())
	}
}

// TestFacadeVerificationReasonMapperRejectsInvalidAndUnknown verifies closed provenance.
func TestFacadeVerificationReasonMapperRejectsInvalidAndUnknown(t *testing.T) {
	for _, reason := range []service.Reason{
		service.ReasonNone, service.ReasonLimitExceeded, service.ReasonMalformedMessage, service.ReasonMalformedProtocol,
		service.ReasonDuplicateHashAlgorithm, service.ReasonInvalidRecipeJSON, service.ReasonDuplicateSelector, service.ReasonTooManySignatures,
		service.ReasonMissingProtocol, service.ReasonSequenceInvalid, service.ReasonUnsupportedAlgorithm,
		service.ReasonHashMismatch, service.ReasonSignatureMismatch, service.ReasonMissingKey, service.ReasonInvalidKey,
		service.ReasonAmbiguousKey, service.ReasonRevokedKey, service.ReasonUnsupportedKeyType,
		service.ReasonKeyAlgorithmMismatch, service.ReasonProviderTemporary, service.ReasonProviderPermanent,
		service.ReasonProviderContract, service.ReasonTimestampInvalid, service.ReasonEnvelopeMismatch,
		service.ReasonDomainAlignmentMismatch, service.ReasonNextDomainMismatch, service.ReasonOutOfBandRequired,
		service.ReasonInternalContract,
	} {
		mapped, ok := mapServiceVerificationReason(reason)
		if !ok || !mapped.Known() || string(mapped) != string(reason) {
			t.Fatalf("reason %q mapped to %q/%v", reason, mapped, ok)
		}
	}
	for _, reason := range []service.Reason{service.ReasonInvalidRequest, futurePolicyValue, ""} {
		if mapped, ok := mapServiceVerificationReason(reason); ok || mapped != "" {
			t.Fatalf("invalid reason %q mapped to %q/%v", reason, mapped, ok)
		}
	}
}

// TestFacadeSealsSequenceFailuresAsUnavailableTargets verifies public authoritative zero targets.
func TestFacadeSealsSequenceFailuresAsUnavailableTargets(t *testing.T) {
	base := string(publicProviderFixture(t))
	start := strings.Index(base, "DKIM2-Signature:")
	end := strings.Index(base[start:], "\r\n")
	if start < 0 || end < 0 {
		t.Fatal("public fixture lacks signature header")
	}
	line := base[start : start+end+2]
	tests := map[string]string{
		"gap":       strings.Replace(base, "DKIM2-Signature: i=1;", "DKIM2-Signature: i=2;", 1),
		"duplicate": base[:start] + line + base[start:],
	}
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			result, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest([]byte(raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if verifyErr != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonSequenceInvalid || result.Target() != (VerificationTarget{}) ||
				!result.sealedPolicyProjection().Valid() || result.sealedPolicyProjection().Form() != policy.TargetUnavailable || result.sealedPolicyProjection().PreTargetReason() != policy.PreTargetSequenceInvalid {
				t.Fatalf("Verify() = %q/%q target=%#v projection=%#v error=%v", result.State(), result.PrimaryReason(), result.Target(), result.sealedPolicyProjection(), verifyErr)
			}
		})
	}
}

// TestFacadeSealsStructuralCustodyFailuresForPolicy proves pre-target chain rejection retains evaluable provenance.
func TestFacadeSealsStructuralCustodyFailuresForPolicy(t *testing.T) {
	digest := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x11", 32)))
	signatureText := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x22", 128)))
	ordinaryMismatch := "From: sender@example.test\r\n" +
		"Message-Instance: m=1; h=sha256:" + digest + ":" + digest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PGFAb3JpZ2luLnRlc3Q+; rt=PGJAcmVsYXkudGVzdD4=; d=origin.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n" +
		"DKIM2-Signature: i=2; m=1; t=1700000000; mf=PGJAZXZpbC50ZXN0Pg==; rt=PGNAZmluYWwudGVzdD4=; d=evil.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n\r\nbody\r\n"
	nextDomainMismatch := "From: sender@example.test\r\n" +
		"Message-Instance: m=1; h=sha256:" + digest + ":" + digest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; nd=wrong.example.test; d=first.example.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n" +
		"DKIM2-Signature: i=2; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=next.example.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n\r\nbody\r\n"
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	tests := []struct {
		name    string
		raw     string
		custody CustodyStructure
	}{
		{"ordinary adjacency", ordinaryMismatch, CustodyStructureNotEvaluated},
		{"next-domain mismatch", nextDomainMismatch, CustodyStructureNDLinksEvaluated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest([]byte(test.raw), nil, nil))
			if verifyErr != nil {
				t.Fatalf("Verify() error = %v", verifyErr)
			}
			if result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonMalformedProtocol || result.CustodyStructure() != test.custody || result.Target() != (VerificationTarget{}) ||
				!result.sealedPolicyProjection().Valid() || result.sealedPolicyProjection().Form() != policy.TargetUnavailable || result.sealedPolicyProjection().PreTargetReason() != policy.PreTargetMalformedProtocol {
				t.Fatalf("custody result = %q/%q/%q target=%#v projection=%#v", result.State(), result.PrimaryReason(), result.CustodyStructure(), result.Target(), result.sealedPolicyProjection())
			}
			decision, evaluateErr := EvaluatePolicy(result)
			if evaluateErr != nil || decision.VerificationState() != ResultStatePERMERROR || decision.Verdict() != PolicyVerdictReject || decision.PrimaryReason() != PolicyReasonProtocolPermerror {
				t.Fatalf("EvaluatePolicy() = state=%q verdict=%q reason=%q error=%v", decision.VerificationState(), decision.Verdict(), decision.PrimaryReason(), evaluateErr)
			}
		})
	}
}

// TestFacadeRejectsUnavailableReasonMismatchWithoutRebuildingProvenance verifies exact binding.
func TestFacadeRejectsUnavailableReasonMismatchWithoutRebuildingProvenance(t *testing.T) {
	pairs := []struct {
		policyReason  policy.PreTargetReason
		serviceReason service.Reason
	}{
		{policy.PreTargetLimitExceeded, service.ReasonLimitExceeded},
		{policy.PreTargetMalformedMessage, service.ReasonMalformedMessage},
		{policy.PreTargetMalformedProtocol, service.ReasonMalformedProtocol},
		{policy.PreTargetMissingProtocol, service.ReasonMissingProtocol},
		{policy.PreTargetSequenceInvalid, service.ReasonSequenceInvalid},
		{policy.PreTargetInternalContract, service.ReasonInternalContract},
	}
	for index, pair := range pairs {
		if !preTargetReasonMatchesService(pair.policyReason, pair.serviceReason) {
			t.Fatalf("exact unavailable pair %d rejected", index)
		}
		wrong := pairs[(index+1)%len(pairs)]
		if preTargetReasonMatchesService(pair.policyReason, wrong.serviceReason) {
			t.Fatalf("cross-row unavailable pair %d accepted", index)
		}
	}
	if preTargetReasonMatchesService("future", service.ReasonInternalContract) {
		t.Fatal("unknown unavailable reason accepted")
	}

	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	coordinator := serviceVerifierForTest(t, verifier)
	serviceResult, err := coordinator.Verify(context.Background(), service.NewRequest([]byte("malformed"), nil, nil))
	if err != nil || serviceResult.State() != service.StatePERMERROR || serviceResult.PrimaryReason() != service.ReasonMalformedMessage {
		t.Fatalf("service result = %q/%q error=%v", serviceResult.State(), serviceResult.PrimaryReason(), err)
	}
	wrong, err := policy.NewUnavailableProjection(policy.PreTargetLimitExceeded)
	if err != nil {
		t.Fatalf("NewUnavailableProjection() error = %v", err)
	}
	if projectionMatchesServiceResult(wrong, serviceResult) {
		t.Fatal("facade accepted mismatched unavailable reason")
	}
	public := adaptServiceResultWithProjection(serviceResult, wrong)
	if public.State() != ResultStatePERMERROR || public.PrimaryReason() != ReasonMalformedMessage || !public.sealedPolicyProjection().IsZero() {
		t.Fatalf("corrupt projection rewrote verification = %q/%q/%#v", public.State(), public.PrimaryReason(), public.sealedPolicyProjection())
	}
}

// serviceVerifierForTest reads the concrete coordinator without extending the production boundary.
func serviceVerifierForTest(t testing.TB, verifier *Verifier) service.Verifier {
	t.Helper()
	if verifier == nil || verifier.state == nil || !verifier.state.initialized {
		t.Fatal("test verifier coordinator unavailable")
	}
	return verifier.state.service
}

// TestFacadePreflightAndManualValuesCannotForgeSelectedProvenance verifies sealed forms.
func TestFacadePreflightAndManualValuesCannotForgeSelectedProvenance(t *testing.T) {
	preflight := publicPreflightLimitResult()
	if !preflight.sealedPolicyProjection().Valid() || preflight.sealedPolicyProjection().Form() != policy.TargetUnavailable || preflight.sealedPolicyProjection().PreTargetReason() != policy.PreTargetLimitExceeded {
		t.Fatalf("preflight projection = %#v", preflight.sealedPolicyProjection())
	}
	manual := VerifyResult{state: &verifyResultState{
		draft: DraftIdentifier, resultState: ResultStatePASS, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotPresent, target: newVerificationTarget(1, 1), primaryReason: ReasonNone,
	}}
	if !manual.sealedPolicyProjection().IsZero() || manual.sealedPolicyProjection().Valid() {
		t.Fatalf("manual result forged projection = %#v", manual.sealedPolicyProjection())
	}
}
