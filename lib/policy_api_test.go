package dkim2

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const futurePolicyValue = "future"

// TestEvaluatePolicyPreservesVerificationAndReturnsOneAction proves the public facade consumes sealed provenance without mutating verification output.
func TestEvaluatePolicyPreservesVerificationAndReturnsOneAction(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)})
	wantChecks, wantSignatures := result.Checks(), result.SignatureSets()

	decision, err := EvaluatePolicy(result)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}
	if decision.VerificationState() != ResultStatePASS || decision.Mode() != PolicyModeStrict || decision.Verdict() != PolicyVerdictAccept || decision.PrimaryReason() != PolicyReasonProtocolPass {
		t.Fatalf("decision = state %q mode %q verdict %q reason %q", decision.VerificationState(), decision.Mode(), decision.Verdict(), decision.PrimaryReason())
	}
	actions := decision.ActionPlan().Actions()
	if len(actions) != 1 || actions[0].Kind() != PolicyActionAccept || !actions[0].Terminal() {
		t.Fatalf("actions = %#v", actions)
	}
	if result.State() != ResultStatePASS || !slices.Equal(result.Checks(), wantChecks) || !slices.Equal(result.SignatureSets(), wantSignatures) {
		t.Fatal("EvaluatePolicy mutated VerifyResult")
	}
	copyResult := result
	if _, err = EvaluatePolicy(copyResult); err != nil {
		t.Fatalf("EvaluatePolicy(copy) error = %v", err)
	}
}

// TestVerifyResultValidRequiresCompleteSealedProvenance proves the public validity seam remains fail closed.
func TestVerifyResultValidRequiresCompleteSealedProvenance(t *testing.T) {
	valid := selectedPolicyResult(t, policy.ProtocolPASS, policy.VerificationReasonNone, ResultStatePASS, ReasonNone, false)
	if !valid.Valid() {
		t.Fatal("library-owned result was not valid")
	}
	if (VerifyResult{}).Valid() {
		t.Fatal("zero result was valid")
	}

	emptyChecks := valid
	emptyChecks.state = emptyChecks.cloneState()
	emptyChecks.state.checks = nil
	if emptyChecks.Valid() {
		t.Fatal("result without checks was valid")
	}

	invalidReason := valid
	invalidReason.state = invalidReason.cloneState()
	invalidReason.state.primaryReason = ReasonInvalidRequest
	if invalidReason.Valid() {
		t.Fatal("error-only invalid_request became a valid result reason")
	}

	halfTarget := valid
	halfTarget.state = halfTarget.cloneState()
	halfTarget.state.target = newVerificationTarget(halfTarget.Target().Sequence(), 0)
	if halfTarget.Valid() {
		t.Fatal("half-present target was valid")
	}

	unavailable := unavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	if !unavailable.Valid() {
		t.Fatalf("sealed unavailable result was invalid: provenance=%t state=%q custody=%q pre=%q reason=%q checks=%d",
			verifyResultPolicyProvenanceValid(unavailable), unavailable.State(), unavailable.CustodyStructure(),
			unavailable.state.policyProjection.PreTargetReason(), unavailable.PrimaryReason(), unavailable.CheckCount())
	}
	actualUnavailable := actualUnavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	if !actualUnavailable.Valid() {
		t.Fatalf("actual unavailable result was invalid: provenance=%t state=%q custody=%q pre=%q reason=%q checks=%d signatures=%d",
			verifyResultPolicyProvenanceValid(actualUnavailable), actualUnavailable.State(), actualUnavailable.CustodyStructure(),
			actualUnavailable.state.policyProjection.PreTargetReason(), actualUnavailable.PrimaryReason(),
			actualUnavailable.CheckCount(), actualUnavailable.SignatureSetCount())
	}
}

// TestEvaluatePolicyUnavailableMatrix proves every sealed pre-target reason preserves PERMERROR while modes only change local disposition.
func TestEvaluatePolicyUnavailableMatrix(t *testing.T) {
	reasons := []struct {
		pre    policy.PreTargetReason
		public ReasonCode
	}{
		{policy.PreTargetLimitExceeded, ReasonLimitExceeded},
		{policy.PreTargetMalformedMessage, ReasonMalformedMessage},
		{policy.PreTargetMalformedProtocol, ReasonMalformedProtocol},
		{policy.PreTargetMissingProtocol, ReasonMissingProtocol},
		{policy.PreTargetSequenceInvalid, ReasonSequenceInvalid},
		{policy.PreTargetInternalContract, ReasonInternalContract},
	}
	modes := []struct {
		mode    PolicyMode
		verdict PolicyVerdict
		primary PolicyReason
		action  PolicyActionKind
	}{
		{PolicyModeStrict, PolicyVerdictReject, PolicyReasonProtocolPermerror, PolicyActionReject},
		{PolicyModePermissive, PolicyVerdictAccept, PolicyReasonPermissiveOverride, PolicyActionAccept},
		{PolicyModeTesting, PolicyVerdictContinue, PolicyReasonTestingModeObserve, PolicyActionContinue},
	}
	for _, reason := range reasons {
		for _, mode := range modes {
			t.Run(string(reason.pre)+"/"+string(mode.mode), func(t *testing.T) {
				result := actualUnavailablePolicyResult(t, reason.pre, reason.public)
				decision, err := EvaluatePolicy(result, WithPolicyMode(mode.mode))
				if err != nil {
					t.Fatalf("EvaluatePolicy() error = %v", err)
				}
				if result.State() != ResultStatePERMERROR || result.Target() != (VerificationTarget{}) || decision.VerificationState() != ResultStatePERMERROR || decision.Verdict() != mode.verdict || decision.PrimaryReason() != mode.primary || decision.DNSTestingEffective() {
					t.Fatalf("decision = state %q verdict %q reason %q dns %t", decision.VerificationState(), decision.Verdict(), decision.PrimaryReason(), decision.DNSTestingEffective())
				}
				if actions := decision.ActionPlan().Actions(); len(actions) != 1 || actions[0].Kind() != mode.action || actions[0].Terminal() != (mode.action != PolicyActionContinue) {
					t.Fatalf("actions = %#v", actions)
				}
				for _, finding := range decision.Findings() {
					if finding.Reason() == PolicyReasonDNSTestingEffective || finding.Reason() == PolicyReasonDNSTestingMixed || finding.Reason() == PolicyReasonDNSTestingIneligible {
						t.Fatalf("unavailable decision invented DNS finding %q", finding.Reason())
					}
				}
			})
		}
	}
}

// TestEvaluatePolicyRejectsMissingAndIncoherentProvenance proves callers cannot synthesize policy authority from public-looking fields.
func TestEvaluatePolicyRejectsMissingAndIncoherentProvenance(t *testing.T) {
	valid := unavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	for name, result := range map[string]VerifyResult{
		"zero":   {},
		"manual": {state: &verifyResultState{draft: DraftIdentifier, resultState: ResultStatePERMERROR, scope: VerificationScopeCurrent, historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated, custodyStructure: CustodyStructureNotEvaluated, primaryReason: ReasonMissingProtocol}},
		"reason mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.primaryReason = ReasonMalformedProtocol
			return r
		}(),
		"target mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.target = newVerificationTarget(1, 1)
			return r
		}(),
		"state mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.resultState = ResultStateFAIL
			return r
		}(),
		"scope mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.scope = futurePolicyValue
			return r
		}(),
		"history mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.historicalContent = futurePolicyValue
			return r
		}(),
		"signature history": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.historicalSignatures = futurePolicyValue
			return r
		}(),
		"draft mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.draft = futurePolicyValue
			return r
		}(),
		"custody mismatch": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.custodyStructure = futurePolicyValue
			return r
		}(),
		"projection missing": func() VerifyResult {
			r := valid
			r.state = r.cloneState()
			r.state.policyProjection = policy.Projection{}
			return r
		}(),
		"selected mismatch": selectedPolicyResult(t, policy.ProtocolPASS, policy.VerificationReasonNone, ResultStateFAIL, ReasonHashMismatch, false),
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := EvaluatePolicy(result)
			if !decision.IsZero() || !errors.Is(err, &PolicyError{code: PolicyErrorInvalidInput}) {
				t.Fatalf("decision = %#v, error = %v", decision, err)
			}
		})
	}
}

// TestEvaluatePolicySelectedFourStateModeMatrix proves policy never rewrites the authoritative selected verification state.
func TestEvaluatePolicySelectedFourStateModeMatrix(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	tests := []struct {
		name     string
		vector   string
		provider goldenProviderMode
		state    ResultState
	}{
		{"pass", goldenVectorRSAPass, goldenProviderKeys, ResultStatePASS},
		{"ed25519 pass", goldenVectorEd25519Pass, goldenProviderKeys, ResultStatePASS},
		{"fail", "body_mismatch", goldenProviderKeys, ResultStateFAIL},
		{"permerror", goldenVectorRSAPass, goldenProviderMissing, ResultStatePERMERROR},
		{"temperror", goldenVectorRSAPass, goldenProviderTemporary, ResultStateTEMPERROR},
	}
	modes := []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting}
	for _, test := range tests {
		provider := publicGoldenProvider{mode: test.provider, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)}
		result := verifyDNSVector(context.Background(), t, corpus, test.vector, provider)
		for _, mode := range modes {
			t.Run(test.name+"/"+string(mode), func(t *testing.T) {
				decision, err := EvaluatePolicy(result, WithPolicyMode(mode))
				if err != nil {
					t.Fatalf("EvaluatePolicy() error = %v", err)
				}
				wantVerdict, wantPrimary := expectedPublicBaseOutcome(test.state, mode)
				if decision.VerificationState() != test.state || decision.Verdict() != wantVerdict || decision.PrimaryReason() != wantPrimary {
					t.Fatalf("decision = %q/%q/%q", decision.VerificationState(), decision.Verdict(), decision.PrimaryReason())
				}
				actions := decision.ActionPlan().Actions()
				if len(actions) != 1 || actions[0].Kind() != PolicyActionKind(wantVerdict) || actions[0].Terminal() != (wantVerdict != PolicyVerdictContinue) {
					t.Fatalf("actions = %#v", actions)
				}
			})
		}
	}
}

// TestEvaluatePolicyUsesSealedAuthenticatedFlags proves current flags cross only a cryptographically authenticated seam.
func TestEvaluatePolicyUsesSealedAuthenticatedFlags(t *testing.T) {
	flaggedRaw, flaggedKey := signedPublicFlaggedPolicyMessage(t, publicVectorClock)
	flaggedVerifier, err := NewVerifier(publicGoldenProvider{mode: goldenProviderKeys, rsa: flaggedKey}, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier(flags) error = %v", err)
	}
	flagged, err := flaggedVerifier.Verify(context.Background(), NewVerifyRequest(flaggedRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || flagged.State() != ResultStatePASS {
		t.Fatalf("Verify(flags) = %q, %v", flagged.State(), err)
	}
	decision, err := EvaluatePolicy(flagged)
	if err != nil {
		t.Fatalf("EvaluatePolicy(flags) error = %v", err)
	}
	if decision.FeedbackIntent().Requested() != true || decision.DoNotModifyCompliance() != PolicyComplianceNotEvaluated || decision.DoNotExplodeCompliance() != PolicyComplianceNotEvaluated {
		t.Fatalf("flag decision = %#v", decision)
	}
	if !decision.FeedbackIntent().RelayRequired() || decision.FeedbackIntent().RelaySequence() != 1 {
		t.Fatalf("feedback intent = %#v", decision.FeedbackIntent())
	}
	wantFlagReasons := []PolicyReason{PolicyReasonProtocolPass, PolicyReasonDoNotModifyNotEvaluated, PolicyReasonDoNotExplodeNotEvaluated, PolicyReasonFeedbackRequested, PolicyReasonFeedbackRelaySelected, PolicyReasonExplodedReported}
	flagFindings := decision.Findings()
	gotFlagReasons := make([]PolicyReason, len(flagFindings))
	for index, finding := range flagFindings {
		gotFlagReasons[index] = finding.Reason()
	}
	if !slices.Equal(gotFlagReasons, wantFlagReasons) {
		t.Fatalf("flag findings = %q", gotFlagReasons)
	}
}

// TestEvaluatePolicyUsesEligibleDNSTesting proves all-relevant DNS testing metadata changes only eligible policy.
func TestEvaluatePolicyUsesEligibleDNSTesting(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	transport := &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorEdOwner {
			return foundPublicTXT(t, manifest.Ed25519LowerTXT+"; t=y", DNSSECStatusUnavailable), nil
		}
		return foundPublicTXT(t, manifest.RSADefaultTXT+"; t=y", DNSSECStatusUnavailable), nil
	}}
	dnsResult := verifyDNSVector(context.Background(), t, corpus, "supported_mixed_fail", mustDNSVectorProvider(t, transport, DefaultDNSProviderConfig()))
	dnsDecision, err := EvaluatePolicy(dnsResult)
	if err != nil {
		t.Fatalf("EvaluatePolicy(DNS) error = %v", err)
	}
	if dnsDecision.VerificationState() != ResultStateFAIL || dnsDecision.Verdict() != PolicyVerdictContinue || dnsDecision.PrimaryReason() != PolicyReasonDNSTestingEffective || !dnsDecision.DNSTestingEffective() {
		t.Fatalf("DNS decision = %q/%q/%q/%t", dnsDecision.VerificationState(), dnsDecision.Verdict(), dnsDecision.PrimaryReason(), dnsDecision.DNSTestingEffective())
	}
	static := verifyDNSVector(context.Background(), t, corpus, "supported_mixed_fail", publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)})
	staticDecision, err := EvaluatePolicy(static)
	if err != nil || staticDecision.DNSTestingEffective() || staticDecision.Verdict() != PolicyVerdictReject {
		t.Fatalf("static decision = %q/%t/%v", staticDecision.Verdict(), staticDecision.DNSTestingEffective(), err)
	}
}

// TestEvaluatePolicyTreatsPassingTestingSignerAsNonTerminal proves DNS testing never grants authentication policy weight.
func TestEvaluatePolicyTreatsPassingTestingSignerAsNonTerminal(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	transport := dnsPassTransport(t, manifest.RSATestingTXT, manifest.Ed25519LowerTXT+"; t=y", DNSSECStatusUnavailable)
	result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, transport, DefaultDNSProviderConfig()))
	for _, mode := range []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting} {
		decision, err := EvaluatePolicy(result, WithPolicyMode(mode))
		if err != nil {
			t.Fatalf("EvaluatePolicy(%s) error = %v", mode, err)
		}
		actions := decision.ActionPlan().Actions()
		if result.State() != ResultStatePASS || decision.VerificationState() != ResultStatePASS || decision.Verdict() != PolicyVerdictContinue || decision.PrimaryReason() != PolicyReasonDNSTestingEffective || !decision.DNSTestingEffective() || len(actions) != 1 || actions[0].Kind() != PolicyActionContinue || actions[0].Terminal() {
			t.Fatalf("testing PASS mode %q = state %q verdict %q reason %q dns %t actions %#v", mode, decision.VerificationState(), decision.Verdict(), decision.PrimaryReason(), decision.DNSTestingEffective(), actions)
		}
	}
}

// TestEvaluatePolicySuppressesTestingSignerFlags proves a testing PASS grants no authenticated policy side effects.
func TestEvaluatePolicySuppressesTestingSignerFlags(t *testing.T) {
	raw, key := signedPublicFlaggedPolicyMessage(t, publicVectorClock)
	provider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return withKeyPolicyMetadata(FoundRSAPublicKey(key), newKeyPolicyMetadata(true, false)), nil
	})
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || result.State() != ResultStatePASS {
		t.Fatalf("Verify() = %q, %v", result.State(), err)
	}
	for _, mode := range []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting} {
		decision, evaluateErr := EvaluatePolicy(result, WithPolicyMode(mode))
		if evaluateErr != nil {
			t.Fatalf("EvaluatePolicy(%s) error = %v", mode, evaluateErr)
		}
		intent := decision.FeedbackIntent()
		if decision.Verdict() != PolicyVerdictContinue || decision.PrimaryReason() != PolicyReasonDNSTestingEffective || decision.DoNotModifyCompliance() != PolicyComplianceNotEvaluated || decision.DoNotExplodeCompliance() != PolicyComplianceNotEvaluated || intent.Requested() || intent.RelayRequired() || intent.RelaySequence() != 0 {
			t.Fatalf("testing flag decision %q = %#v", mode, decision)
		}
		for _, finding := range decision.Findings() {
			if _, sequenced := finding.Sequence(); sequenced {
				t.Fatalf("testing signer flag produced finding %#v", finding)
			}
		}
	}
}

// TestEvaluatePolicyUsesPostKeyPermanentDNSTesting proves coherent post-key failures receive literal DNS testing treatment.
func TestEvaluatePolicyUsesPostKeyPermanentDNSTesting(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	newProvider := func() PublicKeyProvider {
		return mustDNSVectorProvider(t, dnsPassTransport(t, manifest.RSATestingTXT, manifest.Ed25519LowerTXT+"; t=y", DNSSECStatusUnavailable), DefaultDNSProviderConfig())
	}
	results := []VerifyResult{
		verifyDNSVector(context.Background(), t, corpus, "age_over", newProvider()),
		verifyDNSVector(context.Background(), t, corpus, "alignment_mismatch", newProvider()),
		verifyDNSVector(context.Background(), t, corpus, "terminal_nd", newProvider()),
	}
	vector := corpus.Vectors["mail_exact"]
	verifier, err := NewVerifier(newProvider(), WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier(envelope) error = %v", err)
	}
	envelope, err := verifier.Verify(context.Background(), NewVerifyRequest(decodeGoldenBytes(t, vector.Raw), []byte("<sender@example.test>"), decodeGoldenPaths(t, vector.Forward)))
	if err != nil {
		t.Fatalf("Verify(envelope) error = %v", err)
	}
	results = append(results, envelope)
	wantReasons := []ReasonCode{ReasonTimestampInvalid, ReasonDomainAlignmentMismatch, ReasonOutOfBandRequired, ReasonEnvelopeMismatch}
	for index, result := range results {
		decision, evaluateErr := EvaluatePolicy(result)
		if evaluateErr != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != wantReasons[index] || decision.VerificationState() != ResultStatePERMERROR || decision.Verdict() != PolicyVerdictContinue || decision.PrimaryReason() != PolicyReasonDNSTestingEffective || !decision.DNSTestingEffective() {
			t.Fatalf("post-key row %q = result %q/%q decision %q/%q/%t error %v", wantReasons[index], result.State(), result.PrimaryReason(), decision.Verdict(), decision.PrimaryReason(), decision.DNSTestingEffective(), evaluateErr)
		}
	}
}

// TestEvaluatePolicyUsesHiddenPreRetentionDNSFacts proves public output narrowing cannot erase sealed policy metadata.
func TestEvaluatePolicyUsesHiddenPreRetentionDNSFacts(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	vector := corpus.Vectors["supported_mixed_fail"]
	retentionTransport := &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorEdOwner {
			return foundPublicTXT(t, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable), nil
		}
		return foundPublicTXT(t, manifest.RSADefaultTXT+"; t=y", DNSSECStatusUnavailable), nil
	}}
	retainedVerifier, err := NewVerifier(mustDNSVectorProvider(t, retentionTransport, DefaultDNSProviderConfig()), WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }), WithMaxSignatureFacts(1))
	if err != nil {
		t.Fatalf("NewVerifier(retention) error = %v", err)
	}
	retained, err := retainedVerifier.Verify(context.Background(), NewVerifyRequest(decodeGoldenBytes(t, vector.Raw), decodeGoldenBytes(t, vector.Reverse), decodeGoldenPaths(t, vector.Forward)))
	if err != nil || retained.State() != ResultStateFAIL || retained.SignatureSetCount() != 1 || retained.SignatureSets()[0].KeyPolicyMetadata().TestingDeclared() {
		t.Fatalf("Verify(retention) count/error = %d/%v", retained.SignatureSetCount(), err)
	}
	retainedDecision, err := EvaluatePolicy(retained)
	if err != nil || retainedDecision.DNSTestingEffective() || retainedDecision.Verdict() != PolicyVerdictReject || !policyDecisionHasReason(retainedDecision, PolicyReasonDNSTestingMixed) {
		t.Fatalf("retained decision = %q/%t/%v reason=%q projection_reason=%q facts=%#v public=%#v", retainedDecision.Verdict(), retainedDecision.DNSTestingEffective(), err, retained.PrimaryReason(), retained.sealedPolicyProjection().VerificationReason(), retained.sealedPolicyProjection().SignatureFacts(), retained.SignatureSets())
	}
}

// policyDecisionHasReason reports whether one public decision contains a reason.
func policyDecisionHasReason(decision PolicyDecision, reason PolicyReason) bool {
	for _, finding := range decision.Findings() {
		if finding.Reason() == reason {
			return true
		}
	}
	return false
}

// TestPublicPolicyVocabulariesAreClosed proves every public enum rejects zero and unknown future values.
func TestPublicPolicyVocabulariesAreClosed(t *testing.T) {
	for _, value := range []interface{ Known() bool }{
		PolicyModeStrict, PolicyModePermissive, PolicyModeTesting,
		PolicyVerdictAccept, PolicyVerdictReject, PolicyVerdictTempfail, PolicyVerdictContinue,
		PolicySeverityInfo, PolicySeverityWarning, PolicySeverityPermanent, PolicySeverityTemporary,
		PolicyComplianceNotRequested, PolicyComplianceHonored, PolicyComplianceViolated, PolicyComplianceIndeterminate, PolicyComplianceNotEvaluated,
		PolicyHistoryNotEvaluated, PolicyHistoryComplete, PolicyHistoryIndeterminate,
		PolicyActionAccept, PolicyActionReject, PolicyActionTempfail, PolicyActionContinue,
	} {
		if !value.Known() {
			t.Fatalf("known value rejected: %v", value)
		}
	}
	for _, value := range []interface{ Known() bool }{PolicyMode(""), PolicyMode("future"), PolicyVerdict(""), PolicyVerdict("future"), PolicyFindingSeverity(""), PolicyFindingSeverity("future"), PolicyCompliance(""), PolicyCompliance("future"), PolicyHistoryCoverage(""), PolicyHistoryCoverage("future"), PolicyActionKind(""), PolicyActionKind("future")} {
		if value.Known() {
			t.Fatalf("unknown value accepted: %v", value)
		}
	}
	reasons := []PolicyReason{
		PolicyReasonInvalidInput, PolicyReasonLimitExceeded, PolicyReasonInternalContract,
		PolicyReasonProtocolPass, PolicyReasonProtocolFail, PolicyReasonProtocolPermerror, PolicyReasonProtocolTemperror,
		PolicyReasonPermissiveOverride, PolicyReasonTestingModeObserve,
		PolicyReasonDNSTestingEffective, PolicyReasonDNSTestingMixed, PolicyReasonDNSTestingIneligible,
		PolicyReasonDoNotModifyHonored, PolicyReasonDoNotModifyViolated, PolicyReasonDoNotModifyIndeterminate, PolicyReasonDoNotModifyNotEvaluated,
		PolicyReasonDoNotExplodeViolated, PolicyReasonDoNotExplodeIndeterminate, PolicyReasonDoNotExplodeNotEvaluated,
		PolicyReasonFeedbackRequested, PolicyReasonFeedbackRelaySelected, PolicyReasonFeedHereInert, PolicyReasonExplodedReported,
	}
	for _, reason := range reasons {
		if !reason.Known() {
			t.Fatalf("known reason rejected: %q", reason)
		}
	}
	if PolicyReason("").Known() || PolicyReason("future-secret").Known() || (PolicyFinding{}).Valid() || (PolicyFeedbackIntent{}).Valid() || (PolicyAction{}).Valid() || (PolicyActionPlan{}).Valid() || !(PolicyDecision{}).IsZero() {
		t.Fatal("zero or future public policy value accepted")
	}
	for index, plan := range []PolicyActionPlan{
		{initialized: true},
		{initialized: true, actions: []PolicyAction{{kind: PolicyActionAccept, initialized: true}, {kind: PolicyActionAccept, initialized: true}}},
		{initialized: true, actions: []PolicyAction{{kind: PolicyActionKind(futurePolicyValue), initialized: true}}},
	} {
		if plan.Valid() {
			t.Fatalf("corrupt public action plan %d accepted", index)
		}
	}
	if (PolicyFinding{state: &policyFindingState{reason: PolicyReasonProtocolPass, severity: PolicySeverityPermanent, initialized: true}}).Valid() ||
		(PolicyFinding{state: &policyFindingState{reason: PolicyReasonFeedbackRequested, severity: PolicySeverityInfo, initialized: true}}).Valid() ||
		(PolicyFinding{state: &policyFindingState{reason: PolicyReasonProtocolPass, severity: PolicySeverityInfo, sequence: 1, hasSequence: true, initialized: true}}).Valid() ||
		(PolicyFinding{state: &policyFindingState{reason: PolicyReasonInternalContract, severity: PolicySeverityPermanent, initialized: true}}).Valid() {
		t.Fatal("incoherent public finding accepted")
	}
	for _, partial := range []PolicyDecision{
		{state: &policyDecisionState{modify: PolicyComplianceNotEvaluated}},
		{state: &policyDecisionState{explode: PolicyComplianceNotEvaluated}},
		{state: &policyDecisionState{feedback: PolicyFeedbackIntent{state: &policyFeedbackIntentState{initialized: true}}}},
		{state: &policyDecisionState{dnsEffective: true}},
	} {
		if partial.IsZero() {
			t.Fatal("partially initialized public decision reported zero")
		}
	}
}

// TestEvaluatePolicyReturnsBoundedLimitError proves a narrowed output limit fails without a partial decision or raw cause.
func TestEvaluatePolicyReturnsBoundedLimitError(t *testing.T) {
	result := unavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	decision, err := EvaluatePolicy(result, WithPolicyMode(PolicyModePermissive), WithPolicyMaxFindings(1))
	var policyErr *PolicyError
	if !decision.IsZero() || !errors.As(err, &policyErr) || policyErr.Code() != PolicyErrorLimitExceeded || policyErr.LimitName() != "max_findings" || policyErr.ConfiguredLimit() != 1 || policyErr.ObservedCount() != 2 || errors.Unwrap(policyErr) != nil {
		t.Fatalf("decision/error = %#v/%#v", decision, err)
	}
}

// TestPublicPolicyErrorsAreClosedAndCauseFree proves public failures support code matching without wrapping raw causes.
func TestPublicPolicyErrorsAreClosedAndCauseFree(t *testing.T) {
	for _, code := range []PolicyErrorCode{PolicyErrorInvalidOption, PolicyErrorInvalidInput, PolicyErrorLimitExceeded, PolicyErrorInternalContract} {
		if !code.Known() || !errors.Is(newPolicyError(code), &PolicyError{code: code}) {
			t.Fatalf("known code rejected: %q", code)
		}
	}
	if PolicyErrorCode("").Known() || PolicyErrorCode("future-secret").Known() || (*PolicyError)(nil).Code() != "" || (*PolicyError)(nil).LimitName() != "" || (*PolicyError)(nil).ConfiguredLimit() != 0 || (*PolicyError)(nil).ObservedCount() != 0 {
		t.Fatal("zero, future, or nil public error contract failed")
	}
	if errors.Unwrap(newPolicyError(PolicyErrorInvalidInput)) != nil {
		t.Fatal("public policy error retained a raw cause")
	}
}

// TestPolicyOptionsAcceptExactHardLimits proves explicit hard maxima are valid non-widening choices.
func TestPolicyOptionsAcceptExactHardLimits(t *testing.T) {
	result := unavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	decision, err := EvaluatePolicy(result, WithPolicyMaxAuthenticatedHops(HardMaxPolicyAuthenticatedHops), WithPolicyMaxFindings(HardMaxPolicyFindings))
	if err != nil || !decision.Valid() {
		t.Fatalf("EvaluatePolicy(exact limits) = %#v, %v", decision, err)
	}
}

// expectedPublicBaseOutcome returns the exact public base matrix cell.
func expectedPublicBaseOutcome(state ResultState, mode PolicyMode) (PolicyVerdict, PolicyReason) {
	protocolReason := map[ResultState]PolicyReason{ResultStatePASS: PolicyReasonProtocolPass, ResultStateFAIL: PolicyReasonProtocolFail, ResultStatePERMERROR: PolicyReasonProtocolPermerror, ResultStateTEMPERROR: PolicyReasonProtocolTemperror}[state]
	if mode == PolicyModeTesting {
		return PolicyVerdictContinue, PolicyReasonTestingModeObserve
	}
	if mode == PolicyModePermissive && (state == ResultStateFAIL || state == ResultStatePERMERROR) {
		return PolicyVerdictAccept, PolicyReasonPermissiveOverride
	}
	return map[ResultState]PolicyVerdict{ResultStatePASS: PolicyVerdictAccept, ResultStateFAIL: PolicyVerdictReject, ResultStatePERMERROR: PolicyVerdictReject, ResultStateTEMPERROR: PolicyVerdictTempfail}[state], protocolReason
}

// selectedPolicyResult constructs one library-owned selected projection for facade seam tests.
func selectedPolicyResult(t *testing.T, protocol policy.ProtocolClass, verificationReason policy.VerificationReason, state ResultState, reason ReasonCode, flags bool) VerifyResult {
	t.Helper()
	hop, err := policy.NewAuthenticatedHopFact(1, policy.TransitionOrigin, flags, flags, flags, flags, flags)
	if err != nil {
		t.Fatalf("NewAuthenticatedHopFact() error = %v", err)
	}
	signature, err := policy.NewSignatureFact(policy.SetAlgorithmRSA, policy.SetStatusPass, policy.SetReasonNone, false, false)
	if err != nil {
		t.Fatalf("NewSignatureFact() error = %v", err)
	}
	projection, err := policy.NewSelectedProjection(protocol, verificationReason, 1, []policy.HopFact{hop}, []policy.SignatureFact{signature}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	return newVerifyResult(verifyResultData{
		state: state, scope: VerificationScopeCurrent, historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotPresent, target: newVerificationTarget(1, 1), primaryReason: reason,
		checks: []CheckFact{newCheckFact(CheckClassProtocol, reason)}, policyProjection: projection,
	})
}

// TestPolicyOptionsRejectUnsafeAndDuplicateValues proves policy configuration can only narrow defaults once.
func TestPolicyOptionsRejectUnsafeAndDuplicateValues(t *testing.T) {
	result := unavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	tests := []struct {
		name    string
		options []PolicyOption
	}{
		{"nil", []PolicyOption{nil}},
		{"unknown mode", []PolicyOption{WithPolicyMode(futurePolicyValue)}},
		{"duplicate mode", []PolicyOption{WithPolicyMode(PolicyModeStrict), WithPolicyMode(PolicyModeTesting)}},
		{"zero hops", []PolicyOption{WithPolicyMaxAuthenticatedHops(0)}},
		{"wide hops", []PolicyOption{WithPolicyMaxAuthenticatedHops(HardMaxPolicyAuthenticatedHops + 1)}},
		{"duplicate hops", []PolicyOption{WithPolicyMaxAuthenticatedHops(1), WithPolicyMaxAuthenticatedHops(1)}},
		{"zero findings", []PolicyOption{WithPolicyMaxFindings(0)}},
		{"wide findings", []PolicyOption{WithPolicyMaxFindings(HardMaxPolicyFindings + 1)}},
		{"duplicate findings", []PolicyOption{WithPolicyMaxFindings(2), WithPolicyMaxFindings(2)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := EvaluatePolicy(result, test.options...)
			if !decision.IsZero() || !errors.Is(err, &PolicyError{code: PolicyErrorInvalidOption}) {
				t.Fatalf("decision = %#v, error = %v", decision, err)
			}
		})
	}
}

// TestPolicyDecisionClonesAndSupportsConcurrentReuse proves all collection accessors and repeated evaluation are independent.
func TestPolicyDecisionClonesAndSupportsConcurrentReuse(t *testing.T) {
	result := unavailablePolicyResult(t, policy.PreTargetMissingProtocol, ReasonMissingProtocol)
	decision, err := EvaluatePolicy(result, WithPolicyMode(PolicyModeTesting))
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}
	findings := decision.Findings()
	actions := decision.ActionPlan().Actions()
	findings[0] = PolicyFinding{}
	actions[0] = PolicyAction{}
	if !decision.Findings()[0].Valid() || !decision.ActionPlan().Actions()[0].Valid() {
		t.Fatal("public decision leaked mutable slice ownership")
	}
	contradictions := []PolicyDecision{
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.verificationState = ResultStatePASS
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.mode = PolicyModeStrict
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.verdict = PolicyVerdictAccept
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.primaryReason = PolicyReasonInvalidInput
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			slices.Reverse(got.state.findings)
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			findingState := *got.state.findings[0].state
			findingState.reason = PolicyReasonProtocolPass
			got.state.findings[0].state = &findingState
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.dnsEffective = true
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.modify = PolicyComplianceViolated
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.explode = PolicyComplianceViolated
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.feedback.state.requested = true
			return got
		}(),
		func() PolicyDecision {
			got := clonePublicPolicyDecision(decision)
			got.state.actionPlan.actions[0].kind = PolicyActionReject
			return got
		}(),
	}
	for index, contradiction := range contradictions {
		if contradiction.Valid() {
			t.Fatalf("contradictory decision %d accepted", index)
		}
	}
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, evaluateErr := EvaluatePolicy(result, WithPolicyMode(PolicyModeTesting))
			if evaluateErr != nil || got.Verdict() != PolicyVerdictContinue {
				t.Errorf("EvaluatePolicy() = %q, %v", got.Verdict(), evaluateErr)
			}
		}()
	}
	wait.Wait()
}

// clonePublicPolicyDecision returns a structurally independent test mutation candidate.
func clonePublicPolicyDecision(decision PolicyDecision) PolicyDecision {
	if decision.state == nil {
		return PolicyDecision{}
	}
	state := *decision.state
	state.findings = slices.Clone(state.findings)
	state.actionPlan.actions = slices.Clone(state.actionPlan.actions)
	if state.feedback.state != nil {
		feedback := *state.feedback.state
		state.feedback.state = &feedback
	}
	return PolicyDecision{state: &state}
}

// unavailablePolicyResult constructs a library-owned sealed unavailable result for facade contract tests.
func unavailablePolicyResult(t *testing.T, pre policy.PreTargetReason, reason ReasonCode) VerifyResult {
	t.Helper()
	projection, err := policy.NewUnavailableProjection(pre)
	if err != nil {
		t.Fatalf("NewUnavailableProjection() error = %v", err)
	}
	return newVerifyResult(verifyResultData{
		state: ResultStatePERMERROR, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotEvaluated, primaryReason: reason,
		checks: []CheckFact{newCheckFact(CheckClassProtocol, reason)}, policyProjection: projection,
	})
}

// actualUnavailablePolicyResult obtains each public pre-target form through Verifier.Verify except the trusted internal-contract sentinel.
func actualUnavailablePolicyResult(t *testing.T, pre policy.PreTargetReason, reason ReasonCode) VerifyResult {
	t.Helper()
	if pre == policy.PreTargetInternalContract {
		return internalContractResult(VerificationTarget{})
	}
	corpus := loadPublicGoldenCorpus(t)
	vectorName := map[policy.PreTargetReason]string{
		policy.PreTargetMalformedMessage:  goldenVectorMalformed,
		policy.PreTargetMissingProtocol:   goldenVectorMissingProtocol,
		policy.PreTargetSequenceInvalid:   goldenVectorInconsistentSequence,
		policy.PreTargetMalformedProtocol: goldenVectorRSAPass,
		policy.PreTargetLimitExceeded:     goldenVectorRSAPass,
	}[pre]
	vector := corpus.Vectors[vectorName]
	raw := decodeGoldenBytes(t, vector.Raw)
	if pre == policy.PreTargetMalformedProtocol {
		raw = malformedGoldenProtocol(t, raw)
	}
	options := []VerifierOption{WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) })}
	if pre == policy.PreTargetLimitExceeded {
		options = append(options, WithMaxRawMessageBytes(len(raw)-1))
	}
	verifier, err := NewVerifier(publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)}, options...)
	if err != nil {
		t.Fatalf("NewVerifier(%s) error = %v", pre, err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, decodeGoldenBytes(t, vector.Reverse), decodeGoldenPaths(t, vector.Forward)))
	if err != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != reason {
		t.Fatalf("Verify(%s) = %q/%q, %v", pre, result.State(), result.PrimaryReason(), err)
	}
	return result
}

// signedPublicFlaggedPolicyMessage creates a passing public RSA fixture carrying all five known current flags.
func signedPublicFlaggedPolicyMessage(t testing.TB, timestamp int64) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: flagged policy\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	build := func(signature string) string {
		return "From: sender@example.test\r\nSubject: flagged policy\r\n" +
			"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
			"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatInt(timestamp, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; f=donotmodify,donotexplode,feedback,feedhere,exploded,TOXIC-UNKNOWN; d=example.test; s=selector.test:rsa-sha256:" + signature + ";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return []byte(build(base64.StdEncoding.EncodeToString(sealed))), &key.PublicKey
}

// signedPublicHistoriedMessage creates a current PASS fixture with sealed m=2 history work.
func signedPublicHistoriedMessage(t testing.TB, timestamp int64) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: current history\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	build := func(signature string) string {
		hashes := "sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64()
		return "From: sender@example.test\r\nSubject: current history\r\n" +
			"Message-Instance: m=1; h=" + hashes + ";\r\n" +
			"Message-Instance: m=2; h=" + hashes + "; r=" + base64.StdEncoding.EncodeToString([]byte(`{`)) + ";\r\n" +
			"DKIM2-Signature: i=1; m=2; t=" + strconv.FormatInt(timestamp, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=selector.test:rsa-sha256:" + signature + ";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return []byte(build(base64.StdEncoding.EncodeToString(sealed))), &key.PublicKey
}
