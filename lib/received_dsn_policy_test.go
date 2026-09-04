package dkim2

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
)

// receivedDSNOuterVerification verifies the outer DSN as an ordinary message
// with the fixture clock and the given provider.
func receivedDSNOuterVerification(t *testing.T, provider PublicKeyProvider, raw []byte) VerifyResult {
	t.Helper()
	verifier, err := NewVerifier(provider, receivedDSNClockOption())
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}))
	if err != nil || !result.Valid() {
		t.Fatalf("Verify() valid=%t error=%v", result.Valid(), err)
	}
	return result
}

// receivedDSNFindingReasons returns the received-DSN finding reasons in order.
func receivedDSNFindingReasons(findings []PolicyFinding) []PolicyReason {
	var reasons []PolicyReason
	for _, finding := range findings {
		if strings.HasPrefix(string(finding.Reason()), "received_dsn_") {
			reasons = append(reasons, finding.Reason())
		}
	}
	return reasons
}

// assertReceivedDSNDecision proves one decision carries exactly one
// received-DSN finding, recorded last, with a single coherent action.
func assertReceivedDSNDecision(t *testing.T, decision PolicyDecision, outerFindings int, reason PolicyReason) {
	t.Helper()
	if !decision.Valid() {
		t.Fatal("decision is not valid")
	}
	findings := decision.Findings()
	if got := receivedDSNFindingReasons(findings); len(got) != 1 || got[0] != reason || findings[len(findings)-1].Reason() != reason || len(findings) != outerFindings+1 {
		t.Fatalf("received-DSN findings=%v total=%d want one %q recorded last after %d outer findings", got, len(findings), reason, outerFindings)
	}
	if actions := decision.ActionPlan().Actions(); len(actions) != 1 || actions[0].Kind() != PolicyActionKind(decision.Verdict()) || !decision.ActionPlan().Valid() {
		t.Fatalf("action plan=%#v verdict=%q", actions, decision.Verdict())
	}
}

// receivedDSNPolicyRow describes one mapping-table row fixture, its reason,
// its verdict per mode, and whether the row replaces the outer verdict.
type receivedDSNPolicyRow struct {
	name       string
	spec       receivedDSNSpec
	authority  LocalAuthority
	provider   PublicKeyProvider
	reason     PolicyReason
	strict     PolicyVerdict
	permissive PolicyVerdict
	testing    PolicyVerdict
	replaces   bool
}

// receivedDSNPolicyRows lists every row of the mapping table for an outer PASS.
func receivedDSNPolicyRows() []receivedDSNPolicyRow {
	corrupt := receivedDSNDefaultHops()
	corrupt[1].CorruptSignature = true
	local := newReceivedDSNAuthority(receivedDSNLocalDomain)
	delayed := strings.Replace(dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, receivedDSNDestinationRaw, "4.4.1"), "Action: failed", "Action: delayed", 1)
	return []receivedDSNPolicyRow{
		{name: "structure malformed", spec: receivedDSNSpec{deliveryStatus: receivedDSNMalformedStatus}, authority: local,
			reason: PolicyReasonReceivedDSNStructureInvalid, strict: PolicyVerdictReject, permissive: PolicyVerdictContinue, testing: PolicyVerdictContinue, replaces: true},
		{name: "embedded unverified", spec: receivedDSNSpec{hops: corrupt}, authority: local,
			reason: PolicyReasonReceivedDSNEmbeddedUnverified, strict: PolicyVerdictReject, permissive: PolicyVerdictContinue, testing: PolicyVerdictContinue, replaces: true},
		{name: "embedded absent", spec: receivedDSNSpec{unsigned: true}, authority: local,
			reason: PolicyReasonReceivedDSNEmbeddedAbsent, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
		{name: "embedded temperror", spec: receivedDSNSpec{}, authority: local, provider: &receivedDSNProvider{temporaryDomain: receivedDSNLocalDomain},
			reason: PolicyReasonReceivedDSNTemporaryFailure, strict: PolicyVerdictTempfail, permissive: PolicyVerdictTempfail, testing: PolicyVerdictContinue, replaces: true},
		{name: "local hop temperror", spec: receivedDSNSpec{}, authority: &receivedDSNAuthority{temporary: true},
			reason: PolicyReasonReceivedDSNTemporaryFailure, strict: PolicyVerdictTempfail, permissive: PolicyVerdictTempfail, testing: PolicyVerdictContinue, replaces: true},
		{name: "no tenant", spec: receivedDSNSpec{}, authority: nil,
			reason: PolicyReasonReceivedDSNTenantUnavailable, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
		{name: "local hop mismatch", spec: receivedDSNSpec{outerRecipient: receivedDSNOtherLocal}, authority: local,
			reason: PolicyReasonReceivedDSNIdentityMismatch, strict: PolicyVerdictReject, permissive: PolicyVerdictContinue, testing: PolicyVerdictContinue, replaces: true},
		{name: "outer misaligned", spec: receivedDSNSpec{outerSigner: receivedDSNOtherDomain}, authority: local,
			reason: PolicyReasonReceivedDSNIdentityMismatch, strict: PolicyVerdictReject, permissive: PolicyVerdictContinue, testing: PolicyVerdictContinue, replaces: true},
		{name: "not local", spec: receivedDSNSpec{}, authority: newReceivedDSNAuthority(receivedDSNOtherDomain),
			reason: PolicyReasonReceivedDSNNotLocal, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
		{name: "foreign parent-domain signer not local", spec: receivedDSNSpec{hops: receivedDSNParentSignerHops()}, authority: local,
			reason: PolicyReasonReceivedDSNNotLocal, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
		{name: "unlinked recipient group", spec: receivedDSNSpec{deliveryStatus: dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, "other@destination.example", "5.1.1")}, authority: local,
			reason: PolicyReasonReceivedDSNRecipientUnlinked, strict: PolicyVerdictReject, permissive: PolicyVerdictContinue, testing: PolicyVerdictContinue, replaces: true},
		{name: "linked eligible", spec: receivedDSNSpec{}, authority: local,
			reason: PolicyReasonReceivedDSNLinked, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
		{name: "linked not failure", spec: receivedDSNSpec{deliveryStatus: delayed}, authority: local,
			reason: PolicyReasonReceivedDSNLinked, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
		{name: "linked terminal origin", spec: receivedDSNSpec{hops: []dsntest.Hop{receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination)}}, authority: local,
			reason: PolicyReasonReceivedDSNLinked, strict: PolicyVerdictAccept, permissive: PolicyVerdictAccept, testing: PolicyVerdictContinue},
	}
}

// TestReceivedDSNPolicyMappingTable proves every row of the received-DSN
// mapping table through EvaluatePolicy and EvaluateAuthenticationPolicy in
// strict, permissive, and testing modes: the row is recorded as the single
// last finding on the one PolicyDecision, reject, tempfail, and continue rows
// replace the outer verdict and primary reason, and accept rows keep them.
func TestReceivedDSNPolicyMappingTable(t *testing.T) {
	verification := receivedDSNOuterVerification(t, &receivedDSNProvider{}, receivedDSNSpec{}.build(t))
	if verification.State() != ResultStatePASS {
		t.Fatalf("outer verification state=%q", verification.State())
	}
	final := newAuthenticationResult(verification, ResultStatePASS, ReasonNone, AuthenticationReplayFirstSeen)
	for _, row := range receivedDSNPolicyRows() {
		t.Run(row.name, func(t *testing.T) {
			provider := row.provider
			if provider == nil {
				provider = &receivedDSNProvider{}
			}
			evaluation, err := mustReceivedDSNVerifier(t, provider).EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(row.spec.build(t), []byte("<>"), [][]byte{[]byte(row.spec.recipient())}, row.authority))
			if err != nil {
				t.Fatal(err)
			}
			for _, modeCase := range []struct {
				mode PolicyMode
				want PolicyVerdict
			}{{PolicyModeStrict, row.strict}, {PolicyModePermissive, row.permissive}, {PolicyModeTesting, row.testing}} {
				outer, err := EvaluatePolicy(verification, WithPolicyMode(modeCase.mode))
				if err != nil || !outer.Valid() {
					t.Fatalf("outer EvaluatePolicy(%s) valid=%t error=%v", modeCase.mode, outer.Valid(), err)
				}
				decision, err := EvaluatePolicy(verification, WithPolicyMode(modeCase.mode), WithReceivedDSNEvaluation(evaluation))
				if err != nil {
					t.Fatalf("EvaluatePolicy(%s) error=%v", modeCase.mode, err)
				}
				authenticated, err := EvaluateAuthenticationPolicy(final, WithPolicyMode(modeCase.mode), WithReceivedDSNEvaluation(evaluation))
				if err != nil {
					t.Fatalf("EvaluateAuthenticationPolicy(%s) error=%v", modeCase.mode, err)
				}
				for name, got := range map[string]PolicyDecision{"verification": decision, "authentication": authenticated} {
					assertReceivedDSNDecision(t, got, len(outer.Findings()), row.reason)
					if got.Verdict() != modeCase.want || got.Mode() != modeCase.mode || got.VerificationState() != ResultStatePASS {
						t.Fatalf("%s mode=%s verdict=%q want=%q", name, modeCase.mode, got.Verdict(), modeCase.want)
					}
					wantPrimary := outer.PrimaryReason()
					if row.replaces {
						wantPrimary = row.reason
					} else if got.Verdict() != outer.Verdict() {
						t.Fatalf("%s mode=%s accept row changed the outer verdict %q to %q", name, modeCase.mode, outer.Verdict(), got.Verdict())
					}
					if got.PrimaryReason() != wantPrimary {
						t.Fatalf("%s mode=%s primary=%q want=%q", name, modeCase.mode, got.PrimaryReason(), wantPrimary)
					}
				}
			}
		})
	}
}

// TestReceivedDSNPolicyOuterVerificationNotPassAppliesOuterPolicy proves the
// first row: an outer verification other than PASS keeps the outer verdict and
// primary reason in every mode and records only the outer-policy finding.
func TestReceivedDSNPolicyOuterVerificationNotPassAppliesOuterPolicy(t *testing.T) {
	verification := receivedDSNOuterVerification(t, &receivedDSNProvider{missing: true}, receivedDSNSpec{}.build(t))
	if verification.State() == ResultStatePASS {
		t.Fatal("missing-key outer verification passed")
	}
	evaluation, err := evaluateReceivedDSN(t, receivedDSNSpec{deliveryStatus: receivedDSNMalformedStatus}, newReceivedDSNAuthority(receivedDSNLocalDomain))
	if err != nil || evaluation.Structure() != ReceivedDSNStructureMalformed {
		t.Fatalf("structure=%q error=%v", evaluation.Structure(), err)
	}
	for _, mode := range []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting} {
		outer, err := EvaluatePolicy(verification, WithPolicyMode(mode))
		if err != nil {
			t.Fatal(err)
		}
		decision, err := EvaluatePolicy(verification, WithPolicyMode(mode), WithReceivedDSNEvaluation(evaluation))
		if err != nil {
			t.Fatalf("mode=%s error=%v", mode, err)
		}
		assertReceivedDSNDecision(t, decision, len(outer.Findings()), PolicyReasonReceivedDSNOuterPolicy)
		if decision.Verdict() != outer.Verdict() || decision.PrimaryReason() != outer.PrimaryReason() || decision.VerificationState() != verification.State() {
			t.Fatalf("mode=%s verdict=%q primary=%q outer verdict=%q primary=%q", mode, decision.Verdict(), decision.PrimaryReason(), outer.Verdict(), outer.PrimaryReason())
		}
	}
}

// TestReceivedDSNPolicyAuthenticationFinalNotPassKeepsOuterPolicy proves a
// final replay state other than PASS keeps the replay-owned verdict in every
// mode and retains the received-DSN facts only as the outer-policy finding.
func TestReceivedDSNPolicyAuthenticationFinalNotPassKeepsOuterPolicy(t *testing.T) {
	verification := receivedDSNOuterVerification(t, &receivedDSNProvider{}, receivedDSNSpec{}.build(t))
	evaluation, err := evaluateReceivedDSN(t, receivedDSNSpec{deliveryStatus: receivedDSNMalformedStatus}, newReceivedDSNAuthority(receivedDSNLocalDomain))
	if err != nil {
		t.Fatal(err)
	}
	for _, finalCase := range []struct {
		result AuthenticationResult
		want   PolicyVerdict
	}{
		{result: newAuthenticationResult(verification, ResultStateTEMPERROR, AuthenticationReasonReplayEvidenceUnavailable, AuthenticationReplayIndeterminate), want: PolicyVerdictTempfail},
		{result: newAuthenticationResult(verification, ResultStateFAIL, AuthenticationReasonDuplicateMessageWithoutExploded, AuthenticationReplayReplayed), want: PolicyVerdictReject},
	} {
		for _, mode := range []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting} {
			outer, err := EvaluateAuthenticationPolicy(finalCase.result, WithPolicyMode(mode))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := EvaluateAuthenticationPolicy(finalCase.result, WithPolicyMode(mode), WithReceivedDSNEvaluation(evaluation))
			if err != nil {
				t.Fatalf("state=%s mode=%s error=%v", finalCase.result.State(), mode, err)
			}
			assertReceivedDSNDecision(t, decision, len(outer.Findings()), PolicyReasonReceivedDSNOuterPolicy)
			if decision.Verdict() != finalCase.want || decision.Verdict() != outer.Verdict() || decision.PrimaryReason() != outer.PrimaryReason() || decision.VerificationState() != finalCase.result.State() {
				t.Fatalf("state=%s mode=%s verdict=%q primary=%q want=%q outer=%q", finalCase.result.State(), mode, decision.Verdict(), decision.PrimaryReason(), finalCase.want, outer.Verdict())
			}
		}
	}
}

// TestReceivedDSNPolicyOptionRejectsInvalidAndDuplicate proves the option
// fails closed on a zero evaluation and on a second use without a partial decision.
func TestReceivedDSNPolicyOptionRejectsInvalidAndDuplicate(t *testing.T) {
	verification := receivedDSNOuterVerification(t, &receivedDSNProvider{}, receivedDSNSpec{}.build(t))
	evaluation, err := evaluateReceivedDSN(t, receivedDSNSpec{}, newReceivedDSNAuthority(receivedDSNLocalDomain))
	if err != nil {
		t.Fatal(err)
	}
	for name, options := range map[string][]PolicyOption{
		"zero evaluation": {WithReceivedDSNEvaluation(ReceivedDSNEvaluation{})},
		"duplicate":       {WithReceivedDSNEvaluation(evaluation), WithReceivedDSNEvaluation(evaluation)},
	} {
		decision, err := EvaluatePolicy(verification, options...)
		if !decision.IsZero() || !errors.Is(err, newPolicyError(PolicyErrorInvalidOption)) {
			t.Fatalf("%s: decision zero=%t error=%v", name, decision.IsZero(), err)
		}
	}
	if _, err := EvaluatePolicy(VerifyResult{}, WithReceivedDSNEvaluation(evaluation)); !errors.Is(err, newPolicyError(PolicyErrorInvalidInput)) {
		t.Fatalf("zero result error=%v", err)
	}
	if _, err := (ReceivedDSNEvaluation{}).policyFacts(); !errors.Is(err, newPolicyError(PolicyErrorInvalidInput)) {
		t.Fatalf("zero evaluation facts error=%v", err)
	}
}

// TestReceivedDSNPolicyReasonsAreClosedTokens proves the public received-DSN
// policy reasons are known, unique, pvalue tokens with the frozen severities.
func TestReceivedDSNPolicyReasonsAreClosedTokens(t *testing.T) {
	token := regexp.MustCompile(`^received_dsn_[a-z][a-z0-9_]*$`)
	seen := make(map[PolicyReason]struct{})
	for _, tt := range []struct {
		reason   PolicyReason
		severity PolicyFindingSeverity
	}{
		{PolicyReasonReceivedDSNOuterPolicy, PolicySeverityInfo},
		{PolicyReasonReceivedDSNStructureInvalid, PolicySeverityPermanent},
		{PolicyReasonReceivedDSNEmbeddedUnverified, PolicySeverityPermanent},
		{PolicyReasonReceivedDSNEmbeddedAbsent, PolicySeverityInfo},
		{PolicyReasonReceivedDSNTemporaryFailure, PolicySeverityTemporary},
		{PolicyReasonReceivedDSNTenantUnavailable, PolicySeverityWarning},
		{PolicyReasonReceivedDSNIdentityMismatch, PolicySeverityPermanent},
		{PolicyReasonReceivedDSNNotLocal, PolicySeverityInfo},
		{PolicyReasonReceivedDSNRecipientUnlinked, PolicySeverityPermanent},
		{PolicyReasonReceivedDSNLinked, PolicySeverityInfo},
	} {
		if !tt.reason.Known() || !token.MatchString(string(tt.reason)) || publicSeverityForReason(tt.reason) != tt.severity || publicFindingRequiresSequence(tt.reason) {
			t.Fatalf("reason %q known=%t severity=%q", tt.reason, tt.reason.Known(), publicSeverityForReason(tt.reason))
		}
		if _, duplicate := seen[tt.reason]; duplicate {
			t.Fatalf("reason %q duplicated", tt.reason)
		}
		seen[tt.reason] = struct{}{}
	}
	if len(seen) != 10 || PolicyReason("received_dsn_future").Known() {
		t.Fatalf("received-DSN reason vocabulary count=%d", len(seen))
	}
}
