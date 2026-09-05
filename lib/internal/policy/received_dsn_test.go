package policy

import (
	"slices"
	"testing"
)

// receivedDSNFactsRow pairs one stage-coherent fact set with its row reason and verdicts.
type receivedDSNFactsRow struct {
	name       string
	facts      ReceivedDSNFacts
	reason     PolicyReason
	strict     Verdict
	permissive Verdict
	testing    Verdict
}

// mustReceivedDSNFacts seals one fact set or fails the test.
func mustReceivedDSNFacts(t *testing.T, structure ReceivedDSNStructure, embedded ReceivedDSNEmbedded, localHop ReceivedDSNLocalHop, alignment ReceivedDSNOuterAlignment, linkage ReceivedDSNRecipientLinkage) ReceivedDSNFacts {
	t.Helper()
	facts, err := NewReceivedDSNFacts(structure, embedded, localHop, alignment, linkage)
	if err != nil {
		t.Fatalf("NewReceivedDSNFacts() error = %v", err)
	}
	return facts
}

// receivedDSNRows lists every row of the mapping table for an outer PASS.
func receivedDSNRows(t *testing.T) []receivedDSNFactsRow {
	t.Helper()
	stopped := func(embedded ReceivedDSNEmbedded, localHop ReceivedDSNLocalHop) ReceivedDSNFacts {
		return mustReceivedDSNFacts(t, ReceivedDSNStructureValid, embedded, localHop, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated)
	}
	return []receivedDSNFactsRow{
		{name: "structure malformed", facts: mustReceivedDSNFacts(t, ReceivedDSNStructureMalformed, ReceivedDSNEmbeddedNotEvaluated, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated),
			reason: ReasonReceivedDSNStructureInvalid, strict: VerdictReject, permissive: VerdictContinue, testing: VerdictContinue},
		{name: "structure limit exceeded", facts: mustReceivedDSNFacts(t, ReceivedDSNStructureLimitExceeded, ReceivedDSNEmbeddedNotEvaluated, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated),
			reason: ReasonReceivedDSNStructureInvalid, strict: VerdictReject, permissive: VerdictContinue, testing: VerdictContinue},
		{name: "embedded unverified", facts: stopped(ReceivedDSNEmbeddedUnverified, ReceivedDSNLocalHopNotEvaluated),
			reason: ReasonReceivedDSNEmbeddedUnverified, strict: VerdictReject, permissive: VerdictContinue, testing: VerdictContinue},
		{name: "embedded absent", facts: stopped(ReceivedDSNEmbeddedAbsent, ReceivedDSNLocalHopNotEvaluated),
			reason: ReasonReceivedDSNEmbeddedAbsent, strict: VerdictAccept, permissive: VerdictAccept, testing: VerdictContinue},
		{name: "embedded temperror", facts: stopped(ReceivedDSNEmbeddedTemperror, ReceivedDSNLocalHopNotEvaluated),
			reason: ReasonReceivedDSNTemporaryFailure, strict: VerdictTempfail, permissive: VerdictTempfail, testing: VerdictContinue},
		{name: "local hop temperror", facts: stopped(ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopTemperror),
			reason: ReasonReceivedDSNTemporaryFailure, strict: VerdictTempfail, permissive: VerdictTempfail, testing: VerdictContinue},
		{name: "no tenant", facts: stopped(ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopNotEvaluated),
			reason: ReasonReceivedDSNTenantUnavailable, strict: VerdictAccept, permissive: VerdictAccept, testing: VerdictContinue},
		{name: "local hop mismatch", facts: stopped(ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopMismatch),
			reason: ReasonReceivedDSNIdentityMismatch, strict: VerdictReject, permissive: VerdictContinue, testing: VerdictContinue},
		{name: "outer misaligned", facts: mustReceivedDSNFacts(t, ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerifiedHeadersOnly, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentMisaligned, ReceivedDSNRecipientLinkageNotEvaluated),
			reason: ReasonReceivedDSNIdentityMismatch, strict: VerdictReject, permissive: VerdictContinue, testing: VerdictContinue},
		{name: "not local", facts: stopped(ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopNotLocal),
			reason: ReasonReceivedDSNNotLocal, strict: VerdictAccept, permissive: VerdictAccept, testing: VerdictContinue},
		{name: "recipient unlinked", facts: mustReceivedDSNFacts(t, ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageUnlinked),
			reason: ReasonReceivedDSNRecipientUnlinked, strict: VerdictReject, permissive: VerdictContinue, testing: VerdictContinue},
		{name: "linked", facts: mustReceivedDSNFacts(t, ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked),
			reason: ReasonReceivedDSNLinked, strict: VerdictAccept, permissive: VerdictAccept, testing: VerdictContinue},
	}
}

// mustReceivedDSNProjection seals a PASS projection carrying the facts.
func mustReceivedDSNProjection(t *testing.T, protocol ProtocolClass, reason VerificationReason, facts ReceivedDSNFacts, hops []HopFact) Projection {
	t.Helper()
	signatureFacts := []SignatureFact{mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusPass, SetReasonNone, false, false)}
	if protocol != ProtocolPASS {
		signatureFacts = []SignatureFact{mustProjectionSignatureFact(t, SetAlgorithmEd25519, SetStatusFail, SetReasonSignatureMismatch, false, false)}
	}
	base, err := NewSelectedProjection(protocol, reason, 1, hops, signatureFacts, DefaultLimits())
	if err != nil {
		t.Fatalf("NewSelectedProjection() error = %v", err)
	}
	projection, err := base.WithReceivedDSN(facts)
	if err != nil {
		t.Fatalf("WithReceivedDSN() error = %v", err)
	}
	if got, ok := projection.ReceivedDSN(); !ok || got != facts || projection.IsZero() || !projection.Valid() {
		t.Fatalf("projection lost the received-DSN facts")
	}
	if _, ok := base.ReceivedDSN(); ok {
		t.Fatal("WithReceivedDSN() mutated the sealed projection")
	}
	return projection
}

// TestReceivedDSNRowsReplaceOrKeepOuterVerdict proves every row of the
// mapping table in every mode: reject, tempfail, and continue rows replace
// the outer verdict and primary reason, accept rows keep them, and exactly one
// received-DSN finding is recorded last.
func TestReceivedDSNRowsReplaceOrKeepOuterVerdict(t *testing.T) {
	hop := mustProjectionHop(t, 1, TransitionOrigin)
	for _, row := range receivedDSNRows(t) {
		for _, modeCase := range []struct {
			mode Mode
			want Verdict
		}{{ModeStrict, row.strict}, {ModePermissive, row.permissive}, {ModeTesting, row.testing}} {
			t.Run(row.name+"/"+string(modeCase.mode), func(t *testing.T) {
				config := DefaultConfig()
				config.Mode = modeCase.mode
				evaluator, err := NewEvaluator(config)
				if err != nil {
					t.Fatal(err)
				}
				projection := mustReceivedDSNProjection(t, ProtocolPASS, VerificationReasonNone, row.facts, []HopFact{hop})
				outer, err := evaluator.EvaluateProjection(projection.Clone().withoutReceivedDSN())
				if err != nil {
					t.Fatal(err)
				}
				decision, err := evaluator.EvaluateProjection(projection)
				if err != nil || !decision.Valid() {
					t.Fatalf("EvaluateProjection() valid=%t error=%v", decision.Valid(), err)
				}
				if decision.Verdict() != modeCase.want {
					t.Fatalf("verdict=%q want=%q", decision.Verdict(), modeCase.want)
				}
				_, replace := receivedDSNRowVerdict(modeCase.mode, row.reason)
				wantPrimary := outer.PrimaryReason()
				if replace {
					wantPrimary = row.reason
				} else if decision.Verdict() != outer.Verdict() {
					t.Fatalf("accept row changed the outer verdict %q to %q", outer.Verdict(), decision.Verdict())
				}
				if decision.PrimaryReason() != wantPrimary {
					t.Fatalf("primary=%q want=%q", decision.PrimaryReason(), wantPrimary)
				}
				findings := decision.Findings()
				if len(findings) != len(outer.Findings())+1 || findings[len(findings)-1].Reason() != row.reason || receivedDSNFindingCount(findings) != 1 {
					t.Fatalf("findings=%v want outer findings plus %q", findingReasons(findings), row.reason)
				}
				if actions := decision.Actions(); len(actions) != 1 || actions[0].Kind() != actionForVerdict(decision.Verdict()) {
					t.Fatalf("actions=%#v", actions)
				}
			})
		}
	}
}

// withoutReceivedDSN strips the received-DSN facts for outer comparison.
func (p Projection) withoutReceivedDSN() Projection {
	p.receivedDSN, p.hasReceivedDSN = ReceivedDSNFacts{}, false
	return p
}

// TestReceivedDSNOuterNotPassKeepsOuterPolicy proves the first row: a non-PASS
// outer verification keeps the outer policy and records the outer-policy finding.
func TestReceivedDSNOuterNotPassKeepsOuterPolicy(t *testing.T) {
	facts := mustReceivedDSNFacts(t, ReceivedDSNStructureMalformed, ReceivedDSNEmbeddedNotEvaluated, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated)
	for _, modeCase := range []struct {
		mode Mode
		want Verdict
	}{{ModeStrict, VerdictReject}, {ModePermissive, VerdictAccept}, {ModeTesting, VerdictContinue}} {
		config := DefaultConfig()
		config.Mode = modeCase.mode
		evaluator, err := NewEvaluator(config)
		if err != nil {
			t.Fatal(err)
		}
		projection := mustReceivedDSNProjection(t, ProtocolFAIL, VerificationReasonSignatureMismatch, facts, nil)
		decision, err := evaluator.EvaluateProjection(projection)
		if err != nil || !decision.Valid() || decision.Verdict() != modeCase.want {
			t.Fatalf("mode=%s verdict=%q valid=%t error=%v", modeCase.mode, decision.Verdict(), decision.Valid(), err)
		}
		if reason, ok := receivedDSNFindingReason(decision.Findings()); !ok || reason != ReasonReceivedDSNOuterPolicy {
			t.Fatalf("mode=%s findings=%v", modeCase.mode, findingReasons(decision.Findings()))
		}
	}
}

// TestReceivedDSNAuthenticationFinalDowngradesToOuterPolicy proves a final
// replay failure keeps the received-DSN fact only as the outer-policy finding.
func TestReceivedDSNAuthenticationFinalDowngradesToOuterPolicy(t *testing.T) {
	facts := mustReceivedDSNFacts(t, ReceivedDSNStructureMalformed, ReceivedDSNEmbeddedNotEvaluated, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated)
	projection := mustReceivedDSNProjection(t, ProtocolPASS, VerificationReasonNone, facts, []HopFact{mustProjectionHop(t, 1, TransitionOrigin)})
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := evaluator.EvaluateAuthenticationProjection(projection, ProtocolTEMPERROR)
	if err != nil || !decision.Valid() || decision.Verdict() != VerdictTempfail || decision.PrimaryReason() != ReasonProtocolTemperror {
		t.Fatalf("decision verdict=%q primary=%q valid=%t error=%v", decision.Verdict(), decision.PrimaryReason(), decision.Valid(), err)
	}
	if reason, ok := receivedDSNFindingReason(decision.Findings()); !ok || reason != ReasonReceivedDSNOuterPolicy || receivedDSNFindingCount(decision.Findings()) != 1 {
		t.Fatalf("findings=%v", findingReasons(decision.Findings()))
	}
}

// TestReceivedDSNDecisionInvariants proves corrupt decisions with incoherent
// received-DSN findings are rejected by Valid.
func TestReceivedDSNDecisionInvariants(t *testing.T) {
	facts := mustReceivedDSNFacts(t, ReceivedDSNStructureValid, ReceivedDSNEmbeddedUnverified, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated)
	projection := mustReceivedDSNProjection(t, ProtocolPASS, VerificationReasonNone, facts, []HopFact{mustProjectionHop(t, 1, TransitionOrigin)})
	evaluator, err := NewEvaluator(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if err != nil || !decision.Valid() || decision.Verdict() != VerdictReject {
		t.Fatalf("decision verdict=%q valid=%t error=%v", decision.Verdict(), decision.Valid(), err)
	}
	keptOuter := decision
	keptOuter.verdict, keptOuter.primaryReason, keptOuter.actions = VerdictAccept, ReasonProtocolPass, []Action{{kind: ActionAccept}}
	if keptOuter.Valid() {
		t.Fatal("reject row without verdict replacement accepted")
	}
	outerPolicyOnPass := decision
	outerPolicyOnPass.findings = slices.Clone(decision.findings)
	outerPolicyOnPass.findings[len(outerPolicyOnPass.findings)-1] = Finding{reason: ReasonReceivedDSNOuterPolicy, severity: SeverityInfo}
	if outerPolicyOnPass.Valid() {
		t.Fatal("outer-policy finding on a PASS decision accepted")
	}
	duplicated := decision
	duplicated.findings = append(slices.Clone(decision.findings), decision.findings[len(decision.findings)-1])
	if duplicated.Valid() {
		t.Fatal("two received-DSN findings accepted")
	}
	sequenced := decision
	sequenced.findings = slices.Clone(decision.findings)
	sequenced.findings[len(sequenced.findings)-1] = Finding{reason: ReasonReceivedDSNEmbeddedUnverified, severity: SeverityPermanent, sequence: 1, hasSequence: true}
	if sequenced.Valid() {
		t.Fatal("sequenced received-DSN finding accepted")
	}
}

// TestReceivedDSNFactsRejectIncoherentStages proves the fact constructor
// enforces the stop-at-first-failure stage order and closed vocabularies.
func TestReceivedDSNFactsRejectIncoherentStages(t *testing.T) {
	for _, tt := range []struct {
		name      string
		structure ReceivedDSNStructure
		embedded  ReceivedDSNEmbedded
		localHop  ReceivedDSNLocalHop
		alignment ReceivedDSNOuterAlignment
		linkage   ReceivedDSNRecipientLinkage
	}{
		{name: "unknown structure", structure: "not_a_structure", localHop: ReceivedDSNLocalHopNotEvaluated, alignment: ReceivedDSNOuterAlignmentNotEvaluated, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "malformed with embedded", structure: ReceivedDSNStructureMalformed, embedded: ReceivedDSNEmbeddedVerified, localHop: ReceivedDSNLocalHopNotEvaluated, alignment: ReceivedDSNOuterAlignmentNotEvaluated, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "valid without embedded", structure: ReceivedDSNStructureValid, localHop: ReceivedDSNLocalHopNotEvaluated, alignment: ReceivedDSNOuterAlignmentNotEvaluated, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "valid with unevaluated embedded", structure: ReceivedDSNStructureValid, embedded: ReceivedDSNEmbeddedNotEvaluated, localHop: ReceivedDSNLocalHopNotEvaluated, alignment: ReceivedDSNOuterAlignmentNotEvaluated, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "malformed with empty embedded", structure: ReceivedDSNStructureMalformed, embedded: "", localHop: ReceivedDSNLocalHopNotEvaluated, alignment: ReceivedDSNOuterAlignmentNotEvaluated, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "unverified with local hop", structure: ReceivedDSNStructureValid, embedded: ReceivedDSNEmbeddedUnverified, localHop: ReceivedDSNLocalHopLocal, alignment: ReceivedDSNOuterAlignmentNotEvaluated, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "not local with alignment", structure: ReceivedDSNStructureValid, embedded: ReceivedDSNEmbeddedVerified, localHop: ReceivedDSNLocalHopNotLocal, alignment: ReceivedDSNOuterAlignmentAligned, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
		{name: "misaligned with linkage", structure: ReceivedDSNStructureValid, embedded: ReceivedDSNEmbeddedVerified, localHop: ReceivedDSNLocalHopLocal, alignment: ReceivedDSNOuterAlignmentMisaligned, linkage: ReceivedDSNRecipientLinkageLinked},
		{name: "aligned without linkage", structure: ReceivedDSNStructureValid, embedded: ReceivedDSNEmbeddedVerified, localHop: ReceivedDSNLocalHopLocal, alignment: ReceivedDSNOuterAlignmentAligned, linkage: ReceivedDSNRecipientLinkageNotEvaluated},
	} {
		t.Run(tt.name, func(t *testing.T) {
			facts, err := NewReceivedDSNFacts(tt.structure, tt.embedded, tt.localHop, tt.alignment, tt.linkage)
			if !IsErrorCode(err, ErrorInvalidInput) || facts.Valid() {
				t.Fatalf("incoherent facts accepted: %+v error=%v", facts, err)
			}
		})
	}
	if _, err := (Projection{}).WithReceivedDSN(receivedDSNRows(t)[0].facts); !IsErrorCode(err, ErrorInvalidInput) {
		t.Fatalf("WithReceivedDSN(zero projection) error = %v", err)
	}
}
