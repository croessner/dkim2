package dkim2

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
)

// receivedDSNProjection flattens the six closed members for comparison.
type receivedDSNProjection struct {
	structure   ReceivedDSNStructure
	embedded    ReceivedDSNEmbedded
	localHop    ReceivedDSNLocalHop
	alignment   ReceivedDSNOuterAlignment
	linkage     ReceivedDSNRecipientLinkage
	propagation ReceivedDSNPropagation
}

// receivedDSNProjectionOf reads the projection from one evaluation.
func receivedDSNProjectionOf(evaluation ReceivedDSNEvaluation) receivedDSNProjection {
	return receivedDSNProjection{
		structure: evaluation.Structure(), embedded: evaluation.Embedded(), localHop: evaluation.LocalHop(),
		alignment: evaluation.OuterAlignment(), linkage: evaluation.RecipientLinkage(), propagation: evaluation.Propagation(),
	}
}

// TestEvaluateReceivedDSNEligibleProjection proves the public facade projects
// the positive path for both original representations with bounded facts only.
func TestEvaluateReceivedDSNEligibleProjection(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		headersOnly bool
		embedded    ReceivedDSNEmbedded
		form        ReceivedDSNOriginalForm
	}{
		{name: "complete", embedded: ReceivedDSNEmbeddedVerified, form: ReceivedDSNOriginalComplete},
		{name: "headers only", headersOnly: true, embedded: ReceivedDSNEmbeddedVerifiedHeadersOnly, form: ReceivedDSNOriginalHeadersOnly},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceivedDSN(t, receivedDSNSpec{headersOnly: testCase.headersOnly}, newReceivedDSNAuthority(receivedDSNLocalDomain))
			if err != nil || !evaluation.Valid() {
				t.Fatalf("EvaluateReceivedDSN() valid=%t error=%v", evaluation.Valid(), err)
			}
			want := receivedDSNProjection{
				structure: ReceivedDSNStructureValid, embedded: testCase.embedded, localHop: ReceivedDSNLocalHopLocal,
				alignment: ReceivedDSNOuterAlignmentAligned, linkage: ReceivedDSNRecipientLinkageLinked, propagation: ReceivedDSNPropagationEligible,
			}
			if got := receivedDSNProjectionOf(evaluation); got != want {
				t.Fatalf("projection=%+v", got)
			}
			if evaluation.OriginalForm() != testCase.form || evaluation.CompletionSequence() != 2 || evaluation.LocalHopRunLength() != 1 {
				t.Fatalf("facts form=%q sequence=%d run=%d", evaluation.OriginalForm(), evaluation.CompletionSequence(), evaluation.LocalHopRunLength())
			}
		})
	}
}

// TestEvaluateReceivedDSNStageOutcomes proves every stage's negative outcome
// reaches the public projection with later members not evaluated.
func TestEvaluateReceivedDSNStageOutcomes(t *testing.T) {
	corrupt := receivedDSNDefaultHops()
	corrupt[1].CorruptSignature = true
	stopped := func(structure ReceivedDSNStructure, embedded ReceivedDSNEmbedded, localHop ReceivedDSNLocalHop, alignment ReceivedDSNOuterAlignment, linkage ReceivedDSNRecipientLinkage, propagation ReceivedDSNPropagation) receivedDSNProjection {
		return receivedDSNProjection{structure: structure, embedded: embedded, localHop: localHop, alignment: alignment, linkage: linkage, propagation: propagation}
	}
	local := newReceivedDSNAuthority(receivedDSNLocalDomain)
	for _, testCase := range []struct {
		name      string
		spec      receivedDSNSpec
		authority LocalAuthority
		want      receivedDSNProjection
	}{
		{name: "malformed delivery status", spec: receivedDSNSpec{deliveryStatus: receivedDSNMalformedStatus}, authority: local,
			want: stopped(ReceivedDSNStructureMalformed, "", ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "embedded absent", spec: receivedDSNSpec{unsigned: true}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedAbsent, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotApplicable)},
		{name: "embedded unverified", spec: receivedDSNSpec{hops: corrupt}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedUnverified, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "no tenant", spec: receivedDSNSpec{}, authority: nil,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "not local", spec: receivedDSNSpec{}, authority: newReceivedDSNAuthority(receivedDSNOtherDomain),
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopNotLocal, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "verified foreign parent-domain signer naming a local address", spec: receivedDSNSpec{hops: receivedDSNParentSignerHops()}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopNotLocal, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "old forwarding with a DSN generated a day later", spec: receivedDSNSpec{hops: receivedDSNHopsAt(dsntest.DefaultTimestamp - 30*receivedDSNDay), outerTimestamp: dsntest.DefaultTimestamp - 29*receivedDSNDay}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked, ReceivedDSNPropagationEligible)},
		{name: "DSN generated after the maximum age of the forwarding", spec: receivedDSNSpec{outerTimestamp: dsntest.DefaultTimestamp + 30*receivedDSNDay}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedUnverified, ReceivedDSNLocalHopNotEvaluated, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "mismatch", spec: receivedDSNSpec{outerRecipient: receivedDSNOtherLocal}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopMismatch, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "datasource outage", spec: receivedDSNSpec{}, authority: &receivedDSNAuthority{temporary: true},
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopTemperror, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "authority contract violation", spec: receivedDSNSpec{}, authority: &receivedDSNAuthority{unknown: true},
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopTemperror, ReceivedDSNOuterAlignmentNotEvaluated, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "misaligned", spec: receivedDSNSpec{outerSigner: receivedDSNOtherDomain}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentMisaligned, ReceivedDSNRecipientLinkageNotEvaluated, ReceivedDSNPropagationNotEvaluated)},
		{name: "unlinked recipient group", spec: receivedDSNSpec{deliveryStatus: dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, "other@destination.example", "5.1.1")}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageUnlinked, ReceivedDSNPropagationNotEvaluated)},
		{name: "not failure", spec: receivedDSNSpec{deliveryStatus: strings.Replace(dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, receivedDSNDestinationRaw, "4.4.1"), "Action: failed", "Action: delayed", 1)}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked, ReceivedDSNPropagationNotFailure)},
		{name: "terminal origin", spec: receivedDSNSpec{hops: []dsntest.Hop{receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination)}}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked, ReceivedDSNPropagationTerminalOrigin)},
		{name: "null previous sender", spec: receivedDSNSpec{hops: []dsntest.Hop{receivedDSNHop(receivedDSNRemoteDomain, "<>", receivedDSNLocalRecipient), receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination)}}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked, ReceivedDSNPropagationForbiddenNullPreviousSender)},
		{name: "previous hop nd", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNOriginDomain, "<sender@origin.example>", "<relay@remote.example>"),
			receivedDSNNextDomainHop(receivedDSNRemoteDomain, receivedDSNLocalDomain),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
		}}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked, ReceivedDSNPropagationUnsupportedChain)},
		{name: "ambiguous previous recipient", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient, "<other@local.example>"),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
		}}, authority: local,
			want: stopped(ReceivedDSNStructureValid, ReceivedDSNEmbeddedVerified, ReceivedDSNLocalHopLocal, ReceivedDSNOuterAlignmentAligned, ReceivedDSNRecipientLinkageLinked, ReceivedDSNPropagationNotReconstructable)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceivedDSN(t, testCase.spec, testCase.authority)
			if err != nil || !evaluation.Valid() {
				t.Fatalf("EvaluateReceivedDSN() valid=%t error=%v", evaluation.Valid(), err)
			}
			if got := receivedDSNProjectionOf(evaluation); got != testCase.want {
				t.Fatalf("projection=%+v want=%+v", got, testCase.want)
			}
		})
	}
}

// TestEvaluateReceivedDSNRunAcrossNextDomainAndImaginaryHops proves the public
// facade reports the run length across both Section 9.3 custody schemes.
func TestEvaluateReceivedDSNRunAcrossNextDomainAndImaginaryHops(t *testing.T) {
	corruptMember := receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain)
	corruptMember.CorruptSignature = true
	for _, testCase := range []struct {
		name        string
		hops        []dsntest.Hop
		propagation ReceivedDSNPropagation
		runLength   int
	}{
		{name: "nd run", hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
			receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain),
			receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
		}, propagation: ReceivedDSNPropagationEligible, runLength: 2},
		{name: "imaginary hop run", hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalRecipient, "<user@forward.local.example>"),
			receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
		}, propagation: ReceivedDSNPropagationEligible, runLength: 2},
		{name: "non-verifying run member", hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
			corruptMember,
			receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
		}, propagation: ReceivedDSNPropagationUnsupportedChain, runLength: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			evaluation, err := evaluateReceivedDSN(t, receivedDSNSpec{hops: testCase.hops, outerRecipient: receivedDSNForwardMailFrom}, newReceivedDSNAuthority(receivedDSNLocalDomain, receivedDSNForwardDomain))
			if err != nil || evaluation.Propagation() != testCase.propagation || evaluation.LocalHopRunLength() != testCase.runLength || evaluation.CompletionSequence() != 3 {
				t.Fatalf("propagation=%q run=%d sequence=%d error=%v", evaluation.Propagation(), evaluation.LocalHopRunLength(), evaluation.CompletionSequence(), err)
			}
		})
	}
}

// TestEvaluateReceivedDSNTemporaryKeyFailure proves temporary key failures on
// the completion signature and on a run member are temporary, never permanent.
func TestEvaluateReceivedDSNTemporaryKeyFailure(t *testing.T) {
	evaluator := mustReceivedDSNVerifier(t, &receivedDSNProvider{temporaryDomain: receivedDSNLocalDomain})
	authority := newReceivedDSNAuthority(receivedDSNLocalDomain, receivedDSNForwardDomain)
	evaluation, err := evaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(receivedDSNSpec{}.build(t), []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority))
	if err != nil || evaluation.Embedded() != ReceivedDSNEmbeddedTemperror || evaluation.LocalHop() != ReceivedDSNLocalHopNotEvaluated {
		t.Fatalf("completion temporary: projection=%+v error=%v", receivedDSNProjectionOf(evaluation), err)
	}
	hops := []dsntest.Hop{
		receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
		receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain),
		receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
	}
	raw := receivedDSNSpec{hops: hops, outerRecipient: receivedDSNForwardMailFrom}.build(t)
	evaluation, err = evaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNForwardMailFrom)}, authority))
	if err != nil || evaluation.Embedded() != ReceivedDSNEmbeddedTemperror || evaluation.Propagation() != ReceivedDSNPropagationNotEvaluated {
		t.Fatalf("run member temporary: projection=%+v error=%v", receivedDSNProjectionOf(evaluation), err)
	}
}

// TestEvaluateReceivedDSNRequestValidationAndCancellation proves the facade
// fails closed on request shape and preserves context errors with a closed stage.
func TestEvaluateReceivedDSNRequestValidationAndCancellation(t *testing.T) {
	evaluator := mustReceivedDSNVerifier(t, &receivedDSNProvider{})
	raw := receivedDSNSpec{}.build(t)
	authority := newReceivedDSNAuthority(receivedDSNLocalDomain)
	for _, testCase := range []struct {
		name    string
		ctx     context.Context
		request ReceivedDSNRequest
	}{
		{name: "nil context", ctx: nil, request: NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority)},
		{name: "zero request", ctx: context.Background(), request: ReceivedDSNRequest{}},
		{name: "non-null reverse path", ctx: context.Background(), request: NewReceivedDSNRequest(raw, []byte("<bounce@destination.example>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority)},
		{name: "no recipient", ctx: context.Background(), request: NewReceivedDSNRequest(raw, []byte("<>"), nil, authority)},
		{name: "two recipients", ctx: context.Background(), request: NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom), []byte("<second@local.example>")}, authority)},
		{name: "invalid recipient", ctx: context.Background(), request: NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte("forwarded@local.example")}, authority)},
		{name: "empty message", ctx: context.Background(), request: NewReceivedDSNRequest(nil, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := evaluator.EvaluateReceivedDSN(testCase.ctx, testCase.request)
			if !errors.Is(err, newAPIError(APIErrorCodeInvalidRequest)) || ReceivedDSNStageOf(err) != ReceivedDSNStagePreflight {
				t.Fatalf("error=%v stage=%q", err, ReceivedDSNStageOf(err))
			}
		})
	}
	var nilEvaluator *Verifier
	if _, err := nilEvaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority)); !errors.Is(err, newAPIError(APIErrorCodeInvalidRequest)) {
		t.Fatalf("nil evaluator error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := evaluator.EvaluateReceivedDSN(ctx, NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, authority))
	if !errors.Is(err, context.Canceled) || ReceivedDSNStageOf(err) != ReceivedDSNStagePreflight {
		t.Fatalf("pre-canceled error=%v stage=%q", err, ReceivedDSNStageOf(err))
	}
	lateCtx, cancelLate := context.WithCancel(context.Background())
	late := &cancellingLocalAuthority{cancel: cancelLate}
	_, err = evaluator.EvaluateReceivedDSN(lateCtx, NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, late))
	if !errors.Is(err, context.Canceled) || ReceivedDSNStageOf(err) != ReceivedDSNStageLocalHop {
		t.Fatalf("in-flight cancellation error=%v stage=%q", err, ReceivedDSNStageOf(err))
	}
	for _, rendered := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(rendered, "local.example") || strings.Contains(rendered, "forwarded") {
			t.Fatalf("error leaked content: %q", rendered)
		}
	}
}

// cancellingLocalAuthority cancels the caller context during the first lookup.
type cancellingLocalAuthority struct{ cancel context.CancelFunc }

// LookupLocalAuthority cancels and returns the context error.
func (a *cancellingLocalAuthority) LookupLocalAuthority(ctx context.Context, _ string) (LocalAuthorityStatus, error) {
	a.cancel()
	return "", ctx.Err()
}

// TestReceivedDSNVocabulariesAreClosedTokens proves every public projection
// value is known, unique, and a pvalue token, and matches the protocol-core spelling.
func TestReceivedDSNVocabulariesAreClosedTokens(t *testing.T) {
	token := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	check := func(name string, values []string, known func(string) bool) {
		t.Helper()
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if !token.MatchString(value) || !known(value) {
				t.Fatalf("%s value %q is not a known pvalue token", name, value)
			}
			if _, duplicate := seen[value]; duplicate {
				t.Fatalf("%s value %q duplicated", name, value)
			}
			seen[value] = struct{}{}
		}
		if known("") || known("Unknown") {
			t.Fatalf("%s accepted an unknown value", name)
		}
	}
	check("structure", []string{string(ReceivedDSNStructureValid), string(ReceivedDSNStructureMalformed), string(ReceivedDSNStructureLimitExceeded)}, func(v string) bool { return ReceivedDSNStructure(v).Known() })
	check("embedded", []string{string(ReceivedDSNEmbeddedVerified), string(ReceivedDSNEmbeddedVerifiedHeadersOnly), string(ReceivedDSNEmbeddedUnverified), string(ReceivedDSNEmbeddedTemperror), string(ReceivedDSNEmbeddedAbsent)}, func(v string) bool { return ReceivedDSNEmbedded(v).Known() })
	check("local_hop", []string{string(ReceivedDSNLocalHopLocal), string(ReceivedDSNLocalHopNotLocal), string(ReceivedDSNLocalHopMismatch), string(ReceivedDSNLocalHopTemperror), string(ReceivedDSNLocalHopNotEvaluated)}, func(v string) bool { return ReceivedDSNLocalHop(v).Known() })
	check("outer_alignment", []string{string(ReceivedDSNOuterAlignmentAligned), string(ReceivedDSNOuterAlignmentMisaligned), string(ReceivedDSNOuterAlignmentNotEvaluated)}, func(v string) bool { return ReceivedDSNOuterAlignment(v).Known() })
	check("recipient_linkage", []string{string(ReceivedDSNRecipientLinkageLinked), string(ReceivedDSNRecipientLinkageUnlinked), string(ReceivedDSNRecipientLinkageNotEvaluated)}, func(v string) bool { return ReceivedDSNRecipientLinkage(v).Known() })
	check("propagation", []string{string(ReceivedDSNPropagationNotApplicable), string(ReceivedDSNPropagationEligible), string(ReceivedDSNPropagationTerminalOrigin), string(ReceivedDSNPropagationNotFailure), string(ReceivedDSNPropagationForbiddenNullPreviousSender), string(ReceivedDSNPropagationUnsupportedChain), string(ReceivedDSNPropagationNotReconstructable), string(ReceivedDSNPropagationNotEvaluated)}, func(v string) bool { return ReceivedDSNPropagation(v).Known() })
	check("stage", []string{string(ReceivedDSNStagePreflight), string(ReceivedDSNStageStructure), string(ReceivedDSNStageEmbeddedVerification), string(ReceivedDSNStageLocalHop), string(ReceivedDSNStageOuterAlignment), string(ReceivedDSNStageRecipientLinkage), string(ReceivedDSNStageFailureClass), string(ReceivedDSNStagePreviousHop)}, func(v string) bool { return ReceivedDSNStage(v).Known() })
	check("authority", []string{string(LocalAuthorityLocal), string(LocalAuthorityNotLocal)}, func(v string) bool { return LocalAuthorityStatus(v).Known() })
	check("form", []string{string(ReceivedDSNOriginalComplete), string(ReceivedDSNOriginalHeadersOnly)}, func(v string) bool { return ReceivedDSNOriginalForm(v).Known() })
	check("policy reason", []string{
		string(PolicyReasonReceivedDSNOuterPolicy), string(PolicyReasonReceivedDSNStructureInvalid), string(PolicyReasonReceivedDSNEmbeddedUnverified),
		string(PolicyReasonReceivedDSNEmbeddedAbsent), string(PolicyReasonReceivedDSNTemporaryFailure), string(PolicyReasonReceivedDSNTenantUnavailable),
		string(PolicyReasonReceivedDSNIdentityMismatch), string(PolicyReasonReceivedDSNNotLocal), string(PolicyReasonReceivedDSNRecipientUnlinked), string(PolicyReasonReceivedDSNLinked),
	}, func(v string) bool { return PolicyReason(v).Known() })
}

// TestReceivedDSNEvaluationExposesNoContent proves by reflection that the
// public evaluation cannot leak bytes, addresses, domains, or identifiers and
// therefore cannot serve as a signing authority input.
func TestReceivedDSNEvaluationExposesNoContent(t *testing.T) {
	evaluationType := reflect.TypeOf(ReceivedDSNEvaluation{})
	for index := range evaluationType.NumMethod() {
		method := evaluationType.Method(index)
		if method.Name == "String" || method.Name == "GoString" || method.Name == "Format" || method.Name == "MarshalJSON" || method.Name == "MarshalText" {
			continue
		}
		for output := range method.Type.NumOut() {
			kind := method.Type.Out(output).Kind()
			if kind == reflect.Slice || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Interface ||
				kind == reflect.String && !strings.HasPrefix(method.Type.Out(output).Name(), "ReceivedDSN") {
				t.Fatalf("method %s exposes %s", method.Name, method.Type.Out(output))
			}
		}
	}
	evaluation, err := evaluateReceivedDSN(t, receivedDSNSpec{}, newReceivedDSNAuthority(receivedDSNLocalDomain))
	if err != nil {
		t.Fatal(err)
	}
	request := NewReceivedDSNRequest(receivedDSNSpec{}.build(t), []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, newReceivedDSNAuthority(receivedDSNLocalDomain))
	evaluator := mustReceivedDSNVerifier(t, &receivedDSNProvider{})
	for _, rendered := range []string{
		evaluation.String(), fmt.Sprintf("%+v", evaluation), fmt.Sprintf("%#v", evaluation),
		request.String(), fmt.Sprintf("%+v", request), fmt.Sprintf("%#v", request),
		fmt.Sprintf("%+v", evaluator), fmt.Sprintf("%#v", *evaluator),
	} {
		for _, forbidden := range []string{"local.example", "destination.example", "forwarded", "5.1.1", "boundary"} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("formatting leaked %q: %q", forbidden, rendered)
			}
		}
	}
	for _, marshal := range []func() ([]byte, error){evaluation.MarshalJSON, evaluation.MarshalText, request.MarshalJSON, request.MarshalText, evaluator.MarshalJSON, evaluator.MarshalText} {
		if _, err := marshal(); !errors.Is(err, newAPIError(APIErrorCodeInvalidRequest)) {
			t.Fatalf("marshal accepted sealed state: %v", err)
		}
	}
	var zero ReceivedDSNEvaluation
	if zero.Valid() || zero.Structure() != "" || zero.Propagation() != "" || zero.CompletionSequence() != 0 || zero.LocalHopRunLength() != 0 || zero.OriginalForm() != "" {
		t.Fatal("zero evaluation is not inert")
	}
}

// TestReceivedDSNRequestClonesInput proves the request snapshots caller bytes.
func TestReceivedDSNRequestClonesInput(t *testing.T) {
	raw := receivedDSNSpec{}.build(t)
	recipient := []byte(receivedDSNLocalMailFrom)
	request := NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{recipient}, newReceivedDSNAuthority(receivedDSNLocalDomain))
	raw[0] = 'X'
	recipient[1] = 'X'
	evaluation, err := mustReceivedDSNVerifier(t, &receivedDSNProvider{}).EvaluateReceivedDSN(context.Background(), request)
	if err != nil || evaluation.Propagation() != ReceivedDSNPropagationEligible {
		t.Fatalf("mutated caller bytes changed the request: propagation=%q error=%v", evaluation.Propagation(), err)
	}
	var typedNil *receivedDSNAuthority
	evaluation, err = mustReceivedDSNVerifier(t, &receivedDSNProvider{}).EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(receivedDSNSpec{}.build(t), []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, typedNil))
	if err != nil || evaluation.LocalHop() != ReceivedDSNLocalHopNotEvaluated {
		t.Fatalf("typed-nil authority local_hop=%q error=%v", evaluation.LocalHop(), err)
	}
}

// TestReceivedDSNEvaluatorConcurrentReuse proves one verifier evaluates received DSNs concurrently.
func TestReceivedDSNEvaluatorConcurrentReuse(t *testing.T) {
	evaluator := mustReceivedDSNVerifier(t, &receivedDSNProvider{})
	raw := receivedDSNSpec{}.build(t)
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			evaluation, err := evaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(raw, []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, newReceivedDSNAuthority(receivedDSNLocalDomain)))
			if err != nil || evaluation.Propagation() != ReceivedDSNPropagationEligible {
				t.Errorf("EvaluateReceivedDSN() propagation=%q error=%v", evaluation.Propagation(), err)
			}
		})
	}
	group.Wait()
}

// TestReceivedDSNLimitsNarrowParser proves narrowed raw-message limits apply to the DSN parser.
func TestReceivedDSNLimitsNarrowParser(t *testing.T) {
	evaluator, err := NewVerifier(&receivedDSNProvider{}, receivedDSNClockOption(), WithMaxRawMessageBytes(1024))
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := evaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(receivedDSNSpec{}.build(t), []byte("<>"), [][]byte{[]byte(receivedDSNLocalMailFrom)}, newReceivedDSNAuthority(receivedDSNLocalDomain)))
	if err != nil || evaluation.Structure() != ReceivedDSNStructureLimitExceeded || evaluation.Propagation() != ReceivedDSNPropagationNotEvaluated {
		t.Fatalf("structure=%q propagation=%q error=%v", evaluation.Structure(), evaluation.Propagation(), err)
	}
}
