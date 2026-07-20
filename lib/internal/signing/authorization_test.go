package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

type authorizerFunc func(context.Context, AuthorizationQuery) (AuthorizationResult, error)

// Authorize delegates one test authorization.
func (f authorizerFunc) Authorize(ctx context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
	return f(ctx, query)
}

// TestAuthorizationSessionEnforcesExactMatrixBindingAndBudget proves fail-closed authorizers.
func TestAuthorizationSessionEnforcesExactMatrixBindingAndBudget(t *testing.T) {
	ticket := testRouteTicket(t, 1, [][]byte{[]byte("<a@example.test>"), []byte("<b@example.test>")})
	query, err := NewDisclosureAuthorizationQuery(ticket)
	if err != nil {
		t.Fatalf("NewDisclosureAuthorizationQuery() error = %v", err)
	}
	var key [sha256.Size]byte
	key[0] = 1
	session, err := newAuthorizationSession(2, key)
	if err != nil {
		t.Fatalf("NewAuthorizationSession() error = %v", err)
	}
	allow := authorizerFunc(func(_ context.Context, got AuthorizationQuery) (AuthorizationResult, error) {
		recipients := got.Recipients()
		recipients[0][1] = 'X'
		return NewAuthorizationResult(got, AuthorizationAuthorized), nil
	})
	authorization, status, err := session.Evaluate(context.Background(), allow, query)
	if err != nil || status != AuthorizationAuthorized || !session.ValidAuthorization(authorization, query) {
		t.Fatalf("authorized = %q/%t/%v", status, authorization.Valid(), err)
	}
	deny := authorizerFunc(func(_ context.Context, got AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(got, AuthorizationDenied), nil
	})
	authorization, status, err = session.Evaluate(context.Background(), deny, query)
	if err != nil || status != AuthorizationDenied || authorization.Valid() {
		t.Fatalf("denied = %q/%t/%v", status, authorization.Valid(), err)
	}
	if _, _, err = session.Evaluate(context.Background(), allow, query); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over authorizer call error = %v", err)
	}
}

// TestAuthorizationSessionRejectsIllegalPairsTypedNilsAndMixing locks the shared matrix.
func TestAuthorizationSessionRejectsIllegalPairsTypedNilsAndMixing(t *testing.T) {
	ticket := testRouteTicket(t, 1, [][]byte{[]byte("<a@example.test>"), []byte("<b@example.test>")})
	query, err := NewDisclosureAuthorizationQuery(ticket)
	if err != nil {
		t.Fatalf("NewDisclosureAuthorizationQuery() error = %v", err)
	}
	var key [sha256.Size]byte
	key[0] = 2
	tests := []struct {
		name string
		fn   authorizerFunc
		code ErrorCode
	}{
		{name: "zero plus nil", fn: func(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
			return AuthorizationResult{}, nil
		}, code: ErrorCodeInternalInvariant},
		{name: "result plus error", fn: func(_ context.Context, q AuthorizationQuery) (AuthorizationResult, error) {
			return NewAuthorizationResult(q, AuthorizationAuthorized), provider.NewFailure(provider.FailureTemporary)
		}, code: ErrorCodeInternalInvariant},
		{name: "raw error", fn: func(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
			return AuthorizationResult{}, errors.New("temporary SECRET")
		}, code: ErrorCodeInternalInvariant},
		{name: "typed temporary", fn: func(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
			return AuthorizationResult{}, provider.NewFailure(provider.FailureTemporary)
		}, code: ErrorCodeCallbackTemporary},
		{name: "typed permanent", fn: func(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
			return AuthorizationResult{}, provider.NewFailure(provider.FailurePermanent)
		}, code: ErrorCodeCallbackPermanent},
		{name: "wrong binding", fn: func(_ context.Context, q AuthorizationQuery) (AuthorizationResult, error) {
			q.binding[0] ^= 1
			return NewAuthorizationResult(q, AuthorizationAuthorized), nil
		}, code: ErrorCodeInternalInvariant},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session, sessionErr := newAuthorizationSession(1, key)
			if sessionErr != nil {
				t.Fatalf("NewAuthorizationSession() error = %v", sessionErr)
			}
			if _, _, err := session.Evaluate(context.Background(), test.fn, query); !IsErrorCode(err, test.code) {
				t.Fatalf("Evaluate() error = %v, want %q", err, test.code)
			}
		})
	}
	var nilAuthorizer *nilTestAuthorizer
	session, _ := newAuthorizationSession(1, key)
	if _, _, err := session.Evaluate(context.Background(), nilAuthorizer, query); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("typed-nil authorizer error = %v", err)
	}
}

// TestAuthorizationCancellationCannotMaskMalformedPairs proves callback contracts precede post-call context.
func TestAuthorizationCancellationCannotMaskMalformedPairs(t *testing.T) {
	ticket := testRouteTicket(t, 1, [][]byte{[]byte("<a@example.test>"), []byte("<b@example.test>")})
	query, err := NewDisclosureAuthorizationQuery(ticket)
	if err != nil {
		t.Fatalf("NewDisclosureAuthorizationQuery() error = %v", err)
	}
	var key [sha256.Size]byte
	key[0] = 12
	session, err := newAuthorizationSession(1, key)
	if err != nil {
		t.Fatalf("newAuthorizationSession() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, _, err = session.Evaluate(ctx, authorizerFunc(func(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
		cancel()
		return AuthorizationResult{}, nil
	}), query)
	if !IsErrorCode(err, ErrorCodeInternalInvariant) {
		t.Fatalf("malformed pair hidden by cancellation: %v", err)
	}
}

// TestAuthorizationSealsRejectBitFlipsCrossIssuersAndQueries proves evidence is session-specific.
func TestAuthorizationSealsRejectBitFlipsCrossIssuersAndQueries(t *testing.T) {
	ticket := testRouteTicket(t, 1, [][]byte{[]byte("<a@example.test>"), []byte("<b@example.test>")})
	query, err := NewDisclosureAuthorizationQuery(ticket)
	if err != nil {
		t.Fatalf("NewDisclosureAuthorizationQuery() error = %v", err)
	}
	var firstKey, secondKey [sha256.Size]byte
	firstKey[0], secondKey[0] = 13, 14
	first, _ := newAuthorizationSession(1, firstKey)
	second, _ := newAuthorizationSession(1, secondKey)
	authorization, _, err := first.Evaluate(context.Background(), authorizerFunc(func(_ context.Context, got AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(got, AuthorizationAuthorized), nil
	}), query)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if second.ValidAuthorization(authorization, query) {
		t.Fatal("cross-issuer authorization accepted")
	}
	forged := authorization
	forged.seal[0] ^= 1
	if first.ValidAuthorization(forged, query) {
		t.Fatal("bit-flipped authorization accepted")
	}
	otherQuery, err := NewDisclosureAuthorizationQuery(testRouteTicket(t, 1, [][]byte{
		[]byte("<c@example.test>"), []byte("<d@example.test>"),
	}))
	if err != nil {
		t.Fatalf("other disclosure query error = %v", err)
	}
	if first.ValidAuthorization(authorization, otherQuery) {
		t.Fatal("cross-query authorization accepted")
	}
}

type nilTestAuthorizer struct{}

// Authorize exists only to create a typed-nil authorizer test.
func (*nilTestAuthorizer) Authorize(context.Context, AuthorizationQuery) (AuthorizationResult, error) {
	return AuthorizationResult{}, nil
}

// TestSigningMetadataRejectsDerivedFlagsAndDerivesFixedOrder proves caller/route ownership.
func TestSigningMetadataRejectsDerivedFlagsAndDerivesFixedOrder(t *testing.T) {
	for _, flags := range [][]string{
		{signature.FlagExploded}, {signature.FlagFeedHere}, {"future"}, {signature.FlagFeedback, signature.FlagFeedback},
	} {
		if _, err := NewSigningMetadata(nil, false, flags); err == nil {
			t.Fatalf("NewSigningMetadata(%v) accepted", flags)
		}
	}
	if _, err := NewSigningMetadata([]byte("nonce"), false, nil); err == nil {
		t.Fatal("nonce without presence accepted")
	}
	if _, err := NewSigningMetadata([]byte("nonce;bad"), true, nil); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("semicolon nonce error = %v", err)
	}
	if metadata, err := NewSigningMetadata([]byte("printable nonce"), true, nil); err != nil {
		t.Fatalf("space-bearing nonce rejected: metadata=%v error=%v", metadata, err)
	}
	metadata, err := NewSigningMetadata([]byte("nonce"), true,
		[]string{signature.FlagFeedback, signature.FlagDoNotExplode, signature.FlagDoNotModify})
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	ticket := testRouteTicket(t, 2, nil)
	effective, err := DeriveEffectiveMetadata(metadata, VerifiedRevisionInput{}, ticket, Authorization{}, nil)
	if err != nil {
		t.Fatalf("DeriveEffectiveMetadata() error = %v", err)
	}
	want := []string{signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedback, signature.FlagExploded}
	if got := effective.Flags(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("fixed flags = %v, want %v", got, want)
	}
	nonce, present := metadata.Nonce()
	nonce[0] = 'X'
	if original, again := metadata.Nonce(); !present || !again || string(original) != "nonce" {
		t.Fatal("nonce accessor retained alias")
	}
}

// TestEffectiveMetadataRejectsCapabilityTicketMixing proves origin and revision ownership are exact.
func TestEffectiveMetadataRejectsCapabilityTicketMixing(t *testing.T) {
	metadata, err := NewSigningMetadata(nil, false, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	origin := testRouteTicket(t, 1, nil)
	capability := testRevisionCapabilityWithFlags(t, []string{signature.FlagFeedback}, false)
	for _, malformed := range []VerifiedRevisionInput{capability, {initialized: true}} {
		if _, err := DeriveEffectiveMetadata(metadata, malformed, origin, Authorization{}, nil); !IsErrorCode(err, ErrorCodeInvalidRequest) {
			t.Fatalf("origin accepted nonzero capability: %v", err)
		}
	}
	revision := testBoundRouteTicket(t, capability, routeplan.PurposeRevision, nil)
	if _, err := DeriveEffectiveMetadata(metadata, VerifiedRevisionInput{}, revision, Authorization{}, nil); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("revision accepted zero capability: %v", err)
	}
	other := testRevisionCapabilityWithFlags(t, []string{signature.FlagFeedback}, true)
	if other.seal == capability.seal {
		t.Fatal("cross-capability fixture did not differ")
	}
	if _, err := DeriveEffectiveMetadata(metadata, other, revision, Authorization{}, nil); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("revision accepted cross-capability evidence: %v", err)
	}
}

// TestInheritedPolicyAndFeedbackBindExactTicketAndMultiRecipientMultiplicity proves closed derivation.
func TestInheritedPolicyAndFeedbackBindExactTicketAndMultiRecipientMultiplicity(t *testing.T) {
	capability := testRevisionCapabilityWithFlags(t, []string{
		signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedback,
	}, false)
	ticket := testBoundRouteTicket(t, capability, routeplan.PurposeRevision,
		[][]byte{[]byte("<a@example.test>"), []byte("<b@example.test>")})
	factsEvidence := testModificationFacts(capability, ticket, true, false)
	policyQuery, err := NewPolicyAuthorizationQuery(capability, ticket, factsEvidence)
	if err != nil {
		t.Fatalf("NewPolicyAuthorizationQuery() error = %v", err)
	}
	facts, restriction, ok := policyQuery.PolicyFacts()
	if !ok || !facts.BodyChanged() || restriction != RestrictionLocalOnly {
		t.Fatalf("policy facts = %#v/%q/%t", facts, restriction, ok)
	}
	if _, err := NewPolicyAuthorizationQuery(capability, ticket, ModificationFacts{}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("zero caller facts bypass error = %v", err)
	}
	metadata, err := NewSigningMetadata(nil, false, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	withoutFeedback, err := DeriveEffectiveMetadata(metadata, capability, ticket, Authorization{}, nil)
	if err != nil {
		t.Fatalf("DeriveEffectiveMetadata(no feedback) error = %v", err)
	}
	if got := withoutFeedback.Flags(); fmt.Sprint(got) != fmt.Sprint([]string{
		signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagExploded,
	}) {
		t.Fatalf("inherited/multi-recipient flags = %v", got)
	}

	feedbackQuery, err := NewFeedbackAuthorizationQuery(capability, ticket)
	if err != nil {
		t.Fatalf("NewFeedbackAuthorizationQuery() error = %v", err)
	}
	session, err := NewAuthorizationSession(1)
	if err != nil {
		t.Fatalf("NewAuthorizationSession() error = %v", err)
	}
	feedback, _, err := session.Evaluate(context.Background(), authorizerFunc(func(_ context.Context, q AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(q, AuthorizationAuthorized), nil
	}), feedbackQuery)
	if err != nil {
		t.Fatalf("feedback Evaluate() error = %v", err)
	}
	effective, err := DeriveEffectiveMetadata(metadata, capability, ticket, feedback, session)
	if err != nil || fmt.Sprint(effective.Flags()) != fmt.Sprint([]string{
		signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedHere, signature.FlagExploded,
	}) {
		t.Fatalf("effective feedback flags=%v error=%v", effective.Flags(), err)
	}
	other := testBoundRouteTicket(t, capability, routeplan.PurposeRevision, nil)
	if _, err := DeriveEffectiveMetadata(metadata, capability, other, feedback, session); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("cross-ticket feedback error = %v", err)
	}
	if _, err := NewPolicyAuthorizationQuery(capability, other, factsEvidence); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("cross-ticket policy facts error = %v", err)
	}
	otherCapability := testRevisionCapabilityWithFlags(t, []string{
		signature.FlagDoNotModify, signature.FlagDoNotExplode, signature.FlagFeedback,
	}, true)
	if otherCapability.seal == capability.seal {
		t.Fatal("cross-capability fixture did not produce distinct sealed evidence")
	}
	if _, err := NewPolicyAuthorizationQuery(otherCapability, ticket, factsEvidence); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("cross-capability policy error = %v", err)
	}
	if _, err := NewFeedbackAuthorizationQuery(otherCapability, ticket); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("cross-capability feedback error = %v", err)
	}
}

// testModificationFacts constructs exact bound comparison evidence only inside tests.
func testModificationFacts(capability VerifiedRevisionInput, ticket routeplan.CopyTicket, bodyChanged, headersChanged bool) ModificationFacts {
	return ModificationFacts{
		bodyChanged: bodyChanged, existingHeadersChanged: headersChanged, initialized: true,
		capabilitySeal: capability.seal, parentID: ticket.ParentIdentity(),
		ticketID: ticket.TicketIdentity(), ticketBinding: ticket.BindingIdentity(),
	}
}

// TestReceiveAndSendNextDomainQueriesHaveDistinctExactEvidence proves OOB purpose separation.
func TestReceiveAndSendNextDomainQueriesHaveDistinctExactEvidence(t *testing.T) {
	terminal := testRevisionCapabilityWithFlags(t, nil, true)
	ticket := testBoundRouteTicket(t, terminal, routeplan.PurposeNextDomain, nil)
	credential, public := testEd25519Credential(t, "oob-publication")
	providerFunc := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		return verify.PublicKey{Algorithm: query.Algorithm, Material: public, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
	})
	var seal [sha256.Size]byte
	seal[0] = 9
	publication, err := newPublicationAuthority(providerFunc, func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}, time.Minute, seal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("NewPublicationAuthority() error = %v", err)
	}
	published, err := publication.IssueNextDomain(context.Background(), signerTestFutureDomain, credential)
	if err != nil {
		t.Fatalf("IssueNextDomain() error = %v", err)
	}
	receive, err := NewReceiveNextDomainAuthorizationQuery(terminal, ticket, "next.example.test")
	if err != nil {
		t.Fatalf("NewReceiveNextDomainAuthorizationQuery() error = %v", err)
	}
	receiveFacts, ok := receive.OutOfBandFacts()
	if !ok || receiveFacts.ProposedNextDomain() != "" ||
		receiveFacts.PredecessorKind() != PredecessorNextDomain ||
		string(receiveFacts.ReversePath()) != "<inbound@example.test>" ||
		len(receiveFacts.ForwardPaths()) != 1 ||
		string(receiveFacts.ForwardPaths()[0]) != "<accepted@next.example.test>" ||
		string(receiveFacts.ReceiverBinding()) != "bound-inbound-receiver" {
		t.Fatalf("receive facts = %#v/%t", receiveFacts, ok)
	}
	mismatchedReceive := receive
	mismatchedReceive.oobFacts.proposedNextDomain = signerTestFutureDomain
	if mismatchedReceive.Valid() {
		t.Fatal("receive purpose accepted send-shaped OOB facts")
	}
	send, err := NewSendNextDomainAuthorizationQuery(terminal, ticket, published, "next.example.test", signerTestFutureDomain)
	if err != nil {
		t.Fatalf("NewSendNextDomainAuthorizationQuery() error = %v", err)
	}
	sendFacts, ok := send.OutOfBandFacts()
	if !ok || sendFacts.ProposedNextDomain() != signerTestFutureDomain ||
		string(sendFacts.ReversePath()) != "<sender@example.test>" ||
		len(sendFacts.ForwardPaths()) != 1 ||
		string(sendFacts.ForwardPaths()[0]) != "<next@example.test>" ||
		string(sendFacts.ReceiverBinding()) != "bound-outbound-receiver" ||
		send.Binding() == receive.Binding() {
		t.Fatalf("send facts = %#v/%t distinct=%t", sendFacts, ok, send.Binding() != receive.Binding())
	}
	mismatchedSend := send
	mismatchedSend.oobFacts.proposedNextDomain = ""
	if mismatchedSend.Valid() {
		t.Fatal("send purpose accepted receive-shaped OOB facts")
	}
	ordinary := testRevisionCapabilityWithFlags(t, nil, false)
	ordinaryTicket := testBoundRouteTicket(t, ordinary, routeplan.PurposeRevision, nil)
	if _, err := NewReceiveNextDomainAuthorizationQuery(ordinary, ordinaryTicket, "example.test"); err == nil {
		t.Fatal("ordinary predecessor accepted receive authorization")
	}
	sameDomainPublished, err := publication.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil {
		t.Fatalf("same-domain publication error = %v", err)
	}
	if sameDomain, err := NewSendNextDomainAuthorizationQuery(terminal, ticket, sameDomainPublished, "next.example.test", "next.example.test"); err != nil || !sameDomain.Valid() {
		t.Fatalf("same profile/proposed nd rejected: valid=%t error=%v", sameDomain.Valid(), err)
	}
}

// TestAuthorizationFormattingNeverLeaksProtectedInputs proves all formatting paths are redacted.
func TestAuthorizationFormattingNeverLeaksProtectedInputs(t *testing.T) {
	ticket := testRouteTicket(t, 1, [][]byte{[]byte("<SECRET@example.test>"), []byte("<other@example.test>")})
	query, err := NewDisclosureAuthorizationQuery(ticket)
	if err != nil {
		t.Fatalf("NewDisclosureAuthorizationQuery() error = %v", err)
	}
	result := NewAuthorizationResult(query, AuthorizationAuthorized)
	var sealKey [sha256.Size]byte
	sealKey[0] = 11
	session, err := newAuthorizationSession(1, sealKey)
	if err != nil {
		t.Fatalf("newAuthorizationSession() error = %v", err)
	}
	authorization, _, err := session.Evaluate(context.Background(), authorizerFunc(func(_ context.Context, got AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(got, AuthorizationAuthorized), nil
	}), query)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	for _, value := range []any{
		query, result, authorization, session, OutOfBandFacts{profileDomain: "SECRET.example.test"},
		ModificationFacts{initialized: true, capabilitySeal: [sha256.Size]byte{1}, parentID: [sha256.Size]byte{2},
			ticketID: [sha256.Size]byte{3}, ticketBinding: [sha256.Size]byte{4}},
	} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(formatted, "SECRET") || strings.Contains(formatted, "example.test") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
}

// testRouteTicket issues one ticket from a parent with the requested multiplicity.
func testRouteTicket(t *testing.T, multiplicity int, firstRecipients [][]byte) routeplan.CopyTicket {
	t.Helper()
	if multiplicity <= 0 {
		multiplicity = 1
	}
	source, err := routeplan.NewImmutableSource([]byte("Subject: route\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entries := make([]routeplan.Entry, multiplicity)
	for index := range entries {
		recipients := [][]byte{[]byte(fmt.Sprintf("<user%d@example.test>", index))}
		class := routeplan.DisclosureSingle
		if index == 0 && len(firstRecipients) > 0 {
			recipients = firstRecipients
			if len(recipients) > 1 {
				class = routeplan.DisclosureAuthorizedGroup
			}
		}
		entries[index], err = routeplan.NewEntry(source, routeplan.PurposeOrigin,
			[]byte("<sender@example.test>"), recipients, class, []byte(fmt.Sprintf("route-%d", index)), nil)
		if err != nil {
			t.Fatalf("routeplan.NewEntry() error = %v", err)
		}
	}
	coordinator, err := routeplan.NewCoordinator(routeplan.NewMemoryAuthority(), routeplan.Limits{})
	if err != nil {
		t.Fatalf("routeplan.NewCoordinator() error = %v", err)
	}
	request, err := routeplan.NewPlanRequest(entries)
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := coordinator.Finalize(context.Background(), request)
	if err != nil {
		t.Fatalf("routeplan.Finalize() error = %v", err)
	}
	return tickets[0]
}

// testBoundRouteTicket issues one revision/next-domain ticket bound to a sealed capability.
func testBoundRouteTicket(t *testing.T, capability VerifiedRevisionInput, purpose routeplan.Purpose, recipients [][]byte) routeplan.CopyTicket {
	t.Helper()
	if len(recipients) == 0 {
		recipients = [][]byte{[]byte("<next@example.test>")}
	}
	source, err := routeplan.NewImmutableSource([]byte("Subject: bound\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	class := routeplan.DisclosureSingle
	if len(recipients) > 1 {
		class = routeplan.DisclosureAuthorizedGroup
	}
	entry, err := NewBoundRouteEntry(capability, source, purpose, []byte("<sender@example.test>"), recipients,
		class, []byte("bound-route"))
	if purpose == routeplan.PurposeNextDomain {
		inboundReceiver := []byte(nil)
		if capability.proof.State() == verify.RevisionProofTerminalNextDomainAuthorizationRequired {
			inboundReceiver = []byte("bound-inbound-receiver")
		}
		entry, err = routeplan.NewDualReceiverClassifiedEntry(
			source, purpose, []byte("<sender@example.test>"), recipients, class,
			routeplan.RouteOutOfBand, []byte("bound-route"), inboundReceiver,
			[]byte("bound-outbound-receiver"),
			capability.seal[:],
		)
	}
	if err != nil {
		t.Fatalf("routeplan.NewEntry(bound) error = %v", err)
	}
	coordinator, err := routeplan.NewCoordinator(routeplan.NewMemoryAuthority(), routeplan.Limits{})
	if err != nil {
		t.Fatalf("routeplan.NewCoordinator() error = %v", err)
	}
	request, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest(bound) error = %v", err)
	}
	_, tickets, err := coordinator.Finalize(context.Background(), request)
	if err != nil {
		t.Fatalf("routeplan.Finalize(bound) error = %v", err)
	}
	return tickets[0]
}

// testRevisionCapabilityWithFlags issues one exact valid revision capability.
func testRevisionCapabilityWithFlags(t *testing.T, flags []string, terminal bool) VerifiedRevisionInput {
	t.Helper()
	fixture := newRevisionTestFixtureWithFlags(t, nil, terminal, flags)
	if terminal {
		fixture.envelope = verify.NewEnvelope(
			[]byte("<inbound@example.test>"),
			[][]byte{[]byte("<accepted@next.example.test>")},
		)
	}
	verifier := newRevisionTestVerifier(t, fixture, nil)
	outcome, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || !capability.Valid() ||
		outcome.Status() != map[bool]RevisionVerificationStatus{false: RevisionVerificationVerified, true: RevisionVerificationTerminalNextDomainAuthorizationRequired}[terminal] {
		t.Fatalf("VerifyForRevision(flags) outcome=%q valid=%t error=%v", outcome.Status(), capability.Valid(), err)
	}
	return capability
}

// testEd25519Credential constructs one deterministic credential.
func testEd25519Credential(t *testing.T, marker string) (Credential, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte(marker))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	handle, err := NewPrivateKeyHandle([]byte("handle-" + marker))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewCredential("selector", AlgorithmEd25519SHA256, public, handle, Limits{})
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	return credential, public
}
