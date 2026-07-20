package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	eventPublishFutureEd       = "publish-future:ed25519-sha256"
	eventAuthorizeReceiveNext  = "authorize:receive_terminal_next_domain"
	eventAuthorizeSendNext     = "authorize:send_terminal_next_domain"
	nextDomainContinuationTime = int64(1_700_003_600)
)

// newContinuationSignerHarness constructs one feedback-bearing terminal
// predecessor and a dual-algorithm nd-to-nd signing request.
func newContinuationSignerHarness(t *testing.T) signerHarness {
	t.Helper()
	fixture := newRevisionTestFixtureWithFlags(t, nil, true, []string{signerTestFeedbackFlag})
	events := &signingEventLog{}
	revisionProvider := &recordingRevisionProvider{
		delegate: mustRevisionStaticProvider(t, fixture), events: events,
	}
	proofVerifier, err := verify.NewVerifier(revisionProvider, revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	revision, err := newRevisionVerifier(
		proofVerifier, Limits{}, bytes.NewReader(bytes.Repeat([]byte{0x4d}, sha256.Size)),
	)
	if err != nil {
		t.Fatalf("newRevisionVerifier() error = %v", err)
	}
	inbound := verify.NewEnvelope(
		[]byte("<inbound@next.example.test>"),
		[][]byte{[]byte("<accepted@next.example.test>")},
	)
	outcome, capability, err := revision.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: inbound,
	})
	if err != nil ||
		outcome.Status() != RevisionVerificationTerminalNextDomainAuthorizationRequired ||
		!capability.Valid() {
		t.Fatalf("VerifyForRevision() status=%q capability=%t error=%v",
			outcome.Status(), capability.Valid(), err)
	}

	authority := &recordingRouteAuthority{
		delegate: routeplan.NewMemoryAuthority(), events: events,
	}
	routes, err := routeplan.NewCoordinator(authority, routeplan.Limits{})
	if err != nil {
		t.Fatalf("routeplan.NewCoordinator() error = %v", err)
	}
	source, err := routeplan.NewImmutableSource(fixture.message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entry, err := NewDualReceiverClassifiedBoundRouteEntry(
		capability, source, routeplan.PurposeNextDomain,
		[]byte("<outbound@next.example.test>"),
		[][]byte{[]byte("<next@future.example.test>")},
		routeplan.DisclosureSingle, routeplan.RouteOutOfBand,
		[]byte("continuation-route"), []byte("inbound-acceptance"),
		[]byte("outbound-acceptance"),
	)
	if err != nil {
		t.Fatalf("NewDualReceiverClassifiedBoundRouteEntry() error = %v", err)
	}
	routeRequest, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := routes.Finalize(context.Background(), routeRequest)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	planner, err := NewHashPlanCoordinator(revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	plan, err := planner.PlanNextDomain(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: tickets[0],
	})
	if err != nil || !plan.Valid() {
		t.Fatalf("PlanNextDomain() valid=%t error=%v", plan.Valid(), err)
	}

	profile, privateKeys, profileMaterial := newTestSigningProfile(
		t, "next.example.test",
		[]Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256},
	)
	futureCredential, futurePublic := testEd25519Credential(t, "future-publication")
	publicationProvider := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		if query.Domain == signerTestFutureDomain &&
			query.Selector == futureCredential.Selector() &&
			query.Algorithm == verify.AlgorithmEd25519SHA256 {
			events.add(eventPublishFutureEd)
			return verify.PublicKey{
				Algorithm: query.Algorithm, Material: futurePublic,
				Metadata: verify.KeyMetadata{
					Status: verify.KeyStatusFound, Source: signerTestKeySource,
				},
			}, nil
		}
		material, ok := profileMaterial[string(query.Algorithm)+"\x00"+query.Selector]
		if !ok || query.Domain != profile.Domain() {
			return verify.PublicKey{}, errors.New("unexpected continuation publication query")
		}
		events.add("publish:" + string(query.Algorithm))
		return verify.PublicKey{
			Algorithm: query.Algorithm, Material: material,
			Metadata: verify.KeyMetadata{
				Status: verify.KeyStatusFound, Source: signerTestKeySource,
			},
		}, nil
	})
	var publicationSeal [sha256.Size]byte
	publicationSeal[0] = 0x5e
	publication, err := newPublicationAuthority(
		publicationProvider,
		func() time.Time { return time.Unix(nextDomainContinuationTime, 0) },
		time.Minute, publicationSeal, maxConsumedPublicationCapabilities,
	)
	if err != nil {
		t.Fatalf("newPublicationAuthority() error = %v", err)
	}
	published, err := publication.IssueNextDomain(
		context.Background(), signerTestFutureDomain, futureCredential,
	)
	if err != nil || !published.Valid() {
		t.Fatalf("IssueNextDomain() valid=%t error=%v", published.Valid(), err)
	}
	metadata, err := NewSigningMetadata(nil, false, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	events.reset()
	return signerHarness{
		revision: revision, routes: routes, publication: publication,
		privateKeys: privateKeys, events: events, inherited: revisionProvider,
		authority: authority,
		request: SignFieldRequest{
			Plan: plan, Capability: capability, Message: fixture.message,
			Ticket: tickets[0], ReversePath: tickets[0].ReversePath(),
			ForwardPaths: tickets[0].DisclosureRecipients(),
			Profile:      profile, Metadata: metadata,
			Transport:    rawmsg.TransportFormFinalNetworkPreDotStuffing,
			EnvelopeForm: SignatureEnvelopeNextDomain,
			NextDomain:   signerTestFutureDomain, Published: published,
		},
	}
}

// TestContinuationSigningFreezesEveryExternalCallback proves exact route,
// inherited proof, both publication, authorization, and signer order.
func TestContinuationSigningFreezesEveryExternalCallback(t *testing.T) {
	harness := newContinuationSignerHarness(t)
	authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		harness.events.add("authorize:" + string(query.Purpose()))
		return NewAuthorizationResult(query, AuthorizationAuthorized), nil
	})
	coordinator := harness.newCoordinatorWithAuthorizer(
		t, authorizer, harness.defaultSigner(t), Limits{},
	)
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !completed.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() completed=%t recovery=%t error=%v",
			completed.Valid(), recovery.Valid(), err)
	}
	want := []string{
		eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
		eventPublishRSA, eventPublishEd25519, eventPublishFutureEd,
		eventAuthorizeReceiveNext, eventAuthorizeSendNext,
		eventAuthorizePolicy, eventAuthorizeFeedbackRelay,
		eventSignRSA, eventSignEd25519,
	}
	if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("continuation callback order = %v, want %v", got, want)
	}
}

// TestContinuationAuthorizationDenialStopsEveryLaterStage proves required OOB
// and policy denials cannot reach later authorizers or private signing.
func TestContinuationAuthorizationDenialStopsEveryLaterStage(t *testing.T) {
	for _, testCase := range []struct {
		name string
		deny AuthorizationPurpose
		want []string
	}{
		{
			name: "receive", deny: AuthorizationReceiveNextDomain,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
				eventPublishRSA, eventPublishEd25519, eventPublishFutureEd,
				eventAuthorizeReceiveNext, eventRouteReplace,
			},
		},
		{
			name: "send", deny: AuthorizationSendNextDomain,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
				eventPublishRSA, eventPublishEd25519, eventPublishFutureEd,
				eventAuthorizeReceiveNext, eventAuthorizeSendNext, eventRouteReplace,
			},
		},
		{
			name: signerTestPolicyLabel, deny: AuthorizationPolicy,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
				eventPublishRSA, eventPublishEd25519, eventPublishFutureEd,
				eventAuthorizeReceiveNext, eventAuthorizeSendNext,
				eventAuthorizePolicy, eventRouteReplace,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newContinuationSignerHarness(t)
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				harness.events.add("authorize:" + string(query.Purpose()))
				status := AuthorizationAuthorized
				if query.Purpose() == testCase.deny {
					status = AuthorizationDenied
				}
				return NewAuthorizationResult(query, status), nil
			})
			coordinator := harness.newCoordinatorWithAuthorizer(
				t, authorizer, harness.defaultSigner(t), Limits{},
			)
			completed, recovery, err := coordinator.CompleteField(
				context.Background(), harness.request,
			)
			if !IsErrorCode(err, ErrorCodeAuthorizationDenied) ||
				completed.Valid() || !recovery.Valid() || !recovery.ReplacementReady() {
				t.Fatalf("CompleteField() completed=%t recovery=%t/%t error=%v",
					completed.Valid(), recovery.Valid(), recovery.ReplacementReady(), err)
			}
			if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(testCase.want) {
				t.Fatalf("denial callback order = %v, want %v", got, testCase.want)
			}
		})
	}
}
