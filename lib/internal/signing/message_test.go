package signing

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
)

// TestCompleteMessageProvesAndReturnsOneImmutableUnrestrictedMessage covers the ordinary success boundary.
func TestCompleteMessageProvesAndReturnsOneImmutableUnrestrictedMessage(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})

	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	result, recovery, err := coordinator.CompleteMessage(context.Background(), field)
	if err != nil || !result.Valid() || recovery.Valid() {
		t.Fatalf("CompleteMessage() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	if result.Role() != RoleOriginator || result.NewInstanceNumber() != 1 ||
		result.Sequence() != 1 || result.Restriction() != RestrictionUnrestricted ||
		result.BodyUnavailable() {
		t.Fatalf("unexpected bounded result facts: role=%q m=%d i=%d restriction=%q unavailable=%t",
			result.Role(), result.NewInstanceNumber(), result.Sequence(), result.Restriction(), result.BodyUnavailable())
	}
	if got := result.Algorithms(); len(got) != 1 || got[0] != AlgorithmEd25519SHA256 {
		t.Fatalf("algorithms = %v", got)
	}

	raw, ok := result.UnrestrictedBytes()
	if !ok || len(raw) == 0 {
		t.Fatal("unrestricted result did not expose a complete byte copy")
	}
	parsed, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse(result) error = %v", err)
	}
	if got := parsed.Headers().FieldsByName(instance.HeaderName); len(got) != 1 {
		t.Fatalf("Message-Instance fields = %d, want 1", len(got))
	}
	if got := parsed.Headers().FieldsByName(signature.HeaderName); len(got) != 1 {
		t.Fatalf("DKIM2-Signature fields = %d, want 1", len(got))
	}
	if !bytes.Equal(parsed.Body().Bytes(), harness.request.Message.Body().Bytes()) {
		t.Fatal("finalization changed inherited body bytes")
	}
	raw[0] ^= 0xff
	again, ok := result.UnrestrictedBytes()
	if !ok || bytes.Equal(raw, again) {
		t.Fatal("unrestricted byte accessor retained caller mutation")
	}

	duplicate, duplicateRecovery, duplicateErr := coordinator.CompleteField(context.Background(), harness.request)
	if duplicate.Valid() || duplicateRecovery.Valid() || duplicateErr == nil {
		t.Fatalf("same ticket reused: field=%t recovery=%t error=%v", duplicate.Valid(), duplicateRecovery.Valid(), duplicateErr)
	}
}

// TestCompleteMessageSerializesDuplicateFinalization proves exactly one final success transition.
func TestCompleteMessageSerializesDuplicateFinalization(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}

	type outcome struct {
		result   CompletedMessage
		recovery Recovery
		err      error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			<-start
			result, duplicateRecovery, duplicateErr := coordinator.CompleteMessage(context.Background(), field)
			outcomes <- outcome{result: result, recovery: duplicateRecovery, err: duplicateErr}
		})
	}
	close(start)
	workers.Wait()
	close(outcomes)

	var succeeded, rejected int
	for current := range outcomes {
		switch {
		case current.err == nil && current.result.Valid() && !current.recovery.Valid():
			succeeded++
		case IsErrorCode(current.err, ErrorCodeInvalidRequest) &&
			!current.result.Valid() && !current.recovery.Valid():
			rejected++
		default:
			t.Fatalf("unexpected duplicate outcome result=%t recovery=%t error=%v",
				current.result.Valid(), current.recovery.Valid(), current.err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("duplicate outcomes succeeded=%d rejected=%d", succeeded, rejected)
	}
}

// TestCompleteMessageReportsHashUnchangedAuthorizationFacts proves bounded ordinary result metadata.
func TestCompleteMessageReportsHashUnchangedAuthorizationFacts(t *testing.T) {
	for _, test := range []struct {
		name           string
		feedbackStatus AuthorizationStatus
		wantFeedHere   bool
	}{
		{name: "feedback authorized", feedbackStatus: AuthorizationAuthorized, wantFeedHere: true},
		{name: "feedback denied", feedbackStatus: AuthorizationDenied, wantFeedHere: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				status := AuthorizationAuthorized
				if query.Purpose() == AuthorizationFeedbackRelay {
					status = test.feedbackStatus
				}
				return NewAuthorizationResult(query, status), nil
			})
			coordinator := harness.newCoordinatorWithAuthorizer(
				t, authorizer, harness.defaultSigner(t), Limits{},
			)
			field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
			if err != nil || !field.Valid() || recovery.Valid() {
				t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
			}
			result, recovery, err := coordinator.CompleteMessage(context.Background(), field)
			if err != nil || !result.Valid() || recovery.Valid() {
				t.Fatalf("CompleteMessage() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
			}
			if result.Role() != RoleHashUnchangedForwarder || result.NewInstanceNumber() != 0 ||
				result.Sequence() != 2 || result.Multiplicity() != 1 ||
				result.Restriction() != RestrictionUnrestricted {
				t.Fatalf("unexpected result facts role=%q m=%d i=%d copies=%d restriction=%q",
					result.Role(), result.NewInstanceNumber(), result.Sequence(),
					result.Multiplicity(), result.Restriction())
			}
			facts := result.Authorizations()
			if len(facts) != 3 ||
				facts[0].Purpose() != AuthorizationPolicy || facts[0].Status() != AuthorizationAuthorized ||
				facts[1].Purpose() != AuthorizationFeedbackRelay || facts[1].Status() != test.feedbackStatus ||
				facts[2].Purpose() != AuthorizationDisclosure || facts[2].Status() != AuthorizationAuthorized {
				t.Fatalf("authorization facts = %#v", facts)
			}
			hasFeedHere := false
			for _, flag := range result.Flags() {
				hasFeedHere = hasFeedHere || flag == signature.FlagFeedHere
			}
			if hasFeedHere != test.wantFeedHere {
				t.Fatalf("feedhere=%t want=%t flags=%v", hasFeedHere, test.wantFeedHere, result.Flags())
			}
		})
	}
}

// TestCompleteMessageRetainsLocalOnlyOutputWithoutAByteEscape proves the restricted ordinary variant.
func TestCompleteMessageRetainsLocalOnlyOutputWithoutAByteEscape(t *testing.T) {
	fixture := newRevisionTestFixtureWithFlags(t, nil, false, []string{signature.FlagDoNotModify})
	harness := newExistingSignerHarnessForFixture(
		t, fixture, [][]byte{[]byte("<next@example.test>")}, AlgorithmEd25519SHA256,
	)
	changed := bytes.Replace(fixture.message.RawBytes(),
		[]byte("Subject: current\r\n"), []byte("Subject: locally changed\r\n"), 1)
	if bytes.Equal(changed, fixture.message.RawBytes()) {
		t.Fatal("changed-header fixture did not change")
	}
	message, err := rawmsg.Parse(changed)
	if err != nil {
		t.Fatalf("rawmsg.Parse(changed) error = %v", err)
	}
	source, err := routeplan.NewImmutableSource(message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entry, err := NewClassifiedBoundRouteEntry(
		harness.request.Capability, source, routeplan.PurposeRevision, []byte("<rcpt@example.test>"),
		[][]byte{[]byte("<next@example.test>")}, routeplan.DisclosureSingle,
		routeplan.RouteInControl, []byte("local-only-route"), nil,
	)
	if err != nil {
		t.Fatalf("NewBoundRouteEntry() error = %v", err)
	}
	routeRequest, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := harness.routes.Finalize(context.Background(), routeRequest)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	planner, err := NewHashPlanCoordinator(harness.revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	plan, err := planner.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: harness.request.Capability, Message: message, Ticket: tickets[0],
		LiteralPolicy: recipe.AllowLiterals,
	})
	if err != nil || plan.Role() != RoleReviser {
		t.Fatalf("PlanExisting() role=%q error=%v", plan.Role(), err)
	}
	harness.request.Message = message
	harness.request.Ticket = tickets[0]
	harness.request.ReversePath = tickets[0].ReversePath()
	harness.request.ForwardPaths = tickets[0].DisclosureRecipients()
	harness.request.Plan = plan
	harness.events.reset()
	authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(query, AuthorizationAuthorized), nil
	})
	coordinator := harness.newCoordinatorWithAuthorizer(
		t, authorizer, harness.defaultSigner(t), Limits{},
	)
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	result, recovery, err := coordinator.CompleteMessage(context.Background(), field)
	if err != nil || !result.Valid() || recovery.Valid() {
		t.Fatalf("CompleteMessage() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	if result.Role() != RoleReviser || result.NewInstanceNumber() != 2 ||
		result.Sequence() != 2 || result.Restriction() != RestrictionLocalOnly {
		t.Fatalf("restricted facts role=%q m=%d i=%d restriction=%q",
			result.Role(), result.NewInstanceNumber(), result.Sequence(), result.Restriction())
	}
	if raw, ok := result.UnrestrictedBytes(); ok || raw != nil {
		t.Fatalf("local-only result exposed bytes: ok=%t bytes=%d", ok, len(raw))
	}
	facts := result.Authorizations()
	if len(facts) != 1 || facts[0].Purpose() != AuthorizationPolicy ||
		facts[0].Status() != AuthorizationAuthorized ||
		facts[0].Restriction() != RestrictionLocalOnly {
		t.Fatalf("local-only authorization facts = %#v", facts)
	}
	unknownReason := result
	unknownReason.unavailable = recipe.BodyUnavailableReason("future")
	if unknownReason.Valid() {
		t.Fatal("result accepted an unknown stray unavailable-body reason")
	}
	strayReason := result
	strayReason.unavailable = recipe.BodyUnavailableReasonLiteralRequired
	if strayReason.Valid() {
		t.Fatal("result accepted a known reason without b:null")
	}
	missingReason := result
	missingReason.bodyUnavailable = true
	if missingReason.Valid() {
		t.Fatal("result accepted b:null without a known unavailable-body reason")
	}
}

// TestCompleteMessagePreservesHeaderOnlyFraming proves finalization never invents a body separator.
func TestCompleteMessagePreservesHeaderOnlyFraming(t *testing.T) {
	harness := rebindOriginMessage(
		t, newSignerHarness(t, AlgorithmEd25519SHA256),
		[]byte("Subject: header only\r\n"), "header-only-route",
	)
	message := harness.request.Message
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	result, recovery, err := coordinator.CompleteMessage(context.Background(), field)
	if err != nil || !result.Valid() || recovery.Valid() {
		t.Fatalf("CompleteMessage() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	raw, ok := result.UnrestrictedBytes()
	if !ok || bytes.Contains(raw, []byte("\r\n\r\n")) ||
		!bytes.HasPrefix(raw, message.RawBytes()) {
		t.Fatalf("header-only framing exposed=%t separator=%t prefix=%t",
			ok, bytes.Contains(raw, []byte("\r\n\r\n")), bytes.HasPrefix(raw, message.RawBytes()))
	}
	reparsed, err := rawmsg.Parse(raw)
	if err != nil || reparsed.Metadata().BodyBytes != 0 {
		t.Fatalf("reparse body_bytes=%d error=%v", reparsed.Metadata().BodyBytes, err)
	}
}

// TestCompleteMessageHashesGeneralHeadersOutsideProtocolLimits proves independent canonical bounds.
func TestCompleteMessageHashesGeneralHeadersOutsideProtocolLimits(t *testing.T) {
	manyHeaders := bytes.Repeat([]byte("X-Ordinary: value\r\n"), 300)
	manyHeaders = append(manyHeaders, []byte("\r\nbody\r\n")...)
	harness := rebindOriginMessage(
		t, newSignerHarness(t, AlgorithmEd25519SHA256), manyHeaders, "many-headers-route",
	)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	result, recovery, err := coordinator.CompleteMessage(context.Background(), field)
	if err != nil || !result.Valid() || recovery.Valid() {
		t.Fatalf("CompleteMessage() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	raw, ok := result.UnrestrictedBytes()
	reparsed, parseErr := rawmsg.Parse(raw)
	if !ok || parseErr != nil || reparsed.Metadata().HeaderFields != 302 {
		t.Fatalf("completed general headers exposed=%t fields=%d error=%v",
			ok, reparsed.Metadata().HeaderFields, parseErr)
	}

	var large bytes.Buffer
	large.WriteString("X-Large: ")
	for index := range 16 {
		if index > 0 {
			large.WriteString("\r\n\t")
		}
		large.Write(bytes.Repeat([]byte{'a'}, 500))
	}
	large.WriteString("\r\n\r\nbody\r\n")
	narrowHarness := rebindOriginMessage(
		t, newSignerHarness(t, AlgorithmEd25519SHA256), large.Bytes(), "large-header-route",
	)
	narrow := narrowHarness.newCoordinator(
		t, narrowHarness.defaultSigner(t), Limits{MaxFieldBytes: 4096, MaxDecodedRecipeBytes: 1024},
	)
	field, recovery, err = narrow.CompleteField(context.Background(), narrowHarness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("narrow CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	if result, recovery, err = narrow.CompleteMessage(context.Background(), field); err != nil ||
		!result.Valid() || recovery.Valid() {
		t.Fatalf("narrow CompleteMessage() result=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
}

// rebindOriginMessage creates a new origin ticket and plan for exact replacement source bytes.
func rebindOriginMessage(t *testing.T, harness signerHarness, raw []byte, route string) signerHarness {
	t.Helper()
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse(origin source) error = %v", err)
	}
	source, err := routeplan.NewImmutableSource(message.RawBytes())
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error = %v", err)
	}
	entry, err := routeplan.NewEntry(
		source, routeplan.PurposeOrigin, []byte("<sender@signer.example.test>"),
		[][]byte{[]byte("<recipient@example.test>")}, routeplan.DisclosureSingle,
		[]byte(route), nil,
	)
	if err != nil {
		t.Fatalf("routeplan.NewEntry() error = %v", err)
	}
	routeRequest, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("routeplan.NewPlanRequest() error = %v", err)
	}
	_, tickets, err := harness.routes.Finalize(context.Background(), routeRequest)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("routeplan.Finalize() tickets=%d error=%v", len(tickets), err)
	}
	planner, err := NewHashPlanCoordinator(harness.revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	plan, err := planner.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: message, Ticket: tickets[0],
	})
	if err != nil {
		t.Fatalf("PlanOriginator() error = %v", err)
	}
	harness.request.Message = message
	harness.request.Ticket = tickets[0]
	harness.request.ReversePath = tickets[0].ReversePath()
	harness.request.ForwardPaths = tickets[0].DisclosureRecipients()
	harness.request.Plan = plan
	harness.events.reset()
	return harness
}

// TestCompleteMessageFailureReturnsOnlyOneReplacementRecovery proves atomic post-burn failure handling.
func TestCompleteMessageFailureReturnsOnlyOneReplacementRecovery(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}

	field.input, err = canonical.NewCanonicalBytes(canonical.KindSignatureInput, []byte("wrong-final-input"), canonical.Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}
	result, recovery, err := coordinator.CompleteMessage(context.Background(), field)
	if result.Valid() || err == nil || !IsErrorCode(err, ErrorCodeInternalInvariant) || !recovery.Valid() {
		t.Fatalf("CompleteMessage() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	replacement, recoverErr := recovery.Recover(context.Background())
	if recoverErr != nil || !replacement.Valid() || recovery.Valid() {
		t.Fatalf("Recover() replacement=%t recovery=%t error=%v", replacement.Valid(), recovery.Valid(), recoverErr)
	}
	if replacement.TicketIdentity() == harness.request.Ticket.TicketIdentity() ||
		replacement.ParentIdentity() != harness.request.Ticket.ParentIdentity() ||
		replacement.BindingIdentity() != harness.request.Ticket.BindingIdentity() {
		t.Fatal("replacement did not preserve exact lineage with a fresh ticket identity")
	}
	if second, secondErr := recovery.Recover(context.Background()); second.Valid() || secondErr == nil {
		t.Fatalf("consumed recovery returned ticket=%t error=%v", second.Valid(), secondErr)
	}
}

// TestCompleteMessageCancellationAfterFieldCompletionReturnsReplacement proves post-burn cancellation atomicity.
func TestCompleteMessageCancellationAfterFieldCompletionReturnsReplacement(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !field.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, recovery, err := coordinator.CompleteMessage(ctx, field)
	if result.Valid() || !errors.Is(err, context.Canceled) ||
		!recovery.Valid() || !recovery.ReplacementReady() {
		t.Fatalf("CompleteMessage() result=%t recovery=%t/%t error=%v",
			result.Valid(), recovery.Valid(), recovery.ReplacementReady(), err)
	}
}

// TestCompleteFieldRejectsTransportBeforeEveryCallback proves transport metadata is pure preflight.
func TestCompleteFieldRejectsTransportBeforeEveryCallback(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})
	harness.request.Transport = rawmsg.TransportForm("post_dot_stuffing")
	harness.events.reset()
	field, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if field.Valid() || recovery.Valid() || !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", field.Valid(), recovery.Valid(), err)
	}
	if events := harness.events.snapshot(); len(events) != 0 {
		t.Fatalf("invalid transport crossed callbacks: %v", events)
	}
}
