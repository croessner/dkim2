package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/verify"
)

type countingPlanKeyProvider struct {
	delegate verify.KeyProvider
	calls    atomic.Int64
}

// LookupKey records and delegates one revision-verification key lookup.
func (p *countingPlanKeyProvider) LookupKey(ctx context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
	p.calls.Add(1)
	return p.delegate.LookupKey(ctx, query)
}

// TestHashPlanOriginatorAndExistingRoles locks the exact Section 9.1 role gate.
func TestHashPlanOriginatorAndExistingRoles(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)

	origin := mustParseRevisionMessage(t, []byte("Subject: origin\r\n\r\nbody\r\n"))
	originTicket := testPlanTicket(t, origin.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	originPlan, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{Message: origin, Ticket: originTicket})
	assertOriginPlan(t, originPlan, err)

	outcome, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || outcome.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("revision capability status=%q valid=%t code=%s", outcome.Status(), capability.Valid(), testErrorCode(err))
	}
	unchangedTicket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeRevision, capability)
	unchanged, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: unchangedTicket,
	})
	if err != nil || !unchanged.Valid() || unchanged.Role() != RoleHashUnchangedForwarder ||
		unchanged.HasNewInstance() || unchanged.NewInstanceNumber() != 0 ||
		unchanged.HighestInstance() != 1 || unchanged.NextSequence() != 2 || unchanged.SignatureInstance() != 1 {
		t.Fatalf("unchanged plan valid=%t role=%q has_instance=%t new=%d highest=%d next=%d reference=%d code=%s",
			unchanged.Valid(), unchanged.Role(), unchanged.HasNewInstance(), unchanged.NewInstanceNumber(),
			unchanged.HighestInstance(), unchanged.NextSequence(), unchanged.SignatureInstance(), testErrorCode(err))
	}

	revised := mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "Subject: current", "Subject: revised", 1,
	)))
	revisedTicket := testPlanTicket(t, revised.RawBytes(), routeplan.PurposeRevision, capability)
	revision, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: revised, Ticket: revisedTicket,
		LiteralPolicy: recipe.AllowLiterals,
	})
	if err != nil || !revision.Valid() || revision.Role() != RoleReviser ||
		!revision.HasNewInstance() || revision.NewInstanceNumber() != 2 ||
		revision.NextSequence() != 2 || revision.SignatureInstance() != 2 {
		t.Fatalf("revision plan valid=%t generation_valid=%t sizes_valid=%t mods=%t role=%q has_instance=%t new=%d next=%d reference=%d code=%s",
			revision.Valid(), revision.GenerationFacts().Valid(), revision.SizeFacts().Valid(),
			revision.ModificationFacts().initialized, revision.Role(), revision.HasNewInstance(), revision.NewInstanceNumber(),
			revision.NextSequence(), revision.SignatureInstance(), testErrorCode(err))
	}
	generation := revision.GenerationFacts()
	if generation.Outcome() != recipe.GenerationOutcomeRecipe || generation.DecodedBytes() == 0 ||
		generation.DecodedBytes() > DefaultLimits().MaxDecodedRecipeBytes {
		t.Fatalf("revision generation outcome=%q bytes=%d", generation.Outcome(), generation.DecodedBytes())
	}
	rendered := revision.RenderedInstance()
	if !bytes.Contains(rendered, []byte("\tr=")) {
		t.Fatal("reviser instance omitted inverse recipe")
	}
	assertPlanRecipeReconstructs(t, revision, revised, capability)
}

// assertOriginPlan verifies the fixed first-instance and first-signature progression.
func assertOriginPlan(t *testing.T, originPlan UnsignedOperationPlan, err error) {
	t.Helper()
	if err != nil || !originPlan.Valid() || originPlan.Role() != RoleOriginator ||
		originPlan.HighestInstance() != 0 || originPlan.NewInstanceNumber() != 1 ||
		originPlan.NextSequence() != 1 || originPlan.SignatureInstance() != 1 || !originPlan.HasNewInstance() {
		t.Fatalf("origin plan valid=%t role=%q highest=%d new=%d next=%d reference=%d code=%s",
			originPlan.Valid(), originPlan.Role(), originPlan.HighestInstance(), originPlan.NewInstanceNumber(),
			originPlan.NextSequence(), originPlan.SignatureInstance(), testErrorCode(err))
	}
	if generation := originPlan.GenerationFacts(); generation.Outcome() != recipe.GenerationOutcomeUnchanged {
		t.Fatalf("origin generation outcome=%q", generation.Outcome())
	}
}

// assertPlanRecipeReconstructs proves the emitted recipe direction against sealed prior hashes.
func assertPlanRecipeReconstructs(t *testing.T, revision UnsignedOperationPlan, revised rawmsg.Message, capability VerifiedRevisionInput) {
	t.Helper()
	model, ok := revision.MessageInstance()
	encodedRecipe, recipeOK := model.Recipe()
	parser, parserErr := recipe.NewParser(recipe.DefaultLimits())
	parsedRecipe, _, parseErr := parser.Parse(encodedRecipe.Decoded())
	applier, applierErr := recipe.NewApplier(recipe.DefaultLimits())
	currentState, stateErr := recipe.NewState(revised)
	reconstructed, _, applyErr := applier.Apply(currentState, parsedRecipe)
	if !ok || !recipeOK || parserErr != nil || parseErr != nil || applierErr != nil || stateErr != nil || applyErr != nil {
		t.Fatal("rendered recipe did not independently parse and apply")
	}
	canonicalizer, canonicalErr := canonical.NewCanonicalizer()
	headerResult, headerErr := canonicalizer.HeaderHash(reconstructed.Headers())
	body, bodyOK := reconstructed.Body()
	bodyResult, bodyErr := canonicalizer.BodyHash(body)
	headerDigest, headerOK := headerResult.Digest()
	bodyDigest, digestBodyOK := bodyResult.Digest()
	previousHashes := capability.proof.Facts().Hashes()
	previousHeader := previousHashes.HeaderDigest()
	previousBody := previousHashes.BodyDigest()
	if canonicalErr != nil || headerErr != nil || bodyErr != nil || !bodyOK || !headerOK || !digestBodyOK ||
		!bytes.Equal(headerDigest.Bytes(), previousHeader[:]) ||
		!bytes.Equal(bodyDigest.Bytes(), previousBody[:]) {
		t.Fatal("rendered recipe did not reconstruct the sealed exact hash tuple")
	}
}

// TestHashPlanGateDimensionsAndDonotmodifyFacts proves body/header decisions remain independent.
func TestHashPlanGateDimensionsAndDonotmodifyFacts(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	fixture.message = mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "Subject: current\r\n",
		"X-Trace: original\r\nSubject: current\r\n", 1,
	)))
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || !capability.Valid() {
		t.Fatalf("revision capability valid=%t code=%s", capability.Valid(), testErrorCode(err))
	}

	excludedRaw := strings.Replace(string(fixture.message.RawBytes()), "Subject: current\r\n",
		"Subject: current\r\nX-Trace: added\r\n", 1)
	excluded := mustParseRevisionMessage(t, []byte(excludedRaw))
	excludedTicket := testPlanTicket(t, excluded.RawBytes(), routeplan.PurposeRevision, capability)
	excludedPlan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: excluded, Ticket: excludedTicket,
	})
	if err != nil || excludedPlan.Role() != RoleHashUnchangedForwarder || excludedPlan.ModificationFacts().ExistingHeadersChanged() {
		t.Fatalf("excluded addition role=%q headers_changed=%t code=%s",
			excludedPlan.Role(), excludedPlan.ModificationFacts().ExistingHeadersChanged(), testErrorCode(err))
	}

	rewrittenRaw := strings.Replace(string(fixture.message.RawBytes()), "X-Trace: original", "X-Trace: rewritten", 1)
	rewritten := mustParseRevisionMessage(t, []byte(rewrittenRaw))
	rewrittenTicket := testPlanTicket(t, rewritten.RawBytes(), routeplan.PurposeRevision, capability)
	rewrittenPlan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: rewritten, Ticket: rewrittenTicket,
	})
	if err != nil {
		t.Fatalf("excluded rewrite code=%s", testErrorCode(err))
	}
	if rewrittenPlan.Role() != RoleHashUnchangedForwarder || !rewrittenPlan.ModificationFacts().ExistingHeadersChanged() {
		t.Fatalf("excluded rewrite role=%q headers_changed=%t",
			rewrittenPlan.Role(), rewrittenPlan.ModificationFacts().ExistingHeadersChanged())
	}
	for _, test := range []struct {
		name string
		raw  string
	}{
		{
			name: "remove inherited excluded occurrence",
			raw:  strings.Replace(string(fixture.message.RawBytes()), "X-Trace: original\r\n", "", 1),
		},
		{
			name: "reorder inherited excluded occurrence",
			raw: strings.Replace(
				string(fixture.message.RawBytes()),
				"X-Trace: original\r\nSubject: current\r\n",
				"Subject: current\r\nX-Trace: original\r\n", 1,
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := mustParseRevisionMessage(t, []byte(test.raw))
			ticket := testPlanTicket(t, message.RawBytes(), routeplan.PurposeRevision, capability)
			plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
				Capability: capability, Message: message, Ticket: ticket,
			})
			if planErr != nil || plan.Role() != RoleHashUnchangedForwarder ||
				!plan.ModificationFacts().ExistingHeadersChanged() {
				t.Fatalf("role=%q headers_changed=%t code=%s",
					plan.Role(), plan.ModificationFacts().ExistingHeadersChanged(), testErrorCode(planErr))
			}
		})
	}

	body := mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "current body", "changed body", 1,
	)))
	bodyTicket := testPlanTicket(t, body.RawBytes(), routeplan.PurposeRevision, capability)
	bodyPlan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: body, Ticket: bodyTicket, LiteralPolicy: recipe.AllowLiterals,
	})
	if err != nil || bodyPlan.Role() != RoleReviser || !bodyPlan.ModificationFacts().BodyChanged() {
		t.Fatalf("body revision role=%q body_changed=%t header_equal=%t body_equal=%t raw_equal=%t code=%s",
			bodyPlan.Role(), bodyPlan.ModificationFacts().BodyChanged(),
			bodyPlan.CurrentHashes().Header() == capability.proof.Facts().Hashes().HeaderDigest(),
			bodyPlan.CurrentHashes().Body() == capability.proof.Facts().Hashes().BodyDigest(),
			bytes.Equal(body.RawBytes(), fixture.message.RawBytes()), testErrorCode(err))
	}
	if query, queryErr := NewPolicyAuthorizationQuery(capability, bodyTicket, bodyPlan.ModificationFacts()); queryErr != nil || !query.Valid() {
		t.Fatalf("produced modification facts rejected same-ticket policy query code=%s", testErrorCode(queryErr))
	}
	otherTicket := testPlanTicket(t, body.RawBytes(), routeplan.PurposeRevision, capability)
	if _, queryErr := NewPolicyAuthorizationQuery(capability, otherTicket, bodyPlan.ModificationFacts()); !IsErrorCode(queryErr, ErrorCodeInvalidRequest) {
		t.Fatalf("produced modification facts accepted cross-ticket code=%s", testErrorCode(queryErr))
	}
}

// TestHashPlanRejectsLocalAmbiguityBeforeProducingAPlan covers sealed and bounded failures.
func TestHashPlanRejectsLocalAmbiguityBeforeProducingAPlan(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || !capability.Valid() {
		t.Fatalf("revision capability valid=%t code=%s", capability.Valid(), testErrorCode(err))
	}

	existingOriginTicket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	if plan, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: fixture.message, Ticket: existingOriginTicket,
	}); err == nil || plan.Valid() {
		t.Fatal("originator accepted inherited protocol fields")
	}

	wrongTicket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	if plan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: wrongTicket,
	}); err == nil || plan.Valid() {
		t.Fatal("existing plan accepted wrong ticket purpose/binding")
	}

	changed := mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "Subject: current", "Subject: changed", 1,
	)))
	changedTicket := testPlanTicket(t, changed.RawBytes(), routeplan.PurposeRevision, capability)
	if plan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: changed, Ticket: changedTicket,
	}); err == nil || plan.Valid() {
		t.Fatal("copy-only revision accepted required literal")
	}

	if _, _, err := nextProgression(^uint64(0), 1, true); !IsErrorCode(err, ErrorCodeSequenceFailure) {
		t.Fatalf("instance overflow code=%s", testErrorCode(err))
	}
	if _, _, err := nextProgression(1, ^uint64(0), false); !IsErrorCode(err, ErrorCodeSequenceFailure) {
		t.Fatalf("sequence overflow code=%s", testErrorCode(err))
	}
}

// TestUnsignedOperationPlanIsImmutableDeterministicConcurrentAndRedacted proves the pure-plan boundary.
func TestUnsignedOperationPlanIsImmutableDeterministicConcurrentAndRedacted(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || !capability.Valid() {
		t.Fatalf("revision capability valid=%t code=%s", capability.Valid(), testErrorCode(err))
	}
	revised := mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "Subject: current", "Subject: protected-plan-marker", 1,
	)))
	ticket := testPlanTicket(t, revised.RawBytes(), routeplan.PurposeRevision, capability)
	request := ExistingPlanRequest{
		Capability: capability, Message: revised, Ticket: ticket, LiteralPolicy: recipe.AllowLiterals,
	}
	baseline, err := coordinator.PlanExisting(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline plan code=%s", testErrorCode(err))
	}
	want := baseline.RenderedInstance()
	copyBytes := baseline.RenderedInstance()
	copyBytes[0] ^= 0xff
	if !bytes.Equal(baseline.RenderedInstance(), want) {
		t.Fatal("rendered instance accessor exposed mutable storage")
	}
	formatted := fmt.Sprintf("%v %+v %#v", baseline, baseline, baseline)
	if strings.Contains(formatted, "protected-plan-marker") || !strings.Contains(formatted, "redacted") {
		t.Fatal("plan formatting exposed protected content")
	}

	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			got, planErr := coordinator.PlanExisting(context.Background(), request)
			if planErr != nil || !bytes.Equal(got.RenderedInstance(), want) || got.CurrentHashes() != baseline.CurrentHashes() {
				t.Errorf("concurrent deterministic plan failed code=%s", testErrorCode(planErr))
			}
		})
	}
	wait.Wait()
}

// TestUnsignedOperationPlanRejectsEveryMismatchedOperationBinding locks exact pre-sign rebinding.
func TestUnsignedOperationPlanRejectsEveryMismatchedOperationBinding(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	origin := mustParseRevisionMessage(t, []byte("Subject: exact source\r\n\r\nbody\r\n"))
	originTicket := testPlanTicket(t, origin.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	originPlan, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: origin, Ticket: originTicket,
	})
	if err != nil || !originPlan.Valid() || !originPlan.matchesOperation(origin, originTicket, VerifiedRevisionInput{}) {
		t.Fatalf("origin baseline valid:%t matches:%t code:%s",
			originPlan.Valid(), originPlan.matchesOperation(origin, originTicket, VerifiedRevisionInput{}), testErrorCode(err))
	}

	wrongRole := originPlan
	wrongRole.role = RoleReviser
	if wrongRole.matchesOperation(origin, originTicket, VerifiedRevisionInput{}) {
		t.Fatal("role-corrupted plan matched an operation")
	}
	malformedCapability := VerifiedRevisionInput{initialized: true}
	if malformedCapability.IsZero() || originPlan.matchesOperation(origin, originTicket, malformedCapability) {
		t.Fatal("origin plan accepted malformed nonzero capability state")
	}
	rawDifferent := mustParseRevisionMessage(t, []byte("subject: exact source\r\n\r\nbody\r\n"))
	if originPlan.matchesOperation(rawDifferent, originTicket, VerifiedRevisionInput{}) {
		t.Fatal("origin plan accepted raw-different source")
	}
	otherOriginTicket := testPlanTicket(t, origin.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	if otherOriginTicket.TicketIdentity() == originTicket.TicketIdentity() {
		t.Fatal("test ticket authority unexpectedly repeated a ticket identity")
	}
	if originPlan.matchesOperation(origin, otherOriginTicket, VerifiedRevisionInput{}) {
		t.Fatal("origin plan accepted different ticket identity")
	}

	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || !capability.Valid() {
		t.Fatalf("revision capability valid:%t code:%s", capability.Valid(), testErrorCode(err))
	}
	revisionTicket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeRevision, capability)
	revisionPlan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: revisionTicket,
	})
	if err != nil || !revisionPlan.Valid() ||
		!revisionPlan.matchesOperation(fixture.message, revisionTicket, capability) {
		t.Fatalf("revision baseline valid:%t matches:%t code:%s",
			revisionPlan.Valid(), revisionPlan.matchesOperation(fixture.message, revisionTicket, capability), testErrorCode(err))
	}

	wrongPurpose := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeNextDomain, capability)
	if revisionPlan.matchesOperation(fixture.message, wrongPurpose, capability) {
		t.Fatal("revision plan accepted next-domain ticket purpose")
	}
	wrongCapability := cloneVerifiedRevisionInput(capability)
	wrongCapability.seal[0] ^= 1
	if !wrongCapability.Valid() || revisionPlan.matchesOperation(fixture.message, revisionTicket, wrongCapability) {
		t.Fatal("revision plan accepted a different capability binding")
	}
}

// TestHashPlanCanonicalNeutralChangesKeepTheHashRoleButPreservePolicyFacts covers Section 6 independence.
func TestHashPlanCanonicalNeutralChangesKeepTheHashRoleButPreservePolicyFacts(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil {
		t.Fatalf("VerifyForRevision() code=%s", testErrorCode(err))
	}

	for _, test := range []struct {
		name               string
		raw                []byte
		wantExistingChange bool
	}{
		{
			name: "body trailing empty line",
			raw:  []byte(string(fixture.message.RawBytes()) + "\r\n"),
		},
		{
			name: "relevant header refold",
			raw: []byte(strings.Replace(
				string(fixture.message.RawBytes()), "Subject: current\r\n", "Subject:\tcurrent\r\n", 1,
			)),
			wantExistingChange: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := mustParseRevisionMessage(t, test.raw)
			ticket := testPlanTicket(t, message.RawBytes(), routeplan.PurposeRevision, capability)
			plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
				Capability: capability, Message: message, Ticket: ticket,
			})
			if planErr != nil || plan.Role() != RoleHashUnchangedForwarder ||
				plan.ModificationFacts().BodyChanged() ||
				plan.ModificationFacts().ExistingHeadersChanged() != test.wantExistingChange {
				t.Fatalf("role=%q body_changed=%t headers_changed=%t code=%s",
					plan.Role(), plan.ModificationFacts().BodyChanged(),
					plan.ModificationFacts().ExistingHeadersChanged(), testErrorCode(planErr))
			}
		})
	}
}

// TestHashPlanUnavailableBodyPolicyIsExplicit proves b:null cannot arise from an implicit fallback.
func TestHashPlanUnavailableBodyPolicyIsExplicit(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil {
		t.Fatalf("VerifyForRevision() code=%s", testErrorCode(err))
	}
	changed := mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "current body", "replacement body", 1,
	)))
	ticket := testPlanTicket(t, changed.RawBytes(), routeplan.PurposeRevision, capability)
	if plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: changed, Ticket: ticket,
	}); !IsErrorCode(planErr, ErrorCodePolicyRestriction) || plan.Valid() {
		t.Fatalf("copy-only unavailable denial valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
	allowed, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: changed, Ticket: ticket,
		BodyPolicy: recipe.AllowUnavailableBody,
	})
	if err != nil || !allowed.Valid() || allowed.GenerationFacts().BodyOutcome() != recipe.BodyGenerationUnavailable ||
		!allowed.GenerationFacts().BodyUnavailableReason().Known() ||
		allowed.GenerationFacts().BodyUnavailablePolicy() != recipe.AllowUnavailableBody ||
		!allowed.GenerationFacts().ParseUsage().Valid() || !allowed.GenerationFacts().ApplyUsage().Valid() {
		t.Fatalf("allowed b:null valid=%t outcome=%q reason=%q code=%s",
			allowed.Valid(), allowed.GenerationFacts().BodyOutcome(),
			allowed.GenerationFacts().BodyUnavailableReason(), testErrorCode(err))
	}
	separator := bytes.Index(fixture.message.RawBytes(), []byte("\r\n\r\n"))
	headerOnly := mustParseRevisionMessage(t, fixture.message.RawBytes()[:separator+2])
	headerOnlyTicket := testPlanTicket(t, headerOnly.RawBytes(), routeplan.PurposeRevision, capability)
	headerOnlyPlan, err := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: headerOnly, Ticket: headerOnlyTicket,
		BodyPolicy: recipe.AllowUnavailableBody, LiteralPolicy: recipe.AllowLiterals,
	})
	if err != nil || !headerOnlyPlan.Valid() || headerOnlyPlan.Role() != RoleReviser {
		t.Fatalf("header-only existing valid=%t role=%q code=%s",
			headerOnlyPlan.Valid(), headerOnlyPlan.Role(), testErrorCode(err))
	}
}

// TestHashPlanClosedPoliciesCancellationAndTamperingPreserveTypedFailures covers local fail-closed lanes.
func TestHashPlanClosedPoliciesCancellationAndTamperingPreserveTypedFailures(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil {
		t.Fatalf("VerifyForRevision() code=%s", testErrorCode(err))
	}
	ticket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeRevision, capability)
	if plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: ticket,
		BodyPolicy: recipe.BodyUnavailablePolicy(255),
	}); !IsErrorCode(planErr, ErrorCodeInvalidRequest) || plan.Valid() {
		t.Fatalf("unknown equal-path policy valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if plan, planErr := coordinator.PlanExisting(ctx, ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: ticket,
	}); !errors.Is(planErr, context.Canceled) || plan.Valid() {
		t.Fatalf("canceled plan valid=%t error=%v", plan.Valid(), planErr)
	}

	tampered := mustParseRevisionMessage(t, []byte(strings.Replace(
		string(fixture.message.RawBytes()), "Message-Instance: m=1;", "Message-Instance:\tm=1;", 1,
	)))
	tamperedTicket := testPlanTicket(t, tampered.RawBytes(), routeplan.PurposeRevision, capability)
	if plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: tampered, Ticket: tamperedTicket,
	}); !IsErrorCode(planErr, ErrorCodeProtocolTampering) || plan.Valid() {
		t.Fatalf("protocol tampering valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
	nextTicket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeNextDomain, capability)
	if plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: nextTicket,
	}); !IsErrorCode(planErr, ErrorCodeInvalidRequest) || plan.Valid() {
		t.Fatalf("next-domain purpose erasure valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
	bounded, err := NewHashPlanCoordinator(verifier, recipe.GenerationLimits{}, Limits{MaxSignatures: 1})
	if err != nil {
		t.Fatalf("bounded coordinator code=%s", testErrorCode(err))
	}
	if plan, planErr := bounded.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: ticket,
	}); !IsErrorCode(planErr, ErrorCodeLimitExceeded) || plan.Valid() {
		t.Fatalf("signature cap valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	} else if details := planErr.(*Error).Details(); details.LimitName != LimitNameMaxSignatures {
		t.Fatalf("signature cap limit_name=%q", details.LimitName)
	}

	terminalFixture := newRevisionTestFixture(t, nil, true)
	terminalCoordinator, terminalVerifier := newTestHashPlanCoordinator(t, terminalFixture)
	outcome, terminalCapability, err := terminalVerifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: terminalFixture.message,
	})
	if err != nil || outcome.Status() != RevisionVerificationTerminalNextDomainAuthorizationRequired {
		t.Fatalf("terminal capability status=%q code=%s", outcome.Status(), testErrorCode(err))
	}
	ordinaryTicket := testPlanTicket(t, terminalFixture.message.RawBytes(), routeplan.PurposeRevision, terminalCapability)
	if plan, planErr := terminalCoordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: terminalCapability, Message: terminalFixture.message, Ticket: ordinaryTicket,
	}); planErr != nil || !plan.Valid() {
		t.Fatalf("terminal capability completion plan valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
}

// TestHashPlanPreflightLimitsAndPrivacy covers signing-subset and remaining-field bounds.
func TestHashPlanPreflightLimitsAndPrivacy(t *testing.T) {
	limits := DefaultLimits()
	if _, err := PreflightMessageInstanceField(2, limits.MaxDecodedRecipeBytes, true, limits); err != nil {
		t.Fatalf("45 KiB exact code=%s", testErrorCode(err))
	}
	for _, count := range []int{limits.MaxDecodedRecipeBytes + 1, 49_152} {
		if _, err := PreflightMessageInstanceField(2, count, true, limits); !IsErrorCode(err, ErrorCodeLimitExceeded) {
			t.Fatalf("recipe bytes=%d code=%s", count, testErrorCode(err))
		}
	}

	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, _ := newTestHashPlanCoordinator(t, fixture)
	origin := mustParseRevisionMessage(t, []byte("Subject: size\r\n"))
	originTicket := testPlanTicket(t, origin.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	originPlan, originErr := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: origin, Ticket: originTicket,
	})
	if originErr != nil || !originPlan.Valid() || originPlan.SizeFacts().MessageBytes() < origin.Metadata().StoredBytes {
		t.Fatalf("header-only origin valid=%t code=%s", originPlan.Valid(), testErrorCode(originErr))
	}
	instanceBytes, err := PreflightMessageInstanceField(1, 0, false, coordinator.limits)
	if err != nil {
		t.Fatalf("instance preflight code=%s", testErrorCode(err))
	}
	exactMessage := testHeaderOnlyMessageSize(t, coordinator.limits.MaxHeaderBytes-instanceBytes-1)
	exactTicket := testPlanTicket(t, exactMessage.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	exactPlan, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: exactMessage, Ticket: exactTicket,
	})
	sizes := exactPlan.SizeFacts()
	if err != nil || !exactPlan.Valid() || sizes.SignatureFieldAllowanceBytes() != 1 ||
		sizes.HeaderBytes() != coordinator.limits.MaxHeaderBytes ||
		sizes.MessageBytes() != coordinator.limits.MaxHeaderBytes {
		t.Fatalf("exact allowance=%d header=%d message=%d code=%s",
			sizes.SignatureFieldAllowanceBytes(), sizes.HeaderBytes(), sizes.MessageBytes(), testErrorCode(err))
	}
	oneOverMessage := testHeaderOnlyMessageSize(t, coordinator.limits.MaxHeaderBytes-instanceBytes)
	oneOverTicket := testPlanTicket(t, oneOverMessage.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	if _, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
		Message: oneOverMessage, Ticket: oneOverTicket,
	}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over header code=%s", testErrorCode(err))
	}

	markerMessage := mustParseRevisionMessage(t, []byte("Subject: protected-request-marker\r\n\r\nbody\r\n"))
	markerTicket := testPlanTicket(t, markerMessage.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	values := []any{
		OriginatorPlanRequest{Message: markerMessage, Ticket: markerTicket},
		ExistingPlanRequest{Message: markerMessage, Ticket: markerTicket},
		coordinator,
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(formatted, "protected-request-marker") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("protected formatting leaked for %T", value)
		}
	}
}

// TestHashPlanReservesMinimumOriginFieldCapacityBeforeHashing proves exact and one-over planning.
func TestHashPlanReservesMinimumOriginFieldCapacityBeforeHashing(t *testing.T) {
	message := mustParseRevisionMessage(t, []byte("Subject: minimum capacity\r\n\r\nbody\r\n"))
	for _, test := range []struct {
		name      string
		exact     Limits
		oneUnder  Limits
		limitName LimitName
	}{
		{
			name:      "all header fields",
			exact:     Limits{MaxHeaderFields: message.Metadata().HeaderFields + 2},
			oneUnder:  Limits{MaxHeaderFields: message.Metadata().HeaderFields + 1},
			limitName: LimitNameMaxHeaderFields,
		},
		{
			name:      "protocol fields",
			exact:     Limits{MaxProtocolFields: 2},
			oneUnder:  Limits{MaxProtocolFields: 1},
			limitName: LimitNameMaxProtocolFields,
		},
	} {
		t.Run(test.name+" exact", func(t *testing.T) {
			fixture := newRevisionTestFixture(t, nil, false)
			coordinator, verifier := newTestHashPlanCoordinatorWithLimits(t, fixture, test.exact)
			ticket := testPlanTicket(t, message.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
			plan, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
				Message: message, Ticket: ticket,
			})
			if err != nil || !plan.Valid() || !verifier.valid() {
				t.Fatalf("exact plan=%t verifier=%t error=%v", plan.Valid(), verifier.valid(), err)
			}
		})
		t.Run(test.name+" one over", func(t *testing.T) {
			fixture := newRevisionTestFixture(t, nil, false)
			coordinator, _ := newTestHashPlanCoordinatorWithLimits(t, fixture, test.oneUnder)
			ticket := testPlanTicket(t, message.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
			plan, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{
				Message: message, Ticket: ticket,
			})
			var typed *Error
			if plan.Valid() || !errors.As(err, &typed) || typed.Details().LimitName != test.limitName {
				t.Fatalf("one-over plan=%t error=%v", plan.Valid(), err)
			}
		})
	}
}

// newTestHashPlanCoordinatorWithLimits constructs a pure planner with shared narrowed limits.
func newTestHashPlanCoordinatorWithLimits(t *testing.T, fixture revisionTestFixture, limits Limits) (HashPlanCoordinator, RevisionVerifier) {
	t.Helper()
	proof, err := verify.NewVerifier(mustRevisionStaticProvider(t, fixture), revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	revision, err := newRevisionVerifier(
		proof, limits, bytes.NewReader(bytes.Repeat([]byte{0x6e}, sha256.Size)),
	)
	if err != nil {
		t.Fatalf("newRevisionVerifier() error = %v", err)
	}
	coordinator, err := NewHashPlanCoordinator(revision, recipe.GenerationLimits{}, limits)
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() error = %v", err)
	}
	return coordinator, revision
}

// TestHashPlanDoesNotReenterKeyProvider proves pure planning never performs hidden key callbacks.
func TestHashPlanDoesNotReenterKeyProvider(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	provider := &countingPlanKeyProvider{delegate: mustRevisionStaticProvider(t, fixture)}
	proof, err := verify.NewVerifier(provider, revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier() error=%v", err)
	}
	verifier, err := newRevisionVerifier(proof, Limits{}, bytes.NewReader(bytes.Repeat([]byte{0x83}, sha256.Size)))
	if err != nil {
		t.Fatalf("newRevisionVerifier() code=%s", testErrorCode(err))
	}
	coordinator, err := NewHashPlanCoordinator(verifier, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() code=%s", testErrorCode(err))
	}
	_, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil {
		t.Fatalf("VerifyForRevision() code=%s", testErrorCode(err))
	}
	baseline := provider.calls.Load()
	ticket := testPlanTicket(t, fixture.message.RawBytes(), routeplan.PurposeRevision, capability)
	if plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: ticket,
	}); planErr != nil || !plan.Valid() {
		t.Fatalf("pure success valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
	if plan, planErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
		Capability: capability, Message: fixture.message, Ticket: ticket,
		LiteralPolicy: recipe.LiteralDisclosurePolicy(255),
	}); !IsErrorCode(planErr, ErrorCodeInvalidRequest) || plan.Valid() {
		t.Fatalf("pure local failure valid=%t code=%s", plan.Valid(), testErrorCode(planErr))
	}
	if got := provider.calls.Load(); got != baseline {
		t.Fatalf("planning key-provider calls=%d want=%d", got, baseline)
	}
}

// testHeaderOnlyMessageSize constructs an exact-size valid header block under parser line/count bounds.
func testHeaderOnlyMessageSize(t *testing.T, size int) rawmsg.Message {
	t.Helper()
	if size < 5 {
		t.Fatalf("header-only test size=%d", size)
	}
	fields := (size + 999) / 1000
	base := size / fields
	extra := size % fields
	var raw bytes.Buffer
	raw.Grow(size)
	for index := range fields {
		fieldSize := base
		if index < extra {
			fieldSize++
		}
		raw.WriteString("X: ")
		raw.WriteString(strings.Repeat("a", fieldSize-5))
		raw.WriteString("\r\n")
	}
	if raw.Len() != size {
		t.Fatalf("header-only test bytes=%d want=%d", raw.Len(), size)
	}
	return mustParseRevisionMessage(t, raw.Bytes())
}

// newTestHashPlanCoordinator constructs one deterministic pure planner and its capability issuer.
func newTestHashPlanCoordinator(t *testing.T, fixture revisionTestFixture) (HashPlanCoordinator, RevisionVerifier) {
	t.Helper()
	verifier := newRevisionTestVerifier(t, fixture, bytes.NewReader(bytes.Repeat([]byte{0x71}, sha256.Size)))
	coordinator, err := NewHashPlanCoordinator(verifier, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatalf("NewHashPlanCoordinator() code=%s", testErrorCode(err))
	}
	return coordinator, verifier
}

// TestSignatureFieldAllowanceSealsOnlySizeDimensionsAndDeterministicTies verifies plan taxonomy.
func TestSignatureFieldAllowanceSealsOnlySizeDimensionsAndDeterministicTies(t *testing.T) {
	for _, test := range []struct {
		field, header, message int
		wantBytes              int
		wantName               LimitName
	}{
		{100, 100, 100, 100, LimitNameMaxFieldBytes},
		{100, 90, 90, 90, LimitNameMaxHeaderBytes},
		{100, 100, 90, 90, LimitNameMaxMessageBytes},
	} {
		bytes, name := signatureFieldAllowance(test.field, test.header, test.message)
		if bytes != test.wantBytes || name != test.wantName {
			t.Fatalf("allowance=%d/%q want=%d/%q", bytes, name, test.wantBytes, test.wantName)
		}
		facts := PlanSizeFacts{
			signatureFieldBytes: bytes, signatureLimit: name,
			headerBytes: 10 + bytes, messageBytes: 30 + bytes,
			protocolFields: 1, signatureFields: 1, finalHeaderFields: 1, initialized: true,
		}
		if !facts.Valid() || facts.SignatureFieldLimitName() != test.wantName {
			t.Fatalf("facts valid=%t limit=%q", facts.Valid(), facts.SignatureFieldLimitName())
		}
		gotName, gotLimit, gotActual, exceeded := facts.signatureAllowanceFailure(bytes + 1)
		wantLimit, wantActual := bytes, bytes+1
		if name == LimitNameMaxHeaderBytes {
			wantLimit, wantActual = 10+bytes, 10+bytes+1
		}
		if name == LimitNameMaxMessageBytes {
			wantLimit, wantActual = 30+bytes, 30+bytes+1
		}
		if !exceeded || gotName != name || gotLimit != wantLimit || gotActual != wantActual {
			t.Fatalf("failure=%q/%d/%d/%t want=%q/%d/%d/true",
				gotName, gotLimit, gotActual, exceeded, name, wantLimit, wantActual)
		}
	}
	corrupted := PlanSizeFacts{
		signatureFieldBytes: 1, signatureLimit: LimitNameMaxNonceBytes,
		headerBytes: 1, messageBytes: 1, protocolFields: 1, signatureFields: 1, initialized: true,
	}
	if corrupted.Valid() {
		t.Fatal("non-size signature allowance dimension accepted")
	}
}

// testPlanTicket issues one exact source-bound ticket for pure plan tests.
func testPlanTicket(t *testing.T, raw []byte, purpose routeplan.Purpose, capability VerifiedRevisionInput) routeplan.CopyTicket {
	t.Helper()
	source, err := routeplan.NewImmutableSource(raw)
	if err != nil {
		t.Fatalf("routeplan.NewImmutableSource() error")
	}
	var entry routeplan.Entry
	if purpose == routeplan.PurposeOrigin {
		entry, err = routeplan.NewEntry(source, purpose, []byte("<sender@example.test>"),
			[][]byte{[]byte("<next@example.test>")}, routeplan.DisclosureSingle, []byte("plan-route"), nil)
	} else if purpose == routeplan.PurposeNextDomain {
		inboundReceiver := []byte(nil)
		if capability.proof.State() == verify.RevisionProofTerminalNextDomainAuthorizationRequired {
			inboundReceiver = []byte("plan-inbound-receiver")
		}
		entry, err = NewDualReceiverClassifiedBoundRouteEntry(
			capability, source, purpose, []byte("<sender@example.test>"),
			[][]byte{[]byte("<next@example.test>")}, routeplan.DisclosureSingle,
			routeplan.RouteOutOfBand, []byte("plan-route"),
			inboundReceiver, []byte("plan-outbound-receiver"),
		)
	} else if capability.proof.State() == verify.RevisionProofTerminalNextDomainAuthorizationRequired {
		entry, err = NewDualReceiverClassifiedBoundRouteEntry(
			capability, source, purpose, []byte("<sender@example.test>"),
			[][]byte{[]byte("<next@example.test>")}, routeplan.DisclosureSingle,
			routeplan.RouteExternal, []byte("plan-route"),
			[]byte("plan-inbound-receiver"), nil,
		)
	} else {
		entry, err = NewBoundRouteEntry(capability, source, purpose, []byte("<sender@example.test>"),
			[][]byte{[]byte("<next@example.test>")}, routeplan.DisclosureSingle, []byte("plan-route"))
	}
	if err != nil {
		t.Fatalf("route entry error")
	}
	routeCoordinator, err := routeplan.NewCoordinator(routeplan.NewMemoryAuthority(), routeplan.Limits{})
	if err != nil {
		t.Fatalf("route coordinator error")
	}
	request, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatalf("route request error")
	}
	_, tickets, err := routeCoordinator.Finalize(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("route finalize error")
	}
	return tickets[0]
}
