package verify

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/recipe"
)

const (
	historicalCompletionTimestamp = dsntest.DefaultTimestamp + 3600
	historicalDay                 = uint64(24 * 60 * 60)
)

// historicalOriginal returns the forwarded chain whose previous hop is the
// origin signature over m=1 and whose completion signature is the local hop.
func historicalOriginal(previous dsntest.Hop) dsntest.Original {
	completion := withInstance(runHop(runLocalDomain, runLocalMailFrom, runDestination), 2)
	completion.Timestamp = historicalCompletionTimestamp
	return dsntest.Original{
		Headers: descentCurrentHeaders, Body: descentCurrentBody,
		Revisions: []dsntest.Revision{{Headers: descentOriginHeaders, Body: descentOriginBody, Recipe: descentSubjectRecipe}},
		Hops:      []dsntest.Hop{previous, completion},
	}
}

// historicalRequest builds the seam request at the completion instant.
func historicalRequest(state recipe.State) HistoricalTargetRequest {
	return HistoricalTargetRequest{
		State: state, Sequence: 1,
		ReferenceTime: time.Unix(int64(historicalCompletionTimestamp), 0), MaxTimestamp: historicalCompletionTimestamp,
	}
}

// mustReconstructedState descends the embedded run to the origin instance.
func mustReconstructedState(t *testing.T, verifier Verifier, input EmbeddedInput, initial recipe.State) recipe.State {
	t.Helper()
	descent, err := verifier.DescendEmbeddedRun(context.Background(), input, initial, 1)
	if err != nil || descent.Outcome() != RunDescentReconstructed {
		t.Fatalf("DescendEmbeddedRun() outcome=%q error=%v", descent.Outcome(), err)
	}
	state, _ := descent.State()
	return state
}

// TestHistoricalTargetVerificationVerifiesPreviousHop proves the previous hop
// signature verifies over the reconstructed state with the completion t= as
// the reference instant, for complete and headers-only states.
func TestHistoricalTargetVerificationVerifiesPreviousHop(t *testing.T) {
	verifier := mustRunVerifier(t)
	previous := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
	message, input := mustDescentInput(t, verifier, historicalOriginal(previous))
	state := mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	outcome, err := verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
	if err != nil || outcome != HistoricalTargetVerified {
		t.Fatalf("VerifyHistoricalTarget() outcome=%q error=%v", outcome, err)
	}
	headersOnly := mustReconstructedState(t, verifier, input, mustHeadersOnlyState(t, message))
	outcome, err = verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(headersOnly))
	if err != nil || outcome != HistoricalTargetVerified {
		t.Fatalf("VerifyHistoricalTarget(headers only) outcome=%q error=%v", outcome, err)
	}
}

// TestHistoricalTargetVerificationRejectsUnprovenState proves a state whose
// hashes do not match the target instance is rejected before any key lookup.
func TestHistoricalTargetVerificationRejectsUnprovenState(t *testing.T) {
	verifier := mustRunVerifier(t)
	previous := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
	message, input := mustDescentInput(t, verifier, historicalOriginal(previous))
	outcome, err := verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(mustKnownState(t, message)))
	if err != nil || outcome != HistoricalTargetHashMismatch {
		t.Fatalf("VerifyHistoricalTarget(current state) outcome=%q error=%v", outcome, err)
	}
}

// TestHistoricalTargetVerificationRejectsSignatureFailures proves a corrupt
// signature and a missing key are permanent, and a temporary provider is temporary.
func TestHistoricalTargetVerificationRejectsSignatureFailures(t *testing.T) {
	verifier := mustRunVerifier(t)
	corrupt := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
	corrupt.CorruptSignature = true
	message, input := mustDescentInput(t, verifier, historicalOriginal(corrupt))
	state := mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	outcome, err := verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
	if err != nil || outcome != HistoricalTargetSignatureUnverified {
		t.Fatalf("corrupt signature outcome=%q error=%v", outcome, err)
	}
	missing := dsntest.Hop{Domain: "unknown.example", Key: dsntest.KeyForLabel("unknown", "sel"), MailFrom: "<sender@unknown.example>", Recipients: []string{runLocalRecipient}}
	message, input = mustDescentInput(t, verifier, historicalOriginal(missing))
	state = mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	outcome, err = verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
	if err != nil || outcome != HistoricalTargetSignatureUnverified {
		t.Fatalf("missing key outcome=%q error=%v", outcome, err)
	}
	temporary, err := NewVerifier(temporaryKeyProvider{})
	if err != nil {
		t.Fatal(err)
	}
	previous := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
	message, input = mustDescentInput(t, temporary, historicalOriginal(previous))
	state = mustReconstructedState(t, temporary, input, mustKnownState(t, message))
	outcome, err = temporary.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
	if err != nil || outcome != HistoricalTargetTemporary {
		t.Fatalf("temporary provider outcome=%q error=%v", outcome, err)
	}
}

// TestHistoricalTargetVerificationTimestampWindow proves the Section 8.4
// window is evaluated at the completion t= and that the previous t= must not
// exceed it.
func TestHistoricalTargetVerificationTimestampWindow(t *testing.T) {
	verifier := mustRunVerifier(t)
	cases := []struct {
		name      string
		timestamp uint64
		outcome   HistoricalTargetOutcome
	}{
		{"later than completion", historicalCompletionTimestamp + 1, HistoricalTargetTimestampRejected},
		{"equal to completion", historicalCompletionTimestamp, HistoricalTargetVerified},
		{"within maximum age", historicalCompletionTimestamp - 13*historicalDay, HistoricalTargetVerified},
		{"beyond maximum age", historicalCompletionTimestamp - 15*historicalDay, HistoricalTargetTimestampRejected},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			previous := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
			previous.Timestamp = testCase.timestamp
			message, input := mustDescentInput(t, verifier, historicalOriginal(previous))
			state := mustReconstructedState(t, verifier, input, mustKnownState(t, message))
			outcome, err := verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
			if err != nil || outcome != testCase.outcome {
				t.Fatalf("outcome=%q error=%v", outcome, err)
			}
		})
	}
}

// TestHistoricalTargetVerificationAlignmentAndNullSender proves the Section
// 11.4 d=/mf= match and the non-null mf= requirement.
func TestHistoricalTargetVerificationAlignmentAndNullSender(t *testing.T) {
	verifier := mustRunVerifier(t)
	misaligned := runHop(runSecondDomain, "<sender@remote.example>", runLocalRecipient)
	message, input := mustDescentInput(t, verifier, historicalOriginal(misaligned))
	state := mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	outcome, err := verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
	if err != nil || outcome != HistoricalTargetAlignmentRejected {
		t.Fatalf("misaligned outcome=%q error=%v", outcome, err)
	}
	nullSender := runHop(runRemoteDomain, "<>", runLocalRecipient)
	message, input = mustDescentInput(t, verifier, historicalOriginal(nullSender))
	state = mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	outcome, err = verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state))
	if err != nil || outcome != HistoricalTargetNullSender {
		t.Fatalf("null sender outcome=%q error=%v", outcome, err)
	}
}

// TestHistoricalTargetVerificationRejectsMisuse proves invalid sequences,
// nd= targets, zero reference instants, and cancellation are Go errors.
func TestHistoricalTargetVerificationRejectsMisuse(t *testing.T) {
	verifier := mustRunVerifier(t)
	previous := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
	message, input := mustDescentInput(t, verifier, historicalOriginal(previous))
	state := mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	valid := historicalRequest(state)
	for name, mutate := range map[string]func(*HistoricalTargetRequest){
		"zero sequence":         func(r *HistoricalTargetRequest) { r.Sequence = 0 },
		"highest sequence":      func(r *HistoricalTargetRequest) { r.Sequence = 2 },
		"missing sequence":      func(r *HistoricalTargetRequest) { r.Sequence = 7 },
		"zero reference":        func(r *HistoricalTargetRequest) { r.ReferenceTime = time.Time{} },
		"zero maximum":          func(r *HistoricalTargetRequest) { r.MaxTimestamp = 0 },
		"reference past bounds": func(r *HistoricalTargetRequest) { r.ReferenceTime = time.Unix(int64(maxRepresentableUnixSeconds), 0) },
		"zero state":            func(r *HistoricalTargetRequest) { r.State = recipe.State{} },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := verifier.VerifyHistoricalTarget(context.Background(), input, request); err == nil {
				t.Fatal("misuse accepted")
			}
		})
	}
	if _, err := verifier.VerifyHistoricalTarget(context.Background(), EmbeddedInput{}, valid); err == nil {
		t.Fatal("zero embedded input accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.VerifyHistoricalTarget(ctx, input, valid); err == nil {
		t.Fatal("cancelled context accepted")
	}
	nextDomain := historicalOriginal(runNextDomainHop(runRemoteDomain, runLocalDomain))
	message, input = mustDescentInput(t, verifier, nextDomain)
	state = mustReconstructedState(t, verifier, input, mustKnownState(t, message))
	if _, err := verifier.VerifyHistoricalTarget(context.Background(), input, historicalRequest(state)); err == nil {
		t.Fatal("nd= historical target accepted")
	}
}

// historicalTwoHopOriginal returns a chain whose previous hop is i=2: the
// origin at second.example signed m=1 towards remote.example, remote.example
// forwarded the unchanged instance as i=2, and the local hop completed with
// m=2. originRecipient is the origin's rt= path, which links or breaks the
// custody chain below the previous hop.
func historicalTwoHopOriginal(originRecipient string) dsntest.Original {
	origin := runHop(runSecondDomain, "<origin@second.example>", originRecipient)
	previous := runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient)
	completion := withInstance(runHop(runLocalDomain, runLocalMailFrom, runDestination), 2)
	completion.Timestamp = historicalCompletionTimestamp
	return dsntest.Original{
		Headers: descentCurrentHeaders, Body: descentCurrentBody,
		Revisions: []dsntest.Revision{{Headers: descentOriginHeaders, Body: descentOriginBody, Recipe: descentSubjectRecipe}},
		Hops:      []dsntest.Hop{origin, previous, completion},
	}
}

// TestHistoricalTargetVerificationCustodyBelowPreviousHop proves the custody
// chain below and including i=k-1 is validated as a whole: a linked chain
// verifies and a broken link below the previous hop is the distinct
// custody_rejected outcome rather than an alignment failure of i=k-1.
func TestHistoricalTargetVerificationCustodyBelowPreviousHop(t *testing.T) {
	verifier := mustRunVerifier(t)
	for _, testCase := range []struct {
		name            string
		originRecipient string
		outcome         HistoricalTargetOutcome
	}{
		{"linked chain", "<user@remote.example>", HistoricalTargetVerified},
		{"broken lower link", "<user@elsewhere.example>", HistoricalTargetCustodyRejected},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			message, input := mustDescentInput(t, verifier, historicalTwoHopOriginal(testCase.originRecipient))
			state := mustReconstructedState(t, verifier, input, mustKnownState(t, message))
			request := historicalRequest(state)
			request.Sequence = 2
			outcome, err := verifier.VerifyHistoricalTarget(context.Background(), input, request)
			if err != nil || outcome != testCase.outcome {
				t.Fatalf("VerifyHistoricalTarget(i=2) outcome=%q error=%v", outcome, err)
			}
		})
	}
	if !HistoricalTargetCustodyRejected.Known() || HistoricalTargetCustodyRejected == HistoricalTargetAlignmentRejected {
		t.Fatal("custody_rejected is not a distinct known outcome")
	}
}

// TestRevisionInstantWithinSkewOf proves a caller-supplied instant is
// accepted only from the same verifier and within the future tolerance of a
// fresh capture in either direction.
func TestRevisionInstantWithinSkewOf(t *testing.T) {
	now := time.Unix(int64(historicalCompletionTimestamp), 0)
	clock := func() time.Time { return now }
	verifier, err := NewVerifier(temporaryKeyProvider{}, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	reference, err := verifier.CaptureRevisionInstant()
	if err != nil {
		t.Fatal(err)
	}
	tolerance := DefaultTimestampPolicy().FutureTolerance
	for name, offset := range map[string]time.Duration{"same": 0, "earlier within": -tolerance, "later within": tolerance} {
		now = time.Unix(int64(historicalCompletionTimestamp), 0).Add(offset)
		candidate, err := verifier.CaptureRevisionInstant()
		if err != nil || !candidate.WithinSkewOf(reference) {
			t.Fatalf("%s: instant rejected error=%v", name, err)
		}
	}
	for name, offset := range map[string]time.Duration{"earlier beyond": -tolerance - time.Second, "later beyond": tolerance + time.Second} {
		now = time.Unix(int64(historicalCompletionTimestamp), 0).Add(offset)
		candidate, err := verifier.CaptureRevisionInstant()
		if err != nil || candidate.WithinSkewOf(reference) {
			t.Fatalf("%s: instant accepted error=%v", name, err)
		}
	}
	now = time.Unix(int64(historicalCompletionTimestamp), 0)
	other, err := NewVerifier(temporaryKeyProvider{}, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.CaptureRevisionInstant()
	if err != nil || foreign.WithinSkewOf(reference) || reference.WithinSkewOf(foreign) {
		t.Fatalf("foreign verifier instant accepted error=%v", err)
	}
	if (RevisionInstant{}).WithinSkewOf(reference) || reference.WithinSkewOf(RevisionInstant{}) {
		t.Fatal("zero instant accepted")
	}
}
