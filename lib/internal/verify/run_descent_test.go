package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

const (
	descentOriginHeaders  = "From: sender@remote.example\r\nSubject: origin\r\n"
	descentOriginBody     = "origin\r\n"
	descentCurrentHeaders = "From: sender@remote.example\r\nSubject: forwarded\r\n"
	descentCurrentBody    = "forwarded\r\n"
	descentSubjectRecipe  = `{"h":{"subject":[{"d":[" origin"]}]},"b":[{"d":["origin"]}]}`
	descentHeaderOnly     = `{"h":{"subject":[{"d":[" origin"]}]}}`
	descentNullBody       = `{"h":{"subject":[{"d":[" origin"]}]},"b":null}`
)

// descentOriginal returns the two-instance forwarded chain whose current
// state was produced from the origin state by the local forwarder.
func descentOriginal(recipeJSON string) dsntest.Original {
	return dsntest.Original{
		Headers: descentCurrentHeaders, Body: descentCurrentBody,
		Revisions: []dsntest.Revision{{Headers: descentOriginHeaders, Body: descentOriginBody, Recipe: recipeJSON}},
		Hops: []dsntest.Hop{
			runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
			withInstance(runHop(runLocalDomain, runLocalMailFrom, runDestination), 2),
		},
	}
}

// withInstance binds one hop to the named Message-Instance number.
func withInstance(hop dsntest.Hop, number uint64) dsntest.Hop {
	hop.Instance = number
	return hop
}

// mustDescentInput builds the original, parses it, and extracts its embedded protocol fields.
func mustDescentInput(t *testing.T, verifier Verifier, original dsntest.Original) (rawmsg.Message, EmbeddedInput) {
	t.Helper()
	raw, err := original.Build()
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error=%v", err)
	}
	return message, mustEmbeddedInput(t, verifier, message)
}

// mustKnownState wraps a parsed message into a body-known reconstruction state.
func mustKnownState(t *testing.T, message rawmsg.Message) recipe.State {
	t.Helper()
	state, err := recipe.NewState(message)
	if err != nil {
		t.Fatalf("recipe.NewState() error=%v", err)
	}
	return state
}

// mustHeadersOnlyState wraps a message's header block into a headers-only state.
func mustHeadersOnlyState(t *testing.T, message rawmsg.Message) recipe.State {
	t.Helper()
	state, err := recipe.NewHeadersOnlyState(message.Headers())
	if err != nil {
		t.Fatalf("recipe.NewHeadersOnlyState() error=%v", err)
	}
	return state
}

// TestRunDescentReconstructsPreviousState proves a one-transition descent
// reproduces the origin headers and body and reports no degradation.
func TestRunDescentReconstructsPreviousState(t *testing.T) {
	verifier := mustRunVerifier(t)
	message, input := mustDescentInput(t, verifier, descentOriginal(descentSubjectRecipe))
	descent, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil || descent.Outcome() != RunDescentReconstructed || !descent.Valid() {
		t.Fatalf("DescendEmbeddedRun() outcome=%q valid=%t failure=%q error=%v", descent.Outcome(), descent.Valid(), descent.Failure(), err)
	}
	state, ok := descent.State()
	if !ok || descent.Degraded() || descent.ReachedInstance() != 1 {
		t.Fatalf("descent state ok=%t degraded=%t reached=%d", ok, descent.Degraded(), descent.ReachedInstance())
	}
	subject, ok := state.Headers().LastFieldByName("subject")
	if !ok || !bytes.Equal(subject.UnfoldedValue(), []byte(" origin")) {
		t.Fatalf("reconstructed subject=%q ok=%t", subject.UnfoldedValue(), ok)
	}
	body, known := state.Body()
	if !known || !bytes.Equal(body.Bytes(), []byte(descentOriginBody)) {
		t.Fatalf("reconstructed body known=%t", known)
	}
}

// TestRunDescentFloorEqualsCurrentIsIdentity proves a floor at the current
// instance performs no transition and returns the proven initial state.
func TestRunDescentFloorEqualsCurrentIsIdentity(t *testing.T) {
	verifier := mustRunVerifier(t)
	message, input := mustDescentInput(t, verifier, descentOriginal(descentSubjectRecipe))
	descent, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 2)
	if err != nil || descent.Outcome() != RunDescentReconstructed || descent.Degraded() || descent.ReachedInstance() != 2 {
		t.Fatalf("identity descent outcome=%q degraded=%t reached=%d error=%v", descent.Outcome(), descent.Degraded(), descent.ReachedInstance(), err)
	}
	state, ok := descent.State()
	if !ok || !bytes.Equal(state.Headers().OriginalBytes(), message.Headers().OriginalBytes()) {
		t.Fatal("identity descent changed the header block")
	}
}

// TestRunDescentDescendsSeveralTransitions proves a three-instance run walks
// down to the requested floor and stops there rather than at the origin.
func TestRunDescentDescendsSeveralTransitions(t *testing.T) {
	verifier := mustRunVerifier(t)
	original := dsntest.Original{
		Headers: "From: sender@remote.example\r\nSubject: third\r\n", Body: "third\r\n",
		Revisions: []dsntest.Revision{
			{Headers: descentOriginHeaders, Body: descentOriginBody, Recipe: descentSubjectRecipe},
			{Headers: "From: sender@remote.example\r\nSubject: second\r\n", Body: "second\r\n", Recipe: `{"h":{"subject":[{"d":[" second"]}]},"b":[{"d":["second"]}]}`},
		},
		Hops: []dsntest.Hop{
			runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
			withInstance(runHop(runLocalDomain, runLocalMailFrom, "<next@forward.local.example>"), 2),
			withInstance(runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination), 3),
		},
	}
	message, input := mustDescentInput(t, verifier, original)
	descent, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 2)
	if err != nil || descent.Outcome() != RunDescentReconstructed || descent.ReachedInstance() != 2 {
		t.Fatalf("floor two descent outcome=%q reached=%d error=%v", descent.Outcome(), descent.ReachedInstance(), err)
	}
	state, _ := descent.State()
	subject, _ := state.Headers().LastFieldByName("subject")
	body, _ := state.Body()
	if !bytes.Equal(subject.UnfoldedValue(), []byte(" second")) || !bytes.Equal(body.Bytes(), []byte("second\r\n")) {
		t.Fatalf("floor two state subject=%q body=%q", subject.UnfoldedValue(), body.Bytes())
	}
	toOrigin, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil || toOrigin.Outcome() != RunDescentReconstructed || toOrigin.ReachedInstance() != 1 {
		t.Fatalf("origin descent outcome=%q reached=%d error=%v", toOrigin.Outcome(), toOrigin.ReachedInstance(), err)
	}
}

// TestRunDescentDegradesOnNullRecipeAndHeadersOnlyInput proves body-unavailable
// transitions and headers-only input degrade instead of failing.
func TestRunDescentDegradesOnNullRecipeAndHeadersOnlyInput(t *testing.T) {
	verifier := mustRunVerifier(t)
	message, input := mustDescentInput(t, verifier, descentOriginal(descentNullBody))
	descent, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil || descent.Outcome() != RunDescentReconstructed || !descent.Degraded() {
		t.Fatalf("null recipe descent outcome=%q degraded=%t error=%v", descent.Outcome(), descent.Degraded(), err)
	}
	state, _ := descent.State()
	if state.BodyState() != recipe.BodyAvailabilityUnavailable {
		t.Fatalf("null recipe body state=%q", state.BodyState())
	}
	message, input = mustDescentInput(t, verifier, descentOriginal(descentHeaderOnly))
	headersOnly, err := verifier.DescendEmbeddedRun(context.Background(), input, mustHeadersOnlyState(t, message), 1)
	if err != nil || headersOnly.Outcome() != RunDescentReconstructed || !headersOnly.Degraded() {
		t.Fatalf("headers-only descent outcome=%q degraded=%t error=%v", headersOnly.Outcome(), headersOnly.Degraded(), err)
	}
	state, _ = headersOnly.State()
	subject, _ := state.Headers().LastFieldByName("subject")
	if !bytes.Equal(subject.UnfoldedValue(), []byte(" origin")) || state.BodyState() != recipe.BodyAvailabilityUnavailable {
		t.Fatalf("headers-only state subject=%q body=%q", subject.UnfoldedValue(), state.BodyState())
	}
	message, input = mustDescentInput(t, verifier, descentOriginal(descentSubjectRecipe))
	bodyCopyOnHeaders, err := verifier.DescendEmbeddedRun(context.Background(), input, mustHeadersOnlyState(t, message), 1)
	if err != nil || bodyCopyOnHeaders.Outcome() != RunDescentReconstructed || !bodyCopyOnHeaders.Degraded() {
		t.Fatalf("headers-only descent with body recipe outcome=%q degraded=%t error=%v", bodyCopyOnHeaders.Outcome(), bodyCopyOnHeaders.Degraded(), err)
	}
}

// TestRunDescentFailsClosedOnUnprovableStates proves unsupported tuples,
// mismatches, malformed recipes, and limits are not reconstructable.
func TestRunDescentFailsClosedOnUnprovableStates(t *testing.T) {
	verifier := mustRunVerifier(t)
	cases := []struct {
		name    string
		mutate  func([]byte) []byte
		failure RunDescentFailure
	}{
		{"unsupported historical hash tuple", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte("Message-Instance: m=1; h=sha256:"), []byte("Message-Instance: m=1; h=sha999:"), 1)
		}, RunDescentUnsupportedHash},
		{"hash mismatch during re-proof", mutateOriginHeaderHash, RunDescentHashMismatch},
		{"malformed recipe", func(raw []byte) []byte {
			return replaceRecipe(raw, descentSubjectRecipe, `{"h":{"subject":[{"x":1}]}}`)
		}, RunDescentRecipeInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := descentOriginal(descentSubjectRecipe).Build()
			if err != nil {
				t.Fatal(err)
			}
			mutated := testCase.mutate(raw)
			if bytes.Equal(mutated, raw) {
				t.Fatal("mutation did not apply")
			}
			message, err := rawmsg.Parse(mutated)
			if err != nil {
				t.Fatal(err)
			}
			input := mustEmbeddedInput(t, verifier, message)
			descent, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
			if err != nil || descent.Outcome() != RunDescentNotReconstructable || descent.Failure() != testCase.failure {
				t.Fatalf("outcome=%q failure=%q error=%v", descent.Outcome(), descent.Failure(), err)
			}
			if _, ok := descent.State(); ok {
				t.Fatal("not reconstructable descent exposed a state")
			}
		})
	}
}

// replaceRecipe swaps one base64 recipe inside a rendered Message-Instance field.
func replaceRecipe(raw []byte, from, to string) []byte {
	encodedFrom := "r=" + base64.StdEncoding.EncodeToString([]byte(from)) + ";"
	encodedTo := "r=" + base64.StdEncoding.EncodeToString([]byte(to)) + ";"
	return []byte(strings.Replace(string(raw), encodedFrom, encodedTo, 1))
}

// mutateOriginHeaderHash flips the first base64 character of the m=1 header hash.
func mutateOriginHeaderHash(raw []byte) []byte {
	marker := []byte("Message-Instance: m=1; h=sha256:")
	offset := bytes.Index(raw, marker)
	if offset < 0 {
		return raw
	}
	mutated := bytes.Clone(raw)
	position := offset + len(marker)
	if mutated[position] == 'A' {
		mutated[position] = 'B'
	} else {
		mutated[position] = 'A'
	}
	return mutated
}

// TestRunDescentLimitExhaustionIsNotReconstructable proves a transition limit
// below the run depth fails closed instead of emitting a partial state.
func TestRunDescentLimitExhaustionIsNotReconstructable(t *testing.T) {
	limits := DefaultHistoryLimits()
	limits.MaxTransitions = 1
	limits.MaxRetainedTransitions = 1
	coordinator := mustHistoryCoordinator(t, limits)
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), `{"h":{"subject":[{"d":["origin"]}]},"b":[{"d":["origin"]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"subject":[{"d":["middle"]}]},"b":[{"d":["middle"]}]}`),
	)
	descent, err := coordinator.Descend(context.Background(), collection, mustHistoryState(t, currentBytes), 1, DefaultRevisionLimits().MaxCanonicalWorkBytes)
	if err != nil || descent.Outcome() != RunDescentNotReconstructable || descent.Failure() != RunDescentLimitExceeded {
		t.Fatalf("limit descent outcome=%q failure=%q error=%v", descent.Outcome(), descent.Failure(), err)
	}
	within, err := coordinator.Descend(context.Background(), collection, mustHistoryState(t, currentBytes), 2, DefaultRevisionLimits().MaxCanonicalWorkBytes)
	if err != nil || within.Outcome() != RunDescentReconstructed || within.ReachedInstance() != 2 {
		t.Fatalf("within-limit descent outcome=%q reached=%d error=%v", within.Outcome(), within.ReachedInstance(), err)
	}
}

// TestRunDescentRejectsMisuseAndCancellation proves invalid floors, an
// initial state that does not match the current instance, and cancellation
// are Go errors rather than descents.
func TestRunDescentRejectsMisuseAndCancellation(t *testing.T) {
	verifier := mustRunVerifier(t)
	message, input := mustDescentInput(t, verifier, descentOriginal(descentSubjectRecipe))
	state := mustKnownState(t, message)
	for _, floor := range []uint64{0, 3} {
		if _, err := verifier.DescendEmbeddedRun(context.Background(), input, state, floor); err == nil {
			t.Fatalf("floor %d accepted", floor)
		}
	}
	foreign, err := rawmsg.Parse([]byte("Subject: other\r\n\r\nother\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, foreign), 1); err == nil {
		t.Fatal("initial state that does not match the current instance was accepted")
	}
	if _, err := verifier.DescendEmbeddedRun(context.Background(), EmbeddedInput{}, state, 1); err == nil {
		t.Fatal("zero embedded input accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.DescendEmbeddedRun(ctx, input, state, 1); err == nil {
		t.Fatal("cancelled context accepted")
	}
	if descent := (RunDescent{}); descent.Valid() || descent.Outcome() != "" {
		t.Fatal("zero descent is valid")
	}
	if !strings.Contains((RunDescent{}).String(), "redacted") {
		t.Fatal("descent formatting is not redacted")
	}
}

// TestRunDescentCanonicalWorkCeiling proves the descent charges the
// initial-state proof and every transition against the caller's canonical
// work ceiling and fails closed as limit_exceeded when it is exhausted, while
// the verifier seam applies its own revision ceiling.
func TestRunDescentCanonicalWorkCeiling(t *testing.T) {
	coordinator := mustHistoryCoordinator(t, DefaultHistoryLimits())
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"subject":[{"d":["origin"]}]},"b":[{"d":["origin"]}]}`),
	)
	generous, err := coordinator.Descend(context.Background(), collection, mustHistoryState(t, currentBytes), 1, DefaultRevisionLimits().MaxCanonicalWorkBytes)
	if err != nil || generous.Outcome() != RunDescentReconstructed {
		t.Fatalf("generous ceiling outcome=%q failure=%q error=%v", generous.Outcome(), generous.Failure(), err)
	}
	for _, ceiling := range []int{0, 1, len(currentBytes)} {
		limited, err := coordinator.Descend(context.Background(), collection, mustHistoryState(t, currentBytes), 1, ceiling)
		if err != nil || limited.Outcome() != RunDescentNotReconstructable || limited.Failure() != RunDescentLimitExceeded {
			t.Fatalf("ceiling %d outcome=%q failure=%q error=%v", ceiling, limited.Outcome(), limited.Failure(), err)
		}
		if _, ok := limited.State(); ok {
			t.Fatal("limited descent exposed a state")
		}
	}
	limits := DefaultRevisionLimits()
	limits.MaxCanonicalWorkBytes = 1
	keys := make([]StaticKey, 0, len(runKeys()))
	for domain, key := range runKeys() {
		keys = append(keys, StaticKey{Domain: domain, Selector: key.Selector, Algorithm: AlgorithmEd25519SHA256, Material: key.Public()})
	}
	provider, err := NewStaticKeyProvider(keys)
	if err != nil {
		t.Fatal(err)
	}
	limitedVerifier, err := NewVerifier(provider, testClockOption(), WithRevisionLimits(limits))
	if err != nil {
		t.Fatal(err)
	}
	message, input := mustDescentInput(t, limitedVerifier, descentOriginal(descentSubjectRecipe))
	descent, err := limitedVerifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil || descent.Outcome() != RunDescentNotReconstructable || descent.Failure() != RunDescentLimitExceeded {
		t.Fatalf("verifier ceiling outcome=%q failure=%q error=%v", descent.Outcome(), descent.Failure(), err)
	}
}

// TestRunDescentReportsRewrittenHeaderNames proves the descent records the
// canonical header names its recipes rewrote and nothing for body-only or
// identity descents.
func TestRunDescentReportsRewrittenHeaderNames(t *testing.T) {
	verifier := mustRunVerifier(t)
	message, input := mustDescentInput(t, verifier, descentOriginal(descentSubjectRecipe))
	descent, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil || strings.Join(descent.RewrittenHeaderNames(), ",") != "subject" {
		t.Fatalf("rewritten names=%v error=%v", descent.RewrittenHeaderNames(), err)
	}
	identity, err := verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 2)
	if err != nil || len(identity.RewrittenHeaderNames()) != 0 {
		t.Fatalf("identity rewritten names=%v error=%v", identity.RewrittenHeaderNames(), err)
	}
	bodyOnly := descentOriginal(`{"b":[{"d":["origin"]}]}`)
	bodyOnly.Revisions[0].Headers = descentCurrentHeaders
	message, input = mustDescentInput(t, verifier, bodyOnly)
	descent, err = verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil || descent.Outcome() != RunDescentReconstructed || len(descent.RewrittenHeaderNames()) != 0 {
		t.Fatalf("body-only rewritten names=%v outcome=%q error=%v", descent.RewrittenHeaderNames(), descent.Outcome(), err)
	}
	message, input = mustDescentInput(t, verifier, descentOriginal(descentSubjectRecipe))
	descent, err = verifier.DescendEmbeddedRun(context.Background(), input, mustKnownState(t, message), 1)
	if err != nil {
		t.Fatal(err)
	}
	names := descent.RewrittenHeaderNames()
	names[0] = "x"
	if strings.Join(descent.RewrittenHeaderNames(), ",") != "subject" {
		t.Fatal("RewrittenHeaderNames() exposed shared storage")
	}
	if (RunDescent{}).RewrittenHeaderNames() != nil {
		t.Fatal("zero descent exposed names")
	}
}
