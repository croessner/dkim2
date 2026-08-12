package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
)

// TestVerifyCurrentMatchesHistoryCapableCurrentFacts proves the shared current-verification contract.
func TestVerifyCurrentMatchesHistoryCapableCurrentFacts(t *testing.T) {
	fixture := newCurrentHistoryVerificationFixture(t, `{`)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{Message: fixture.message, Envelope: matchingEnvelope()}

	current, currentErr := verifier.VerifyCurrent(context.Background(), request)
	full, fullErr := verifier.Verify(context.Background(), request)
	if currentErr != nil || fullErr != nil {
		t.Fatalf("verification errors: current=%v full=%v", currentErr, fullErr)
	}
	assertCurrentVerificationParity(t, current, full)
	if _, ok := current.historyWalk(); ok {
		t.Fatal("current-only verification retained authenticated history")
	}
	walk, ok := full.historyWalk()
	if !ok || walk.StopReason() != HistoryStopRecipeInvalid {
		t.Fatalf("history-capable verification stop = %q, present=%t", walk.StopReason(), ok)
	}
}

// TestVerifyCurrentConcurrentParity proves immutable reuse under race instrumentation.
func TestVerifyCurrentConcurrentParity(t *testing.T) {
	recipeJSON := `{"h":{"Subject":[{"d":["previous"]}]},"b":[{"d":["previous"]}]}`
	fixture := newCurrentHistoryVerificationFixture(t, recipeJSON)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{Message: fixture.message, Envelope: matchingEnvelope()}

	const workers = 8
	currentResults := make([]Result, workers)
	fullResults := make([]Result, workers)
	errs := make([]error, workers*2)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Go(func() {
			currentResults[index], errs[index] = verifier.VerifyCurrent(context.Background(), request)
			fullResults[index], errs[workers+index] = verifier.Verify(context.Background(), request)
		})
	}
	wait.Wait()
	for index := range workers {
		if errs[index] != nil || errs[workers+index] != nil {
			t.Fatalf("concurrent verification errors at %d: current=%v full=%v", index, errs[index], errs[workers+index])
		}
		assertCurrentVerificationParity(t, currentResults[index], fullResults[index])
		if _, ok := currentResults[index].historyWalk(); ok {
			t.Fatalf("current-only worker %d retained history", index)
		}
		walk, ok := fullResults[index].historyWalk()
		if !ok || walk.Coverage() != HistoryCoverageComplete {
			t.Fatalf("history-capable worker %d coverage=%q present=%t", index, walk.Coverage(), ok)
		}
	}
}

// TestVerifyCurrentPreservesCompleteFullHistory proves full verification still authenticates valid history.
func TestVerifyCurrentPreservesCompleteFullHistory(t *testing.T) {
	recipeJSON := `{"h":{"Subject":[{"d":["previous"]}]},"b":[{"d":["previous"]}]}`
	fixture := newCurrentHistoryVerificationFixture(t, recipeJSON)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{Message: fixture.message, Envelope: matchingEnvelope()}

	current, currentErr := verifier.VerifyCurrent(context.Background(), request)
	full, fullErr := verifier.Verify(context.Background(), request)
	if currentErr != nil || fullErr != nil {
		t.Fatalf("verification errors: current=%v full=%v", currentErr, fullErr)
	}
	assertCurrentVerificationParity(t, current, full)
	if _, ok := current.historyWalk(); ok {
		t.Fatal("current-only verification retained complete history")
	}
	walk, ok := full.historyWalk()
	if !ok || walk.Coverage() != HistoryCoverageComplete ||
		walk.StopReason() != HistoryStopOriginReached || walk.ReachedInstance() != 1 {
		t.Fatalf("full history coverage=%q stop=%q reached=%d present=%t", walk.Coverage(), walk.StopReason(), walk.ReachedInstance(), ok)
	}
}

// TestVerifyCurrentNeverDescendsIntoHistory proves malformed history and a broken coordinator are inert.
func TestVerifyCurrentNeverDescendsIntoHistory(t *testing.T) {
	fixture := newCurrentHistoryVerificationFixture(t, `{`)
	verifier := mustVerifierForFixture(t, fixture)
	verifier.history = HistoryCoordinator{}

	result, err := verifier.VerifyCurrent(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("VerifyCurrent() status=%q error=%v", result.Status(), err)
	}
	if _, ok := result.historyWalk(); ok {
		t.Fatal("current-only verification attached a history fallback")
	}
	if projection, ok := result.ReplayProjection(); !ok || !projection.Valid() {
		t.Fatal("current-only verification omitted the sealed replay projection")
	}
}

// TestVerifyCurrentPreservesNoSignatureCustodyError proves shared extraction error annotation.
func TestVerifyCurrentPreservesNoSignatureCustodyError(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	start := strings.Index(fixture.raw, "DKIM2-Signature:")
	if start < 0 {
		t.Fatal("fixture lacks DKIM2-Signature")
	}
	end := strings.Index(fixture.raw[start:], "\r\n")
	if end < 0 {
		t.Fatal("fixture signature lacks line ending")
	}
	raw := fixture.raw[:start] + fixture.raw[start+end+2:]
	message := mustParseVerificationMessage(t, raw)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{Message: message, Envelope: matchingEnvelope()}

	currentResult, currentErr := verifier.VerifyCurrent(context.Background(), request)
	fullResult, fullErr := verifier.Verify(context.Background(), request)
	var currentTyped, fullTyped *Error
	if !errors.As(currentErr, &currentTyped) || !errors.As(fullErr, &fullTyped) ||
		currentTyped.Code() != fullTyped.Code() ||
		currentTyped.CustodyStatus() != fullTyped.CustodyStatus() ||
		currentTyped.CustodyStatus() != CustodyStatusNotPresent ||
		currentResult.Status() != "" || fullResult.Status() != "" {
		t.Fatal("current-only and full no-signature errors differ")
	}
}

// TestVerifyCurrentIgnoresCancellationAfterCurrentWork proves history cancellation is outside its contract.
func TestVerifyCurrentIgnoresCancellationAfterCurrentWork(t *testing.T) {
	fixture := newCurrentHistoryVerificationFixture(t, `{"b":[]}`)
	verifier := mustVerifierForFixture(t, fixture)
	request := Request{Message: fixture.message, Envelope: matchingEnvelope()}

	counting := &cancelBetweenHopsContext{cancelAt: int(^uint(0) >> 1)}
	if result, err := verifier.VerifyCurrent(counting, request); err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("counted VerifyCurrent() status=%q error=%v", result.Status(), err)
	}
	if counting.calls == 0 {
		t.Fatal("current verification made no context checks")
	}

	currentContext := &cancelBetweenHopsContext{cancelAt: counting.calls + 1}
	if result, err := verifier.VerifyCurrent(currentContext, request); err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("boundary VerifyCurrent() status=%q error=%v", result.Status(), err)
	}

	fullContext := &cancelBetweenHopsContext{cancelAt: counting.calls + 1}
	result, err := verifier.Verify(fullContext, request)
	if !errors.Is(err, context.Canceled) || result.Status() != "" || result.Target() != (Target{}) {
		t.Fatalf("history-capable boundary result=%q/%#v error=%v", result.Status(), result.Target(), err)
	}
}

// assertCurrentVerificationParity compares every current fact and replay projection.
func assertCurrentVerificationParity(t testing.TB, current, full Result) {
	t.Helper()
	if current.Draft() != full.Draft() || current.Status() != full.Status() ||
		current.Target() != full.Target() || current.CustodyStatus() != full.CustodyStatus() ||
		!reflect.DeepEqual(current.Checks(), full.Checks()) ||
		!reflect.DeepEqual(current.SignatureSets(), full.SignatureSets()) {
		t.Fatal("current and history-capable verification facts differ")
	}
	currentFlags, currentFlagsOK := current.TargetFlagCandidate()
	fullFlags, fullFlagsOK := full.TargetFlagCandidate()
	if currentFlagsOK != fullFlagsOK || currentFlags != fullFlags {
		t.Fatal("current and history-capable target flags differ")
	}
	currentReplay, currentReplayOK := current.ReplayProjection()
	fullReplay, fullReplayOK := full.ReplayProjection()
	if currentReplayOK != fullReplayOK || !reflect.DeepEqual(currentReplay, fullReplay) {
		t.Fatal("current and history-capable replay projections differ")
	}
}

// newCurrentHistoryVerificationFixture creates a current-PASS m=2 message with controlled history.
func newCurrentHistoryVerificationFixture(t *testing.T, recipeJSON string) verificationFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	previous := historyDigests(t, []byte("From: sender@example.test\r\nSubject:previous\r\n\r\nprevious\r\n"))
	placeholder := base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	unsignedRaw := currentHistoryRaw(headerDigest, bodyDigest, previous, recipeJSON, placeholder)
	unsigned := mustParseVerificationMessage(t, unsignedRaw)
	canonicalizer := mustCanonicalizer(t)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        unsigned.Headers(),
		TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	signatureText := base64.StdEncoding.EncodeToString(signatureBytes)
	fixture, err := parseVerificationFixture(currentHistoryRaw(headerDigest, bodyDigest, previous, recipeJSON, signatureText))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	fixture.algorithm = AlgorithmRSASHA256
	fixture.signatureBase64 = signatureText
	fixture.signatureBytes = signatureBytes
	fixture.bodyDigestBase64 = bodyDigest
	fixture.headerDigestBase64 = headerDigest
	fixture.rsaPublicKey = &key.PublicKey
	return fixture
}

// currentHistoryRaw renders one signed or placeholder current-history message.
func currentHistoryRaw(headerDigest, bodyDigest string, previous historyHashFixture, recipeJSON, signatureText string) string {
	return baseVerificationHeaders() +
		"Message-Instance: m=1; h=sha256:" + previous.header + ":" + previous.body + ";\r\n" +
		"Message-Instance: m=2; h=sha256:" + headerDigest + ":" + bodyDigest +
		"; r=" + base64.StdEncoding.EncodeToString([]byte(recipeJSON)) + ";\r\n" +
		"DKIM2-Signature: i=1; m=2; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=" +
		testDomain + "; s=" + testSelector + ":rsa-sha256:" + signatureText + ";\r\n\r\n" +
		verificationBody()
}
