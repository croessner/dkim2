package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
)

// TestVerifyRevisionProofChecksEveryInheritedSignature proves all-hop crypto instead of highest-target reinterpretation.
func TestVerifyRevisionProofChecksEveryInheritedSignature(t *testing.T) {
	fixture := newNextDomainChainFixture(t, strings.ToUpper(nextHopDomain))
	lookups := 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		lookups++
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	})
	if err != nil {
		t.Fatalf("VerifyRevisionProof() error = %v", err)
	}
	if outcome != RevisionProofVerified || !proof.Valid() || lookups != 2 {
		t.Fatalf("outcome/proof = %q/%v, want verified valid proof", outcome, proof.Valid())
	}
	facts := proof.Facts()
	if facts.SignatureCount() != 2 || facts.InstanceCount() != 1 || facts.HighestSequence() != 2 || facts.HighestInstance() != 1 {
		t.Fatalf("facts = %#v, want complete two-hop evidence", facts)
	}
	if got := facts.Timestamps(); len(got) != 2 || got[0] != testTimestampSeconds || got[1] != testTimestampSeconds {
		t.Fatalf("timestamps = %#v, want both inherited hops", got)
	}

	// Mutate the first inherited set directly while leaving the highest signature valid.
	first := fixture.signatures[0].SignatureSets()[0].Signature().EncodedString()
	badFirst := fixture.signatures[0].SignatureSets()[0].Signature().Decoded()
	badFirst[0] ^= 1
	badRaw := strings.Replace(fixture.raw, first, base64.StdEncoding.EncodeToString(badFirst), 1)
	badMessage := mustParseVerificationMessage(t, badRaw)
	secondOriginal := fixture.signatures[1].SignatureSets()[0].Signature().EncodedString()
	secondDigest := signatureDigestForTarget(t, badMessage, 2)
	secondReplacement, signErr := rsa.SignPKCS1v15(rand.Reader, fixture.rsaPrivateKey, crypto.SHA256, secondDigest)
	if signErr != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", signErr)
	}
	badRaw = strings.Replace(badRaw, secondOriginal, base64.StdEncoding.EncodeToString(secondReplacement), 1)
	tampered := fixture.withRaw(badRaw)
	lookups = 0
	highest, verifyErr := verifier.Verify(context.Background(), Request{Message: tampered.message, Envelope: matchingEnvelope()})
	if verifyErr != nil || highest.Status() != TargetStatusPass {
		t.Fatalf("highest control = %q/%v, want cryptographically valid i=2", highest.Status(), verifyErr)
	}
	lookups = 0
	outcome, proof, err = verifier.VerifyRevisionProof(context.Background(), Request{Message: tampered.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofSignatureMismatch || proof.Valid() || lookups != 1 {
		t.Fatalf("tampered outcome/proof/error/lookups = %q/%v/%v/%d", outcome, proof.Valid(), err, lookups)
	}
}

// TestVerifyRevisionProofAfterCurrentDoesNotRepeatCurrentLookup proves one provider call per inherited signature.
func TestVerifyRevisionProofAfterCurrentDoesNotRepeatCurrentLookup(t *testing.T) {
	fixture := newNextDomainChainFixture(t, strings.ToUpper(nextHopDomain))
	lookups := 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		lookups++
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Message: fixture.message, Envelope: matchingEnvelope()}
	current, err := verifier.VerifyCurrent(context.Background(), request)
	if err != nil || current.Status() != TargetStatusPass || lookups != 1 {
		t.Fatalf("VerifyCurrent() = %q/%v lookups=%d", current.Status(), err, lookups)
	}
	outcome, proof, err := verifier.VerifyRevisionProofAfterCurrent(context.Background(), request, current)
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() || lookups != 2 {
		t.Fatalf("VerifyRevisionProofAfterCurrent() = %q/%t/%v lookups=%d", outcome, proof.Valid(), err, lookups)
	}
}

// TestVerifyRevisionProofCapturesOneClockBeforeProviderCalls locks deterministic all-hop timestamp evaluation.
func TestVerifyRevisionProofCapturesOneClockBeforeProviderCalls(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	nowCalls := 0
	providerCalls := 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		providerCalls++
		if nowCalls != 1 {
			t.Fatalf("provider called after %d clock captures, want 1", nowCalls)
		}
		return publicKeyResult(query.Algorithm, fixture.rsaPublicKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, WithClock(func() time.Time {
		nowCalls++
		return time.Unix(int64(testTimestampSeconds), 0).Add(time.Hour)
	}))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() || nowCalls != 1 || providerCalls != 1 {
		t.Fatalf("outcome/proof/error/clock/provider = %q/%v/%v/%d/%d", outcome, proof.Valid(), err, nowCalls, providerCalls)
	}
}

// TestRevisionInstantIsOwnedByTheConstructingVerifier locks the opaque operation-time boundary.
func TestRevisionInstantIsOwnedByTheConstructingVerifier(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	providerCalls, clockCalls := 0, 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		providerCalls++
		return publicKeyResult(query.Algorithm, fixture.rsaPublicKey, KeyStatusFound), nil
	})
	clock := func() time.Time {
		clockCalls++
		return time.Unix(int64(testTimestampSeconds), 0).Add(time.Hour)
	}
	verifier, err := NewVerifier(provider, WithClock(clock))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	instant, err := verifier.CaptureRevisionInstant()
	if err != nil || !instant.Valid() || instant.UnixSeconds() != testTimestampSeconds+3600 || clockCalls != 1 {
		t.Fatalf("CaptureRevisionInstant() = valid:%t seconds:%d error:%v clock:%d",
			instant.Valid(), instant.UnixSeconds(), err, clockCalls)
	}

	copiedVerifier := verifier
	outcome, prepared, err := copiedVerifier.PrepareRevisionProofAt(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	}, instant)
	if err != nil || outcome != "" || !prepared.Valid() || providerCalls != 0 || clockCalls != 1 {
		t.Fatalf("copied verifier prepare = %q/%t/%v provider:%d clock:%d",
			outcome, prepared.Valid(), err, providerCalls, clockCalls)
	}

	independent, err := NewVerifier(provider, WithClock(clock))
	if err != nil {
		t.Fatalf("NewVerifier(independent) error = %v", err)
	}
	outcome, rejected, err := independent.PrepareRevisionProofAt(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	}, instant)
	if !IsErrorCode(err, ErrorCodeInternalMisuse) || outcome != "" || rejected.Valid() ||
		providerCalls != 0 || clockCalls != 1 {
		t.Fatalf("independent verifier accepted instant = %q/%t/%v provider:%d clock:%d",
			outcome, rejected.Valid(), err, providerCalls, clockCalls)
	}

	outcome, rejected, err = verifier.PrepareRevisionProofAt(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	}, RevisionInstant{})
	if !IsErrorCode(err, ErrorCodeInternalMisuse) || outcome != "" || rejected.Valid() ||
		providerCalls != 0 || clockCalls != 1 {
		t.Fatalf("zero instant accepted = %q/%t/%v provider:%d clock:%d",
			outcome, rejected.Valid(), err, providerCalls, clockCalls)
	}
}

// TestPreparedRevisionProofIsProviderFreeFixedOrderAndSingleUse locks the two-phase callback contract.
func TestPreparedRevisionProofIsProviderFreeFixedOrderAndSingleUse(t *testing.T) {
	fixture := newReversedMultiSignatureFixture(t)
	var calls []Algorithm
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		calls = append(calls, query.Algorithm)
		switch query.Algorithm {
		case AlgorithmRSASHA256:
			return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
		case AlgorithmEd25519SHA256:
			return publicKeyResult(query.Algorithm, fixture.ed25519Key, KeyStatusFound), nil
		default:
			t.Fatalf("unexpected provider algorithm %q", query.Algorithm)
			return PublicKey{}, nil
		}
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	instant, err := verifier.CaptureRevisionInstant()
	if err != nil {
		t.Fatalf("CaptureRevisionInstant() error = %v", err)
	}
	outcome, prepared, err := verifier.PrepareRevisionProofAt(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	}, instant)
	if err != nil || outcome != "" || !prepared.Valid() || len(calls) != 0 {
		t.Fatalf("PrepareRevisionProofAt() = %q/%t/%v calls:%#v", outcome, prepared.Valid(), err, calls)
	}
	if usage := prepared.Usage(); !usage.Valid() || usage.ProviderCalls() != 2 || usage.KeyLookups() != 2 {
		t.Fatalf("prepared usage = %#v", usage)
	}

	outcome, proof, err := verifier.ExecutePreparedRevisionProof(context.Background(), prepared)
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
		t.Fatalf("ExecutePreparedRevisionProof() = %q/%t/%v", outcome, proof.Valid(), err)
	}
	if len(calls) != 2 || calls[0] != AlgorithmRSASHA256 || calls[1] != AlgorithmEd25519SHA256 {
		t.Fatalf("provider order = %#v", calls)
	}
	outcome, proof, err = verifier.ExecutePreparedRevisionProof(context.Background(), prepared)
	if !IsErrorCode(err, ErrorCodeInternalMisuse) || outcome != "" || proof.Valid() || len(calls) != 2 {
		t.Fatalf("second execute = %q/%t/%v calls:%#v", outcome, proof.Valid(), err, calls)
	}
}

// TestPreparedRevisionProofCopiesShareConcurrentSingleUseState locks copy-safe execution ownership.
func TestPreparedRevisionProofCopiesShareConcurrentSingleUseState(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	var callMu sync.Mutex
	providerCalls := 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		callMu.Lock()
		providerCalls++
		callMu.Unlock()
		return publicKeyResult(query.Algorithm, fixture.rsaPublicKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	instant, err := verifier.CaptureRevisionInstant()
	if err != nil {
		t.Fatalf("CaptureRevisionInstant() error = %v", err)
	}
	outcome, prepared, err := verifier.PrepareRevisionProofAt(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	}, instant)
	if err != nil || outcome != "" || !prepared.Valid() {
		t.Fatalf("PrepareRevisionProofAt() = %q/%t/%v", outcome, prepared.Valid(), err)
	}

	type result struct {
		outcome RevisionProofOutcome
		proof   RevisionProof
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		copied := prepared
		go func() {
			defer wait.Done()
			<-start
			gotOutcome, gotProof, gotErr := verifier.ExecutePreparedRevisionProof(context.Background(), copied)
			results <- result{outcome: gotOutcome, proof: gotProof, err: gotErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	successes, rejected := 0, 0
	for got := range results {
		switch {
		case got.err == nil && got.outcome == RevisionProofVerified && got.proof.Valid():
			successes++
		case IsErrorCode(got.err, ErrorCodeInternalMisuse) && got.outcome == "" && !got.proof.Valid():
			rejected++
		default:
			t.Fatalf("unexpected concurrent result = %q/%t/%v", got.outcome, got.proof.Valid(), got.err)
		}
	}
	callMu.Lock()
	gotCalls := providerCalls
	callMu.Unlock()
	if successes != 1 || rejected != 1 || gotCalls != 1 {
		t.Fatalf("concurrent execute successes:%d rejected:%d provider:%d", successes, rejected, gotCalls)
	}
}

// TestPreparedRevisionProofStopsBeforeLaterProviderCallsOnCancellation locks fail-closed I/O ordering.
func TestPreparedRevisionProofStopsBeforeLaterProviderCallsOnCancellation(t *testing.T) {
	fixture := newReversedMultiSignatureFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	var calls []Algorithm
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		calls = append(calls, query.Algorithm)
		cancel()
		switch query.Algorithm {
		case AlgorithmRSASHA256:
			return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
		case AlgorithmEd25519SHA256:
			return publicKeyResult(query.Algorithm, fixture.ed25519Key, KeyStatusFound), nil
		default:
			return PublicKey{}, nil
		}
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	instant, err := verifier.CaptureRevisionInstant()
	if err != nil {
		t.Fatalf("CaptureRevisionInstant() error = %v", err)
	}
	outcome, prepared, err := verifier.PrepareRevisionProofAt(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	}, instant)
	if err != nil || outcome != "" || !prepared.Valid() || len(calls) != 0 {
		t.Fatalf("PrepareRevisionProofAt() = %q/%t/%v calls:%#v", outcome, prepared.Valid(), err, calls)
	}
	outcome, proof, err := verifier.ExecutePreparedRevisionProof(ctx, prepared)
	if !errors.Is(err, context.Canceled) || outcome != "" || proof.Valid() ||
		len(calls) != 1 || calls[0] != AlgorithmRSASHA256 {
		t.Fatalf("canceled execute = %q/%t/%v calls:%#v", outcome, proof.Valid(), err, calls)
	}
}

// TestVerifyRevisionProofRejectsUnsupportedOnlyAndAllowsTerminalNextDomain locks the two legal issuance lanes.
func TestVerifyRevisionProofRejectsUnsupportedOnlyAndAllowsTerminalNextDomain(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	unsupported := fixture.withSignatureSet("future.test:future-sha256:AA==")
	verifier := mustVerifierForFixture(t, fixture)
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: unsupported.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofUnsupported || proof.Valid() {
		t.Fatalf("unsupported-only outcome/proof/error = %q/%v/%v", outcome, proof.Valid(), err)
	}

	terminal := newHighestNextDomainFixture(t)
	terminalVerifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: terminal.rsaKey,
	}})
	outcome, proof, err = terminalVerifier.VerifyRevisionProof(context.Background(), Request{Message: terminal.message})
	if err != nil || outcome != RevisionProofTerminalNextDomainAuthorizationRequired || !proof.Valid() || proof.State() != RevisionProofTerminalNextDomainAuthorizationRequired {
		t.Fatalf("terminal outcome/proof/error = %q/%q/%v", outcome, proof.State(), err)
	}
}

// TestVerifyRevisionProofRequiresEveryKnownSetAndIgnoresOnlyMixedUnknownExtensions locks per-field set semantics.
func TestVerifyRevisionProofRequiresEveryKnownSetAndIgnoresOnlyMixedUnknownExtensions(t *testing.T) {
	for _, fixture := range []multiSignatureFixture{newMultiSignatureFixture(t), newSupportedAndUnknownSignatureFixture(t)} {
		keys := fixture.validKeys()
		if len(fixture.ed25519Key) == 0 {
			keys = keys[:1]
		}
		verifier := mustVerifierWithKeys(t, keys)
		outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
		if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
			t.Fatalf("mixed-set outcome/proof/error = %q/%v/%v", outcome, proof.Valid(), err)
		}
	}

	fixture := newMultiSignatureFixture(t)
	keys := fixture.validKeys()
	keys[1].Material = fixture.wrongEd25519
	verifier := mustVerifierWithKeys(t, keys)
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofSignatureMismatch || proof.Valid() {
		t.Fatalf("one-known-failure outcome/proof/error = %q/%v/%v", outcome, proof.Valid(), err)
	}
}

// TestVerifyRevisionProofUsesCanonicalCallbackOrderAndSourceIndexedFacts locks RSA-before-Ed25519 evaluation.
func TestVerifyRevisionProofUsesCanonicalCallbackOrderAndSourceIndexedFacts(t *testing.T) {
	fixture := newReversedMultiSignatureFixture(t)
	var calls []Algorithm
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		calls = append(calls, query.Algorithm)
		switch query.Algorithm {
		case AlgorithmRSASHA256:
			return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
		case AlgorithmEd25519SHA256:
			return publicKeyResult(query.Algorithm, fixture.ed25519Key, KeyStatusFound), nil
		default:
			t.Fatalf("unexpected provider algorithm %q", query.Algorithm)
			return PublicKey{}, nil
		}
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	})
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
		t.Fatalf("revision proof = %q/%t/%v", outcome, proof.Valid(), err)
	}
	if len(calls) != 2 || calls[0] != AlgorithmRSASHA256 || calls[1] != AlgorithmEd25519SHA256 {
		t.Fatalf("provider callback order = %#v", calls)
	}
	facts := proof.Facts().Signatures()
	if len(facts) != 1 {
		t.Fatalf("signature facts = %d", len(facts))
	}
	sets := facts[0].Sets()
	if len(sets) != 2 || sets[0].Index() != 0 || sets[0].Algorithm() != AlgorithmEd25519SHA256 ||
		sets[1].Index() != 1 || sets[1].Algorithm() != AlgorithmRSASHA256 {
		t.Fatalf("source-indexed facts = %#v", sets)
	}
}

// TestRevisionProofRevalidationChecksEveryTimestampWithOneClock proves capabilities cannot outlive any inherited hop.
func TestRevisionProofRevalidationChecksEveryTimestampWithOneClock(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	now := time.Unix(int64(testTimestampSeconds), 0).Add(time.Hour)
	verifier := mustVerifierForFixtureWithOptions(t, fixture, WithClock(func() time.Time { return now }))
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
		t.Fatalf("issuance outcome/proof/error = %q/%v/%v", outcome, proof.Valid(), err)
	}

	now = time.Unix(int64(testTimestampSeconds), 0).Add(defaultMaxSignatureAge + time.Second)
	revalidation, err := verifier.RevalidateRevisionProof(context.Background(), proof)
	if err != nil || revalidation != RevisionProofTimestampInvalid {
		t.Fatalf("RevalidateRevisionProof() = %q/%v, want timestamp_invalid", revalidation, err)
	}
}

// TestVerifyRevisionProofRejectsTargetOverridesAndUnsafeTimePolicyBeforeWork locks the whole-chain API contract.
func TestVerifyRevisionProofRejectsTargetOverridesAndUnsafeTimePolicyBeforeWork(t *testing.T) {
	fixture := newHighestNextDomainFixture(t)
	providerCalls, clockCalls := 0, 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		providerCalls++
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	})
	clock := func() time.Time {
		clockCalls++
		return time.Unix(int64(testTimestampSeconds), 0)
	}
	verifier, err := NewVerifier(provider, WithClock(clock))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, request := range []Request{
		{Message: fixture.message, TargetSequence: 1},
		{Message: fixture.message, SkipEnvelopeForNonCurrentTarget: true},
	} {
		outcome, proof, verifyErr := verifier.VerifyRevisionProof(context.Background(), request)
		if verifyErr == nil || outcome.Known() || proof.Valid() || providerCalls != 0 || clockCalls != 0 {
			t.Fatalf("override result = %q/%v/%v calls=%d/%d", outcome, proof.Valid(), verifyErr, providerCalls, clockCalls)
		}
	}

	for _, policy := range []TimestampPolicy{
		{FutureTolerance: defaultFutureTolerance, MaxAge: 0},
		{FutureTolerance: defaultFutureTolerance, MaxAge: time.Hour},
		{FutureTolerance: defaultFutureTolerance, MaxAge: 15 * 24 * time.Hour},
		{FutureTolerance: 0, MaxAge: defaultMaxSignatureAge},
		{FutureTolerance: defaultFutureTolerance + time.Second, MaxAge: defaultMaxSignatureAge},
	} {
		unsafeVerifier, newErr := NewVerifier(provider, WithClock(clock), WithTimestampPolicy(policy))
		if newErr != nil {
			t.Fatalf("NewVerifier(custom policy) error = %v", newErr)
		}
		outcome, proof, verifyErr := unsafeVerifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message})
		if verifyErr == nil || outcome.Known() || proof.Valid() || providerCalls != 0 || clockCalls != 0 {
			t.Fatalf("unsafe policy result = %q/%v/%v calls=%d/%d", outcome, proof.Valid(), verifyErr, providerCalls, clockCalls)
		}
	}
}

// TestRevisionSignatureOutcomePrecedenceIsOrderIndependent locks provider-contract dominance.
func TestRevisionSignatureOutcomePrecedenceIsOrderIndependent(t *testing.T) {
	contract := SignatureSetResult{Status: SignatureSetStatusProviderContract}
	temporary := SignatureSetResult{Status: SignatureSetStatusProviderTemporary}
	permanent := SignatureSetResult{Status: SignatureSetStatusProviderPermanent}
	for _, sets := range [][]SignatureSetResult{
		{temporary, contract}, {contract, temporary}, {permanent, contract}, {contract, permanent},
	} {
		if got := revisionSignatureOutcome(signatureEvaluation{sets: sets}); got != RevisionProofProviderContract {
			t.Fatalf("revisionSignatureOutcome(%v) = %q, want provider_contract", sets, got)
		}
	}
	for _, sets := range [][]SignatureSetResult{{temporary, permanent}, {permanent, temporary}} {
		if got := revisionSignatureOutcome(signatureEvaluation{sets: sets}); got != RevisionProofProviderRejected {
			t.Fatalf("revisionSignatureOutcome(%v) = %q, want provider_rejected", sets, got)
		}
	}
}

// TestVerifyRevisionProofAllowsSignedRecipientSupersetsAndRejectsUnsignedRecipients locks Section 9.2 membership.
func TestVerifyRevisionProofAllowsSignedRecipientSupersetsAndRejectsUnsignedRecipients(t *testing.T) {
	recipients := [][]byte{[]byte("<a@example.test>"), []byte("<b@example.test>")}
	fixture := newRSAVerificationFixtureWithEnvelopeAt(t, testTimestampSeconds, []byte("<>"), recipients)
	verifier := mustVerifierForFixture(t, fixture)
	for _, envelope := range []Envelope{
		NewEnvelope([]byte("<>"), [][]byte{[]byte("<a@example.test>")}),
		NewEnvelope([]byte("<>"), [][]byte{[]byte("<a@example.test>"), []byte("<a@example.test>")}),
	} {
		outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: envelope})
		if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
			t.Fatalf("valid subset/duplicate envelope result = %q/%v/%v", outcome, proof.Valid(), err)
		}
	}
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
		Message: fixture.message, Envelope: NewEnvelope([]byte("<>"), [][]byte{[]byte("<c@example.test>")}),
	})
	if err != nil || outcome != RevisionProofProtocolRejected || proof.Valid() {
		t.Fatalf("unsigned recipient result = %q/%v/%v", outcome, proof.Valid(), err)
	}
}

// TestVerifyRevisionProofPreflightsWholeChainBeforeProviderCallbacks locks local timestamp and aggregate-limit ordering.
func TestVerifyRevisionProofPreflightsWholeChainBeforeProviderCallbacks(t *testing.T) {
	fixture := newSequentialSignatureFixture(t)
	for _, test := range []struct {
		name      string
		configure func(*RevisionLimits)
	}{
		{
			name: "aggregate signature sets",
			configure: func(limits *RevisionLimits) {
				limits.MaxTotalSignatureSets = 1
				limits.MaxPublicKeyLookups = 1
			},
		},
		{
			name: "aggregate key lookups",
			configure: func(limits *RevisionLimits) {
				limits.MaxPublicKeyLookups = 1
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerCalls := 0
			provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
				providerCalls++
				return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
			})
			limits := DefaultRevisionLimits()
			test.configure(&limits)
			verifier, err := NewVerifier(provider, testClockOption(), WithRevisionLimits(limits))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
				Message: fixture.message, Envelope: sequentialCurrentEnvelope(),
			})
			if err != nil || outcome != RevisionProofLimitExceeded || proof.Valid() || providerCalls != 0 {
				t.Fatalf("preflight result = %q/%t/%v calls=%d", outcome, proof.Valid(), err, providerCalls)
			}
		})
	}

	laterTimestamp := strings.LastIndex(fixture.raw, "t="+strconv.FormatUint(testTimestampSeconds, 10))
	if laterTimestamp < 0 {
		t.Fatal("sequential fixture lacks second timestamp")
	}
	timestampEnd := laterTimestamp + len("t="+strconv.FormatUint(testTimestampSeconds, 10))
	futureRaw := fixture.raw[:laterTimestamp] + "t=" + strconv.FormatUint(testTimestampSeconds+uint64(defaultFutureTolerance/time.Second)+1, 10) + fixture.raw[timestampEnd:]
	future := mustParseVerificationMessage(t, futureRaw)
	providerCalls := 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		providerCalls++
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, WithClock(func() time.Time {
		return time.Unix(int64(testTimestampSeconds), 0)
	}))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
		Message: future, Envelope: sequentialCurrentEnvelope(),
	})
	if err != nil || outcome != RevisionProofProtocolRejected || proof.Valid() || providerCalls != 0 {
		t.Fatalf("later timestamp result = %q/%t/%v calls=%d", outcome, proof.Valid(), err, providerCalls)
	}

	firstTimestamp := strings.Index(fixture.raw, "t="+strconv.FormatUint(testTimestampSeconds, 10))
	if firstTimestamp < 0 {
		t.Fatal("sequential fixture lacks first timestamp")
	}
	firstTimestampEnd := firstTimestamp + len("t="+strconv.FormatUint(testTimestampSeconds, 10))
	for _, test := range []struct {
		name      string
		timestamp uint64
	}{
		{
			name:      "old hop future",
			timestamp: testTimestampSeconds + uint64(defaultFutureTolerance/time.Second) + 1,
		},
		{
			name:      "old hop expired",
			timestamp: testTimestampSeconds - uint64(defaultMaxSignatureAge/time.Second) - 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := fixture.raw[:firstTimestamp] + "t=" + strconv.FormatUint(test.timestamp, 10) + fixture.raw[firstTimestampEnd:]
			message := mustParseVerificationMessage(t, raw)
			calls := 0
			provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
				calls++
				return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
			})
			verifier, err := NewVerifier(provider, WithClock(func() time.Time {
				return time.Unix(int64(testTimestampSeconds), 0)
			}))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
				Message: message, Envelope: sequentialCurrentEnvelope(),
			})
			if err != nil || outcome != RevisionProofProtocolRejected || proof.Valid() || calls != 0 {
				t.Fatalf("old-hop timestamp result = %q/%t/%v calls=%d", outcome, proof.Valid(), err, calls)
			}
		})
	}
}

// TestVerifyRevisionProofRejectsLaterUnsupportedOnlyBeforeProviderCallbacks locks global local preflight.
func TestVerifyRevisionProofRejectsLaterUnsupportedOnlyBeforeProviderCallbacks(t *testing.T) {
	fixture := newSequentialSignatureFixture(t)
	algorithm := string(AlgorithmRSASHA256)
	later := strings.LastIndex(fixture.raw, algorithm)
	if later < 0 {
		t.Fatal("sequential fixture lacks later algorithm")
	}
	raw := fixture.raw[:later] + "future-sha256" + fixture.raw[later+len(algorithm):]
	message := mustParseVerificationMessage(t, raw)
	calls := 0
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		calls++
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
		Message: message, Envelope: sequentialCurrentEnvelope(),
	})
	if err != nil || outcome != RevisionProofUnsupported || proof.Valid() || calls != 0 {
		t.Fatalf("later unsupported result = %q/%t/%v calls=%d", outcome, proof.Valid(), err, calls)
	}
}

// TestVerifyRevisionProofCanonicalWorkCapsAtExactAndOneOver locks aggregate and per-signature byte boundaries.
func TestVerifyRevisionProofCanonicalWorkCapsAtExactAndOneOver(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	baseline := mustVerifierForFixture(t, fixture)
	outcome, proof, err := baseline.VerifyRevisionProof(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	})
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
		t.Fatalf("baseline proof = %q/%t/%v", outcome, proof.Valid(), err)
	}
	usage := proof.Facts().Usage()
	if usage.CanonicalBytes() <= 1 || usage.SignatureCanonicalBytes() <= 1 {
		t.Fatalf("baseline usage = %#v", usage)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("canonical.NewCanonicalizer() error = %v", err)
	}
	signatureInput, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers: fixture.message.Headers(), TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	signatureInputBytes := signatureInput.Len()
	if signatureInputBytes <= 1 {
		t.Fatalf("signature input bytes = %d", signatureInputBytes)
	}

	for _, test := range []struct {
		name      string
		configure func(*RevisionLimits)
		want      RevisionProofOutcome
		wantCalls int
	}{
		{
			name: "aggregate exact",
			configure: func(limits *RevisionLimits) {
				limits.MaxCanonicalWorkBytes = usage.CanonicalBytes()
			},
			want: RevisionProofVerified, wantCalls: 1,
		},
		{
			name: "aggregate one over",
			configure: func(limits *RevisionLimits) {
				limits.MaxCanonicalWorkBytes = usage.CanonicalBytes() - 1
			},
			want: RevisionProofLimitExceeded,
		},
		{
			name: "signature exact",
			configure: func(limits *RevisionLimits) {
				limits.MaxSignatureInputBytes = signatureInputBytes
			},
			want: RevisionProofVerified, wantCalls: 1,
		},
		{
			name: "signature one over",
			configure: func(limits *RevisionLimits) {
				limits.MaxSignatureInputBytes = signatureInputBytes - 1
			},
			want: RevisionProofLimitExceeded,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
				calls++
				return publicKeyResult(query.Algorithm, fixture.rsaPublicKey, KeyStatusFound), nil
			})
			limits := DefaultRevisionLimits()
			test.configure(&limits)
			verifier, err := NewVerifier(provider, testClockOption(), WithRevisionLimits(limits))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
				Message: fixture.message, Envelope: matchingEnvelope(),
			})
			if err != nil || outcome != test.want || proof.Valid() != (test.want == RevisionProofVerified) || calls != test.wantCalls {
				t.Fatalf("work-cap result = %q/%t/%v calls=%d", outcome, proof.Valid(), err, calls)
			}
		})
	}
}

// TestVerifyRevisionProofRejectsUnsafeClockBeforeProviderCallbacks locks representable nonnegative operation time.
func TestVerifyRevisionProofRejectsUnsafeClockBeforeProviderCallbacks(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	for _, test := range []struct {
		name  string
		clock Clock
	}{
		{name: "negative", clock: func() time.Time { return time.Unix(-1, 0) }},
		{name: "unrepresentable callback", clock: func() time.Time { panic("clock state is not representable") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerCalls := 0
			provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
				providerCalls++
				return publicKeyResult(query.Algorithm, fixture.rsaPublicKey, KeyStatusFound), nil
			})
			verifier, err := NewVerifier(provider, WithClock(test.clock))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
				Message: fixture.message, Envelope: matchingEnvelope(),
			})
			if err == nil || outcome.Known() || proof.Valid() || providerCalls != 0 {
				t.Fatalf("unsafe clock result = %q/%t/%v calls=%d", outcome, proof.Valid(), err, providerCalls)
			}
		})
	}
}
