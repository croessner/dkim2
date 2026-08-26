package verify

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const ed25519Selector = "ed-selector.test"
const secondRSASelector = "rsa-selector-two.test"

type multiSignatureFixture struct {
	verificationFixture
	rsaPrivateKey *rsa.PrivateKey
	rsaKey        *rsa.PublicKey
	ed25519Key    ed25519.PublicKey
	wrongEd25519  ed25519.PublicKey
	sequenceOne   uint64
	sequenceTwo   uint64
}

type sameAlgorithmFixture struct {
	verificationFixture
	firstKey  *rsa.PublicKey
	secondKey *rsa.PublicKey
}

type selectorRecordingProvider struct {
	keys     map[string]any
	statuses map[string]KeyStatus
	queries  []KeyQuery
}

// LookupKey records each positional selector query and returns its controlled key result.
func (p *selectorRecordingProvider) LookupKey(_ context.Context, query KeyQuery) (PublicKey, error) {
	p.queries = append(p.queries, query)
	if status, present := p.statuses[query.Selector]; present {
		return PublicKey{Algorithm: query.Algorithm, Metadata: KeyMetadata{Status: status}}, nil
	}
	key, ok := p.keys[query.Selector]
	if !ok {
		return PublicKey{Algorithm: query.Algorithm, Metadata: KeyMetadata{Status: KeyStatusMissing}}, NewProviderFailure(ProviderFailurePermanent)
	}
	return PublicKey{Algorithm: query.Algorithm, Material: key, Metadata: KeyMetadata{Status: KeyStatusFound}}, nil
}

// TestVerifierChecksSameAlgorithmSignaturesPositionally proves selector lookup, k= matching, and crypto remain occurrence-bound.
func TestVerifierChecksSameAlgorithmSignaturesPositionally(t *testing.T) {
	fixture := newSameAlgorithmFixture(t)
	provider := &selectorRecordingProvider{keys: map[string]any{testSelector: fixture.firstKey, secondRSASelector: fixture.secondKey}}
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	requireSameAlgorithmResult(t, "correct", result, err, TargetStatusPass, SignatureSetStatusPass)
	if len(provider.queries) != 2 || provider.queries[0].Selector != testSelector || provider.queries[1].Selector != secondRSASelector || provider.queries[0].Algorithm != AlgorithmRSASHA256 || provider.queries[1].Algorithm != AlgorithmRSASHA256 {
		t.Fatalf("key queries = %#v", provider.queries)
	}

	wrong, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	provider = &selectorRecordingProvider{keys: map[string]any{testSelector: fixture.firstKey, secondRSASelector: &wrong.PublicKey}}
	verifier, err = NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	result, err = verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	requireSameAlgorithmResult(t, "wrong second RSA material", result, err, TargetStatusMixed, SignatureSetStatusFail)
	if !orderedSameAlgorithmQueries(provider.queries) {
		t.Fatalf("crypto-mismatch key queries = %#v", provider.queries)
	}

	provider = &selectorRecordingProvider{
		keys:     map[string]any{testSelector: fixture.firstKey},
		statuses: map[string]KeyStatus{secondRSASelector: KeyStatusAlgorithmMismatch},
	}
	verifier, err = NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	result, err = verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	requireSameAlgorithmResult(t, "second k= algorithm mismatch", result, err, TargetStatusMixed, SignatureSetStatusKeyAlgorithmMismatch)
	if !orderedSameAlgorithmQueries(provider.queries) {
		t.Fatalf("algorithm-mismatch key queries = %#v", provider.queries)
	}
}

// requireSameAlgorithmResult asserts the two positional occurrence results for one integration variant.
func requireSameAlgorithmResult(t *testing.T, name string, result Result, err error, wantTarget TargetStatus, wantSecond SignatureSetStatus) {
	t.Helper()
	sets := result.SignatureSets()
	if err != nil || result.Status() != wantTarget || len(sets) != 2 || sets[0].Index != 0 || sets[0].Status != SignatureSetStatusPass || sets[1].Index != 1 || sets[1].Status != wantSecond {
		t.Fatalf("Verify(%s) = status:%q sets:%#v error:%v", name, result.Status(), sets, err)
	}
}

// orderedSameAlgorithmQueries reports whether both selector lookups occurred once in source order.
func orderedSameAlgorithmQueries(queries []KeyQuery) bool {
	return len(queries) == 2 && queries[0].Selector == testSelector && queries[1].Selector == secondRSASelector &&
		queries[0].Algorithm == AlgorithmRSASHA256 && queries[1].Algorithm == AlgorithmRSASHA256
}

// TestVerifierAggregatesMultipleSignatureSets verifies all-checkable-signatures behavior.
func TestVerifierAggregatesMultipleSignatureSets(t *testing.T) {
	fixture := newMultiSignatureFixture(t)

	tests := []struct {
		name       string
		keys       []StaticKey
		wantStatus TargetStatus
		wantRSA    SignatureSetStatus
		wantEd     SignatureSetStatus
	}{
		{
			name:       "all pass",
			keys:       fixture.validKeys(),
			wantStatus: TargetStatusPass,
			wantRSA:    SignatureSetStatusPass,
			wantEd:     SignatureSetStatusPass,
		},
		{
			name: "mixed crypto failure",
			keys: []StaticKey{
				{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: fixture.rsaKey},
				{Domain: testDomain, Selector: ed25519Selector, Algorithm: AlgorithmEd25519SHA256, Material: fixture.wrongEd25519},
			},
			wantStatus: TargetStatusMixed,
			wantRSA:    SignatureSetStatusPass,
			wantEd:     SignatureSetStatusFail,
		},
		{
			name: "missing key mixed state",
			keys: []StaticKey{
				{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: fixture.rsaKey},
			},
			wantStatus: TargetStatusMixed,
			wantRSA:    SignatureSetStatusPass,
			wantEd:     SignatureSetStatusMissingKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := mustVerifierWithKeys(t, tt.keys)

			result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status() != tt.wantStatus {
				t.Fatalf("Status() = %q, want %q; sets=%#v checks=%#v", result.Status(), tt.wantStatus, result.SignatureSets(), result.Checks())
			}
			if !hasSignatureSet(result, AlgorithmRSASHA256, tt.wantRSA) || !hasSignatureSet(result, AlgorithmEd25519SHA256, tt.wantEd) {
				t.Fatalf("sets = %#v, want rsa=%s ed=%s", result.SignatureSets(), tt.wantRSA, tt.wantEd)
			}
		})
	}
}

// TestVerifierReportsUnknownOnlySignatureSets verifies unsupported-only targets cannot pass.
func TestVerifierReportsUnknownOnlySignatureSets(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	unsupported := fixture.withSignatureSet("selector.test:future-sha999:" + fixture.signatureBase64)
	verifier := mustVerifierWithKeys(t, nil)

	result, err := verifier.Verify(context.Background(), Request{Message: unsupported.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusUnsupported || !hasSignatureSet(result, AlgorithmUnknown, SignatureSetStatusUnsupportedAlgorithm) {
		t.Fatalf("result = %#v sets=%#v, want unsupported-only state", result, result.SignatureSets())
	}
	if projection, ok := result.ReplayProjection(); ok || projection.Valid() {
		t.Fatal("unsupported-only result produced replay projection")
	}
}

// TestVerifierIgnoresUnknownSignatureSetBesideSupportedPass verifies Section 3.4 aggregation.
func TestVerifierIgnoresUnknownSignatureSetBesideSupportedPass(t *testing.T) {
	fixture := newSupportedAndUnknownSignatureFixture(t)
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
		Material:  fixture.rsaKey,
	}})

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusPass {
		t.Fatalf("Status() = %q, want pass; sets=%#v checks=%#v", result.Status(), result.SignatureSets(), result.Checks())
	}
	if !hasSignatureSet(result, AlgorithmRSASHA256, SignatureSetStatusPass) ||
		!hasSignatureSet(result, AlgorithmUnknown, SignatureSetStatusUnsupportedAlgorithm) {
		t.Fatalf("sets = %#v, want supported pass plus ignored unknown", result.SignatureSets())
	}
	if projection, ok := result.ReplayProjection(); !ok || !projection.Valid() {
		t.Fatal("supported PASS plus ignored unknown set did not produce replay projection")
	}
}

// TestVerifierSelectsHighestCurrentSignature verifies default selection uses the largest contiguous i= sequence.
func TestVerifierSelectsHighestCurrentSignature(t *testing.T) {
	fixture := newSequentialSignatureFixture(t)
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
		Material:  fixture.rsaKey,
	}})

	result, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: sequentialCurrentEnvelope()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Status() != TargetStatusPass || result.Target().Sequence != fixture.sequenceTwo {
		t.Fatalf("target/status = %#v/%s, want highest sequence pass", result.Target(), result.Status())
	}
}

// TestVerifierRejectsCustodyBeforeProviderLookup verifies structural early failure.
func TestVerifierRejectsCustodyBeforeProviderLookup(t *testing.T) {
	fixture := newSequentialSignatureFixture(t)
	raw := strings.Replace(fixture.raw, "mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+", "mf=PHNlbmRlckBldmlsLnRlc3Q+", 1)
	message := mustParseVerificationMessage(t, raw)
	provider := &countingMissingProvider{}
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	_, err = verifier.Verify(context.Background(), Request{Message: message, Envelope: sequentialCurrentEnvelope()})
	if !IsErrorCode(err, ErrorCodeCustodyMismatch) || provider.count != 0 {
		t.Fatalf("Verify() error=%v provider_calls=%d, want early custody rejection", err, provider.count)
	}
}

// TestVerifierDoesNotExemptCurrentMismatchForHistoricalSelection verifies target binding.
func TestVerifierDoesNotExemptCurrentMismatchForHistoricalSelection(t *testing.T) {
	fixture := newSequentialSignatureFixture(t)
	raw := strings.Replace(fixture.raw, "mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+", "mf=PHNlbmRlckBldmlsLnRlc3Q+", 1)
	message := mustParseVerificationMessage(t, raw)
	provider := &countingMissingProvider{}
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	_, err = verifier.Verify(context.Background(), Request{Message: message, TargetSequence: fixture.sequenceOne})
	if !IsErrorCode(err, ErrorCodeCustodyMismatch) || provider.count != 0 {
		t.Fatalf("historical Verify() error=%v provider_calls=%d", err, provider.count)
	}
}

// TestVerifierCanSkipEnvelopeOnlyForExplicitNonCurrentDiagnostics verifies visible non-current skip facts.
func TestVerifierCanSkipEnvelopeOnlyForExplicitNonCurrentDiagnostics(t *testing.T) {
	fixture := newSequentialSignatureFixture(t)
	verifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
		Material:  fixture.rsaKey,
	}})

	strictResult, err := verifier.Verify(context.Background(), Request{
		Message:        fixture.message,
		TargetSequence: fixture.sequenceOne,
	})
	if err != nil {
		t.Fatalf("Verify() strict non-current error = %v", err)
	}
	if strictResult.Status() != TargetStatusFail || !hasEnvelopeCheck(strictResult, EnvelopeStatusMissing, CheckStatusFail) {
		t.Fatalf("strict result = %#v checks=%#v, want missing envelope failure", strictResult, strictResult.Checks())
	}

	result, err := verifier.Verify(context.Background(), Request{
		Message:                         fixture.message,
		TargetSequence:                  fixture.sequenceOne,
		SkipEnvelopeForNonCurrentTarget: true,
	})
	if err != nil {
		t.Fatalf("Verify() diagnostic non-current error = %v", err)
	}
	if result.Status() != TargetStatusPass || !hasEnvelopeCheck(result, EnvelopeStatusNotApplicable, CheckStatusNotApplicable) {
		t.Fatalf("result = %#v checks=%#v, want non-current envelope skip pass", result, result.Checks())
	}
}

// newMultiSignatureFixture creates one target field with RSA and Ed25519 signature sets.
func newMultiSignatureFixture(t *testing.T) multiSignatureFixture {
	return newOrderedMultiSignatureFixture(t, false)
}

// newReversedMultiSignatureFixture creates one target whose Ed25519 set precedes its RSA set in source order.
func newReversedMultiSignatureFixture(t *testing.T) multiSignatureFixture {
	return newOrderedMultiSignatureFixture(t, true)
}

// newOrderedMultiSignatureFixture creates one dual-signature target in controlled source order.
func newOrderedMultiSignatureFixture(t *testing.T, reverse bool) multiSignatureFixture {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(wrong) error = %v", err)
	}

	headerDigest, bodyDigest := baseMessageDigests(t)
	rsaPlaceholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	edPlaceholder := ed25519Selector + ":" + string(AlgorithmEd25519SHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, ed25519.SignatureSize))
	placeholderSet := orderedMultiSignatureSets(rsaPlaceholder, edPlaceholder, reverse)
	unsignedRaw := rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, placeholderSet)})
	unsigned := mustParseVerificationMessage(t, unsignedRaw)
	digest := signatureDigestForTarget(t, unsigned, 1)
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	edSignature := ed25519.Sign(edPrivate, digest)
	rsaSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(rsaSignature)
	edSet := ed25519Selector + ":" + string(AlgorithmEd25519SHA256) + ":" + base64.StdEncoding.EncodeToString(edSignature)
	signedSet := orderedMultiSignatureSets(rsaSet, edSet, reverse)
	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, signedSet)}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}

	return multiSignatureFixture{
		verificationFixture: parsed,
		rsaKey:              &rsaKey.PublicKey,
		ed25519Key:          edPublic,
		wrongEd25519:        wrongPublic,
	}
}

// newSameAlgorithmFixture signs two RSA occurrences with distinct selector-owned keys.
func newSameAlgorithmFixture(t *testing.T) sameAlgorithmFixture {
	t.Helper()
	first, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	placeholder := base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	set := func(selector, signatureText string) string {
		return selector + ":" + string(AlgorithmRSASHA256) + ":" + signatureText
	}
	unsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, set(testSelector, placeholder)+","+set(secondRSASelector, placeholder))}))
	digest := signatureDigestForTarget(t, unsigned, 1)
	firstSignature, err := rsa.SignPKCS1v15(rand.Reader, first, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	secondSignature, err := rsa.SignPKCS1v15(rand.Reader, second, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	signedSets := set(testSelector, base64.StdEncoding.EncodeToString(firstSignature)) + "," + set(secondRSASelector, base64.StdEncoding.EncodeToString(secondSignature))
	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, signedSets)}))
	if err != nil {
		t.Fatal(err)
	}
	return sameAlgorithmFixture{verificationFixture: parsed, firstKey: &first.PublicKey, secondKey: &second.PublicKey}
}

// orderedMultiSignatureSets joins controlled RSA and Ed25519 sets in source or reversed order.
func orderedMultiSignatureSets(rsaSet, edSet string, reverse bool) string {
	if reverse {
		return edSet + "," + rsaSet
	}
	return rsaSet + "," + edSet
}

// newSupportedAndUnknownSignatureFixture signs a target containing one supported and one future set.
func newSupportedAndUnknownSignatureFixture(t *testing.T) multiSignatureFixture {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	unknownSignature := base64.StdEncoding.EncodeToString(bytesOf(0x42, 32))
	placeholderSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128)) + "," +
		"future-selector.test:future-sha999:" + unknownSignature
	unsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, placeholderSet)}))
	digest := signatureDigestForTarget(t, unsigned, 1)
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	signedSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(rsaSignature) + "," +
		"future-selector.test:future-sha999:" + unknownSignature
	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, signedSet)}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}

	return multiSignatureFixture{verificationFixture: parsed, rsaKey: &rsaKey.PublicKey}
}

// newSequentialSignatureFixture creates two contiguous DKIM2-Signature fields.
func newSequentialSignatureFixture(t *testing.T) multiSignatureFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))

	firstUnsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, placeholder)}))
	firstDigest := signatureDigestForTarget(t, firstUnsigned, 1)
	firstSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, firstDigest)
	if err != nil {
		t.Fatalf("first rsa.SignPKCS1v15() error = %v", err)
	}
	firstSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(firstSignature)

	secondField := func(sequence uint64, sets string) string {
		return strings.Replace(signatureField(sequence, sets), "mf=PD4=", "mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+", 1)
	}
	secondUnsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{
		signatureField(1, firstSet),
		secondField(2, placeholder),
	}))
	secondDigest := signatureDigestForTarget(t, secondUnsigned, 2)
	secondSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, secondDigest)
	if err != nil {
		t.Fatalf("second rsa.SignPKCS1v15() error = %v", err)
	}
	secondSet := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(secondSignature)

	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{
		signatureField(1, firstSet),
		secondField(2, secondSet),
	}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}

	return multiSignatureFixture{
		verificationFixture: parsed,
		rsaKey:              &key.PublicKey,
		sequenceOne:         1,
		sequenceTwo:         2,
	}
}

// sequentialCurrentEnvelope returns the non-null envelope recorded by the second fixture signature.
func sequentialCurrentEnvelope() Envelope {
	return NewEnvelope([]byte("<sender@example.test>"), [][]byte{[]byte("<rcpt@example.test>")})
}

// validKeys returns static keys for every known signature set in the fixture.
func (f multiSignatureFixture) validKeys() []StaticKey {
	return []StaticKey{
		{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: f.rsaKey},
		{Domain: testDomain, Selector: ed25519Selector, Algorithm: AlgorithmEd25519SHA256, Material: f.ed25519Key},
	}
}

// baseMessageDigests returns current M3 header and body digest strings.
func baseMessageDigests(t *testing.T) (string, string) {
	t.Helper()

	canonicalizer := mustCanonicalizer(t)
	message := mustParseVerificationMessage(t, baseVerificationHeaders()+"\r\n"+verificationBody())
	bodyHash, err := canonicalizer.BodyHashFromMessage(message)
	if err != nil {
		t.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	headerHash, err := canonicalizer.HeaderHashFromMessage(message)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}

	return mustDigest(t, headerHash).Base64(), mustDigest(t, bodyHash).Base64()
}

// signatureDigestForTarget returns the SHA-256 digest over Section 9.6 input.
func signatureDigestForTarget(t *testing.T, message rawmsg.Message, target uint64) []byte {
	t.Helper()

	canonicalizer := mustCanonicalizer(t)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        message.Headers(),
		TargetSequence: target,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())

	return digest[:]
}

// rawWithSignatureFields renders a synthetic message with supplied signature field bodies.
func rawWithSignatureFields(headerDigest string, bodyDigest string, signatureFields []string) string {
	var raw strings.Builder
	raw.WriteString(baseVerificationHeaders() +
		"Message-Instance: m=1; h=sha256:" + headerDigest + ":" + bodyDigest + ";\r\n")
	for _, field := range signatureFields {
		raw.WriteString("DKIM2-Signature: " + field + "\r\n")
	}

	return raw.String() + "\r\n" + verificationBody()
}

// signatureField renders a bounded synthetic DKIM2-Signature value.
func signatureField(sequence uint64, signatureSets string) string {
	return "i=" + strconv.FormatUint(sequence, 10) + "; m=1; t=" + strconv.FormatUint(testTimestampSeconds, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=" + testDomain + "; s=" + signatureSets + ";"
}
