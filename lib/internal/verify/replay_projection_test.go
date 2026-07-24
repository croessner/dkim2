package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/replay"
)

// TestRecipientScopeUsesExactFrozenCanonicalizationAndFraming verifies the published SHA-256 vector.
func TestRecipientScopeUsesExactFrozenCanonicalizationAndFraming(t *testing.T) {
	scope, err := recipientScopeFromValidatedPath([]byte("<Local@EXAMPLE.COM>"))
	if err != nil {
		t.Fatalf("recipientScopeFromValidatedPath() error = %v", err)
	}
	want, err := hex.DecodeString("3e99bb34388fad3ca2111ccd467029a2a4582b94b9012f3ac603894972291305")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scope.digest[:], want) {
		t.Fatal("recipient digest mismatch")
	}

	equivalent, err := recipientScopeFromValidatedPath([]byte("<Local@example.com>"))
	if err != nil || scope != equivalent {
		t.Fatalf("ASCII domain case was not canonicalized: equal=%t error=%v", scope == equivalent, err)
	}
	differentLocal, err := recipientScopeFromValidatedPath([]byte("<local@example.com>"))
	if err != nil || scope == differentLocal {
		t.Fatalf("local-part case was normalized: equal=%t error=%v", scope == differentLocal, err)
	}
}

// TestRecipientScopePreservesAlreadyValidatedPathBytes verifies no unsupported normalization is invented.
func TestRecipientScopePreservesAlreadyValidatedPathBytes(t *testing.T) {
	cases := [][2]string{
		{"<@ROUTE.TEST:Local@EXAMPLE.COM>", "<@route.test:Local@example.com>"},
		{"<\"A@B\"@EXAMPLE.COM>", "<\"A@B\"@example.com>"},
		{"<local@[IPv6:2001:DB8::1]>", "<local@[ipv6:2001:db8::1]>"},
		{"<local@[TAG:A@B]>", "<local@[tag:a@b]>"},
	}
	for _, test := range cases {
		left, err := recipientScopeFromValidatedPath([]byte(test[0]))
		if err != nil {
			t.Fatalf("recipientScopeFromValidatedPath(%q) error = %v", test[0], err)
		}
		right, err := recipientScopeFromValidatedPath([]byte(test[1]))
		if err != nil || left != right {
			t.Fatalf("domain canonicalization %q/%q equal=%t error=%v", test[0], test[1], left == right, err)
		}
	}
	for _, path := range [][]byte{
		nil,
		{},
		[]byte("<>"),
		[]byte("<local>"),
		[]byte("<ü@example.test>"),
		[]byte("local@example.test"),
	} {
		if _, scopeErr := recipientScopeFromValidatedPath(path); scopeErr == nil {
			t.Fatalf("recipientScopeFromValidatedPath(%q) accepted invalid framing", path)
		}
	}
}

// TestReplayProjectionIsSealedOnlyByAuthoritativeCurrentPass verifies provenance and exact digest facts.
func TestReplayProjectionIsSealedOnlyByAuthoritativeCurrentPass(t *testing.T) {
	signedRecipients := [][]byte{
		[]byte("<Case@EXAMPLE.TEST>"),
		[]byte("<Case@example.test>"),
		[]byte("<other@example.test>"),
	}
	fixture := newRSAVerificationFixtureWithEnvelopeAt(t, testTimestampSeconds, []byte("<>"), signedRecipients)
	verifier := mustVerifierForFixture(t, fixture)
	currentRecipients := [][]byte{
		[]byte("<Case@example.test>"),
		[]byte("<Case@EXAMPLE.TEST>"),
		[]byte("<other@EXAMPLE.TEST>"),
	}
	result, err := verifier.Verify(context.Background(), Request{
		Message: fixture.message, Envelope: NewEnvelope([]byte("<>"), currentRecipients),
	})
	if err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("Verify() = %q, %v", result.Status(), err)
	}
	projection, ok := result.ReplayProjection()
	if !ok || !projection.Valid() || projection.Draft() != replay.DraftIdentifier ||
		projection.RecipientCount() != 2 || projection.Exploded() {
		t.Fatalf("ReplayProjection() = valid:%t recipients:%d exploded:%t ok:%t",
			projection.Valid(), projection.RecipientCount(), projection.Exploded(), ok)
	}

	hashSet, status := fixture.instances[0].SHA256HashSet()
	if status != instance.HashSelectionStatusSelected {
		t.Fatal("test prerequisite lacks selected SHA-256 set")
	}
	headerHash, ok := hashSet.HeaderHash()
	if !ok {
		t.Fatal("test prerequisite lacks header hash")
	}
	wantMessage := headerHash.Decoded()
	gotMessage, present := projection.MessageDigest()
	if !present || !bytes.Equal(gotMessage[:], wantMessage) {
		t.Fatal("projection message digest is not the selected matched Message-Instance hash")
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal(err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers: fixture.message.Headers(), TargetSequence: result.Target().Sequence,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSignature, err := canonicalizer.SHA256Digest(input)
	if err != nil {
		t.Fatal(err)
	}
	gotSignature, present := projection.SignatureInputDigest()
	if !present || !bytes.Equal(gotSignature[:], wantSignature.Bytes()) {
		t.Fatal("projection signature digest is not the authoritative canonical input digest")
	}

	first, firstOK := projection.RecipientDigest(0)
	second, secondOK := projection.RecipientDigest(1)
	if !firstOK || !secondOK || bytes.Compare(first[:], second[:]) >= 0 {
		t.Fatal("recipient digests are absent, duplicated, or unsorted")
	}
	first = [32]byte{}
	fresh, freshOK := result.ReplayProjection()
	freshFirst, digestOK := fresh.RecipientDigest(0)
	if !freshOK || !digestOK || freshFirst == ([32]byte{}) {
		t.Fatal("projection accessor exposed mutable storage")
	}

	forged := NewResultWithCustody(
		result.Target(), TargetStatusPass, result.Checks(), result.SignatureSets(), result.CustodyStatus(),
	)
	if projection, forgedOK := forged.ReplayProjection(); forgedOK || projection.Valid() {
		t.Fatal("public result facts forged replay provenance")
	}
}

// TestReplayProjectionAcceptsOwnerValidatedOddForwardPaths verifies matching end-to-end evidence.
func TestReplayProjectionAcceptsOwnerValidatedOddForwardPaths(t *testing.T) {
	for _, test := range [][2][]byte{
		{[]byte("<@ROUTE.TEST:local@EXAMPLE.TEST>"), []byte("<@route.test:local@example.test>")},
		{[]byte("<\"quoted@local\"@EXAMPLE.TEST>"), []byte("<\"quoted@local\"@example.test>")},
		{[]byte("<local@[TAG:A@B]>"), []byte("<local@[tag:a@b]>")},
		{[]byte("<local@[IPv6:2001:DB8::1]>"), []byte("<local@[ipv6:2001:db8::1]>")},
	} {
		fixture := newRSAVerificationFixtureWithEnvelopeAt(
			t, testTimestampSeconds, []byte("<>"), [][]byte{test[0]},
		)
		verifier := mustVerifierForFixture(t, fixture)
		result, err := verifier.Verify(context.Background(), Request{
			Message: fixture.message, Envelope: NewEnvelope([]byte("<>"), [][]byte{test[1]}),
		})
		if err != nil || result.Status() != TargetStatusPass {
			t.Fatalf("Verify(%q/%q) = %q, %v", test[0], test[1], result.Status(), err)
		}
		projection, ok := result.ReplayProjection()
		if !ok || !projection.Valid() || projection.RecipientCount() != 1 {
			t.Fatalf("owner-validated path %q/%q lacks projection", test[0], test[1])
		}
	}
}

// TestReplayProjectionExplodedORIncludesAuthenticatedPredecessors verifies complete current-chain coverage.
func TestReplayProjectionExplodedORIncludesAuthenticatedPredecessors(t *testing.T) {
	fixture := newNextDomainChainFixture(t, strings.ToUpper(nextHopDomain))
	firstOriginal := fixture.signatures[0].SignatureSets()[0].Signature().EncodedString()
	raw := strings.Replace(fixture.raw, "; d="+testDomain+";", "; f=exploded; d="+testDomain+";", 1)
	message := mustParseVerificationMessage(t, raw)
	secondOriginal := fixture.signatures[1].SignatureSets()[0].Signature().EncodedString()
	digest := signatureDigestForTarget(t, message, 2)
	secondSignature, err := rsa.SignPKCS1v15(rand.Reader, fixture.rsaPrivateKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	raw = strings.Replace(raw, secondOriginal, base64.StdEncoding.EncodeToString(secondSignature), 1)
	message = mustParseVerificationMessage(t, raw)
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	})
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), Request{Message: message, Envelope: matchingEnvelope()})
	if err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("Verify() = %q, %v (first signature %d bytes)", result.Status(), err, len(firstOriginal))
	}
	projection, ok := result.ReplayProjection()
	if !ok || !projection.Valid() || !projection.Exploded() {
		t.Fatal("authenticated predecessor exploded flag was not ORed")
	}
}

// TestReplayProjectionRejectsHistoricalAndTestingOnlyEvidence verifies non-production provenance lanes.
func TestReplayProjectionRejectsHistoricalAndTestingOnlyEvidence(t *testing.T) {
	chain := newNextDomainChainFixture(t, strings.ToUpper(nextHopDomain))
	chainVerifier := mustVerifierWithKeys(t, []StaticKey{{
		Domain: testDomain, Selector: testSelector,
		Algorithm: AlgorithmRSASHA256, Material: chain.rsaKey,
	}})
	historical, err := chainVerifier.Verify(context.Background(), Request{
		Message: chain.message, TargetSequence: 1,
	})
	if err != nil || historical.Status() != TargetStatusPass {
		t.Fatalf("historical Verify() = %q, %v", historical.Status(), err)
	}
	if projection, ok := historical.ReplayProjection(); ok || projection.Valid() {
		t.Fatal("explicit historical target produced replay projection")
	}

	fixture := newRSAVerificationFixture(t)
	provider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		return PublicKey{
			Algorithm: query.Algorithm,
			Material:  fixture.rsaPublicKey,
			Metadata: KeyMetadata{
				Status: KeyStatusFound,
				Policy: KeyPolicyMetadata{TestingDeclared: true},
			},
		}, nil
	})
	testingVerifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	testingOnly, err := testingVerifier.Verify(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	})
	if err != nil || testingOnly.Status() != TargetStatusPass {
		t.Fatalf("testing Verify() = %q, %v", testingOnly.Status(), err)
	}
	if projection, ok := testingOnly.ReplayProjection(); ok || projection.Valid() {
		t.Fatal("DNS testing-only PASS produced replay projection")
	}

	mixedFixture := newMultiSignatureFixture(t)
	mixedProvider := providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		key := PublicKey{
			Algorithm: query.Algorithm,
			Metadata:  KeyMetadata{Status: KeyStatusFound},
		}
		switch query.Algorithm {
		case AlgorithmRSASHA256:
			key.Material = mixedFixture.rsaKey
			key.Metadata.Policy.TestingDeclared = true
		case AlgorithmEd25519SHA256:
			key.Material = mixedFixture.ed25519Key
		default:
			t.Fatalf("unexpected key query algorithm %q", query.Algorithm)
		}
		return key, nil
	})
	mixedVerifier, err := NewVerifier(mixedProvider, testClockOption())
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := mixedVerifier.Verify(context.Background(), Request{
		Message: mixedFixture.message, Envelope: matchingEnvelope(),
	})
	if err != nil || mixed.Status() != TargetStatusPass {
		t.Fatalf("mixed Verify() = %q, %v", mixed.Status(), err)
	}
	if projection, ok := mixed.ReplayProjection(); !ok || !projection.Valid() {
		t.Fatal("mixed testing/plain PASS did not produce replay projection")
	}
}

// TestReplayProjectionFormattingDoesNotExposePrivateFacts verifies nested Result privacy.
func TestReplayProjectionFormattingDoesNotExposePrivateFacts(t *testing.T) {
	var marker [32]byte
	copy(marker[:], []byte("TOXIC-REPLAY-PROJECTION-MARKER"))
	projection := ReplayProjection{
		draft:         replay.DraftIdentifier,
		messageDigest: marker, hasMessageDigest: true,
		signatureInputDigest: marker, hasSignatureInputDigest: true,
		recipientDigests: [][32]byte{marker},
		sealed:           true,
	}
	result := Result{replayProjection: projection, hasReplayProjection: true}
	for _, value := range []any{
		projection, &projection, result, &result,
		[]Result{result}, map[string]Result{"result": result},
	} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") ||
			strings.Contains(formatted, "84 79 88 73 67") {
			t.Fatalf("%T formatting exposed replay facts: %q", value, formatted)
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "TOXIC") ||
			strings.Contains(string(encoded), "VE9YSUM") {
			t.Fatalf("json.Marshal(%T) = %s, %v", value, encoded, err)
		}
	}
}

// TestReplayIntermediatesFormattingDoesNotExposePrivateFacts verifies transient helper privacy.
func TestReplayIntermediatesFormattingDoesNotExposePrivateFacts(t *testing.T) {
	var marker [32]byte
	copy(marker[:], []byte("TOXIC-REPLAY-INTERMEDIATE"))
	scope := recipientScope{
		canonical: "TOXIC-RECIPIENT@example.test",
		digest:    marker,
		valid:     true,
	}
	hashes := hashCheckResults{
		selectedHeaderDigest:    marker,
		hasSelectedHeaderDigest: true,
	}
	for _, value := range []any{scope, &scope, hashes, &hashes} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") ||
			strings.Contains(formatted, "84 79 88 73 67") {
			t.Fatalf("%T formatting exposed replay intermediate facts: %q", value, formatted)
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "TOXIC") ||
			strings.Contains(string(encoded), "VE9YSUM") {
			t.Fatalf("json.Marshal(%T) = %s, %v", value, encoded, err)
		}
	}
}
