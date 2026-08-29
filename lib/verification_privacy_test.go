package dkim2

import (
	"context"
	"crypto/rsa"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

const protectedVerificationMarker = "TOXIC-VERIFICATION-OWNER"

type markerPublicKeyProvider struct {
	marker string
}

// TestAuthenticReplayVerifyResultHidesSealedDigests proves embedded replay provenance stays opaque.
func TestAuthenticReplayVerifyResultHidesSealedDigests(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	result := verifyDNSVector(
		context.Background(),
		t,
		corpus,
		goldenVectorRSAPass,
		publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)},
	)
	if result.state == nil || !result.state.hasReplayProjection || !result.state.replayProjection.Valid() {
		t.Fatal("authentic PASS result omitted replay provenance")
	}
	origin, originOK := result.state.replayProjection.OriginReplayDigest()
	if !originOK {
		t.Fatal("authentic replay provenance was incomplete")
	}
	values := []any{
		result, &result, any(result), []VerifyResult{result}, map[VerifyResult]bool{result: true},
	}
	var formatted strings.Builder
	for _, value := range values {
		fmt.Fprintf(&formatted, "%s|%q|%v|%+v|%#v|%x|%X|%p\n", value, value, value, value, value, value, value, value)
	}
	text := formatted.String()
	for _, protected := range []string{
		hex.EncodeToString(origin[:]), fmt.Sprint(origin),
		testSigningDomain, "body line",
	} {
		if strings.Contains(text, protected) {
			t.Fatal("authentic result formatting exposed sealed replay or message state")
		}
	}
	assertProtectedVerificationSerializationRejected(t, result)
}

// LookupPublicKey returns a bounded missing-key outcome for privacy tests.
func (markerPublicKeyProvider) LookupPublicKey(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
	return MissingPublicKey(AlgorithmRSASHA256), nil
}

// TestVerificationOwnersHideProtectedStateAcrossFormatting proves pointer-backed public owners resist invalid verbs.
func TestVerificationOwnersHideProtectedStateAcrossFormatting(t *testing.T) {
	request := NewVerifyRequest(
		[]byte("X-Marker: "+protectedVerificationMarker+"\r\n\r\n"),
		[]byte("<"+protectedVerificationMarker+"@example.test>"),
		[][]byte{[]byte("<recipient-" + protectedVerificationMarker + "@example.test>")},
	)
	target := newVerificationTarget(18_446_744_073_709_551_615, 18_446_744_073_709_551_614)
	result := VerifyResult{state: &verifyResultState{
		draft:         protectedVerificationMarker,
		resultState:   ResultStatePASS,
		target:        target,
		primaryReason: ReasonNone,
		checks:        []CheckFact{newCheckFact(CheckClassProtocol, ReasonNone)},
	}}
	query := newPublicKeyQuery(protectedVerificationMarker+".example", protectedVerificationMarker, AlgorithmRSASHA256)
	keyResult := FoundRSAPublicKey((rsaPublicKeyForPrivacyTest{
		n: new(big.Int).SetBytes([]byte(protectedVerificationMarker)),
	}).publicKey())
	verifier, err := NewVerifier(markerPublicKeyProvider{marker: protectedVerificationMarker})
	if err != nil {
		t.Fatal("failed to construct privacy-test verifier")
	}

	values := []any{
		request, &request, target, &target, result, &result, query, &query, keyResult, &keyResult,
		*verifier, verifier,
		[]VerifyRequest{request}, map[VerifyRequest]VerifyResult{request: result},
		[]PublicKeyQuery{query}, map[PublicKeyResult]VerificationTarget{keyResult: target},
		[]Verifier{*verifier}, map[Verifier]PublicKeyQuery{*verifier: query},
	}
	assertProtectedVerificationFormatting(t, values)
	for _, value := range []any{request, target, result, query, keyResult, *verifier} {
		assertProtectedVerificationSerializationRejected(t, value)
	}
}

type rsaPublicKeyForPrivacyTest struct {
	n *big.Int
}

// publicKey returns marker-bearing public material without retaining a private key.
func (k rsaPublicKeyForPrivacyTest) publicKey() *rsa.PublicKey {
	return &rsa.PublicKey{N: k.n, E: 65_537}
}

// assertProtectedVerificationFormatting checks every normal and invalid formatting verb with constant diagnostics.
func assertProtectedVerificationFormatting(t *testing.T, values []any) {
	t.Helper()
	for _, value := range values {
		text := fmt.Sprintf("%s|%q|%v|%+v|%#v|%x|%X|%p", value, value, value, value, value, value, value, value)
		if strings.Contains(text, protectedVerificationMarker) ||
			strings.Contains(strings.ToLower(text), "544f584943") ||
			strings.Contains(text, "18446744073709551615") ||
			strings.Contains(strings.ToLower(text), "ffffffffffffffff") {
			t.Fatal("protected verification formatting exposed retained state")
		}
	}
}

// assertProtectedVerificationSerializationRejected checks both JSON and text serialization boundaries.
func assertProtectedVerificationSerializationRejected(t *testing.T, value any) {
	t.Helper()
	if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
		t.Fatal("protected verification owner allowed JSON serialization")
	}
	marshaler, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatal("protected verification owner omitted text serialization rejection")
	}
	if encoded, err := marshaler.MarshalText(); err == nil || len(encoded) != 0 {
		t.Fatal("protected verification owner allowed text serialization")
	}
}
