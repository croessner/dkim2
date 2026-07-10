package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var syntheticSecretMarkers = []string{
	"HEADER-SECRET-MARKER",
	"BODY-SECRET-MARKER",
	"PATH-SECRET-MARKER",
	"NONCE-SECRET-MARKER",
	"SIGNATURE-SECRET-MARKER",
	"KEY-SECRET-MARKER",
}

// TestVerifierDiagnosticsDoNotExposeSecretMarkers verifies result and error summaries are bounded.
func TestVerifierDiagnosticsDoNotExposeSecretMarkers(t *testing.T) {
	fixture := newDeterministicRSAVerificationFixture(t)
	verifier, err := NewVerifier(providerFunc(func(context.Context, KeyQuery) (PublicKey, error) {
		return publicKeyResult(AlgorithmRSASHA256, nil, KeyStatusProviderError), providerError(AlgorithmRSASHA256, errors.New(strings.Join(syntheticSecretMarkers, " ")))
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	result, err := verifier.Verify(context.Background(), Request{
		Message:  fixture.message,
		Envelope: NewEnvelope([]byte("<PATH-SECRET-MARKER@example.test>"), [][]byte{[]byte("<BODY-SECRET-MARKER@example.test>")}),
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	assertNoSyntheticSecretMarkers(t, fmt.Sprintf("%#v", result))
	for _, check := range result.Checks() {
		assertNoSyntheticSecretMarkers(t, fmt.Sprintf("%#v", check))
	}
	for _, set := range result.SignatureSets() {
		assertNoSyntheticSecretMarkers(t, fmt.Sprintf("%#v", set))
	}
}

// TestVerificationErrorsDoNotExposeSecretMarkers verifies direct error rendering is secret-safe.
func TestVerificationErrorsDoNotExposeSecretMarkers(t *testing.T) {
	err := providerError(Algorithm("rsa-sha256:SIGNATURE-SECRET-MARKER"), errors.New("KEY-SECRET-MARKER BODY-SECRET-MARKER"))
	text := err.Error()

	assertNoSyntheticSecretMarkers(t, text)
	if !strings.Contains(text, "algorithm=redacted") {
		t.Fatalf("Error() = %q, want redacted unsafe algorithm", text)
	}
}

// assertNoSyntheticSecretMarkers fails when text contains synthetic secret markers.
func assertNoSyntheticSecretMarkers(t testing.TB, text string) {
	t.Helper()

	for _, marker := range syntheticSecretMarkers {
		if strings.Contains(text, marker) {
			t.Fatalf("text leaked synthetic marker %q in %q", marker, text)
		}
	}
}
