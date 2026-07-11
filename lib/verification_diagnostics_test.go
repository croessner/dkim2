package dkim2

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

const publicToxicMarker = "PUBLIC-VERIFY-TOXIC-MARKER"

type toxicTemporaryProviderError struct{}

// Error returns provider-owned toxic text that must be discarded at the boundary.
func (toxicTemporaryProviderError) Error() string { return publicToxicMarker }

// ProviderErrorClass classifies the synthetic provider error without relying on its text.
func (toxicTemporaryProviderError) ProviderErrorClass() ProviderErrorClass {
	return ProviderErrorClassTemporary
}

// TestPublicDiagnosticsDiscardProtectedValues proves public formatting retains only bounded tokens.
func TestPublicDiagnosticsDiscardProtectedValues(t *testing.T) {
	toxicRaw := []byte("From: " + publicToxicMarker + "@example.test\r\nSubject: " + publicToxicMarker + "\r\n\r\n" + publicToxicMarker + "\r\n")
	toxicPath := []byte("<" + publicToxicMarker + "@example.test>")
	provider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, toxicTemporaryProviderError{}
	})
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("diagnostic verifier construction failed")
	}

	results := make([]VerifyResult, 0, 2)
	malformed, malformedErr := verifier.Verify(context.Background(), NewVerifyRequest(toxicRaw, toxicPath, [][]byte{toxicPath}))
	if malformedErr != nil {
		t.Fatal("message diagnostic escaped as Go error")
	}
	results = append(results, malformed)
	providerResult, providerErr := verifier.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if providerErr != nil || providerResult.PrimaryReason() != ReasonProviderTemporary {
		t.Fatal("typed provider diagnostic did not remain structured")
	}
	results = append(results, providerResult)
	valid := publicProviderFixture(t)
	lowerMarker := strings.ToLower(publicToxicMarker)
	markerBase64 := base64.StdEncoding.EncodeToString([]byte(publicToxicMarker))
	markerProvider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(&rsa.PublicKey{N: new(big.Int).SetBytes([]byte(publicToxicMarker)), E: 65537}), nil
	})
	for _, testCase := range []struct {
		raw      []byte
		provider PublicKeyProvider
	}{
		{raw: bytes.Replace(valid, []byte("selector.test"), []byte(lowerMarker+".test"), 1), provider: provider},
		{raw: bytes.Replace(valid, []byte("rsa-sha256"), []byte("future-"+lowerMarker), 1), provider: provider},
		{raw: bytes.Replace(valid, []byte("; d=example.test;"), []byte("; n="+lowerMarker+"; d=example.test;"), 1), provider: provider},
		{raw: replacePublicDiagnosticSignature(valid, markerBase64), provider: provider},
		{raw: replacePublicDiagnosticHash(valid, markerBase64), provider: provider},
		{raw: valid, provider: markerProvider},
		{raw: bytes.Replace(valid, []byte("Subject: provider facade"), []byte("Subject: token="+lowerMarker+" credential="+lowerMarker), 1), provider: provider},
	} {
		caseVerifier, constructErr := NewVerifier(testCase.provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
		if constructErr != nil {
			t.Fatal("toxic-case verifier construction failed")
		}
		caseResult, caseErr := caseVerifier.Verify(context.Background(), NewVerifyRequest(testCase.raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
		if caseErr != nil {
			t.Fatal("toxic message-derived state escaped as Go error")
		}
		formatted := fmt.Sprintf("%v %#v %v %v %v %v %v", caseResult, caseResult, caseResult.Checks(), caseResult.SignatureSets(), caseResult.Target(), caseResult.PrimaryReason(), caseErr)
		for _, forbidden := range []string{publicToxicMarker, lowerMarker, markerBase64} {
			if strings.Contains(formatted, forbidden) {
				t.Fatal("public diagnostics leaked a protected marker")
			}
		}
	}

	for _, result := range results {
		formatted := fmt.Sprintf("%v %#v %v %v %v %v", result, result, result.Checks(), result.SignatureSets(), result.Target(), result.PrimaryReason())
		if strings.Contains(formatted, publicToxicMarker) {
			t.Fatal("public result formatting leaked protected input")
		}
	}
	for _, publicErr := range []error{newAPIError(APIErrorCodeInvalidRequest), NewTemporaryProviderError(), NewPermanentProviderError()} {
		if strings.Contains(fmt.Sprintf("%v %#v", publicErr, publicErr), publicToxicMarker) {
			t.Fatal("public error formatting leaked protected input")
		}
	}
}

// replacePublicDiagnosticSignature injects synthetic decoded marker bytes into one signature container.
func replacePublicDiagnosticSignature(raw []byte, replacement string) []byte {
	marker := []byte("s=selector.test:rsa-sha256:")
	start := bytes.Index(raw, marker)
	if start < 0 {
		return bytes.Clone(raw)
	}
	start += len(marker)
	end := bytes.IndexByte(raw[start:], ';')
	if end < 0 {
		return bytes.Clone(raw)
	}
	result := bytes.Clone(raw[:start])
	result = append(result, replacement...)
	return append(result, raw[start+end:]...)
}

// replacePublicDiagnosticHash injects synthetic decoded marker bytes into the SHA-256 header hash container.
func replacePublicDiagnosticHash(raw []byte, replacement string) []byte {
	marker := []byte("h=sha256:")
	start := bytes.Index(raw, marker)
	if start < 0 {
		return bytes.Clone(raw)
	}
	start += len(marker)
	end := bytes.IndexByte(raw[start:], ':')
	if end < 0 {
		return bytes.Clone(raw)
	}
	result := bytes.Clone(raw[:start])
	result = append(result, replacement...)
	return append(result, raw[start+end:]...)
}
