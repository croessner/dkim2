package dkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

//go:embed dkim2wg-overlap.json
var dkim2wgFixtureJSON []byte

type dkim2wgFixture struct {
	Cases []dkim2wgFixtureCase `json:"cases"`
}

type dkim2wgFixtureCase struct {
	ID              string `json:"id"`
	Input           string `json:"input"`
	InputBase64     string `json:"input_base64"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

type dkim2wgStaticKeyFetcher struct {
	key ed25519.PublicKey
}

// FetchPublicKey returns only the exact synthetic Ed25519 fixture authority.
func (f dkim2wgStaticKeyFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	if selector != "ed.test" || domain != "example.test" {
		return nil, "", errors.New("unexpected fixture key request")
	}
	return ed25519.PublicKey(bytes.Clone(f.key)), "ed25519-sha256", nil
}

// loadDKIM2WGFixtureCase returns one exact digest-bound interop case.
func loadDKIM2WGFixtureCase(t *testing.T, id string) dkim2wgFixtureCase {
	t.Helper()
	var fixture dkim2wgFixture
	if err := json.Unmarshal(dkim2wgFixtureJSON, &fixture); err != nil {
		t.Fatal("invalid embedded interop fixture")
	}
	for _, testCase := range fixture.Cases {
		if testCase.ID == id {
			return testCase
		}
	}
	t.Fatal("missing embedded interop fixture case")
	return dkim2wgFixtureCase{}
}

// TestDKIM2WGMessageInstanceDuplicateHash verifies the peer enforces Draft-06 hash-algorithm uniqueness.
func TestDKIM2WGMessageInstanceDuplicateHash(t *testing.T) {
	testCase := loadDKIM2WGFixtureCase(t, "message-instance-duplicate-hash")
	_, err := parseMI(testCase.Input)
	if err == nil || !strings.Contains(err.Error(), "duplicate hash algorithm") {
		t.Fatal("peer accepted a duplicate Message-Instance hash algorithm")
	}
}

// TestDKIM2WGSignatureFWS verifies the peer accepts Draft-06 FWS around tag separators.
func TestDKIM2WGSignatureFWS(t *testing.T) {
	testCase := loadDKIM2WGFixtureCase(t, "signature-fws")
	signature, err := parseSig(testCase.Input)
	if err != nil || signature.Sequence != 1 || signature.Domain != "example.test" {
		t.Fatal("peer result did not match the closed accepted state")
	}
}

// TestDKIM2WGSignatureSelectorCardinality verifies both Draft-06 signature-set bounds.
func TestDKIM2WGSignatureSelectorCardinality(t *testing.T) {
	duplicate := checkSignatureDuplicates([]SigItem{
		{Selector: "Selector", Algorithm: "rsa-sha256"},
		{Selector: "selector", Algorithm: "ed25519-sha256"},
	}, 1)
	if len(duplicate) != 1 || !strings.Contains(duplicate[0], "duplicate selector") {
		t.Fatal("peer accepted a case-insensitive duplicate Selector")
	}
	tooMany := checkSignatureDuplicates([]SigItem{
		{Selector: "one", Algorithm: "rsa-sha256"},
		{Selector: "two", Algorithm: "rsa-sha256"},
		{Selector: "three", Algorithm: "rsa-sha256"},
	}, 1)
	if len(tooMany) != 1 || !strings.Contains(tooMany[0], "too many signatures") {
		t.Fatal("peer accepted a third signature for one algorithm")
	}
}

// TestDKIM2WGSignatureVerifyEd25519 verifies a local Draft-06 golden message in the independent peer.
func TestDKIM2WGSignatureVerifyEd25519(t *testing.T) {
	testCase := loadDKIM2WGFixtureCase(t, "signature-verify-ed25519")
	message, err := base64.StdEncoding.DecodeString(testCase.InputBase64)
	if err != nil {
		t.Fatal("invalid embedded message fixture")
	}
	publicKey, err := base64.StdEncoding.DecodeString(testCase.PublicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid embedded public-key fixture")
	}
	results, err := Verify(
		bytes.NewReader(message),
		dkim2wgStaticKeyFetcher{key: ed25519.PublicKey(publicKey)},
		VerifyOptions{SkipTimestampCheck: true},
	)
	if err != nil || len(results) != 1 || results[0].Error != nil {
		t.Fatal("peer rejected the local Draft-06 Ed25519 golden message")
	}
}
