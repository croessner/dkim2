package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"
)

const (
	testDomain   = "example.test"
	testSelector = "selector.test"
)

// TestStaticKeyProviderLookupCanonicalTupleAndCopies verifies deterministic key lookup.
func TestStaticKeyProviderLookupCanonicalTupleAndCopies(t *testing.T) {
	key := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 1023), big.NewInt(1)), E: 65537}
	provider, err := NewStaticKeyProvider([]StaticKey{{
		Domain:    "Example.TEST",
		Selector:  "Selector.TEST",
		Algorithm: "RSA-SHA256",
		Material:  key,
		Metadata: KeyMetadata{
			Source: "unit.fixture",
		},
	}})
	if err != nil {
		t.Fatalf("NewStaticKeyProvider() error = %v", err)
	}

	key.N = big.NewInt(17)
	resolved, err := provider.LookupKey(context.Background(), KeyQuery{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
	})
	if err != nil {
		t.Fatalf("LookupKey() error = %v", err)
	}
	if resolved.Algorithm != AlgorithmRSASHA256 || resolved.Metadata.Status != KeyStatusFound || resolved.Metadata.Source != "unit.fixture" {
		t.Fatalf("resolved metadata = %#v algorithm=%q, want found rsa fixture", resolved.Metadata, resolved.Algorithm)
	}
	resolvedKey, ok := resolved.Material.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("resolved material type = %T, want *rsa.PublicKey", resolved.Material)
	}
	if resolvedKey.N.BitLen() != 1024 {
		t.Fatalf("resolved RSA bits = %d, want original 1024-bit copy", resolvedKey.N.BitLen())
	}

	resolvedKey.N = big.NewInt(19)
	again, err := provider.LookupKey(context.Background(), KeyQuery{
		Domain:    "EXAMPLE.TEST",
		Selector:  "SELECTOR.TEST",
		Algorithm: "RSA-SHA256",
	})
	if err != nil {
		t.Fatalf("second LookupKey() error = %v", err)
	}
	if again.Material.(*rsa.PublicKey).N.BitLen() != 1024 {
		t.Fatal("LookupKey() reused mutable returned RSA key storage")
	}
}

// TestStaticKeyProviderAcceptsExactMaximumRSAAndRejectsOneOver locks provider admission.
func TestStaticKeyProviderAcceptsExactMaximumRSAAndRejectsOneOver(t *testing.T) {
	keyAt := func(bits int) *rsa.PublicKey {
		modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		modulus.SetBit(modulus, 0, 1)
		return &rsa.PublicKey{N: modulus, E: 65537}
	}
	if _, err := NewStaticKeyProvider([]StaticKey{{
		Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: keyAt(8192),
	}}); err != nil {
		t.Fatalf("exact 8192-bit static key error = %v", err)
	}
	if _, err := NewStaticKeyProvider([]StaticKey{{
		Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: keyAt(8193),
	}}); !IsErrorCode(err, ErrorCodeKeyPolicyRejected) {
		t.Fatalf("8193-bit static key error = %v, want policy rejection", err)
	}
}

// TestStaticKeyProviderRejectsDuplicateCanonicalTuples verifies duplicate fail-closed state.
func TestStaticKeyProviderRejectsDuplicateCanonicalTuples(t *testing.T) {
	key := ed25519.PublicKey(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize))
	_, err := NewStaticKeyProvider([]StaticKey{
		{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmEd25519SHA256, Material: key},
		{Domain: "EXAMPLE.TEST", Selector: "SELECTOR.TEST", Algorithm: "ED25519-SHA256", Material: key},
	})
	if !IsErrorCode(err, ErrorCodeAmbiguousKey) {
		t.Fatalf("NewStaticKeyProvider() error = %v, want ambiguous key", err)
	}
}

// TestStaticKeyProviderLookupReportsMissingAndProviderErrors verifies typed lookup failures.
func TestStaticKeyProviderLookupReportsMissingAndProviderErrors(t *testing.T) {
	provider, err := NewStaticKeyProvider(nil)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider(nil) error = %v", err)
	}

	key, err := provider.LookupKey(context.Background(), KeyQuery{
		Domain:    testDomain,
		Selector:  "missing.test",
		Algorithm: AlgorithmRSASHA256,
	})
	if !IsErrorCode(err, ErrorCodeMissingKey) || key.Metadata.Status != KeyStatusMissing {
		t.Fatalf("missing lookup key/error = %#v/%v, want missing", key.Metadata, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key, err = provider.LookupKey(ctx, KeyQuery{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmRSASHA256,
	})
	if !IsErrorCode(err, ErrorCodeProviderError) || key.Metadata.Status != KeyStatusProviderError {
		t.Fatalf("canceled lookup key/error = %#v/%v, want provider error", key.Metadata, err)
	}
}

// TestStaticKeyProviderRejectsInvalidWrongTypePolicyAndUnsupportedKeys verifies key states.
func TestStaticKeyProviderRejectsInvalidWrongTypePolicyAndUnsupportedKeys(t *testing.T) {
	tests := []struct {
		name    string
		key     StaticKey
		options []StaticKeyProviderOption
		code    ErrorCode
	}{
		{
			name: "rsa wrong type",
			key: StaticKey{
				Domain:    testDomain,
				Selector:  testSelector,
				Algorithm: AlgorithmRSASHA256,
				Material:  ed25519.PublicKey(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)),
			},
			code: ErrorCodeWrongKeyType,
		},
		{
			name: "rsa too small",
			key: StaticKey{
				Domain:    testDomain,
				Selector:  testSelector,
				Algorithm: AlgorithmRSASHA256,
				Material:  &rsa.PublicKey{N: big.NewInt(65539), E: 3},
			},
			code: ErrorCodeKeyPolicyRejected,
		},
		{
			name: "ed25519 wrong length",
			key: StaticKey{
				Domain:    testDomain,
				Selector:  testSelector,
				Algorithm: AlgorithmEd25519SHA256,
				Material:  ed25519.PublicKey(bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize-1)),
			},
			code: ErrorCodeInvalidKey,
		},
		{
			name: "disabled algorithm",
			key: StaticKey{
				Domain:    testDomain,
				Selector:  testSelector,
				Algorithm: AlgorithmEd25519SHA256,
				Material:  ed25519.PublicKey(bytes.Repeat([]byte{0x33}, ed25519.PublicKeySize)),
			},
			options: []StaticKeyProviderOption{WithStaticKeyAlgorithmPolicy(AlgorithmPolicy{
				AllowedAlgorithms: []Algorithm{AlgorithmRSASHA256},
				MinRSABits:        1024,
				MaxRSABits:        8192,
			})},
			code: ErrorCodeDisabledAlgorithm,
		},
		{
			name: "unsupported algorithm",
			key: StaticKey{
				Domain:    testDomain,
				Selector:  testSelector,
				Algorithm: "future-sha999",
				Material:  ed25519.PublicKey(bytes.Repeat([]byte{0x44}, ed25519.PublicKeySize)),
			},
			code: ErrorCodeUnsupportedAlgorithm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStaticKeyProvider([]StaticKey{tt.key}, tt.options...)
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("NewStaticKeyProvider() error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestStaticKeyProviderErrorsDoNotExposeKeyMaterial verifies secret-safe diagnostics.
func TestStaticKeyProviderErrorsDoNotExposeKeyMaterial(t *testing.T) {
	marker := "PUBLICKEYSECRET"
	_, err := NewStaticKeyProvider([]StaticKey{{
		Domain:    testDomain,
		Selector:  testSelector,
		Algorithm: AlgorithmEd25519SHA256,
		Material:  ed25519.PublicKey([]byte(marker)),
	}})
	if !IsErrorCode(err, ErrorCodeInvalidKey) {
		t.Fatalf("NewStaticKeyProvider() error = %v, want invalid key", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("Error() leaked public key marker in %q", err.Error())
	}
}
