package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
	"testing"
)

// TestAlgorithmPolicyClassifiesAllowedUnsupportedAndDisabled verifies allowlist states.
func TestAlgorithmPolicyClassifiesAllowedUnsupportedAndDisabled(t *testing.T) {
	policy := AlgorithmPolicy{
		AllowedAlgorithms: []Algorithm{AlgorithmRSASHA256},
		MinRSABits:        1024,
		MaxRSABits:        8192,
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []struct {
		name      string
		algorithm Algorithm
		status    KeyStatus
	}{
		{name: "allowed rsa", algorithm: AlgorithmRSASHA256, status: KeyStatusFound},
		{name: "disabled ed25519", algorithm: AlgorithmEd25519SHA256, status: KeyStatusPolicyRejected},
		{name: "unsupported future", algorithm: "future-sha999", status: KeyStatusUnsupportedAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policy.ClassifyAlgorithm(tt.algorithm); got != tt.status {
				t.Fatalf("ClassifyAlgorithm() = %q, want %q", got, tt.status)
			}
		})
	}
}

// TestValidateRSAPublicKeyMaterialEnforcesTypeAndMinimum verifies RSA key policy.
func TestValidateRSAPublicKeyMaterialEnforcesTypeAndMinimum(t *testing.T) {
	policy := DefaultAlgorithmPolicy()
	key := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 1023), big.NewInt(1)), E: 65537}
	material, status, err := validatePublicKeyMaterial(AlgorithmRSASHA256, key, policy)
	if err != nil {
		t.Fatalf("validatePublicKeyMaterial() error = %v", err)
	}
	if status != KeyStatusFound {
		t.Fatalf("status = %q, want found", status)
	}
	gotKey, ok := material.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("material type = %T, want *rsa.PublicKey", material)
	}
	if gotKey == key || gotKey.N == key.N || gotKey.N.BitLen() != 1024 {
		t.Fatal("validated RSA key did not return an independent 1024-bit copy")
	}

	_, status, err = validatePublicKeyMaterial(AlgorithmRSASHA256, rsa.PublicKey{}, policy)
	if !IsErrorCode(err, ErrorCodeWrongKeyType) || status != KeyStatusWrongType {
		t.Fatalf("wrong type status/error = %q/%v, want wrong type", status, err)
	}

	_, status, err = validatePublicKeyMaterial(AlgorithmRSASHA256, &rsa.PublicKey{N: big.NewInt(17), E: 3}, policy)
	if !IsErrorCode(err, ErrorCodeKeyPolicyRejected) || status != KeyStatusPolicyRejected {
		t.Fatalf("small key status/error = %q/%v, want policy rejected", status, err)
	}

	narrow := policy
	narrow.MaxRSABits = 1024
	tooLarge := &rsa.PublicKey{
		N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 1024), big.NewInt(1)),
		E: 65537,
	}
	_, status, err = validatePublicKeyMaterial(AlgorithmRSASHA256, tooLarge, narrow)
	if !IsErrorCode(err, ErrorCodeKeyPolicyRejected) || status != KeyStatusPolicyRejected {
		t.Fatalf("narrow maximum status/error = %q/%v, want policy rejected", status, err)
	}
}

// TestValidateRSAPublicKeyMaterialRejectsEvenModulus verifies the shared RSA invariant.
func TestValidateRSAPublicKeyMaterialRejectsEvenModulus(t *testing.T) {
	modulus := new(big.Int).Lsh(big.NewInt(1), 1023)
	_, status, err := validatePublicKeyMaterial(AlgorithmRSASHA256, &rsa.PublicKey{N: modulus, E: 65537}, DefaultAlgorithmPolicy())
	if !IsErrorCode(err, ErrorCodeInvalidKey) || status != KeyStatusInvalid {
		t.Fatalf("validatePublicKeyMaterial() = %q/%v, want invalid key", status, err)
	}
}

// TestValidateRSAPublicKeyMaterialRejectsInvalidShape verifies RFC 8017 modulus and exponent bounds.
func TestValidateRSAPublicKeyMaterialRejectsInvalidShape(t *testing.T) {
	tests := []struct {
		name string
		key  *rsa.PublicKey
	}{
		{name: "nil key", key: nil},
		{name: "nil modulus", key: &rsa.PublicKey{E: 3}},
		{name: "negative modulus", key: &rsa.PublicKey{N: big.NewInt(-17), E: 3}},
		{name: "zero modulus", key: &rsa.PublicKey{N: big.NewInt(0), E: 3}},
		{name: "zero exponent", key: &rsa.PublicKey{N: big.NewInt(17), E: 0}},
		{name: "even exponent", key: &rsa.PublicKey{N: big.NewInt(17), E: 2}},
		{name: "exponent equals modulus", key: &rsa.PublicKey{N: big.NewInt(17), E: 17}},
		{name: "exponent exceeds modulus", key: &rsa.PublicKey{N: big.NewInt(17), E: 19}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, status, err := validatePublicKeyMaterial(AlgorithmRSASHA256, tt.key, DefaultAlgorithmPolicy())
			if !IsErrorCode(err, ErrorCodeInvalidKey) || status != KeyStatusInvalid {
				t.Fatalf("validatePublicKeyMaterial() = %q/%v, want invalid key", status, err)
			}
		})
	}
}

// TestValidateEd25519PublicKeyMaterialEnforcesTypeAndLength verifies Ed25519 shape.
func TestValidateEd25519PublicKeyMaterialEnforcesTypeAndLength(t *testing.T) {
	policy := DefaultAlgorithmPolicy()
	key := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	material, status, err := validatePublicKeyMaterial(AlgorithmEd25519SHA256, key, policy)
	if err != nil {
		t.Fatalf("validatePublicKeyMaterial() error = %v", err)
	}
	if status != KeyStatusFound {
		t.Fatalf("status = %q, want found", status)
	}
	gotKey, ok := material.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("material type = %T, want ed25519.PublicKey", material)
	}
	gotKey[0] = 0x99
	if key[0] == 0x99 {
		t.Fatal("validated Ed25519 key reused caller storage")
	}

	_, status, err = validatePublicKeyMaterial(AlgorithmEd25519SHA256, []byte(key), policy)
	if !IsErrorCode(err, ErrorCodeWrongKeyType) || status != KeyStatusWrongType {
		t.Fatalf("wrong type status/error = %q/%v, want wrong type", status, err)
	}

	_, status, err = validatePublicKeyMaterial(AlgorithmEd25519SHA256, ed25519.PublicKey(bytes.Repeat([]byte{0x24}, ed25519.PublicKeySize-1)), policy)
	if !IsErrorCode(err, ErrorCodeInvalidKey) || status != KeyStatusInvalid {
		t.Fatalf("bad length status/error = %q/%v, want invalid key", status, err)
	}
}

// TestValidatePublicKeyMaterialRejectsUnsupportedAndDisabledAlgorithms verifies non-success algorithms.
func TestValidatePublicKeyMaterialRejectsUnsupportedAndDisabledAlgorithms(t *testing.T) {
	policy := AlgorithmPolicy{
		AllowedAlgorithms: []Algorithm{AlgorithmRSASHA256},
		MinRSABits:        1024,
		MaxRSABits:        8192,
	}
	key := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))

	_, status, err := validatePublicKeyMaterial(AlgorithmEd25519SHA256, key, policy)
	if !IsErrorCode(err, ErrorCodeDisabledAlgorithm) || status != KeyStatusPolicyRejected {
		t.Fatalf("disabled status/error = %q/%v, want policy rejected", status, err)
	}

	_, status, err = validatePublicKeyMaterial("future-sha999", key, policy)
	if !IsErrorCode(err, ErrorCodeUnsupportedAlgorithm) || status != KeyStatusUnsupportedAlgorithm {
		t.Fatalf("unsupported status/error = %q/%v, want unsupported", status, err)
	}
}
