package keyresolver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"
)

// TestDecodeKeyAcceptsStrictRSAAndClonesMaterial verifies PKCS#1 decoding with fixed crypto policy.
func TestDecodeKeyAcceptsStrictRSAAndClonesMaterial(t *testing.T) {
	key := syntheticRSAKey(1024, 65537)
	record := keyDataRecord(KeyTypeRSA, x509.MarshalPKCS1PublicKey(key), newMetadata(true, true))
	outcome, err := DecodeKey(record, AlgorithmRSASHA256)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}
	if outcome.Status() != KeyOutcomeFound || !outcome.Valid() || !outcome.Metadata().TestingDeclared() || !outcome.Metadata().StrictIdentityDeclared() {
		t.Fatalf("outcome = status %q valid=%v metadata=%#v", outcome.Status(), outcome.Valid(), outcome.Metadata())
	}
	decoded, ok := outcome.Material().(*rsa.PublicKey)
	if !ok || decoded.N.Cmp(key.N) != 0 || decoded.E != key.E {
		t.Fatalf("Material() = %#v, want detached RSA key", outcome.Material())
	}
	decoded.N.SetInt64(99)
	again := outcome.Material().(*rsa.PublicKey)
	if again.N.Cmp(key.N) != 0 {
		t.Fatal("Material() exposed mutable RSA modulus storage")
	}
}

// TestDecodeKeyAcceptsStructurallyValidRSAOutsideCryptoPolicy locks the DNS-policy boundary.
func TestDecodeKeyAcceptsStructurallyValidRSAOutsideCryptoPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		bits     int
		exponent int
	}{
		{name: "non-policy exponent", bits: 1024, exponent: 3},
		{name: "below verifier minimum", bits: 1023, exponent: 65537},
		{name: "above crypto maximum", bits: 8193, exponent: 65537},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome, err := DecodeKey(keyDataRecord(KeyTypeRSA, x509.MarshalPKCS1PublicKey(syntheticRSAKey(test.bits, test.exponent)), newMetadata(false, false)), AlgorithmRSASHA256)
			if err != nil || outcome.Status() != KeyOutcomeFound || !outcome.Valid() {
				t.Fatalf("DecodeKey(%d bits, e=%d) status=%s valid=%v error=%v, want found", test.bits, test.exponent, outcome.Status(), outcome.Valid(), err)
			}
			key, ok := outcome.Material().(*rsa.PublicKey)
			if !ok || key.N.BitLen() != test.bits || key.E != test.exponent {
				t.Fatalf("Material() = %T/%v, want detached %d-bit RSA key with e=%d", outcome.Material(), key, test.bits, test.exponent)
			}
		})
	}
}

// TestDecodeKeyRejectsWrongRSAContainersAndShape verifies strict full PKCS#1 structural decoding.
func TestDecodeKeyRejectsWrongRSAContainersAndShape(t *testing.T) {
	valid := syntheticRSAKey(1024, 65537)
	spki, err := x509.MarshalPKIXPublicKey(valid)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	private := &rsa.PrivateKey{PublicKey: *valid, D: big.NewInt(2753), Primes: []*big.Int{big.NewInt(61), big.NewInt(53)}}
	negativeModulus, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{N: big.NewInt(-3233), E: 17})
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}
	nonMinimal := []byte{0x30, 0x08, 0x02, 0x03, 0x00, 0x0c, 0xa1, 0x02, 0x01, 0x11}
	pemPublic := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(valid)})
	certificateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic.invalid"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1, 0)}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &certificateKey.PublicKey, certificateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	tests := []struct {
		name string
		der  []byte
	}{
		{name: "spki", der: spki},
		{name: "certificate", der: certificate},
		{name: "pem", der: pemPublic},
		{name: "private", der: x509.MarshalPKCS1PrivateKey(private)},
		{name: "trailing", der: append(x509.MarshalPKCS1PublicKey(valid), 0)},
		{name: "malformed", der: []byte{0x30, 0x01, 0x02}},
		{name: "non-minimal integer", der: nonMinimal},
		{name: "negative modulus", der: negativeModulus},
		{name: "even modulus", der: x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3234), E: 17})},
		{name: "exponent below three", der: x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 2})},
		{name: "even exponent", der: x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 18})},
		{name: "exponent not below modulus", der: x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(17), E: 17})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome, decodeErr := DecodeKey(keyDataRecord(KeyTypeRSA, tt.der, newMetadata(false, false)), AlgorithmRSASHA256)
			if decodeErr != nil || outcome.Status() != KeyOutcomeInvalid || !outcome.Valid() || outcome.Material() != nil {
				t.Fatalf("DecodeKey() = status %q valid=%v material=%T error=%v, want invalid", outcome.Status(), outcome.Valid(), outcome.Material(), decodeErr)
			}
		})
	}
}

// TestDecodeKeyAcceptsRawEd25519AndRejectsWrappedOrWrongLength verifies RFC 8463 representation.
func TestDecodeKeyAcceptsRawEd25519AndRejectsWrappedOrWrongLength(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)
	outcome, err := DecodeKey(keyDataRecord(KeyTypeEd25519, raw, newMetadata(false, false)), AlgorithmEd25519SHA256)
	if err != nil || outcome.Status() != KeyOutcomeFound {
		t.Fatalf("DecodeKey() = %q/%v, want found", outcome.Status(), err)
	}
	key, ok := outcome.Material().(ed25519.PublicKey)
	if !ok || !bytes.Equal(key, raw) {
		t.Fatalf("Material() = %T/%x, want Ed25519 public key", outcome.Material(), key)
	}
	key[0] = 0x99
	if outcome.Material().(ed25519.PublicKey)[0] != 0x42 {
		t.Fatal("Material() exposed mutable Ed25519 storage")
	}

	spki, marshalErr := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if marshalErr != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", marshalErr)
	}
	privateKey := ed25519.PrivateKey(bytes.Repeat([]byte{0x33}, ed25519.PrivateKeySize))
	pkcs8, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", marshalErr)
	}
	pemPublic := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	for _, value := range [][]byte{raw[:31], append(bytes.Clone(raw), 0), privateKey, spki, pkcs8, pemPublic} {
		bad, decodeErr := DecodeKey(keyDataRecord(KeyTypeEd25519, value, newMetadata(false, false)), AlgorithmEd25519SHA256)
		if decodeErr != nil || bad.Status() != KeyOutcomeInvalid || bad.Material() != nil {
			t.Fatalf("DecodeKey(wrong representation len=%d) = %q/%v", len(value), bad.Status(), decodeErr)
		}
	}
}

// TestKeyOutcomeMaterialSupportsConcurrentCallerMutation verifies per-call detached key copies.
func TestKeyOutcomeMaterialSupportsConcurrentCallerMutation(t *testing.T) {
	rsaKey := syntheticRSAKey(1024, 65537)
	rsaOutcome, err := DecodeKey(keyDataRecord(KeyTypeRSA, x509.MarshalPKCS1PublicKey(rsaKey), newMetadata(false, false)), AlgorithmRSASHA256)
	if err != nil {
		t.Fatalf("DecodeKey(RSA) error = %v", err)
	}
	edOutcome, err := DecodeKey(keyDataRecord(KeyTypeEd25519, bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize), newMetadata(false, false)), AlgorithmEd25519SHA256)
	if err != nil {
		t.Fatalf("DecodeKey(Ed25519) error = %v", err)
	}
	var callers sync.WaitGroup
	for index := 0; index < 32; index++ {
		callers.Add(2)
		go func(value int64) {
			defer callers.Done()
			rsaOutcome.Material().(*rsa.PublicKey).N.SetInt64(value)
		}(int64(index + 1))
		go func(value byte) {
			defer callers.Done()
			edOutcome.Material().(ed25519.PublicKey)[0] = value
		}(byte(index))
	}
	callers.Wait()
	if rsaOutcome.Material().(*rsa.PublicKey).N.Cmp(rsaKey.N) != 0 || edOutcome.Material().(ed25519.PublicKey)[0] != 0x42 {
		t.Fatal("concurrent caller mutation changed outcome-owned key material")
	}
}

// syntheticRSAKey constructs a structurally valid public key at one exact bit length.
func syntheticRSAKey(bits, exponent int) *rsa.PublicKey {
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	modulus.SetBit(modulus, 0, 1)
	return &rsa.PublicKey{N: modulus, E: exponent}
}

// TestDecodeKeyPreservesClosedNonFoundStatesAndCoherence verifies precedence without decoding.
func TestDecodeKeyPreservesClosedNonFoundStatesAndCoherence(t *testing.T) {
	metadata := newMetadata(true, false)
	tests := []struct {
		name      string
		record    Record
		algorithm Algorithm
		status    KeyOutcomeStatus
	}{
		{name: "revoked decode state", record: Record{draft: DNSDraftIdentifier, status: RecordStatusRevoked, keyType: KeyTypeRSA, metadata: metadata, initialized: true}, algorithm: AlgorithmRSASHA256, status: KeyOutcomeRevoked},
		{name: "unsupported decode state", record: Record{draft: DNSDraftIdentifier, status: RecordStatusUnsupportedKeyType, keyType: KeyTypeUnsupported, metadata: metadata, initialized: true}, algorithm: AlgorithmRSASHA256, status: KeyOutcomeUnsupportedKeyType},
		{name: "rsa requested ed", record: keyDataRecord(KeyTypeRSA, []byte("not DER"), metadata), algorithm: AlgorithmEd25519SHA256, status: KeyOutcomeAlgorithmMismatch},
		{name: "ed requested rsa", record: keyDataRecord(KeyTypeEd25519, []byte("not raw32"), metadata), algorithm: AlgorithmRSASHA256, status: KeyOutcomeAlgorithmMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome, err := DecodeKey(tt.record, tt.algorithm)
			if err != nil || outcome.Status() != tt.status || !outcome.Valid() || outcome.Material() != nil || !outcome.Metadata().TestingDeclared() {
				t.Fatalf("DecodeKey() = status %q valid=%v material=%T error=%v", outcome.Status(), outcome.Valid(), outcome.Material(), err)
			}
		})
	}
}

// TestDecodeKeyRejectsUnknownContractsWithoutMaterial verifies zero and unknown state fail closed.
func TestDecodeKeyRejectsUnknownContractsWithoutMaterial(t *testing.T) {
	tests := []struct {
		name      string
		record    Record
		algorithm Algorithm
	}{
		{name: "zero record", record: Record{}, algorithm: AlgorithmRSASHA256},
		{name: "unknown requested algorithm", record: keyDataRecord(KeyTypeRSA, []byte("SECRET-MARKER"), newMetadata(false, false)), algorithm: "future-sha999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome, err := DecodeKey(tt.record, tt.algorithm)
			if outcome.Valid() || outcome.Material() != nil || !IsErrorClass(err, ErrorClassContract) || bytes.Contains([]byte(err.Error()), []byte("SECRET-MARKER")) {
				t.Fatalf("DecodeKey() = valid=%v material=%T error=%v", outcome.Valid(), outcome.Material(), err)
			}
		})
	}
	if KeyOutcomeStatus("future").Known() || KeyOutcomeStatus("").Known() {
		t.Fatal("zero or unknown key outcome status reported known")
	}
}

// keyDataRecord constructs parser-owned key data for decode-focused tests.
func keyDataRecord(keyType KeyType, publicKey []byte, metadata Metadata) Record {
	return Record{draft: DNSDraftIdentifier, status: RecordStatusKeyData, keyType: keyType, publicKey: bytes.Clone(publicKey), metadata: metadata, initialized: true}
}
