package keyresolver

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// mldsa44RecordKey returns one deterministic raw ML-DSA-44 public key.
func mldsa44RecordKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	seed := sha256.Sum256([]byte("keyresolver-mldsa44"))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey()
}

// TestDecodeKeyAcceptsRawMLDSA44Record proves the local k=mldsa44
// interpretation (DKIM2-ISSUE-0020): an exact 1312-octet raw FIPS 204 key
// (1752 base64 characters, with or without h=) is found for mldsa44.
func TestDecodeKeyAcceptsRawMLDSA44Record(t *testing.T) {
	public := mldsa44RecordKey(t)
	encoded := base64.StdEncoding.EncodeToString(public.Bytes())
	if len(encoded) != 1752 {
		t.Fatalf("raw key encodes to %d characters", len(encoded))
	}
	for _, text := range []string{
		"v=DKIM1; k=mldsa44; p=" + encoded,
		"v=DKIM1; k=mldsa44; h=sha256; p=" + encoded,
	} {
		record, err := ParseRecord([]byte(text), DefaultLimits())
		if err != nil || record.KeyType() != KeyTypeMLDSA44 || record.Status() != RecordStatusKeyData || !record.Valid() {
			t.Fatalf("ParseRecord() type=%q status=%q error=%v", record.KeyType(), record.Status(), err)
		}
		outcome, err := DecodeKey(record, AlgorithmMLDSA44)
		if err != nil || outcome.Status() != KeyOutcomeFound || !outcome.Valid() {
			t.Fatalf("DecodeKey() status=%q error=%v", outcome.Status(), err)
		}
		key, ok := outcome.Material().(*mldsa.PublicKey)
		if !ok || !bytes.Equal(key.Bytes(), public.Bytes()) {
			t.Fatal("decoded mldsa44 material differs")
		}
	}
}

// TestDecodeKeyRejectsMalformedMLDSA44Records is the wrong-length key
// reproducer: any other p= length, or an SPKI wrapper, is invalid_key
// (Draft-08 Section 14.5 "malformed"); k=/algorithm disagreement in both
// directions is an algorithm mismatch; revocation stays revoked.
func TestDecodeKeyRejectsMalformedMLDSA44Records(t *testing.T) {
	raw := mldsa44RecordKey(t).Bytes()
	spki, err := x509.MarshalPKIXPublicKey(mldsa44RecordKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"short":        raw[:len(raw)-1],
		"long":         append(bytes.Clone(raw), 0),
		"ed25519 size": raw[:32],
		"spki wrapper": spki,
	} {
		record, err := ParseRecord([]byte("k=mldsa44; p="+base64.StdEncoding.EncodeToString(data)), DefaultLimits())
		if err != nil {
			t.Fatalf("%s ParseRecord() error = %v", name, err)
		}
		if outcome, err := DecodeKey(record, AlgorithmMLDSA44); err != nil || outcome.Status() != KeyOutcomeInvalid || !outcome.Valid() {
			t.Fatalf("%s DecodeKey() status=%q error=%v", name, outcome.Status(), err)
		}
	}
	record, err := ParseRecord([]byte("k=mldsa44; p="+base64.StdEncoding.EncodeToString(raw)), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256} {
		if outcome, err := DecodeKey(record, algorithm); err != nil || outcome.Status() != KeyOutcomeAlgorithmMismatch {
			t.Fatalf("k=mldsa44 for %s status=%q error=%v", algorithm, outcome.Status(), err)
		}
	}
	edRecord, err := ParseRecord([]byte("k=ed25519; p="+base64.StdEncoding.EncodeToString(raw[:32])), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := DecodeKey(edRecord, AlgorithmMLDSA44); err != nil || outcome.Status() != KeyOutcomeAlgorithmMismatch {
		t.Fatalf("k=ed25519 for mldsa44 status=%q error=%v", outcome.Status(), err)
	}
	revoked, err := ParseRecord([]byte("v=DKIM1; k=mldsa44; p="), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := DecodeKey(revoked, AlgorithmMLDSA44); err != nil || outcome.Status() != KeyOutcomeRevoked {
		t.Fatalf("revoked mldsa44 status=%q error=%v", outcome.Status(), err)
	}
	for _, spelling := range []string{"MLDSA44", "ml-dsa-44", "mldsa44-ed25519"} {
		parsed, err := ParseRecord([]byte("k="+spelling+"; p="+base64.StdEncoding.EncodeToString(raw)), DefaultLimits())
		if err != nil || parsed.KeyType() != KeyTypeUnsupported {
			t.Fatalf("k=%s type=%q error=%v", spelling, parsed.KeyType(), err)
		}
	}
}
