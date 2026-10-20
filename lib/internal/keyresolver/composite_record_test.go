package keyresolver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"testing"

	"github.com/croessner/dkim2/internal/cryptodkim2"
)

// TestParsedCompositeRecordDecodesToFoundKey reproduces DNS-01
// k=mldsa44-ed25519-sha512 records: a parser-produced key-data record must be
// coherent so DecodeKey yields a found composite key, while a wrong-length p=
// stays an invalid-key outcome rather than a resolver contract failure.
func TestParsedCompositeRecordDecodesToFoundKey(t *testing.T) {
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), bytes.Repeat([]byte{0x51}, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x15}, ed25519.SeedSize))
	raw := append(mlKey.PublicKey().Bytes(), edKey.Public().(ed25519.PublicKey)...)

	record, err := ParseRecord([]byte("v=DKIM1; k=mldsa44-ed25519-sha512; p="+base64.StdEncoding.EncodeToString(raw)), DefaultLimits())
	if err != nil || !record.Valid() || record.KeyType() != KeyTypeMLDSA44Ed25519SHA512 {
		t.Fatalf("ParseRecord() valid=%v keyType=%q error=%v", record.Valid(), record.KeyType(), err)
	}
	outcome, err := DecodeKey(record, AlgorithmMLDSA44Ed25519SHA512)
	if err != nil || outcome.Status() != KeyOutcomeFound || !outcome.Valid() {
		t.Fatalf("DecodeKey() = %q/%v", outcome.Status(), err)
	}
	key, ok := outcome.Material().(cryptodkim2.CompositePublicKey)
	if !ok || !bytes.Equal(key.Bytes(), raw) {
		t.Fatalf("Material() = %T, want composite key", outcome.Material())
	}

	oversized, err := ParseRecord([]byte("v=DKIM1; k=mldsa44-ed25519-sha512; p="+base64.StdEncoding.EncodeToString(append(raw, 0))), DefaultLimits())
	if err != nil {
		t.Fatalf("ParseRecord(oversized) error = %v", err)
	}
	invalid, err := DecodeKey(oversized, AlgorithmMLDSA44Ed25519SHA512)
	if err != nil || invalid.Status() != KeyOutcomeInvalid || invalid.Material() != nil {
		t.Fatalf("DecodeKey(oversized) = %q/%v", invalid.Status(), err)
	}
}
