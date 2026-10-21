package cryptodkim2

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// lampsVector is the id-MLDSA44-Ed25519-SHA512 known-answer vector of
// draft-ietf-lamps-pq-composite-sigs as distributed by Stalwart mail-auth.
type lampsVector struct {
	Message          string `json:"m"`
	Context          string `json:"ctx"`
	PublicKey        string `json:"pk"`
	Signature        string `json:"s"`
	SignatureWithCtx string `json:"sWithContext"`
}

// loadLAMPSVector decodes the external composite known-answer vector.
func loadLAMPSVector(t *testing.T) (message, publicKey, signatureBytes, contextSignature []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors/external/stalwart-mail-auth/lamps-mldsa44-ed25519.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var vector lampsVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	decode := func(value string) []byte {
		decoded, decodeErr := base64.StdEncoding.DecodeString(value)
		if decodeErr != nil {
			t.Fatalf("base64 decode error = %v", decodeErr)
		}
		return decoded
	}
	return decode(vector.Message), decode(vector.PublicKey), decode(vector.Signature), decode(vector.SignatureWithCtx)
}

// TestCompositeVerifiesLAMPSKnownAnswerVector proves the verifier implements
// the draft-ietf-lamps-pq-composite-sigs id-MLDSA44-Ed25519-SHA512
// construction used by the DKIM2 interoperability round: the message
// representative binds the composite prefix, label, and an empty application
// context to SHA-512(M), ML-DSA-44 signs it with the label as its context, and
// Ed25519 signs it directly. A signature made with a non-empty application
// context and any changed message must fail.
func TestCompositeVerifiesLAMPSKnownAnswerVector(t *testing.T) {
	message, publicKey, signatureBytes, contextSignature := loadLAMPSVector(t)
	key, err := ParseCompositePublicKey(publicKey)
	if err != nil {
		t.Fatalf("ParseCompositePublicKey() error = %v", err)
	}
	digest := sha512.Sum512(message)
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, key, digest[:], signatureBytes, Limits{}); err != nil {
		t.Fatalf("VerifyDigest(LAMPS vector) error = %v", err)
	}
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, key, digest[:], contextSignature, Limits{}); err == nil {
		t.Fatal("signature with a non-empty application context verified")
	}
	other := sha512.Sum512(append(message, '!'))
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, key, other[:], signatureBytes, Limits{}); err == nil {
		t.Fatal("signature verified over a changed message")
	}
}

// TestCompositeSigningMatchesLAMPSKeysAndRoundTrips proves the signing owner
// derives the LAMPS vector public key from both its raw and PKCS#8 private
// keys, produces signatures the verifier and the vector key accept, and
// round-trips the exact PKCS#8 and SubjectPublicKeyInfo encodings.
func TestCompositeSigningMatchesLAMPSKeysAndRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/external/stalwart-mail-auth/lamps-mldsa44-ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicKey  string `json:"pk"`
		PrivateKey string `json:"sk"`
		PKCS8      string `json:"sk_pkcs8"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	publicKey, _ := base64.StdEncoding.DecodeString(vector.PublicKey)
	seeds, _ := base64.StdEncoding.DecodeString(vector.PrivateKey)
	pkcs8, _ := base64.StdEncoding.DecodeString(vector.PKCS8)
	fromSeeds, err := NewCompositePrivateKey(seeds)
	if err != nil {
		t.Fatalf("NewCompositePrivateKey() error = %v", err)
	}
	fromPKCS8, err := ParseCompositePKCS8(pkcs8)
	if err != nil {
		t.Fatalf("ParseCompositePKCS8() error = %v", err)
	}
	if string(fromSeeds.PublicKey().Bytes()) != string(publicKey) || string(fromPKCS8.PublicKey().Bytes()) != string(publicKey) {
		t.Fatal("derived public key differs from the LAMPS vector")
	}
	if string(fromSeeds.MarshalPKCS8()) != string(pkcs8) {
		t.Fatal("PKCS#8 encoding differs from the LAMPS vector")
	}
	spki := fromSeeds.PublicKey().MarshalSPKI()
	parsed, err := ParseCompositeSPKI(spki)
	if err != nil || string(parsed.Bytes()) != string(publicKey) {
		t.Fatalf("SPKI round trip error = %v", err)
	}
	digest := sha512.Sum512([]byte("canonical signature input"))
	signatureBytes, err := SignCompositeDigest(fromPKCS8, digest[:])
	if err != nil || len(signatureBytes) != CompositeSignatureBytes {
		t.Fatalf("SignCompositeDigest() len=%d error=%v", len(signatureBytes), err)
	}
	vectorKey, _ := ParseCompositePublicKey(publicKey)
	if err := VerifyDigest(signature.AlgorithmMLDSA44Ed25519SHA512, vectorKey, digest[:], signatureBytes, Limits{}); err != nil {
		t.Fatalf("VerifyDigest(own signature) error = %v", err)
	}
	if _, err := NewCompositePrivateKey(seeds[:63]); err == nil {
		t.Fatal("NewCompositePrivateKey() accepted 63 seed bytes")
	}
	otherOID := append([]byte{0x30, 0x51, 0x02, 0x01, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x28, 0x04, 0x40}, seeds...)
	for name, bad := range map[string][]byte{
		"pkcs8 trailing":  append(append([]byte(nil), pkcs8...), 0),
		"pkcs8 other oid": otherOID,
	} {
		if _, err := ParseCompositePKCS8(bad); err == nil {
			t.Fatalf("%s: ParseCompositePKCS8() accepted", name)
		}
	}
	otherSPKI := append([]byte(nil), spki...)
	otherSPKI[15] = 0x28
	for name, bad := range map[string][]byte{
		"spki truncated": spki[:len(spki)-1],
		"spki trailing":  append(append([]byte(nil), spki...), 0),
		"spki other oid": otherSPKI,
	} {
		if _, err := ParseCompositeSPKI(bad); err == nil {
			t.Fatalf("%s: ParseCompositeSPKI() accepted", name)
		}
	}
	if _, err := SignCompositeDigest(fromSeeds, digest[:32]); ErrorCodeOf(err) != ErrorCodeInvalidDigestLength {
		t.Fatalf("SHA-256 digest error = %v", err)
	}
	fromSeeds.Clear()
	if _, err := SignCompositeDigest(fromSeeds, digest[:]); err == nil {
		t.Fatal("cleared key still signed")
	}
}
