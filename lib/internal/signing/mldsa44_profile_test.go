package signing

import (
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/mldsa"
	"crypto/sha256"
	"testing"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/signature"
)

// newMLDSA44TestKey derives one deterministic ML-DSA-44 test key.
func newMLDSA44TestKey(t *testing.T, label string) *mldsa.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed[:])
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	return key
}

// TestMLDSA44CredentialAndThreeAlgorithmProfile proves an mldsa44
// credential is signable, sorts after the classical credentials, and that a
// profile holds at most one credential per algorithm with selectors that are
// distinct across every s= group.
func TestMLDSA44CredentialAndThreeAlgorithmProfile(t *testing.T) {
	if !SignableAlgorithm(AlgorithmMLDSA44) {
		t.Fatal("mldsa44 is not signable")
	}
	handle := func(label string) PrivateKeyHandle {
		value, err := NewPrivateKeyHandle([]byte(label))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	mlKey := newMLDSA44TestKey(t, "profile-mldsa44")
	ml, err := NewCredential("pq", AlgorithmMLDSA44, mlKey.PublicKey(), handle("ml"), Limits{})
	if err != nil {
		t.Fatalf("NewCredential(mldsa44) error = %v", err)
	}
	edSeed := sha256.Sum256([]byte("profile-ed25519"))
	ed, err := NewCredential("ed", AlgorithmEd25519SHA256, ed25519.NewKeyFromSeed(edSeed[:]).Public(), handle("ed"), Limits{})
	if err != nil {
		t.Fatalf("NewCredential(ed25519) error = %v", err)
	}
	profile, err := NewProfile("example.test", []Credential{ml, ed})
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	if credentials := profile.Credentials(); len(credentials) != 2 || credentials[0].Algorithm() != AlgorithmEd25519SHA256 ||
		credentials[1].Algorithm() != AlgorithmMLDSA44 || !cryptodkim2.PublicKeysEqual(credentials[1].PublicKey(), mlKey.PublicKey()) {
		t.Fatal("profile did not keep canonical order and detached mldsa44 material")
	}
	if !profile.Valid() || !profile.ValidForLimits(Limits{}) {
		t.Fatal("mldsa44 profile is not valid for the default limits")
	}
	sameSelector, err := NewCredential("ed", AlgorithmMLDSA44, mlKey.PublicKey(), handle("ml-dup"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProfile("example.test", []Credential{ed, sameSelector}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("duplicate selector across groups error = %v", err)
	}
	second, err := NewCredential("pq2", AlgorithmMLDSA44, newMLDSA44TestKey(t, "profile-mldsa44-two").PublicKey(), handle("ml2"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProfile("example.test", []Credential{ml, second}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("duplicate algorithm error = %v", err)
	}
	if _, err := NewCredential("pq", AlgorithmMLDSA44, ed.PublicKey(), handle("wrong"), Limits{}); !IsErrorCode(err, ErrorCodeKeyMismatch) {
		t.Fatalf("Ed25519 key for mldsa44 error = %v", err)
	}
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCredential("pq", AlgorithmMLDSA44, other.PublicKey(), handle("ml65"), Limits{}); !IsErrorCode(err, ErrorCodeKeyMismatch) {
		t.Fatalf("ML-DSA-65 key error = %v", err)
	}
	if order := signature.SigningAlgorithmOrder(); len(order) != 3 || order[2] != AlgorithmMLDSA44 {
		t.Fatalf("signing order = %v", order)
	}
}

// TestMLDSA44SignRequestCarriesCompleteInput proves the private-signing
// request for mldsa44 carries the complete Section 12.8 input rather than a
// digest, and rejects an empty representative.
func TestMLDSA44SignRequestCarriesCompleteInput(t *testing.T) {
	input := []byte("message-instance:m=1;\r\ndkim2-signature:i=1; s=pq:mldsa44:;\r\n")
	request, err := NewPrivateKeySignRequest(AlgorithmMLDSA44, input)
	if err != nil || !request.Valid() || string(request.MessageRepresentative()) != string(input) {
		t.Fatalf("mldsa44 request valid=%t error=%v", request.Valid(), err)
	}
	if _, err := NewPrivateKeySignRequest(AlgorithmMLDSA44, nil); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("empty mldsa44 representative error = %v", err)
	}
}

// TestMLDSA44CredentialFailsClosedWithoutRuntime proves an mldsa44 signing
// credential cannot be created when the runtime lacks ML-DSA (the FIPS 140-3
// Go Cryptographic Module v1.0.0, exercised by make test-fips140-mldsa44).
func TestMLDSA44CredentialFailsClosedWithoutRuntime(t *testing.T) {
	handle, err := NewPrivateKeyHandle([]byte("fips-ml"))
	if err != nil {
		t.Fatal(err)
	}
	if fips140.Version() != "v1.0.0" {
		if _, err := NewCredential("pq", AlgorithmMLDSA44, newMLDSA44TestKey(t, "fips").PublicKey(), handle, Limits{}); err != nil {
			t.Fatalf("NewCredential(mldsa44) error = %v", err)
		}
		return
	}
	t.Log("built against the FIPS 140-3 Go Cryptographic Module v1.0.0")
	if _, err := NewCredential("pq", AlgorithmMLDSA44, &mldsa.PublicKey{}, handle, Limits{}); !IsErrorCode(err, ErrorCodeUnsupportedAlgorithm) {
		t.Fatalf("NewCredential(mldsa44) under FIPS v1.0.0 error = %v", err)
	}
}
