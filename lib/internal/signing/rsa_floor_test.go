package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/cryptodkim2"
)

// TestRSASigningFloorRejectsKeysBelow2048 proves new RSA signing credentials
// fail closed below 2048 bits with a secret-free key_mismatch naming the
// min_rsa_bits floor, while a 2048-bit key is accepted and verification
// limits still admit 1024-bit keys.
func TestRSASigningFloorRejectsKeysBelow2048(t *testing.T) {
	handle, err := NewPrivateKeyHandle([]byte("rsa-floor"))
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCredential("small", AlgorithmRSASHA256, &small.PublicKey, handle, Limits{})
	var typed *Error
	if !IsErrorCode(err, ErrorCodeKeyMismatch) || !errors.As(err, &typed) ||
		!strings.Contains(err.Error(), "limit_name=min_rsa_bits limit=2048 actual=1024") {
		t.Fatalf("1024-bit RSA credential error = %v", err)
	}
	if strings.Contains(err.Error(), small.N.String()[:16]) {
		t.Fatal("floor diagnostic leaked key material")
	}
	if _, err := cryptodkim2.ValidatePublicKey(AlgorithmRSASHA256, &small.PublicKey, cryptodkim2.DefaultLimits()); err != nil {
		t.Fatalf("verification limits rejected a 1024-bit key: %v", err)
	}
	floor, err := rsa.GenerateKey(rand.Reader, cryptodkim2.MinSigningRSABits)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredential("floor", AlgorithmRSASHA256, &floor.PublicKey, handle, Limits{})
	if err != nil || !credential.Valid() {
		t.Fatalf("2048-bit RSA credential error = %v", err)
	}
	forged := credential
	forged.publicKey = &small.PublicKey
	if forged.Valid() {
		t.Fatal("a credential below the floor reports valid")
	}
	if _, err := NewProfile("example.test", []Credential{forged}); err == nil {
		t.Fatal("a profile with a key below the floor loaded")
	}
}
