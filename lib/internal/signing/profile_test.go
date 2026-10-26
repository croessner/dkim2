package signing

import (
	"crypto/ed25519"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// TestCompositeAlgorithmIsNotSignable proves the unsettled post-quantum
// mldsa44-ed25519-sha512 token is an unknown algorithm for signing: a
// credential declaring it fails closed as an invalid request before any key
// material is inspected, and a private-key request cannot be built for it.
func TestCompositeAlgorithmIsNotSignable(t *testing.T) {
	composite := signature.Algorithm("mldsa44-ed25519-sha512")
	handle, err := NewPrivateKeyHandle([]byte("composite-handle"))
	if err != nil {
		t.Fatal(err)
	}
	if SignableAlgorithm(composite) {
		t.Fatal("composite algorithm reported signable")
	}
	publicKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	if _, err := NewCredential("sel", composite, publicKey, handle, Limits{}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("NewCredential(composite) error = %v", err)
	}
	if request, err := NewPrivateKeySignRequest(composite, make([]byte, 64)); !IsErrorCode(err, ErrorCodeInvalidRequest) || request.Valid() {
		t.Fatalf("NewPrivateKeySignRequest(composite) valid=%t error=%v", request.Valid(), err)
	}
}
