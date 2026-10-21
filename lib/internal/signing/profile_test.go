package signing

import (
	"testing"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/signature"
)

// TestCompositeAlgorithmIsSignable proves mldsa44-ed25519-sha512 is a
// signable algorithm whose credential requires a composite public key.
func TestCompositeAlgorithmIsSignable(t *testing.T) {
	handle, err := NewPrivateKeyHandle([]byte("composite-handle"))
	if err != nil {
		t.Fatal(err)
	}
	if !SignableAlgorithm(signature.AlgorithmMLDSA44Ed25519SHA512) {
		t.Fatal("composite algorithm reported unsignable")
	}
	if _, err := NewCredential("sel", signature.AlgorithmMLDSA44Ed25519SHA512, nil, handle, Limits{}); !IsErrorCode(err, ErrorCodeKeyMismatch) {
		t.Fatalf("NewCredential(composite, nil key) error = %v", err)
	}
	key, err := cryptodkim2.GenerateCompositePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredential("sel", signature.AlgorithmMLDSA44Ed25519SHA512, key.PublicKey(), handle, Limits{})
	if err != nil || !credential.Valid() {
		t.Fatalf("NewCredential(composite) valid=%t error=%v", credential.Valid(), err)
	}
}
