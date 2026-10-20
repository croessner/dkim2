package signing

import (
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// TestCompositeAlgorithmIsNotSignable keeps composite signing unimplemented
// while the Draft-07/LAMPS construction conflict is open.
func TestCompositeAlgorithmIsNotSignable(t *testing.T) {
	handle, err := NewPrivateKeyHandle([]byte("composite-handle"))
	if err != nil {
		t.Fatal(err)
	}
	if SignableAlgorithm(signature.AlgorithmMLDSA44Ed25519SHA512) {
		t.Fatal("composite algorithm reported signable")
	}
	if _, err := NewCredential("sel", signature.AlgorithmMLDSA44Ed25519SHA512, nil, handle, Limits{}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("NewCredential(composite) error = %v", err)
	}
}
