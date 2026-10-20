package datasource

import (
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// TestNewCredentialRejectsVerificationOnlyCompositeAlgorithm proves that a
// datasource row declaring the composite algorithm fails at load time, because
// composite signing is not implemented.
func TestNewCredentialRejectsVerificationOnlyCompositeAlgorithm(t *testing.T) {
	handle, err := NewKeyHandleID("composite-handle")
	if err != nil {
		t.Fatalf("NewKeyHandleID() error = %v", err)
	}
	if _, err := NewCredential("sel", signature.AlgorithmMLDSA44Ed25519SHA512, []byte{1}, handle, DefaultLimits()); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("NewCredential(composite) error = %v", err)
	}
}
