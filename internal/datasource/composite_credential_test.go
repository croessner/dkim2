package datasource

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/croessner/dkim2/internal/signature"
)

// TestNewCredentialRejectsCompositeAlgorithm proves that a datasource row
// declaring the unsettled post-quantum mldsa44-ed25519-sha512 algorithm fails
// closed at load time as an invalid request, even with otherwise valid public
// key material, because the token is outside the signable vocabulary.
func TestNewCredentialRejectsCompositeAlgorithm(t *testing.T) {
	handle, err := NewKeyHandleID("composite-handle")
	if err != nil {
		t.Fatalf("NewKeyHandleID() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	if _, err := NewCredential("sel", signature.Algorithm("mldsa44-ed25519-sha512"), spki, handle, DefaultLimits()); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("NewCredential(composite) error = %v", err)
	}
}
