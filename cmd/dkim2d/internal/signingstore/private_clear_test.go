package signingstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestClearPrivateKeyErasesOwnedRSAAndEd25519Storage freezes the shared cleanup seam.
func TestClearPrivateKeyErasesOwnedRSAAndEd25519Storage(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("generate RSA cleanup fixture")
	}
	edPublic, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate Ed25519 cleanup fixture")
	}
	_ = edPublic
	ClearPrivateKey(rsaKey)
	ClearPrivateKey(edKey)
	if rsaKey.D.Sign() != 0 {
		t.Fatal("RSA private exponent survived cleanup")
	}
	for _, octet := range edKey {
		if octet != 0 {
			t.Fatal("Ed25519 private bytes survived cleanup")
		}
	}
}
