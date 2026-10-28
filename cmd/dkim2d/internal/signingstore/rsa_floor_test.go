package signingstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
)

// TestCustodyRejectsRSAKeysBelowSigningFloor proves loaded signing custody
// keys, native datasource key material, and generated keys below 2048 bits
// fail closed, while a 2048-bit key loads.
func TestCustodyRejectsRSAKeysBelowSigningFloor(t *testing.T) {
	for _, bits := range []int{1024, dkim2.MinSigningRSABits} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		privatePKCS8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		publicSPKI, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _, err := parseNativePrivateKey(privatePKCS8, publicSPKI, provider.AlgorithmRSASHA256)
		if (err == nil) != (bits >= dkim2.MinSigningRSABits) {
			t.Fatalf("%d-bit custody key accepted=%t", bits, err == nil)
		}
		clearPrivateKey(parsed)
	}
	if _, _, err := GeneratePrivateKey(provider.AlgorithmRSASHA256, rand.Reader, 1024); err == nil {
		t.Fatal("generated a 1024-bit RSA custody key")
	}
}
