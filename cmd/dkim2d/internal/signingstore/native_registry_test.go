package signingstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/croessner/dkim2/provider"
)

// TestOpenNativeRegistryValidatesAndOwnsKeyMaterial proves the native
// datasource registry accepts one exact canonical key and detaches its bytes.
func TestOpenNativeRegistryValidatesAndOwnsKeyMaterial(t *testing.T) {
	material, privateDER := nativeRSAMaterial(t, 7, "native-handle")
	registry, err := OpenNativeRegistry(7, []*NativeKeyMaterial{material})
	if err != nil {
		t.Fatalf("OpenNativeRegistry() error = %v", err)
	}
	privateDER[0] ^= 0xff
	if err := material.Close(); err != nil {
		t.Fatalf("material.Close() error = %v", err)
	}

	generation, err := registry.Generation(context.Background())
	if err != nil || generation != 7 || len(registry.Bindings()) != 1 {
		t.Fatalf("native registry metadata unavailable")
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestOpenNativeRegistryRejectsMalformedRelationships covers canonical DER,
// generation, algorithm, SPKI, and duplicate-handle failure boundaries.
func TestOpenNativeRegistryRejectsMalformedRelationships(t *testing.T) {
	valid, _ := nativeRSAMaterial(t, 9, "native-handle")
	duplicate, _ := nativeRSAMaterial(t, 9, "native-handle")
	wrongGeneration, _ := nativeRSAMaterial(t, 10, "other-handle")
	wrongSPKI, _ := nativeRSAMaterial(t, 9, "spki-handle")
	wrongSPKI.publicSPKI[0] ^= 0xff
	noncanonical, _ := nativeRSAMaterial(t, 9, "der-handle")
	noncanonical.privatePKCS8 = append(noncanonical.privatePKCS8, 0)
	wrongAlgorithm, _ := nativeRSAMaterial(t, 9, "algorithm-handle")
	wrongAlgorithm.algorithm = provider.AlgorithmEd25519SHA256

	cases := []struct {
		name       string
		generation uint64
		materials  []*NativeKeyMaterial
	}{
		{name: "zero generation", materials: []*NativeKeyMaterial{valid}},
		{name: "mixed generation", generation: 9, materials: []*NativeKeyMaterial{wrongGeneration}},
		{name: "duplicate handle", generation: 9, materials: []*NativeKeyMaterial{valid, duplicate}},
		{name: "public mismatch", generation: 9, materials: []*NativeKeyMaterial{wrongSPKI}},
		{name: "noncanonical der", generation: 9, materials: []*NativeKeyMaterial{noncanonical}},
		{name: "algorithm mismatch", generation: 9, materials: []*NativeKeyMaterial{wrongAlgorithm}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if registry, err := OpenNativeRegistry(test.generation, test.materials); err == nil || registry != nil {
				t.Fatalf("OpenNativeRegistry() accepted malformed material")
			}
		})
	}
	for _, material := range []*NativeKeyMaterial{
		valid, duplicate, wrongGeneration, wrongSPKI, noncanonical, wrongAlgorithm,
	} {
		if err := material.Close(); err != nil {
			t.Fatalf("material.Close() error = %v", err)
		}
	}
}

// TestNativeKeyMaterialFormattingIsSecretSafe prevents diagnostic traversal of
// native key bytes and protected binding facts.
func TestNativeKeyMaterialFormattingIsSecretSafe(t *testing.T) {
	material, privateDER := nativeRSAMaterial(t, 11, "privacy-handle")
	defer func() {
		if err := material.Close(); err != nil {
			t.Errorf("material.Close() error = %v", err)
		}
	}()
	marker := fmt.Sprintf("%x", privateDER[:16])
	values := []string{
		fmt.Sprint(material), fmt.Sprintf("%#v", material),
		string(mustMarshalNativeMaterial(t, material)),
	}
	for _, value := range values {
		if bytes.Contains([]byte(value), []byte(marker)) || value == "" {
			t.Fatalf("native material formatting exposed protected bytes")
		}
	}
}

// nativeRSAMaterial constructs one canonical synthetic native record.
func nativeRSAMaterial(t *testing.T, generation uint64, handle string) (*NativeKeyMaterial, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	clearPrivateKey(crypto.PrivateKey(key))
	material, err := NewNativeKeyMaterial(
		generation, "tenant", "example.test", provider.ProfileUseOriginator,
		handle, provider.AlgorithmRSASHA256, publicDER, privateDER,
	)
	if err != nil {
		t.Fatalf("NewNativeKeyMaterial() error = %v", err)
	}
	return material, privateDER
}

// mustMarshalNativeMaterial returns the protected JSON representation.
func mustMarshalNativeMaterial(t *testing.T, material *NativeKeyMaterial) []byte {
	t.Helper()
	value, err := material.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	return value
}

// TestImportedPrivateKeyExportsCanonicalPKCS8 proves bootstrap can transfer a
// validated legacy key into native datasource publication without PEM storage.
func TestImportedPrivateKeyExportsCanonicalPKCS8(t *testing.T) {
	material, privateDER := nativeRSAMaterial(t, 13, "import-handle")
	defer func() {
		if err := material.Close(); err != nil {
			t.Errorf("material.Close() error = %v", err)
		}
	}()
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: privateDER})
	imported, err := InspectImportedPrivateKey(privatePEM, "rsa")
	if err != nil {
		t.Fatalf("InspectImportedPrivateKey() error = %v", err)
	}
	defer func() {
		if err := imported.Close(); err != nil {
			t.Errorf("imported.Close() error = %v", err)
		}
	}()
	canonical := imported.NativePKCS8DER()
	if !bytes.Equal(canonical, privateDER) {
		t.Fatalf("canonical native export unavailable")
	}
	clear(canonical)
	clear(privatePEM)
}
