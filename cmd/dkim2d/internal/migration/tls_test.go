package migration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestMigrationRootPoolOwnsCertificateBytes proves principal cleanup cannot corrupt retained trust.
func TestMigrationRootPoolOwnsCertificateBytes(t *testing.T) {
	t.Parallel()

	const serverName = "migration.internal.example"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate CA key")
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "migration-root"},
		NotBefore:             time.Unix(1_700_000_000, 0).UTC(),
		NotAfter:              time.Unix(1_900_000_000, 0).UTC(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, publicKey, privateKey,
	)
	if err != nil {
		t.Fatal("create CA certificate")
	}
	caCertificate, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		t.Fatal("parse CA certificate")
	}
	leafPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate leaf key")
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    template.NotBefore,
		NotAfter:     template.NotAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader, leafTemplate, caCertificate, leafPublicKey, privateKey,
	)
	if err != nil {
		t.Fatal("create leaf certificate")
	}
	candidate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal("parse leaf certificate")
	}
	principalDER := bytes.Clone(der)
	roots, err := migrationRootPool([][]byte{principalDER})
	if err != nil {
		t.Fatal("construct migration root pool")
	}
	clear(principalDER)
	if _, err := candidate.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     serverName,
		CurrentTime: time.Unix(1_800_000_000, 0).UTC(),
	}); err != nil {
		t.Fatal("principal cleanup corrupted retained migration trust")
	}
}
