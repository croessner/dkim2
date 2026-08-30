//go:build linux || darwin

package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestValidatedServerTLSConfigEnforcesIdentityLifetimeAndTLS13 freezes the private-network TLS boundary.
func TestValidatedServerTLSConfigEnforcesIdentityLifetimeAndTLS13(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	certificate, privateKey, ca := serverTLSFixture(t, "dkim2d-inbound", now.Add(-time.Hour), now.Add(time.Hour))
	configuration, err := validatedServerTLSConfig(certificate, privateKey, ca, "dkim2d-inbound", now)
	if err != nil || configuration == nil || configuration.MinVersion != tls.VersionTLS13 ||
		configuration.MaxVersion != tls.VersionTLS13 || len(configuration.Certificates) != 1 ||
		len(configuration.NextProtos) != 1 || configuration.NextProtos[0] != "http/1.1" {
		t.Fatal("valid server identity did not produce the exact TLS 1.3 policy")
	}
	if value, configErr := validatedServerTLSConfig(certificate, privateKey, ca, "other-service", now); value != nil || CodeOf(configErr) != CodeProtectedContent {
		t.Fatal("server certificate with the wrong DNS identity was accepted")
	}
	if value, configErr := validatedServerTLSConfig(certificate, privateKey, ca, "dkim2d-inbound", now.Add(2*time.Hour)); value != nil || CodeOf(configErr) != CodeProtectedContent {
		t.Fatal("expired server certificate was accepted")
	}
	wildcardCertificate, wildcardKey, wildcardCA := serverTLSFixture(t, "*.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	if value, configErr := validatedServerTLSConfig(wildcardCertificate, wildcardKey, wildcardCA, "dkim2d-inbound.example.test", now); value != nil || CodeOf(configErr) != CodeProtectedContent {
		t.Fatal("wildcard server certificate was accepted")
	}
	if value, configErr := validatedServerTLSConfig(append(append([]byte(nil), certificate...), ca...), privateKey, ca, "dkim2d-inbound", now); value != nil || CodeOf(configErr) != CodeProtectedContent {
		t.Fatal("served root certificate was accepted")
	}
	if allowsOnlyServerAuthentication([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Fatal("dual server/client authentication usage was accepted")
	}
}

// TestLoadProtectedOwnsPrivateNetworkTLSIdentity proves all TLS files stay generation-bound.
func TestLoadProtectedOwnsPrivateNetworkTLSIdentity(t *testing.T) {
	fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	now := time.Now()
	certificate, privateKey, ca := serverTLSFixture(t, "dkim2d-inbound", now.Add(-time.Hour), now.Add(time.Hour))
	makeGenerationWritable(t, fixture.generationPath)
	writeProtectedTestFile(t, filepath.Join(fixture.generationPath, "server-cert.pem"), certificate, 0o600)
	writeProtectedTestFile(t, filepath.Join(fixture.generationPath, "server-key.pem"), privateKey, 0o600)
	writeProtectedTestFile(t, filepath.Join(fixture.generationPath, "server-ca.pem"), ca, 0o600)
	sealGeneration(t, fixture.generationPath)
	document, err := os.ReadFile(fixture.yamlPath)
	if err != nil {
		t.Fatal("read protected TLS fixture")
	}
	replacement := "server:\n  listen: 10.73.0.2:8080\n  listener_mode: tls_private_network\n" +
		"  tls:\n" +
		"    certificate_file: " + filepath.Join(fixture.generationPath, "server-cert.pem") + "\n" +
		"    private_key_file: " + filepath.Join(fixture.generationPath, "server-key.pem") + "\n" +
		"    ca_file: " + filepath.Join(fixture.generationPath, "server-ca.pem") + "\n" +
		"    server_name: dkim2d-inbound\n  capability_file:"
	document = []byte(strings.Replace(string(document), "server:\n  capability_file:", replacement, 1))
	writeProtectedTestFile(t, fixture.yamlPath, document, 0o600)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if err != nil || owner == nil {
		t.Fatalf("LoadProtected() failed with code %s", CodeOf(err))
	}
	defer func() { _ = owner.Close() }()
	preparation, err := owner.PrepareRuntime()
	if err != nil || preparation.ServerTLSConfig() == nil {
		t.Fatal("runtime preparation did not retain the validated TLS identity")
	}
}

// serverTLSFixture creates one short-lived self-signed test identity.
func serverTLSFixture(t *testing.T, serverName string, notBefore, notAfter time.Time) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate CA test key")
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("create CA test certificate")
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate issuer test key")
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test issuer"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, caTemplate, &issuerKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("create issuer test certificate")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate server test key")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, &privateKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal("create server test certificate")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal("marshal server test key")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificateDER})
	certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: issuerDER})...)
	return certificatePEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: caDER})
}
