package rotationadmin

import (
	"crypto/ed25519"
	"crypto/rand"
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

// TestLoadConfigRequiresFiveDistinctProtectedRoles freezes the purge and closer authority boundaries.
func TestLoadConfigRequiresFiveDistinctProtectedRoles(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("protect test directory")
	}
	secretPaths := make([]string, 5)
	for index := range secretPaths {
		secretPaths[index] = filepath.Join(directory, "role-"+string(rune('a'+index)))
		if err := os.WriteFile(secretPaths[index], []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "rotation.yaml")
	document := "version: dkim2-rotation-admin-v1\nauthority_id: aaaaaaaaaaaaaaaaaaaaaaaaae\nbackend: ldap\ndeadline: 30s\nlimits:\n  max_work_items: 16\n  max_dns_batch_records: 4\n  max_dns_batches: 4\nroles:\n  snapshot:\n    name: snapshot\n    secret_file: " + secretPaths[0] + "\n  staging:\n    name: staging\n    secret_file: " + secretPaths[1] + "\n  activation:\n    name: activation\n    secret_file: " + secretPaths[2] + "\n  purge:\n    name: purge\n    secret_file: " + secretPaths[3] + "\n  closer:\n    name: closer\n    secret_file: " + secretPaths[4] + "\n"
	if err := os.WriteFile(configPath, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal("five distinct protected roles rejected")
	}
	defer loaded.Close() //nolint:errcheck // Test cleanup cannot affect the assertion.
	if loaded.Backend() != backendLDAP || loaded.Limits().MaxWorkItems != 16 {
		t.Fatal("configuration facts drifted")
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(document, "deadline: 30s", "deadline: 24h", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	longCampaign, longErr := LoadConfig(configPath)
	if longErr != nil || longCampaign.Deadline().Hours() != 24 {
		t.Fatal("bounded large-campaign deadline rejected")
	}
	_ = longCampaign.Close()
	if err := os.WriteFile(configPath, []byte(strings.Replace(document, "deadline: 30s", "deadline: 24h0m1s", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if overlong, overlongErr := LoadConfig(configPath); overlongErr == nil || overlong != nil {
		t.Fatal("deadline beyond the compiled campaign bound accepted")
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(document, "name: purge", "name: staging", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if duplicate, duplicateErr := LoadConfig(configPath); duplicateErr == nil || duplicate != nil {
		t.Fatal("duplicate authority role accepted")
	}
}

// TestLoadConfigAcceptsProtectedTLSBundle proves the configured CA read stays
// within the central protected-document ceiling used by production runtimes.
func TestLoadConfigAcceptsProtectedTLSBundle(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("protect test directory")
	}
	secretPaths := make([]string, 5)
	for index := range secretPaths {
		secretPaths[index] = filepath.Join(directory, "role-"+string(rune('a'+index)))
		if err := os.WriteFile(secretPaths[index], []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	caPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "rotation.yaml")
	document := "version: dkim2-rotation-admin-v1\nauthority_id: aaaaaaaaaaaaaaaaaaaaaaaaae\nbackend: ldap\ndeadline: 30s\nlimits:\n  max_work_items: 16\n  max_dns_batch_records: 4\n  max_dns_batches: 4\nroles:\n  snapshot:\n    name: snapshot\n    secret_file: " + secretPaths[0] + "\n  staging:\n    name: staging\n    secret_file: " + secretPaths[1] + "\n  activation:\n    name: activation\n    secret_file: " + secretPaths[2] + "\n  purge:\n    name: purge\n    secret_file: " + secretPaths[3] + "\n  closer:\n    name: closer\n    secret_file: " + secretPaths[4] + "\ntransport:\n  ldap:\n    address: 127.0.0.1:636\n    server_name: ldap.example.test\n    base_dn: dc=example,dc=test\n    ca_file: " + caPath + "\n    starttls: false\ndns:\n  resolver_class: explicit_recursive\n  resolver_endpoints:\n    - 127.0.0.1:53\n  export_ttl_seconds: 300\n  proof_lifetime_seconds: 60\n  lookup_timeout: 2s\n"
	if err := os.WriteFile(configPath, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal("protected TLS bundle rejected")
	}
	defer loaded.Close() //nolint:errcheck // Test cleanup cannot affect the assertion.
	if _, err := LoadTrustRoots(caPath); err != nil {
		t.Fatal("runtime trust-root read rejected")
	}
	policy, timeout, ok := loaded.DNSProofPolicy()
	if !ok || policy.ResolverClass != canonicalRecursiveResolver || timeout != 2*time.Second {
		t.Fatal("explicit recursive config was not normalized to canonical proof policy")
	}
	if prover, err := NewDNSBatchProver(policy, timeout); err != nil || prover == nil {
		t.Fatal("canonical campaign DNS prover rejected")
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
}

// TestEncodeCommandReportRejectsIdentityMarkers freezes report privacy and stable output shape.
func TestEncodeCommandReportRejectsIdentityMarkers(t *testing.T) {
	report := CommandReport{Command: "status", State: StatePrepared, Backend: backendLDAP, WorkCount: 4, RecordCount: 8, BatchCount: 2, ResultClass: "success"}
	for _, machine := range []bool{false, true} {
		encoded, err := EncodeCommandReport(report, machine)
		if err != nil || len(encoded) == 0 {
			t.Fatal("safe report rejected")
		}
		for _, toxic := range []string{"example.test", "cn=", "password", "private", "digest"} {
			if strings.Contains(string(encoded), toxic) {
				t.Fatalf("report exposed toxic marker %q", toxic)
			}
		}
	}
	if encoded, err := EncodeCommandReport(CommandReport{Command: "status", Backend: backendLDAP, ResultClass: "example.test"}, true); err == nil || encoded != nil {
		t.Fatal("identity-shaped result class accepted")
	}
}
