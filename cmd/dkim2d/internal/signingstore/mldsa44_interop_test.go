package signingstore

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
)

const (
	interopHandleID = "odm-mldsa44-handle"
	interopSelector = "dkim2-6f646d"
	interopDomain   = "example.test"
)

// opendkimManageMLDSA44 is one credential produced by opendkim-manage-go.
type opendkimManageMLDSA44 struct {
	Algorithm    string `json:"algorithm"`
	PrivatePKCS8 string `json:"private_pkcs8_base64"`
	PublicSPKI   string `json:"public_spki_base64"`
	DNSRecord    string `json:"dns_record"`
}

// loadOpendkimManageMLDSA44 decodes the opendkim-manage-go fixture.
func loadOpendkimManageMLDSA44(t *testing.T) (opendkimManageMLDSA44, []byte, []byte) {
	t.Helper()
	content, err := os.ReadFile("testdata/opendkim-manage-go-mldsa44.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var fixture opendkimManageMLDSA44
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	privatePKCS8, err := base64.StdEncoding.DecodeString(fixture.PrivatePKCS8)
	if err != nil {
		t.Fatal("private PKCS#8 base64")
	}
	publicSPKI, err := base64.StdEncoding.DecodeString(fixture.PublicSPKI)
	if err != nil {
		t.Fatal("public SPKI base64")
	}
	return fixture, privatePKCS8, publicSPKI
}

type txtRecordTransport struct{ record []byte }

// LookupTXT serves the exact opendkim-manage-go record for its selector.
func (t txtRecordTransport) LookupTXT(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
	if owner != interopSelector+"._domainkey."+interopDomain+"." {
		return dkim2.NewAbsentTXTLookupResult(dkim2.TXTAbsenceNXDOMAIN, time.Minute, dkim2.DNSSECStatusInsecure)
	}
	return dkim2.NewFoundTXTLookupResult([][]byte{t.record}, time.Minute, dkim2.DNSSECStatusInsecure)
}

// TestOpendkimManageMLDSA44CredentialSignsAndVerifies is the interop proof
// against opendkim-manage-go: the seed-only PKCS#8 and PKIX SPKI it writes to
// LDAP (dkim2PrivateKeyPKCS8, dkim2PublicKeySPKI) load through the native
// custody codec shared by LDAP, PostgreSQL, MySQL/MariaDB, and flat files;
// the derived SPKI equals the stored one; a hedged ML-DSA-44 signature over
// the Section 12.8 input verifies against the exact DNS record it publishes
// ("v=DKIM1; k=mldsa44; p=<raw 1312-octet key>") through the DNS key provider.
func TestOpendkimManageMLDSA44CredentialSignsAndVerifies(t *testing.T) {
	fixture, privatePKCS8, publicSPKI := loadOpendkimManageMLDSA44(t)
	if fixture.Algorithm != string(provider.AlgorithmMLDSA44) || len(privatePKCS8) != 54 || len(publicSPKI) != 1334 {
		t.Fatalf("fixture shape algorithm=%q pkcs8=%d spki=%d", fixture.Algorithm, len(privatePKCS8), len(publicSPKI))
	}
	material, err := NewNativeKeyMaterial(
		7, "tenant", interopDomain, provider.ProfileUseOriginator,
		interopHandleID, provider.AlgorithmMLDSA44, publicSPKI, privatePKCS8,
	)
	if err != nil {
		t.Fatalf("NewNativeKeyMaterial() error = %v", err)
	}
	registry, err := OpenNativeRegistry(7, []*NativeKeyMaterial{material})
	_ = material.Close()
	if err != nil {
		t.Fatalf("OpenNativeRegistry() error = %v", err)
	}
	t.Cleanup(func() { _ = registry.Close(context.Background()) })

	parsed, err := x509.ParsePKIXPublicKey(publicSPKI)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	handle, err := dkim2.NewPrivateKeyHandle([]byte(interopHandleID))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := dkim2.NewMLDSA44SigningCredential(interopSelector, parsed.(*mldsa.PublicKey), handle)
	if err != nil {
		t.Fatalf("NewMLDSA44SigningCredential() error = %v", err)
	}
	profile, err := dkim2.NewMLDSA44SigningProfile(interopDomain, credential)
	if err != nil {
		t.Fatalf("NewMLDSA44SigningProfile() error = %v", err)
	}
	keys, err := dkim2.NewDNSPublicKeyProvider(txtRecordTransport{record: []byte(fixture.DNSRecord)})
	if err != nil {
		t.Fatalf("NewDNSPublicKeyProvider() error = %v", err)
	}
	signer, err := dkim2.NewSigner(keys, dkim2.NewRequestRouteAuthority(), signingStoreAuthorizer{}, registry)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	raw := []byte("From: sender@example.test\r\nSubject: opendkim-manage-go mldsa44\r\n\r\nbody\r\n")
	reverse := []byte("<sender@example.test>")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := dkim2.NewOriginatorRouteEntry(source, reverse, recipients, dkim2.RouteDisclosureSingle, []byte("local"))
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	_, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() error = %v", err)
	}
	result, _, err := signer.SignOriginator(context.Background(), dkim2.NewOriginatorSigningRequest(
		raw, reverse, recipients, tickets[0], profile, dkim2.SigningMetadata{},
		dkim2.SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || !result.Valid() {
		t.Fatalf("SignOriginator() error = %v", err)
	}
	signed, ok := result.Unrestricted()
	if !ok || !bytes.Contains(signed.Bytes(), []byte(interopSelector+":mldsa44:")) {
		t.Fatal("signed output lacks the mldsa44 set")
	}
	verifier, err := dkim2.NewVerifier(keys)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	verified, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(signed.Bytes(), reverse, recipients))
	if err != nil || verified.State() != dkim2.ResultStatePASS {
		t.Fatalf("Verify() state=%q error=%v", verified.State(), err)
	}
}

// TestNativeMLDSA44CustodyRejectsMalformedKeys proves the custody codec
// rejects a non-canonical PKCS#8 encoding, a key of another ML-DSA parameter
// set, a public-key mismatch, and an algorithm mismatch.
func TestNativeMLDSA44CustodyRejectsMalformedKeys(t *testing.T) {
	_, privatePKCS8, publicSPKI := loadOpendkimManageMLDSA44(t)
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	otherPKCS8, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(other.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	_, freshPKCS8, freshSPKI := generateMLDSA44ForTest(t)
	for name, test := range map[string]struct {
		private, public []byte
		algorithm       provider.Algorithm
	}{
		"trailing byte":      {append(bytes.Clone(privatePKCS8), 0), publicSPKI, provider.AlgorithmMLDSA44},
		"ml-dsa-65":          {otherPKCS8, otherSPKI, provider.AlgorithmMLDSA44},
		"public mismatch":    {privatePKCS8, freshSPKI, provider.AlgorithmMLDSA44},
		"algorithm mismatch": {freshPKCS8, freshSPKI, provider.AlgorithmEd25519SHA256},
	} {
		if key, _, err := parseNativePrivateKey(test.private, test.public, test.algorithm); err == nil {
			clearPrivateKey(key)
			t.Fatalf("%s: parseNativePrivateKey() accepted malformed custody", name)
		}
	}
	key, digest, err := parseNativePrivateKey(privatePKCS8, publicSPKI, provider.AlgorithmMLDSA44)
	if err != nil || digest == ([32]byte{}) {
		t.Fatalf("parseNativePrivateKey(valid) error = %v", err)
	}
	clearPrivateKey(key)
}

// TestGeneratePrivateKeyProducesSeedOnlyMLDSA44 proves generation reads a
// 32-byte seed from the injected reader, emits the canonical seed-only
// PKCS#8 and PKIX SPKI forms, and rejects an all-zero seed.
func TestGeneratePrivateKeyProducesSeedOnlyMLDSA44(t *testing.T) {
	seed, privatePKCS8, publicSPKI := generateMLDSA44ForTest(t)
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatal(err)
	}
	wantPKCS8, _ := x509.MarshalPKCS8PrivateKey(key)
	wantSPKI, _ := x509.MarshalPKIXPublicKey(key.PublicKey())
	if !bytes.Equal(privatePKCS8, wantPKCS8) || !bytes.Equal(publicSPKI, wantSPKI) || len(privatePKCS8) != 54 {
		t.Fatal("generated custody is not the seed-only PKCS#8 of the injected seed")
	}
	if _, _, err := GeneratePrivateKey(provider.AlgorithmMLDSA44, bytes.NewReader(make([]byte, 32)), 0); err == nil {
		t.Fatal("all-zero seed accepted")
	}
	if _, _, err := GeneratePrivateKey(provider.AlgorithmMLDSA44, bytes.NewReader(make([]byte, 31)), 0); err == nil {
		t.Fatal("short seed accepted")
	}
}

// generateMLDSA44ForTest generates one custody key from a fixed seed.
func generateMLDSA44ForTest(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x5c}, mldsa.PrivateKeySize)
	privatePKCS8, publicSPKI, err := GeneratePrivateKey(provider.AlgorithmMLDSA44, bytes.NewReader(seed), 0)
	if err != nil {
		t.Fatalf("GeneratePrivateKey(mldsa44) error = %v", err)
	}
	return seed, privatePKCS8, publicSPKI
}
