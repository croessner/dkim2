package migration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

type keyImportClientFake struct {
	values     map[string][]byte
	attributes [][]string
	maximums   []int
}

// FetchKey returns one detached synthetic protected value.
func (f *keyImportClientFake) FetchKey(
	ctx context.Context,
	domain string,
	selector string,
	attributes []string,
	maximum int,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.attributes = append(f.attributes, append([]string(nil), attributes...))
	f.maximums = append(f.maximums, maximum)
	return append([]byte(nil), f.values[domain+"\x00"+selector]...), nil
}

type dnsProverFake struct {
	calls     int
	fail      bool
	selectors []string
}

// Prove records one synthetic exact canonical SPKI proof.
func (f *dnsProverFake) Prove(
	ctx context.Context,
	_ string,
	selector string,
	_ Algorithm,
	spki []byte,
) error {
	f.calls++
	f.selectors = append(f.selectors, selector)
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.fail || len(spki) == 0 {
		return errors.New("synthetic proof failure")
	}
	return nil
}

type txtTransportFake struct {
	lookup dkim2.TXTLookupResult
	calls  int
}

// LookupTXT returns one already-bounded synthetic DNS answer.
func (f *txtTransportFake) LookupTXT(
	ctx context.Context,
	owner string,
) (dkim2.TXTLookupResult, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return dkim2.TXTLookupResult{}, err
	}
	if owner != "selector._domainkey.example.test." {
		return dkim2.TXTLookupResult{}, errors.New("unexpected owner")
	}
	return f.lookup, nil
}

// TestImportKeysBuildsOneExactNativeCandidate proves protected import and DNS
// proof produce canonical datasource-owned key material without local staging.
func TestImportKeysBuildsOneExactNativeCandidate(t *testing.T) {
	privatePEM := rsaPrivatePEM(t)
	config := testConfig()
	records := []LegacyRecord{{
		selector: migrationTestSelector, sourceSelector: migrationTestSelector,
		domain: migrationTestDomain, associated: migrationTestDomain,
		algorithm: AlgorithmRSA, active: true,
	}}
	client := &keyImportClientFake{values: map[string][]byte{
		migrationTestSourceKey: privatePEM,
	}}
	prover := &dnsProverFake{}
	imported, err := ImportKeys(context.Background(), records, config.Plan, client, prover)
	if err != nil {
		t.Fatal("import validated key")
	}
	defer closeImported(imported)
	if prover.calls != 1 || len(client.attributes) != 1 ||
		client.maximums[0] != 64<<10 ||
		!slices.Equal(client.attributes[0], keyImportAttributes) {
		t.Fatal("protected import projection or proof drifted")
	}
	if len(imported) != 1 || imported[0].key == nil ||
		imported[0].mapping != config.Plan.Mappings[0] {
		t.Fatal("imported credential binding drifted")
	}
	candidate, err := BuildPublicationCandidate(config.Plan, imported)
	if err != nil || len(candidate.rows.KeyMaterial) != 1 ||
		len(candidate.rows.KeyMaterial[0].PrivatePKCS8) == 0 {
		t.Fatal("native publication candidate unavailable")
	}
	clearCandidateRows(&candidate.rows)
}

// TestImportUsesExactLegacySelectorAfterCanonicalInventory proves case-exact
// LDAP lookup stays separate from the canonical lowercase DKIM2 identity.
func TestImportUsesExactLegacySelectorAfterCanonicalInventory(t *testing.T) {
	privatePEM := rsaPrivatePEM(t)
	records := []LegacyRecord{{
		selector: migrationTestCanonicalSelector, sourceSelector: migrationTestMixedCaseSelector,
		domain: migrationTestDomain, associated: migrationTestDomain,
		algorithm: AlgorithmRSA, active: true,
	}}
	config := testConfig()
	config.Plan.Mappings[0].Selector = migrationTestCanonicalSelector
	client := &keyImportClientFake{values: map[string][]byte{
		migrationTestDomain + "\x00" + migrationTestMixedCaseSelector: privatePEM,
	}}
	imported, err := ImportKeys(
		context.Background(), records, config.Plan, client, &dnsProverFake{},
	)
	if err != nil || len(imported) != 1 {
		t.Fatal("case-exact legacy import failed")
	}
	closeImported(imported)
}

// TestImportMapsLegacySourceToDistinctDNSSelector proves protected LDAP lookup
// and public DKIM2 DNS proof remain separate explicit identities.
func TestImportMapsLegacySourceToDistinctDNSSelector(t *testing.T) {
	privatePEM := rsaPrivatePEM(t)
	records := []LegacyRecord{{
		selector: migrationTestCanonicalSelector, sourceSelector: migrationTestMixedCaseSelector,
		domain: migrationTestDomain, associated: migrationTestDomain,
		algorithm: AlgorithmRSA, active: true,
	}}
	config := testConfig()
	config.Plan.Mappings[0].SourceSelector = migrationTestCanonicalSelector
	config.Plan.Mappings[0].Selector = "dkim2-ab12"
	client := &keyImportClientFake{values: map[string][]byte{
		migrationTestDomain + "\x00" + migrationTestMixedCaseSelector: privatePEM,
	}}
	prover := &dnsProverFake{}
	imported, err := ImportKeys(
		context.Background(), records, config.Plan, client, prover,
	)
	if err != nil || len(imported) != 1 {
		t.Fatal("distinct source and target selector import failed")
	}
	closeImported(imported)
	if !slices.Equal(prover.selectors, []string{"dkim2-ab12"}) {
		t.Fatal("DNS proof did not use the explicit target selector")
	}
}

// TestImportKeysNormalizesLegacyRSAPKCS1 proves legacy RSA compatibility
// without widening the protected registry's canonical PKCS#8 contract.
func TestImportKeysNormalizesLegacyRSAPKCS1(t *testing.T) {
	records := []LegacyRecord{{
		selector: migrationTestSelector, sourceSelector: migrationTestSelector,
		domain: migrationTestDomain, associated: migrationTestDomain,
		algorithm: AlgorithmRSA, active: true,
	}}
	config := testConfig()
	client := &keyImportClientFake{values: map[string][]byte{
		migrationTestSourceKey: rsaPrivatePKCS1PEM(t),
	}}
	imported, err := ImportKeys(
		context.Background(), records, config.Plan, client, &dnsProverFake{},
	)
	if err != nil || len(imported) != 1 || imported[0].key == nil {
		t.Fatal("import legacy RSA PKCS#1 key")
	}
	defer closeImported(imported)
	encoded := imported[0].key.Encoded()
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != privateKeyPEMType ||
		len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("legacy RSA key was not normalized to canonical PKCS#8 PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal("parse normalized RSA PKCS#8 key")
	}
}

// TestNormalizeLegacyPrivateKeyFailsClosed proves compatibility is limited to
// unencrypted RSA PKCS#1 and does not widen Ed25519 or malformed input.
func TestNormalizeLegacyPrivateKeyFailsClosed(t *testing.T) {
	pkcs1 := rsaPrivatePKCS1PEM(t)
	for _, test := range []struct {
		name      string
		encoded   []byte
		algorithm Algorithm
	}{
		{name: "Ed25519 algorithm", encoded: pkcs1, algorithm: AlgorithmEd25519},
		{name: "trailing data", encoded: append(append([]byte(nil), pkcs1...), []byte("private")...), algorithm: AlgorithmRSA},
		{name: "PEM headers", encoded: pem.EncodeToMemory(&pem.Block{
			Type: legacyRSAPrivateKeyType, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
			Bytes: []byte("private"),
		}), algorithm: AlgorithmRSA},
	} {
		t.Run(test.name, func(t *testing.T) {
			normalized, err := normalizeLegacyPrivateKey(test.encoded, test.algorithm)
			clear(normalized)
			if err == nil {
				t.Fatal("unsupported legacy key input succeeded")
			}
		})
	}
}

// TestClearRSAPrivateKeyClearsCRTSecrets proves compatibility conversion
// cleanup includes parsed and precomputed mutable private integers.
func TestClearRSAPrivateKeyClearsCRTSecrets(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey.Precompute()
	if privateKey.D.Sign() == 0 || privateKey.Primes[0].Sign() == 0 ||
		privateKey.Precomputed.Dp == nil || privateKey.Precomputed.Dp.Sign() == 0 {
		t.Fatal("RSA fixture did not contain private CRT material")
	}
	clearRSAPrivateKey(privateKey)
	if privateKey.D.Sign() != 0 || privateKey.Primes[0].Sign() != 0 ||
		privateKey.Primes[1].Sign() != 0 ||
		privateKey.Precomputed.Dp.Sign() != 0 ||
		privateKey.Precomputed.Dq.Sign() != 0 ||
		privateKey.Precomputed.Qinv.Sign() != 0 {
		t.Fatal("RSA private material survived compatibility cleanup")
	}
}

// TestImportKeysFailsClosedBeforeRegistrySideEffects proves denial cleanup.
func TestImportKeysFailsClosedBeforeRegistrySideEffects(t *testing.T) {
	privatePEM := rsaPrivatePEM(t)
	records := []LegacyRecord{{
		selector: migrationTestSelector, sourceSelector: migrationTestSelector,
		domain: migrationTestDomain, associated: migrationTestDomain,
		algorithm: AlgorithmRSA, active: true,
	}}
	config := testConfig()
	for _, test := range []struct {
		name   string
		value  []byte
		prover *dnsProverFake
	}{
		{name: "toxic pem", value: []byte("TOXIC-PRIVATE"), prover: &dnsProverFake{}},
		{name: "dns mismatch", value: privatePEM, prover: &dnsProverFake{fail: true}},
		{name: "large", value: bytes.Repeat([]byte("x"), (64<<10)+1), prover: &dnsProverFake{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &keyImportClientFake{values: map[string][]byte{
				migrationTestSourceKey: test.value,
			}}
			imported, err := ImportKeys(
				context.Background(), records, config.Plan, client, test.prover,
			)
			if err == nil || imported != nil ||
				strings.Contains(fmt.Sprint(err), "TOXIC") {
				t.Fatal("protected import denial leaked or returned state")
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	imported, err := ImportKeys(
		cancelled, records, config.Plan,
		&keyImportClientFake{values: map[string][]byte{
			migrationTestSourceKey: privatePEM,
		}},
		&dnsProverFake{},
	)
	if err == nil || imported != nil {
		t.Fatal("cancelled import returned state")
	}
}

// TestFreshDNSProverRequiresExactCanonicalSPKI proves cache-bypassed DNS parsing.
func TestFreshDNSProverRequiresExactCanonicalSPKI(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate Ed25519 key")
	}
	record := []byte(
		"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(public),
	)
	lookup, err := dkim2.NewFoundTXTLookupResult(
		[][]byte{record}, time.Minute, dkim2.DNSSECStatusUnavailable,
	)
	if err != nil {
		t.Fatal("construct DNS answer")
	}
	transport := &txtTransportFake{lookup: lookup}
	prover, err := NewFreshDNSProver(transport)
	if err != nil {
		t.Fatal("construct DNS prover")
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("marshal Ed25519 SPKI")
	}
	if err := prover.Prove(
		context.Background(), migrationTestDomain, migrationTestSelector, AlgorithmEd25519, spki,
	); err != nil || transport.calls != 1 {
		t.Fatal("exact DNS proof failed")
	}
	spki[0] ^= 0xff
	if err := prover.Prove(
		context.Background(), migrationTestDomain, migrationTestSelector, AlgorithmEd25519, spki,
	); err == nil || transport.calls != 2 {
		t.Fatal("mismatched DNS proof succeeded")
	}
}

// rsaPrivatePEM returns one exact validated PKCS#8 RSA fixture.
func rsaPrivatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate RSA key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("marshal RSA key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der})
}

// rsaPrivatePKCS1PEM returns one validated legacy RSA PKCS#1 fixture.
func rsaPrivatePKCS1PEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate legacy RSA key")
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: legacyRSAPrivateKeyType, Bytes: der})
}
