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
	"os"
	"path/filepath"
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
	calls int
	fail  bool
}

// Prove records one synthetic exact canonical SPKI proof.
func (f *dnsProverFake) Prove(
	ctx context.Context,
	_ string,
	_ string,
	_ Algorithm,
	spki []byte,
) error {
	f.calls++
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

// TestImportKeysStagesOneExactInertRegistry proves protected ordering and bytes.
func TestImportKeysStagesOneExactInertRegistry(t *testing.T) {
	privatePEM := rsaPrivatePEM(t)
	config := testConfig()
	config.Plan.RegistryRoot = t.TempDir()
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(config.Plan.RegistryRoot, "2"), 0o700)
	})
	if err := os.Chmod(config.Plan.RegistryRoot, 0o700); err != nil {
		t.Fatal("protect registry parent")
	}
	preparedGeneration := filepath.Join(config.Plan.RegistryRoot, "2")
	if err := os.Mkdir(preparedGeneration, 0o700); err != nil {
		t.Fatal("prepare protected generation")
	}
	if err := os.WriteFile(
		filepath.Join(preparedGeneration, "capability"), []byte("prepared"), 0o600,
	); err != nil {
		t.Fatal("prepare generation sibling")
	}
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
	manifestPath, err := StageImportedRegistry(config.Plan, imported)
	if err != nil || manifestPath != "2/private-manifest.json" {
		entries, _ := os.ReadDir(config.Plan.RegistryRoot)
		t.Fatalf("stage exact registry: %v entries=%d", err, len(entries))
	}
	generationPath := filepath.Join(config.Plan.RegistryRoot, "2")
	info, err := os.Stat(generationPath)
	if err != nil || info.Mode().Perm() != 0o500 {
		t.Fatal("staged registry was not sealed")
	}
	if sibling, err := os.ReadFile(
		filepath.Join(generationPath, "capability"),
	); err != nil || string(sibling) != "prepared" {
		t.Fatal("registry staging changed prepared generation siblings")
	}
	if _, err := StageImportedRegistry(config.Plan, imported); err != nil {
		t.Fatal("exact-byte staging was not idempotent")
	}
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
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
