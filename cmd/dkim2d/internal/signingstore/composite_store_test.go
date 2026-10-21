package signingstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
	"golang.org/x/sys/unix"
)

// compositeStoreKey is one generated custody credential of the composite
// store fixture.
type compositeStoreKey struct {
	algorithm provider.Algorithm
	selector  string
	handle    string
	pkcs8     []byte
	spki      []byte
}

type compositeStorePublicKeys struct {
	keys map[dkim2.Algorithm][]byte
}

// LookupPublicKey serves the generated public key for each fixture algorithm.
func (p compositeStorePublicKeys) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	spki, ok := p.keys[query.Algorithm()]
	if !ok {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	switch query.Algorithm() {
	case dkim2.AlgorithmEd25519SHA256:
		return dkim2.FoundEd25519PublicKey(ed25519.PublicKey(spki[len(spki)-ed25519.PublicKeySize:])), nil
	case dkim2.AlgorithmMLDSA44Ed25519SHA512:
		raw, err := dkim2.ParseCompositePublicKeySPKI(spki)
		if err != nil {
			return dkim2.PublicKeyResult{}, err
		}
		return dkim2.FoundCompositePublicKey(raw), nil
	default:
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
}

// TestStoreSignsWithCompositeCustodyKey proves a PEM custody composite key
// loads, signs through the library construction beside Ed25519, and verifies.
func TestStoreSignsWithCompositeCustodyKey(t *testing.T) {
	keys := []compositeStoreKey{
		newCompositeStoreKey(t, provider.AlgorithmEd25519SHA256, "ed1", "ed-key"),
		newCompositeStoreKey(t, provider.AlgorithmMLDSA44Ed25519SHA512, "pq1", "composite-key"),
	}
	rootFD := writeCompositeStoreFixture(t, keys)
	store, err := Open(rootFD, "datasource.json", "private-manifest.json")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	at := time.Unix(1_700_000_000, 0).UTC()
	profile, err := store.ResolvePolicy(context.Background(), fixtureTenant, fixtureDomain, PolicyOriginator, at)
	if err != nil || !profile.Valid() {
		t.Fatalf("ResolvePolicy() valid=%t error=%v", profile.Valid(), err)
	}
	publicKeys := compositeStorePublicKeys{keys: map[dkim2.Algorithm][]byte{}}
	for _, key := range keys {
		publicKeys.keys[dkim2.Algorithm(key.algorithm)] = key.spki
	}
	clock := func() time.Time { return at }
	signer, err := dkim2.NewSigner(
		publicKeys, dkim2.NewRequestRouteAuthority(), signingStoreAuthorizer{}, store,
		dkim2.WithSigningClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	raw := []byte("From: sender@example.test\r\nSubject: composite store\r\n\r\nbody\r\n")
	reverse := []byte("<sender@example.test>")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := dkim2.NewOriginatorRouteEntry(source, reverse, recipients, dkim2.RouteDisclosureSingle, []byte("local"))
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	result, recovery, err := signer.SignOriginator(context.Background(), dkim2.NewOriginatorSigningRequest(
		raw, reverse, recipients, tickets[0], profile, dkim2.SigningMetadata{},
		dkim2.SigningTransportFinalNetworkPreDotStuffing,
	))
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignOriginator() valid=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted output")
	}
	algorithms := signed.Facts().Algorithms()
	if len(algorithms) != 2 || algorithms[0] != dkim2.AlgorithmEd25519SHA256 ||
		algorithms[1] != dkim2.AlgorithmMLDSA44Ed25519SHA512 {
		t.Fatalf("signed algorithms = %v", algorithms)
	}
	verifier, err := dkim2.NewVerifier(publicKeys, dkim2.WithVerificationClock(clock))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	verified, err := verifier.Verify(t.Context(), dkim2.NewVerifyRequest(signed.Bytes(), reverse, recipients))
	if err != nil || verified.State() != dkim2.ResultStatePASS {
		t.Fatalf("Verify() state=%q error=%v", verified.State(), err)
	}
}

// TestCompositeCustodyKeyRejectsAlgorithmMismatch proves a composite PKCS#8
// key never loads under another algorithm and vice versa.
func TestCompositeCustodyKeyRejectsAlgorithmMismatch(t *testing.T) {
	composite := newCompositeStoreKey(t, provider.AlgorithmMLDSA44Ed25519SHA512, "pq1", "composite-key")
	edKey := newCompositeStoreKey(t, provider.AlgorithmEd25519SHA256, "ed1", "ed-key")
	for _, test := range []struct {
		name      string
		der       []byte
		algorithm provider.Algorithm
	}{
		{name: "composite as ed25519", der: composite.pkcs8, algorithm: provider.AlgorithmEd25519SHA256},
		{name: "ed25519 as composite", der: edKey.pkcs8, algorithm: provider.AlgorithmMLDSA44Ed25519SHA512},
		{name: "composite trailing byte", der: append(bytes.Clone(composite.pkcs8), 0), algorithm: provider.AlgorithmMLDSA44Ed25519SHA512},
	} {
		t.Run(test.name, func(t *testing.T) {
			if key, _, err := parseNativePrivateKey(test.der, composite.spki, test.algorithm); err == nil {
				clearPrivateKey(key)
				t.Fatal("parseNativePrivateKey() accepted a mismatched key")
			}
		})
	}
	key, digest, err := parseNativePrivateKey(composite.pkcs8, composite.spki, provider.AlgorithmMLDSA44Ed25519SHA512)
	if err != nil || digest != sha256.Sum256(composite.spki) {
		t.Fatalf("parseNativePrivateKey(composite) error = %v", err)
	}
	clearPrivateKey(key)
	if typed, ok := key.(*dkim2.CompositeSigningKey); !ok || typed.Valid() {
		t.Fatal("clearPrivateKey() left the composite key valid")
	}
}

// newCompositeStoreKey generates one custody key through the production codec.
func newCompositeStoreKey(t *testing.T, algorithm provider.Algorithm, selector, handle string) compositeStoreKey {
	t.Helper()
	pkcs8, spki, err := GeneratePrivateKey(algorithm, rand.Reader, 0)
	if err != nil {
		t.Fatalf("GeneratePrivateKey(%s) error = %v", algorithm, err)
	}
	t.Cleanup(func() { clear(pkcs8) })
	return compositeStoreKey{algorithm: algorithm, selector: selector, handle: handle, pkcs8: pkcs8, spki: spki}
}

// writeCompositeStoreFixture writes one confined multi-credential datasource,
// manifest, and PEM key set and returns the read-only root descriptor.
func writeCompositeStoreFixture(t *testing.T, keys []compositeStoreKey) int {
	t.Helper()
	root := t.TempDir()
	handles := make([]any, 0, len(keys))
	credentials := make([]any, 0, len(keys))
	entries := make([]any, 0, len(keys))
	for index, key := range keys {
		privateFile := "key-" + string(rune('a'+index)) + ".pem"
		handles = append(handles, map[string]any{"id": key.handle})
		credentials = append(credentials, map[string]any{
			fixtureFieldAlgorithm: string(key.algorithm), "selector": key.selector,
			"public_key_spki": base64.StdEncoding.EncodeToString(key.spki), fixtureFieldHandleID: key.handle,
		})
		digest := sha256.Sum256(key.spki)
		entries = append(entries, map[string]any{
			fixtureFieldTenantID: fixtureTenant, fixtureDomainField: fixtureDomain, fixtureFieldUse: fixtureManifestUse,
			fixtureFieldHandleID: key.handle, fixtureFieldAlgorithm: string(key.algorithm),
			"public_spki_sha256": base64.StdEncoding.EncodeToString(digest[:]),
			"private_key_file":   privateFile,
		})
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: key.pkcs8})
		writeProtectedTestFile(t, filepath.Join(root, privateFile), privatePEM)
		clear(privatePEM)
	}
	datasourceBytes, err := json.Marshal(map[string]any{
		fixtureFieldVersion: "dkim2-datasource-v1",
		"handles":           handles,
		"profiles": []any{map[string]any{
			"id": fixtureProfile, fixtureDomainField: fixtureDomain, fixtureFieldStatus: fixtureStatusActive,
			"credentials": credentials,
		}},
		"policies": []any{map[string]any{
			fixtureFieldTenantID: fixtureTenant, fixtureDomainField: fixtureDomain,
			fixtureFieldUse: fixtureManifestUse, "profile_id": fixtureProfile,
			fixtureFieldStatus: fixtureStatusActive, "rollout": "enforce", "compatibility": "strict",
		}},
	})
	if err != nil {
		t.Fatalf("json.Marshal(datasource) error = %v", err)
	}
	manifestBytes, err := json.Marshal(map[string]any{fixtureFieldVersion: manifestVersion, "entries": entries})
	if err != nil {
		t.Fatalf("json.Marshal(manifest) error = %v", err)
	}
	writeProtectedTestFile(t, filepath.Join(root, "datasource.json"), datasourceBytes)
	writeProtectedTestFile(t, filepath.Join(root, "private-manifest.json"), manifestBytes)
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("os.Chmod(root) error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("unix.Open(root) error = %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
