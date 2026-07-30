package signingstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"golang.org/x/sys/unix"
)

const (
	fixtureDomain      = "example.test"
	fixtureDomainField = "domain"
	fixtureHandle      = "origin-key"
	fixtureProfile     = "origin-profile"
	fixtureManifestUse = manifestOriginator
	fixtureAlgorithm   = manifestRSASHA256
)

type signingStorePublicKeys struct {
	key *rsa.PublicKey
}

// LookupPublicKey returns the one exact fixture credential.
func (p signingStorePublicKeys) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

type signingStoreAuthorizer struct{}

// Authorize approves only the exact query already bounded by the test request.
func (signingStoreAuthorizer) Authorize(
	_ context.Context,
	query dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	return dkim2.AuthorizeSigning(query), nil
}

type signingStoreFixture struct {
	rootFD       int
	rootPath     string
	datasource   string
	manifest     string
	privateKey   string
	key          *rsa.PrivateKey
	manifestData []byte
}

// TestStoreComposesDatasourceProjectionAndOpaqueSigner proves the complete
// datasource-to-signing operation path and exact generated-field order.
func TestStoreComposesDatasourceProjectionAndOpaqueSigner(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	store, err := Open(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	profile, err := store.ResolvePolicy(
		context.Background(),
		"tenant-a",
		"example.test",
		PolicyOriginator,
		time.Now().UTC(),
	)
	if err != nil || !profile.Valid() {
		t.Fatalf("ResolvePolicy() valid=%t error=%v", profile.Valid(), err)
	}
	if other, otherErr := store.ResolvePolicy(
		context.Background(),
		"tenant-a",
		"example.test",
		PolicyOrdinaryTransit,
		time.Now().UTC(),
	); otherErr == nil || other.Valid() ||
		dkim2.ProviderErrorClassOf(otherErr) != dkim2.ProviderErrorClassPermanent {
		t.Fatalf(
			"ResolvePolicy() undeclared use valid=%t class=%q",
			other.Valid(),
			dkim2.ProviderErrorClassOf(otherErr),
		)
	}
	signer, err := dkim2.NewSigner(
		signingStorePublicKeys{key: &fixture.key.PublicKey},
		dkim2.NewRequestRouteAuthority(),
		signingStoreAuthorizer{},
		store,
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	raw := []byte("From: sender@example.test\r\nSubject: store\r\n\r\nbody\r\n")
	reverse := []byte("<sender@example.test>")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := dkim2.NewOriginatorRouteEntry(
		source, reverse, recipients, dkim2.RouteDisclosureSingle, []byte("local"),
	)
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
	result, recovery, err := signer.SignOriginator(
		context.Background(),
		dkim2.NewOriginatorSigningRequest(
			raw, reverse, recipients, tickets[0], profile, dkim2.SigningMetadata{},
			dkim2.SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignOriginator() valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted output")
	}
	fields := signed.GeneratedFields()
	if len(fields) != 2 ||
		!bytes.HasPrefix(fields[0], []byte("Message-Instance:")) ||
		!bytes.HasPrefix(fields[1], []byte("DKIM2-Signature:")) {
		t.Fatalf("GeneratedFields() order/count = %d", len(fields))
	}
}

// TestStoreRejectsManifestAndPrivateKeyAmbiguity freezes fail-closed candidate
// loading before a generation can be published.
func TestStoreRejectsManifestAndPrivateKeyAmbiguity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(signingStoreFixture)
	}{
		{
			name: "duplicate object member",
			mutate: func(fixture signingStoreFixture) {
				document := strings.Replace(
					string(fixture.manifestData),
					`"version":"dkim2-private-keys-v1"`,
					`"version":"dkim2-private-keys-v1","version":"dkim2-private-keys-v1"`,
					1,
				)
				rewriteProtectedTestFile(t, filepath.Join(fixture.rootPath, fixture.manifest), []byte(document))
			},
		},
		{
			name: "public identity mismatch",
			mutate: func(fixture signingStoreFixture) {
				digest := publicDigest(t, &fixture.key.PublicKey)
				document := strings.Replace(
					string(fixture.manifestData),
					base64.StdEncoding.EncodeToString(digest[:]),
					base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, sha256.Size)),
					1,
				)
				rewriteProtectedTestFile(t, filepath.Join(fixture.rootPath, fixture.manifest), []byte(document))
			},
		},
		{
			name: "hard linked private key",
			mutate: func(fixture signingStoreFixture) {
				if err := os.Link(
					filepath.Join(fixture.rootPath, fixture.privateKey),
					filepath.Join(fixture.rootPath, "private-link"),
				); err != nil {
					t.Fatalf("os.Link() error = %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSigningStoreFixture(t)
			if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
				t.Fatalf("os.Chmod(unseal) error = %v", err)
			}
			test.mutate(fixture)
			if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
				t.Fatalf("os.Chmod(seal) error = %v", err)
			}
			if store, err := Open(fixture.rootFD, fixture.datasource, fixture.manifest); err == nil || store != nil {
				t.Fatal("Open() accepted an ambiguous protected generation")
			}
		})
	}
}

// TestRuntimeReloadPublishesOnlyCompleteGenerations proves failure retention,
// request leases, atomic publication, and exact recovery.
func TestRuntimeReloadPublishesOnlyCompleteGenerations(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	runtime, err := NewRuntime(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	oldLease, err := runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire(old) error = %v", err)
	}
	if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
		t.Fatal("unseal generation failed")
	}
	rewriteProtectedTestFile(
		t,
		filepath.Join(fixture.rootPath, fixture.manifest),
		[]byte(`{"version":"dkim2-private-keys-v1","entries":[]}`),
	)
	if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
		t.Fatal("reseal generation failed")
	}
	if err := runtime.Reload(context.Background()); err == nil {
		t.Fatal("Reload() published an invalid candidate")
	}
	if profile, resolveErr := oldLease.ResolvePolicy(
		context.Background(), "tenant-a", "example.test",
		PolicyOriginator, time.Now().UTC(),
	); resolveErr != nil || !profile.Valid() {
		t.Fatalf("old lease was lost after failed reload: %v", resolveErr)
	}
	if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
		t.Fatal("unseal generation failed")
	}
	rewriteProtectedTestFile(
		t, filepath.Join(fixture.rootPath, fixture.manifest), fixture.manifestData,
	)
	if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
		t.Fatal("reseal generation failed")
	}
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatalf("Reload(recovered) error = %v", err)
	}
	newLease, err := runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire(new) error = %v", err)
	}
	if profile, resolveErr := newLease.ResolvePolicy(
		context.Background(), "tenant-a", "example.test",
		PolicyOriginator, time.Now().UTC(),
	); resolveErr != nil || !profile.Valid() {
		t.Fatalf("new lease is not complete: %v", resolveErr)
	}
	if profile, resolveErr := oldLease.ResolvePolicy(
		context.Background(), "tenant-a", "example.test",
		PolicyOriginator, time.Now().UTC(),
	); resolveErr != nil || !profile.Valid() {
		t.Fatalf("old in-flight lease did not complete: %v", resolveErr)
	}
	if err := oldLease.Close(); err != nil {
		t.Fatalf("Close(old lease) error = %v", err)
	}
	if err := newLease.Close(); err != nil {
		t.Fatalf("Close(new lease) error = %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close(runtime) error = %v", err)
	}
}

// newSigningStoreFixture constructs one confined same-generation fixture.
func newSigningStoreFixture(t *testing.T) signingStoreFixture {
	t.Helper()
	root := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: pkcs8})
	clear(pkcs8)
	const datasourceFile = "datasource.json"
	const manifestFile = "private-manifest.json"
	const privateFile = "origin-private.pem"
	datasourceDocument := map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": []any{map[string]any{"id": fixtureHandle}},
		"profiles": []any{map[string]any{
			"id": fixtureProfile, fixtureDomainField: fixtureDomain, "status": "active",
			"credentials": []any{map[string]any{
				"algorithm": fixtureAlgorithm, "selector": "s1",
				"public_key_spki": base64.StdEncoding.EncodeToString(spki),
				"handle_id":       fixtureHandle,
			}},
		}},
		"policies": []any{map[string]any{
			"tenant_id": "tenant-a", fixtureDomainField: fixtureDomain,
			"use": fixtureManifestUse, "profile_id": fixtureProfile,
			"status": "active", "rollout": "enforce", "compatibility": "strict",
		}},
	}
	datasourceBytes, err := json.Marshal(datasourceDocument)
	if err != nil {
		t.Fatalf("json.Marshal(datasource) error = %v", err)
	}
	digest := sha256.Sum256(spki)
	manifestDocument := map[string]any{
		"version": manifestVersion,
		"entries": []any{map[string]any{
			"tenant_id": "tenant-a", fixtureDomainField: fixtureDomain, "use": fixtureManifestUse,
			"handle_id": fixtureHandle, "algorithm": fixtureAlgorithm,
			"public_spki_sha256": base64.StdEncoding.EncodeToString(digest[:]),
			"private_key_file":   privateFile,
		}},
	}
	manifestBytes, err := json.Marshal(manifestDocument)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) error = %v", err)
	}
	writeProtectedTestFile(t, filepath.Join(root, datasourceFile), datasourceBytes)
	writeProtectedTestFile(t, filepath.Join(root, manifestFile), manifestBytes)
	writeProtectedTestFile(t, filepath.Join(root, privateFile), privatePEM)
	clear(privatePEM)
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("os.Chmod(root) error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("unix.Open(root) error = %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return signingStoreFixture{
		rootFD: fd, rootPath: root, datasource: datasourceFile,
		manifest: manifestFile, privateKey: privateFile, key: key,
		manifestData: bytes.Clone(manifestBytes),
	}
}

// writeProtectedTestFile creates one exact owner-only fixture child.
func writeProtectedTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
}

// rewriteProtectedTestFile replaces one fixture child while its root is writable.
func rewriteProtectedTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(rewrite) error = %v", err)
	}
}

// publicDigest returns the exact canonical public SPKI identity.
func publicDigest(t *testing.T, key *rsa.PublicKey) [sha256.Size]byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return sha256.Sum256(spki)
}
