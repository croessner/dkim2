//go:build linux || darwin

package config

import (
	"bytes"
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

	"golang.org/x/sys/unix"
)

// TestLoadProtectedNetworkSigningPublishesOnlyDatasourceCredentials proves
// native network custody does not construct a local signer registry.
func TestLoadProtectedNetworkSigningPublishesOnlyDatasourceCredentials(t *testing.T) {
	fixture := newProtectedSigningFixture(t)
	generationPath := filepath.Join(filepath.Dir(fixture.yamlPath), testGeneration)
	if err := os.Chmod(filepath.Dir(generationPath), 0o700); err != nil {
		t.Fatal("protect network registry parent")
	}
	makeGenerationWritable(t, generationPath)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "ldap-password"),
		[]byte("network-password"), 0o600,
	)
	certificate := testProtectedCertificateDER(
		t, 902, true, x509.KeyUsageCertSign,
	)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "ldap-ca"),
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificate}),
		0o600,
	)
	sealGeneration(t, generationPath)
	document := strings.ReplaceAll(
		ldapSigningYAML(), "/secure/"+testGeneration, generationPath,
	)
	writeProtectedTestFile(t, fixture.yamlPath, []byte(document), 0o600)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("LoadProtected(network) failed with code %s", CodeOf(err))
	}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime(network) failed with code %s", CodeOf(err))
	}
	if preparation.SigningStore() != nil {
		t.Fatal("network signing constructed a local signing store")
	}
	var borrowed bool
	if err := preparation.SigningDatasource().Use(
		func(password []byte, roots [][]byte) error {
			borrowed = string(password) == "network-password" && len(roots) == 1
			return nil
		},
	); err != nil || !borrowed {
		t.Fatal("network protected material was unavailable")
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("Close(network owner) failed with code %s", CodeOf(err))
	}
}

const (
	protectedSigningDomainField = "domain"
	protectedSigningDomain      = "example.test"
	protectedSigningHandle      = "origin-key"
)

// TestLoadProtectedSigningPublishesCompleteReloadRuntime proves the enabled
// protected generation constructs and transfers one live compound store.
func TestLoadProtectedSigningPublishesCompleteReloadRuntime(t *testing.T) {
	fixture := newProtectedSigningFixture(t)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("LoadProtected() failed with code %s", CodeOf(err))
	}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
	}
	store := preparation.SigningStore()
	if store == nil {
		t.Fatal("enabled preparation omitted the compound signing store")
	}
	signCapability := preparation.SignCapability()
	reviseCapability := preparation.ReviseCapability()
	lease, err := store.Acquire()
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close(lease) error = %v", err)
	}
	if err := store.StartReload(time.Second); err != nil {
		t.Fatalf("StartReload() error = %v", err)
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	if !signCapability.Equal(fixture.signCapability) ||
		!reviseCapability.Equal(fixture.reviseCapability) {
		t.Fatal("committed runtime omitted separated signing capabilities")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close(runtime) failed with code %s", CodeOf(err))
	}
}

// TestLoadProtectedDisabledDoesNotOpenSigningChildren proves default-disabled
// loading ignores absent or hostile signing-only conventional child names.
func TestLoadProtectedDisabledDoesNotOpenSigningChildren(t *testing.T) {
	fixture := newProtectedLoaderFixture(
		t, bytes.Repeat([]byte{0xa5}, exactKeyBytes),
	)
	makeGenerationWritable(t, fixture.generationPath)
	for _, name := range []string{
		"sign-capability",
		"revise-capability",
		"datasource",
		"private-manifest",
		"private-key",
	} {
		if err := unix.Mkfifo(
			filepath.Join(fixture.generationPath, name), 0o600,
		); err != nil {
			t.Fatalf("unix.Mkfifo(%s) error = %v", name, err)
		}
	}
	sealGeneration(t, fixture.generationPath)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("LoadProtected(disabled) failed with code %s", CodeOf(err))
	}
	if owner.Snapshot().Signing().Enabled() {
		t.Fatal("disabled protected load widened signing authority")
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("Close(owner) failed with code %s", CodeOf(err))
	}
}

type protectedSigningFixture struct {
	yamlPath         string
	signCapability   []byte
	reviseCapability []byte
}

// newProtectedSigningFixture creates one complete same-generation daemon
// signing bundle with independent process, sign, and revise capabilities.
func newProtectedSigningFixture(t *testing.T) protectedSigningFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("EvalSymlinks() failed")
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(
			base,
			func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr == nil && entry.IsDir() {
					_ = os.Chmod(path, 0o700)
				}
				return nil
			},
		)
	})
	generationPath := filepath.Join(base, testGeneration)
	if err := os.Mkdir(generationPath, 0o700); err != nil {
		t.Fatal("mkdir generation failed")
	}
	processCapability := bytes.Repeat([]byte{0xa5}, exactKeyBytes)
	signCapability := bytes.Repeat([]byte{0xb6}, exactKeyBytes)
	reviseCapability := bytes.Repeat([]byte{0xc7}, exactKeyBytes)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "capability"),
		processCapability, 0o600,
	)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "sign-capability"),
		signCapability, 0o600,
	)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "revise-capability"),
		reviseCapability, 0o600,
	)
	writeProtectedSigningStoreFiles(t, generationPath)
	sealGeneration(t, generationPath)
	document := strings.ReplaceAll(
		signingYAML(), "/secure/"+testGeneration, generationPath,
	)
	yamlPath := filepath.Join(base, "dkim2d.yaml")
	writeProtectedTestFile(t, yamlPath, []byte(document), 0o600)
	return protectedSigningFixture{
		yamlPath:         yamlPath,
		signCapability:   bytes.Clone(signCapability),
		reviseCapability: bytes.Clone(reviseCapability),
	}
}

// writeProtectedSigningStoreFiles creates one exact RSA datasource/private-key
// generation for the protected-loader integration.
func writeProtectedSigningStoreFiles(t *testing.T, generationPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	datasource := map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": []any{map[string]any{"id": protectedSigningHandle}},
		"profiles": []any{map[string]any{
			"id": "origin-profile", protectedSigningDomainField: protectedSigningDomain,
			"status": "active",
			"credentials": []any{map[string]any{
				"algorithm": "rsa-sha256", "selector": "s1",
				"public_key_spki": base64.StdEncoding.EncodeToString(spki),
				"handle_id":       protectedSigningHandle,
			}},
		}},
		"policies": []any{map[string]any{
			"tenant_id": "tenant-a", protectedSigningDomainField: protectedSigningDomain,
			"use": "originator", "profile_id": "origin-profile",
			"status": "active", "rollout": "enforce",
			"compatibility": "strict",
		}},
	}
	digest := sha256.Sum256(spki)
	manifest := map[string]any{
		"version": "dkim2-private-keys-v1",
		"entries": []any{map[string]any{
			"tenant_id": "tenant-a", protectedSigningDomainField: protectedSigningDomain,
			"use": "originator", "handle_id": protectedSigningHandle,
			"algorithm":          "rsa-sha256",
			"public_spki_sha256": base64.StdEncoding.EncodeToString(digest[:]),
			"private_key_file":   "origin.pem",
		}},
	}
	writeProtectedSigningJSON(
		t, filepath.Join(generationPath, "datasource"), datasource,
	)
	writeProtectedSigningJSON(
		t, filepath.Join(generationPath, "private-manifest"), manifest,
	)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	defer clear(pkcs8)
	privatePEM := pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8},
	)
	defer clear(privatePEM)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "origin.pem"), privatePEM, 0o600,
	)
}

// writeProtectedSigningJSON encodes one owner-only protected JSON child.
func writeProtectedSigningJSON(t *testing.T, path string, value any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	writeProtectedTestFile(t, path, document, 0o600)
}
