package signingstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRegistryOpensExactGenerationSpecificProtectedMaterial proves the v2 fence.
func TestRegistryOpensExactGenerationSpecificProtectedMaterial(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	var document map[string]any
	if err := json.Unmarshal(fixture.manifestData, &document); err != nil {
		t.Fatal("decode fixture manifest")
	}
	document["version"] = registryManifestVersion
	document["generation"] = "7"
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal("encode registry manifest")
	}
	if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
		t.Fatal("open fixture root")
	}
	rewriteProtectedTestFile(
		t, filepath.Join(fixture.rootPath, fixture.manifest), encoded,
	)
	if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
		t.Fatal("seal fixture root")
	}
	registry, err := OpenRegistry(fixture.rootFD, fixture.manifest)
	if err != nil {
		t.Fatal("open generation-specific registry")
	}
	generation, err := registry.Generation(context.Background())
	if err != nil || generation != 7 || len(registry.Bindings()) != 1 {
		t.Fatal("registry generation or bindings drifted")
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatal("close registry")
	}
	if _, err := registry.Generation(context.Background()); err == nil {
		t.Fatal("closed registry remained available")
	}
}

// TestRegistrySourceLoadsSeedAndHigherGeneration proves one retained protected
// source can bind the initial registry and a later atomically staged sibling.
func TestRegistrySourceLoadsSeedAndHigherGeneration(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal("protect registry parent")
	}
	key := importedRSAFixture(t)
	defer func() { _ = key.Close() }()
	entry, err := NewRegistryStagingEntry(
		"tenant", "example.test", "originator", "opaque-handle", key,
	)
	if err != nil {
		t.Fatal("construct registry entry")
	}
	_, err = StageRegistry(parent, 7, []RegistryStagingEntry{entry})
	if err != nil {
		t.Fatal("stage seed registry")
	}
	firstPath := filepath.Join(parent, "7")
	t.Cleanup(func() {
		_ = os.Chmod(firstPath, 0o700)
		_ = os.Chmod(filepath.Join(parent, "8"), 0o700)
	})
	firstFD, err := unix.Open(
		firstPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		t.Fatal("open seed registry")
	}
	source, err := NewRegistrySource(firstFD, registryManifestFile)
	_ = unix.Close(firstFD)
	if err != nil {
		t.Fatal("construct registry source")
	}
	defer func() { _ = source.Close(context.Background()) }()
	first, err := source.Load(context.Background(), 7)
	if err != nil {
		t.Fatal("load seed registry")
	}
	_ = first.Close(context.Background())
	if _, err := StageRegistry(parent, 8, []RegistryStagingEntry{entry}); err != nil {
		t.Fatal("stage higher registry")
	}
	second, err := source.Load(context.Background(), 8)
	if err != nil {
		t.Fatal("load higher registry")
	}
	_ = second.Close(context.Background())
}

// TestRegistryRejectsNoncanonicalAndLegacyGenerationFences fails closed.
func TestRegistryRejectsNoncanonicalAndLegacyGenerationFences(t *testing.T) {
	for _, generation := range []any{nil, "", "0", "01", "-1", "18446744073709551616"} {
		fixture := newSigningStoreFixture(t)
		var document map[string]any
		if err := json.Unmarshal(fixture.manifestData, &document); err != nil {
			t.Fatal("decode fixture manifest")
		}
		document["version"] = registryManifestVersion
		if generation != nil {
			document["generation"] = generation
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal("encode invalid registry manifest")
		}
		if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
			t.Fatal("open fixture root")
		}
		rewriteProtectedTestFile(
			t, filepath.Join(fixture.rootPath, fixture.manifest), encoded,
		)
		if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
			t.Fatal("seal fixture root")
		}
		if registry, err := OpenRegistry(
			fixture.rootFD, fixture.manifest,
		); err == nil || registry != nil {
			t.Fatal("invalid registry generation accepted")
		}
	}
}

// FuzzImportedPrivateKeyNeverLeaksOrPanics exercises bounded hostile PEM input.
func FuzzImportedPrivateKeyNeverLeaksOrPanics(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nTOXIC\n-----END PRIVATE KEY-----\n"), "rsa")
	f.Add([]byte{}, "ed25519")
	f.Fuzz(func(t *testing.T, encoded []byte, algorithm string) {
		if len(encoded) > maxPrivateBytes+1 || len(algorithm) > 32 {
			return
		}
		key, err := InspectImportedPrivateKey(encoded, algorithm)
		if key != nil {
			_ = key.Close()
		}
		if err != nil && strings.Contains(fmt.Sprint(err), "TOXIC") {
			t.Fatal("protected input reached error")
		}
	})
}

// TestRegistryStagingFaultsNeverClaimAPartialGeneration proves every durable
// interruption leaves either an inert partial directory or one exact result.
func TestRegistryStagingFaultsNeverClaimAPartialGeneration(t *testing.T) {
	for event := registryKeySynchronized; event <= registryParentSynchronized; event++ {
		t.Run(fmt.Sprint(event), func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal("protect registry parent")
			}
			t.Cleanup(func() { _ = os.Chmod(filepath.Join(parent, "9"), 0o700) })
			key := importedRSAFixture(t)
			defer func() { _ = key.Close() }()
			entry, err := NewRegistryStagingEntry(
				"tenant", "example.test", "originator", "opaque-handle", key,
			)
			if err != nil {
				t.Fatal("construct staging entry")
			}
			path, err := stageRegistryObserved(
				parent, 9, []RegistryStagingEntry{entry},
				func(current registryStageEvent) error {
					if current == event {
						return errors.New("injected interruption")
					}
					return nil
				},
			)
			if err == nil || path != "" {
				t.Fatal("interrupted staging claimed success")
			}
			info, statErr := os.Stat(filepath.Join(parent, "9"))
			if statErr == nil && info.Mode().Perm() == 0o500 &&
				event < registryDirectorySealed {
				t.Fatal("pre-seal interruption published a loadable directory")
			}
		})
	}
}

// importedRSAFixture returns one validated short-lived private-key owner.
func importedRSAFixture(t *testing.T) *ImportedPrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("generate RSA fixture")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("marshal RSA fixture")
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der})
	clear(der)
	imported, err := InspectImportedPrivateKey(encoded, "rsa")
	clear(encoded)
	if err != nil {
		t.Fatal("inspect RSA fixture")
	}
	return imported
}
