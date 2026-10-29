//go:build linux || darwin

package config

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/redisgrammar"
)

// TestLoadProtectedRedisSelectsOnlyConfiguredRoles proves every optional
// Redis protected role is opened only when its path is configured and that
// the lent material leaves unconfigured roles nil.
func TestLoadProtectedRedisSelectsOnlyConfiguredRoles(t *testing.T) {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: testProtectedCertificateDER(t, 401, true, 0)})
	tests := []struct {
		name     string
		document string
		files    map[string][]byte
		roles    []protectedFileRole
		check    func(*testing.T, ReplayMaterial)
	}{
		{
			name:     "plaintext without credentials",
			document: redisDocument("    standalone:\n      address: " + testRedisAddress + "\n    tls:\n      enabled: false\n"),
			roles:    []protectedFileRole{protectedCapability, protectedHMAC},
			check: func(t *testing.T, material ReplayMaterial) {
				t.Helper()
				if material.Password() != nil || material.SentinelPassword() != nil || len(material.RootsDER()) != 0 ||
					material.ClientCertificatePEM() != nil || material.ClientKeyPEM() != nil {
					t.Fatal("unconfigured Redis roles were lent")
				}
			},
		},
		{
			name:     "TLS with system roots",
			document: redisClusterYAML(),
			roles:    []protectedFileRole{protectedCapability, protectedHMAC},
			check: func(t *testing.T, material ReplayMaterial) {
				t.Helper()
				if len(material.RootsDER()) != 0 {
					t.Fatal("system-root TLS lent configured roots")
				}
			},
		},
		{
			name:     "password and CA",
			document: redisYAML(),
			files:    map[string][]byte{"redis-password": []byte("redis-password"), "ca": caPEM},
			roles:    []protectedFileRole{protectedCapability, protectedHMAC, protectedRedisPassword, protectedCA},
			check: func(t *testing.T, material ReplayMaterial) {
				t.Helper()
				if string(material.Password()) != "redis-password" || len(material.RootsDER()) != 1 ||
					material.SentinelPassword() != nil || material.ClientCertificatePEM() != nil {
					t.Fatal("password and CA inventory changed")
				}
			},
		},
		{
			name: "Sentinel password only",
			document: redisDocument("    mode: sentinel\n    sentinel:\n      master_name: mymaster\n      addresses: \"" +
				testSentinelAddresses + "\"\n      password_file: /secure/" + testGeneration + "/sentinel-password\n" +
				"    tls:\n      enabled: false\n"),
			files: map[string][]byte{"sentinel-password": []byte("sentinel-password")},
			roles: []protectedFileRole{protectedCapability, protectedHMAC, protectedRedisSentinelPassword},
			check: func(t *testing.T, material ReplayMaterial) {
				t.Helper()
				if string(material.SentinelPassword()) != "sentinel-password" || material.Password() != nil {
					t.Fatal("Sentinel-only inventory changed")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProtectedRedisFixture(t, test.document, test.files)
			var opened []protectedFileRole
			owner, err := loadProtectedObserved(fixture.yamlPath, FlagValues{}, func(event protectedLoadEvent, role protectedFileRole) {
				if event == protectedEventChildOpened {
					opened = append(opened, role)
				}
			})
			if err != nil {
				t.Fatalf("loadProtectedObserved() failed with code %s", CodeOf(err))
			}
			defer func() { _ = owner.Close() }()
			if !slices.Equal(opened, test.roles) {
				t.Fatalf("opened roles = %v, want %v", opened, test.roles)
			}
			preparation, err := owner.PrepareRuntime()
			if err != nil {
				t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
			}
			if err := preparation.ReplayRuntime().UseReplayMaterial(func(material ReplayMaterial) error {
				if !bytes.Equal(material.HMAC(), bytes.Repeat([]byte{0xb6}, exactKeyBytes)) {
					t.Fatal("HMAC bytes changed")
				}
				test.check(t, material)
				return nil
			}); err != nil {
				t.Fatalf("UseReplayMaterial() failed with code %s", CodeOf(err))
			}
		})
	}
}

// TestLoadProtectedRedisClientIdentityPolicy freezes the descriptor and
// content policy of the client certificate and key roles.
func TestLoadProtectedRedisClientIdentityPolicy(t *testing.T) {
	now := time.Now()
	certificate, key, _ := serverTLSFixture(t, "client.example", now.Add(-time.Hour), now.Add(time.Hour))
	document := redisDocument("    standalone:\n      address: " + testRedisAddress + "\n    tls:\n" +
		"      cert: /secure/" + testGeneration + "/client-cert\n      key: /secure/" + testGeneration + "/client-key\n")
	valid := map[string][]byte{"client-cert": certificate, "client-key": key}
	fixture := newProtectedRedisFixture(t, document, valid)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if err != nil {
		t.Fatalf("LoadProtected() rejected a valid client identity with code %s", CodeOf(err))
	}
	_ = owner.Close()

	for name, mutate := range map[string]func(string){
		"group-readable key": func(generation string) {
			if err := os.Chmod(filepath.Join(generation, "client-key"), 0o640); err != nil {
				t.Fatal("chmod failed")
			}
		},
		"world-readable certificate": func(generation string) {
			if err := os.Chmod(filepath.Join(generation, "client-cert"), 0o644); err != nil {
				t.Fatal("chmod failed")
			}
		},
		"linked key": func(generation string) {
			if err := os.Link(filepath.Join(generation, "client-key"), filepath.Join(generation, "client-key-link")); err != nil {
				t.Fatal("link failed")
			}
		},
		"CA bundle as certificate": func(generation string) {
			writeProtectedFileWithoutModeChange(filepath.Join(generation, "client-cert"),
				pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: testProtectedCertificateDER(t, 402, true, 0)}))
		},
		"garbage key": func(generation string) {
			writeProtectedFileWithoutModeChange(filepath.Join(generation, "client-key"), []byte("not a key"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newProtectedRedisFixture(t, document, valid)
			makeGenerationWritable(t, fixture.generationPath)
			mutate(fixture.generationPath)
			sealGeneration(t, fixture.generationPath)
			owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
			if owner != nil || err == nil {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatal("invalid client identity was accepted")
			}
			if strings.Contains(err.Error(), fixture.generationPath) {
				t.Fatal("protected failure exposed a path")
			}
		})
	}
}

// TestValidateRedisProtectedMaterialRequiresExactInventory proves loaded
// Redis material must match the configured paths in both directions.
func TestValidateRedisProtectedMaterialRequiresExactInventory(t *testing.T) {
	clearStableEnvironment(t)
	configured, err := Load([]byte(redisYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	memory, err := Load([]byte(memoryYAML("1", "capability")), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	complete := func() *protectedState {
		return &protectedState{redisPassword: []byte("password"), rootCertificatesDER: [][]byte{{1}}}
	}
	if err := validateRedisProtectedMaterial(configured, complete(), time.Now()); err != nil {
		t.Fatalf("exact inventory rejected with code %s", CodeOf(err))
	}
	for name, mutate := range map[string]func(*protectedState){
		"missing password":     func(state *protectedState) { state.redisPassword = nil },
		"missing roots":        func(state *protectedState) { state.rootCertificatesDER = nil },
		"unexpected sentinel":  func(state *protectedState) { state.redisSentinelPassword = []byte("sentinel") },
		"unexpected client":    func(state *protectedState) { state.redisClientCertificatePEM = []byte("cert") },
		"unexpected clientkey": func(state *protectedState) { state.redisClientKeyPEM = []byte("key") },
	} {
		state := complete()
		mutate(state)
		if CodeOf(validateRedisProtectedMaterial(configured, state, time.Now())) != CodeProtectedContent {
			t.Fatalf("%s was accepted", name)
		}
	}
	if CodeOf(validateRedisProtectedMaterial(memory, complete(), time.Now())) != CodeProtectedContent {
		t.Fatal("memory backend accepted Redis material")
	}
	if err := validateRedisProtectedMaterial(memory, &protectedState{}, time.Now()); err != nil {
		t.Fatalf("memory backend without Redis material returned code %s", CodeOf(err))
	}
	now := time.Now()
	certificate, key, _ := serverTLSFixture(t, "client.example", now.Add(-time.Hour), now.Add(time.Hour))
	if err := validateRedisClientIdentity(certificate, key, now); err != nil {
		t.Fatalf("valid client identity rejected with code %s", CodeOf(err))
	}
	if CodeOf(validateRedisClientIdentity(certificate, key, now.Add(2*time.Hour))) != CodeProtectedContent ||
		CodeOf(validateRedisClientIdentity(certificate, key, now.Add(-2*time.Hour))) != CodeProtectedContent ||
		CodeOf(validateRedisClientIdentity(certificate, key, time.Time{})) != CodeProtectedContent {
		t.Fatal("client identity outside its validity window was accepted")
	}
}

// newProtectedRedisFixture creates one sealed generation for a Redis
// document with the given extra children next to the capability and HMAC.
func newProtectedRedisFixture(t *testing.T, document string, files map[string][]byte) protectedBackendFixture {
	t.Helper()
	clearStableEnvironment(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("EvalSymlinks() failed")
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	generationPath := filepath.Join(base, testGeneration)
	if err := os.Mkdir(generationPath, 0o700); err != nil {
		t.Fatal("mkdir generation failed")
	}
	capabilityPath := filepath.Join(generationPath, "capability")
	writeProtectedTestFile(t, capabilityPath, bytes.Repeat([]byte{0xa5}, exactKeyBytes), 0o600)
	writeProtectedTestFile(t, filepath.Join(generationPath, "hmac"), bytes.Repeat([]byte{0xb6}, exactKeyBytes), 0o600)
	for name, data := range files {
		mode := os.FileMode(0o600)
		if name == "ca" {
			mode = 0o644
		}
		writeProtectedTestFile(t, filepath.Join(generationPath, name), data, mode)
	}
	document = strings.ReplaceAll(document, "/secure/"+testGeneration, generationPath)
	yamlPath := filepath.Join(base, "dkim2d.yaml")
	writeProtectedTestFile(t, yamlPath, []byte(document), 0o600)
	sealGeneration(t, generationPath)
	return protectedBackendFixture{
		yamlPath:       yamlPath,
		yamlBytes:      []byte(document),
		generationPath: generationPath,
		capabilityPath: capabilityPath,
	}
}

// TestRedisClientPEMBoundMatchesTheProvider pins the client certificate and
// key size bound to the shared provider grammar on the loader side.
func TestRedisClientPEMBoundMatchesTheProvider(t *testing.T) {
	for _, role := range []protectedFileRole{protectedRedisClientCertificate, protectedRedisClientKey} {
		if !protectedSizeAccepted(role, redisgrammar.MaxClientPEMBytes) ||
			protectedSizeAccepted(role, redisgrammar.MaxClientPEMBytes+1) ||
			protectedReadCap(role) != redisgrammar.MaxClientPEMBytes {
			t.Fatalf("client PEM bound for role %d diverged from the provider", role)
		}
	}
}
