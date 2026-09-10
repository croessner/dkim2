//go:build linux || darwin

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBatchRevisionCapabilityIsExplicitAndIndependent covers supported-platform protected-file ownership and erasure.
func TestBatchRevisionCapabilityIsExplicitAndIndependent(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "independent", true: "reused"}[reuse], func(t *testing.T) {
			fixture := newProtectedSigningFixture(t)
			generation := filepath.Dir(fixture.signCapabilityPath)
			makeGenerationWritable(t, generation)
			secret := bytes.Repeat([]byte{0xe9}, 32)
			if reuse {
				secret = fixture.reviseCapability
			}
			path := filepath.Join(generation, "batch-revise-capability")
			writeProtectedTestFile(t, path, secret, 0o600)
			sealGeneration(t, generation)
			document, err := os.ReadFile(fixture.yamlPath)
			if err != nil {
				t.Fatal("fixture unavailable")
			}
			document = []byte(strings.Replace(string(document), "server:\n", "server:\n  batch_revise_capability_file: "+path+"\n", 1))
			writeProtectedTestFile(t, fixture.yamlPath, document, 0o600)
			owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
			if reuse {
				if owner != nil || CodeOf(err) != CodeProtectedContent {
					t.Fatal("cross-route capability reuse admitted")
				}
				return
			}
			if err != nil {
				t.Fatalf("protected batch load: %s", CodeOf(err))
			}
			preparation, err := owner.PrepareRuntime()
			if err != nil {
				t.Fatal("prepare failed")
			}
			capability := preparation.BatchReviseCapability()
			if capability.Equal(secret) {
				t.Fatal("capability usable before runtime commit")
			}
			runtime, err := owner.CommitRuntime(preparation)
			if err != nil {
				t.Fatal("commit failed")
			}
			if !capability.Equal(secret) || capability.Equal(fixture.reviseCapability) || preparation.ReviseCapability().Equal(secret) {
				t.Fatal("capability separation failed")
			}
			if err := runtime.Close(); err != nil {
				t.Fatal("close failed")
			}
			if capability.Equal(secret) {
				t.Fatal("released capability remained live")
			}
		})
	}
}
