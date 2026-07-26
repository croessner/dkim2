//go:build linux || darwin

package config

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLoadProtectedDisabledOwnsAndTransfersOneImmutableGeneration exercises the complete disabled bundle.
func TestLoadProtectedDisabledOwnsAndTransfersOneImmutableGeneration(t *testing.T) {
	fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("LoadProtected() failed with code %s", CodeOf(err))
	}
	if !owner.Snapshot().Valid() {
		t.Fatal("prebootstrap owner lost its typed snapshot")
	}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
	}
	if !owner.Snapshot().Valid() {
		t.Fatal("prebootstrap lost access before ownership commit")
	}
	if _, err := owner.PrepareRuntime(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("second PrepareRuntime() returned code %s", CodeOf(err))
	}
	capability := preparation.ProcessCapability()
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	if !runtime.Snapshot().Valid() ||
		!capability.Equal(bytes.Repeat([]byte{0xa5}, exactKeyBytes)) {
		t.Fatal("runtime did not receive the immutable snapshot and capability")
	}
	if err := owner.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("prebootstrap Close() after transfer returned code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second runtime Close() failed with code %s", CodeOf(err))
	}
}

// TestLoadProtectedBackendChildMatrices loads the exact disabled, memory, and Valkey inventories.
func TestLoadProtectedBackendChildMatrices(t *testing.T) {
	for _, backend := range []ReplayBackend{ReplayDisabled, ReplayMemory, ReplayValkey} {
		backend := backend
		t.Run(strconv.Itoa(int(backend)), func(t *testing.T) {
			fixture := newProtectedBackendFixture(t, backend)
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
			startup := preparation.StartupReplay()
			if backend == ReplayDisabled {
				if err := startup.UseReplayMaterial(func(_, _, _ []byte, _ [][]byte) error { return nil }); CodeOf(err) != CodeProtectedContent {
					t.Fatalf("disabled replay borrow returned code %s", CodeOf(err))
				}
			} else {
				err := startup.UseReplayMaterial(func(hmac, applicationPassword, auditorPassword []byte, roots [][]byte) error {
					if !bytes.Equal(hmac, bytes.Repeat([]byte{0xb6}, exactKeyBytes)) {
						t.Fatal("HMAC bytes changed")
					}
					if backend == ReplayValkey {
						if !bytes.Equal(applicationPassword, []byte("application-password")) ||
							!bytes.Equal(auditorPassword, []byte("auditor-password")) ||
							len(roots) != 1 {
							t.Fatal("Valkey protected child inventory changed")
						}
					} else if len(applicationPassword) != 0 || len(auditorPassword) != 0 || len(roots) != 0 {
						t.Fatal("memory backend loaded Valkey-only children")
					}
					return nil
				})
				if err != nil {
					t.Fatalf("UseReplayMaterial() failed with code %s", CodeOf(err))
				}
			}
			runtime, err := owner.CommitRuntime(preparation)
			if err != nil {
				t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
			}
			if err := runtime.Close(); err != nil {
				t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
			}
		})
	}
}

// TestLoadProtectedTracingCAStaysGenerationBoundAndCallbackScoped proves OTLP trust ownership.
func TestLoadProtectedTracingCAStaysGenerationBoundAndCallbackScoped(t *testing.T) {
	fixture := newProtectedBackendFixture(t, ReplayDisabled)
	makeGenerationWritable(t, fixture.generationPath)
	certificate := testProtectedCertificateDER(t, 401, true, x509.KeyUsageCertSign)
	caPath := filepath.Join(fixture.generationPath, "otlp-ca")
	writeProtectedTestFile(
		t,
		caPath,
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificate}),
		0o600,
	)
	sealGeneration(t, fixture.generationPath)
	document := string(fixture.yamlBytes) + `
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://127.0.0.1:4318/v1/traces
    ca_file: ` + caPath + "\n"
	writeProtectedTestFile(t, fixture.yamlPath, []byte(document), 0o600)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil || owner == nil {
		t.Fatalf("LoadProtected() failed with code %s", CodeOf(err))
	}
	defer func() { _ = owner.Close() }()
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatal("runtime preparation failed")
	}
	var borrowed [][]byte
	if err := preparation.TracingMaterial().UseRoots(func(roots [][]byte) error {
		borrowed = roots
		if len(roots) != 1 || !bytes.Equal(roots[0], certificate) {
			return newError(CodeInternal)
		}
		return nil
	}); err != nil {
		t.Fatalf("tracing roots borrow failed with code %s", CodeOf(err))
	}
	if len(borrowed) != 1 || len(borrowed[0]) != 0 {
		t.Fatal("tracing roots survived their callback scope")
	}
}

// TestLoadProtectedRejectsCrossRoleEqualityAndChildIdentityCollisions freezes role separation.
func TestLoadProtectedRejectsCrossRoleEqualityAndChildIdentityCollisions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, protectedBackendFixture)
	}{
		{
			name: "capability equals HMAC",
			mutate: func(t *testing.T, fixture protectedBackendFixture) {
				t.Helper()
				writeProtectedFileWithoutModeChange(filepath.Join(fixture.generationPath, "hmac"), bytes.Repeat([]byte{0xa5}, exactKeyBytes))
			},
		},
		{
			name: "application equals auditor",
			mutate: func(t *testing.T, fixture protectedBackendFixture) {
				t.Helper()
				writeProtectedFileWithoutModeChange(filepath.Join(fixture.generationPath, "auditor-password"), []byte("application-password"))
			},
		},
		{
			name: "HMAC equals application",
			mutate: func(t *testing.T, fixture protectedBackendFixture) {
				t.Helper()
				value := bytes.Repeat([]byte{0xb6}, exactKeyBytes)
				writeProtectedFileWithoutModeChange(filepath.Join(fixture.generationPath, "application-password"), value)
			},
		},
		{
			name: "child inode collision",
			mutate: func(t *testing.T, fixture protectedBackendFixture) {
				t.Helper()
				makeGenerationWritable(t, fixture.generationPath)
				hmacPath := filepath.Join(fixture.generationPath, "hmac")
				if err := os.Remove(hmacPath); err != nil {
					t.Fatal("remove HMAC failed")
				}
				if err := os.Link(fixture.capabilityPath, hmacPath); err != nil {
					t.Fatal("link child identity failed")
				}
				sealGeneration(t, fixture.generationPath)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newProtectedBackendFixture(t, ReplayValkey)
			test.mutate(t, fixture)
			owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
			if CodeOf(err) == CodeProtectedUnsupported {
				t.Skip("test filesystem is outside the closed production allowlist")
			}
			if owner != nil || err == nil {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatal("cross-role equality or identity collision was accepted")
			}
		})
	}
}

// TestLoadProtectedAllowsLinkedPublicCA proves the deliberate non-secret CA link policy.
func TestLoadProtectedAllowsLinkedPublicCA(t *testing.T) {
	fixture := newProtectedBackendFixture(t, ReplayValkey)
	makeGenerationWritable(t, fixture.generationPath)
	if err := os.Link(
		filepath.Join(fixture.generationPath, "ca"),
		filepath.Join(fixture.generationPath, "ca-public-link"),
	); err != nil {
		t.Fatal("link CA failed")
	}
	sealGeneration(t, fixture.generationPath)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("linked public CA rejected with code %s", CodeOf(err))
	}
	_ = owner.Close()
}

// TestProtectedLoadPhaseOrderPreopensEveryChildBeforeReads freezes the bundle algorithm.
func TestProtectedLoadPhaseOrderPreopensEveryChildBeforeReads(t *testing.T) {
	fixture := newProtectedBackendFixture(t, ReplayValkey)
	var events []struct {
		event protectedLoadEvent
		role  protectedFileRole
	}
	owner, err := loadProtectedObserved(fixture.yamlPath, FlagValues{}, func(event protectedLoadEvent, role protectedFileRole) {
		events = append(events, struct {
			event protectedLoadEvent
			role  protectedFileRole
		}{event: event, role: role})
	})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("loadProtectedObserved() failed with code %s", CodeOf(err))
	}
	defer func() { _ = owner.Close() }()
	firstRead := -1
	opened := 0
	finals := 0
	var openedRoles, readRoles, finalRoles []protectedFileRole
	for index, event := range events {
		switch event.event {
		case protectedEventChildOpened:
			opened++
			openedRoles = append(openedRoles, event.role)
		case protectedEventBeforeChildRead:
			if firstRead < 0 {
				firstRead = index
			}
			readRoles = append(readRoles, event.role)
		case protectedEventChildFinal:
			finals++
			finalRoles = append(finalRoles, event.role)
		}
	}
	if opened != 5 || finals != 5 || firstRead < 0 {
		t.Fatalf("phase counts opened=%d finals=%d firstRead=%d", opened, finals, firstRead)
	}
	openedBeforeRead := 0
	for index := 0; index < firstRead; index++ {
		if events[index].event == protectedEventChildOpened {
			openedBeforeRead++
		}
	}
	if openedBeforeRead != 5 {
		t.Fatalf("opened before first read = %d, want 5", openedBeforeRead)
	}
	expectedRoles := []protectedFileRole{
		protectedCapability,
		protectedHMAC,
		protectedApplicationPassword,
		protectedAuditorPassword,
		protectedCA,
	}
	expectedEvents := []struct {
		event protectedLoadEvent
		role  protectedFileRole
	}{
		{event: protectedEventYAMLRead, role: protectedYAML},
		{event: protectedEventGenerationOpened},
	}
	for _, role := range expectedRoles {
		expectedEvents = append(expectedEvents, struct {
			event protectedLoadEvent
			role  protectedFileRole
		}{event: protectedEventChildOpened, role: role})
	}
	for _, role := range expectedRoles {
		expectedEvents = append(expectedEvents,
			struct {
				event protectedLoadEvent
				role  protectedFileRole
			}{event: protectedEventBeforeChildRead, role: role},
			struct {
				event protectedLoadEvent
				role  protectedFileRole
			}{event: protectedEventChildRead, role: role},
		)
	}
	expectedEvents = append(expectedEvents, struct {
		event protectedLoadEvent
		role  protectedFileRole
	}{event: protectedEventBeforeFinalChildren})
	for _, role := range expectedRoles {
		expectedEvents = append(expectedEvents, struct {
			event protectedLoadEvent
			role  protectedFileRole
		}{event: protectedEventChildFinal, role: role})
	}
	expectedEvents = append(expectedEvents,
		struct {
			event protectedLoadEvent
			role  protectedFileRole
		}{event: protectedEventGenerationFinal},
		struct {
			event protectedLoadEvent
			role  protectedFileRole
		}{event: protectedEventYAMLFinal, role: protectedYAML},
	)
	if len(events) != len(expectedEvents) {
		t.Fatalf("phase event count = %d, want %d", len(events), len(expectedEvents))
	}
	for index := range expectedEvents {
		if events[index] != expectedEvents[index] {
			t.Fatalf("phase event %d = %#v, want %#v", index, events[index], expectedEvents[index])
		}
	}
	for _, actual := range [][]protectedFileRole{openedRoles, readRoles, finalRoles} {
		if len(actual) != len(expectedRoles) {
			t.Fatal("phase role inventory length changed")
		}
		for index := range expectedRoles {
			if actual[index] != expectedRoles[index] {
				t.Fatalf("phase role order changed at %d", index)
			}
		}
	}
	for index := firstRead; index < len(events); index++ {
		if events[index].event == protectedEventChildOpened {
			t.Fatal("child opened after reading began")
		}
	}
	lastEvents := []protectedLoadEvent{
		protectedEventGenerationFinal,
		protectedEventYAMLFinal,
	}
	if len(events) < len(lastEvents) {
		t.Fatal("missing terminal phase events")
	}
	for index, want := range lastEvents {
		if events[len(events)-len(lastEvents)+index].event != want {
			t.Fatal("terminal generation/YAML recheck order changed")
		}
	}
}

// TestProtectedLoadDetectsSameInodeAndYAMLRewrites proves final descriptor rechecks.
func TestProtectedLoadDetectsSameInodeAndYAMLRewrites(t *testing.T) {
	tests := []struct {
		name   string
		event  protectedLoadEvent
		role   protectedFileRole
		mutate func(protectedBackendFixture)
	}{
		{
			name:  "earlier child during later read",
			event: protectedEventChildRead,
			role:  protectedHMAC,
			mutate: func(fixture protectedBackendFixture) {
				writeProtectedFileWithoutModeChange(fixture.capabilityPath, bytes.Repeat([]byte{0x5a}, exactKeyBytes))
			},
		},
		{
			name:  "yaml during child load",
			event: protectedEventChildRead,
			role:  protectedHMAC,
			mutate: func(fixture protectedBackendFixture) {
				writeProtectedFileWithoutModeChange(fixture.yamlPath, append(fixture.yamlBytes, '\n'))
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newProtectedBackendFixture(t, ReplayMemory)
			mutated := false
			owner, err := loadProtectedObserved(fixture.yamlPath, FlagValues{}, func(event protectedLoadEvent, role protectedFileRole) {
				if !mutated && event == test.event && role == test.role {
					mutated = true
					test.mutate(fixture)
				}
			})
			if CodeOf(err) == CodeProtectedUnsupported {
				t.Skip("test filesystem is outside the closed production allowlist")
			}
			if owner != nil || CodeOf(err) != CodeProtectedAccess || !mutated {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatalf("rewrite returned code %s mutated=%t", CodeOf(err), mutated)
			}
		})
	}
}

// TestProtectedLoadDetectsImmediateAndFinalMetadataMutations covers every retained phase.
func TestProtectedLoadDetectsImmediateAndFinalMetadataMutations(t *testing.T) {
	tests := []struct {
		name   string
		event  protectedLoadEvent
		role   protectedFileRole
		mutate func(protectedBackendFixture)
	}{
		{
			name:  "child before read immediate check",
			event: protectedEventBeforeChildRead,
			role:  protectedCapability,
			mutate: func(fixture protectedBackendFixture) {
				writeProtectedFileWithoutModeChange(fixture.capabilityPath, bytes.Repeat([]byte{0x5a}, exactKeyBytes))
			},
		},
		{
			name:  "child mode before final pass",
			event: protectedEventBeforeFinalChildren,
			mutate: func(fixture protectedBackendFixture) {
				if err := os.Chmod(fixture.capabilityPath, 0o400); err != nil {
					panic("fixture child chmod failed")
				}
			},
		},
		{
			name:  "generation metadata before final pass",
			event: protectedEventBeforeFinalChildren,
			mutate: func(fixture protectedBackendFixture) {
				if err := os.Chmod(fixture.generationPath, 0o700); err != nil {
					panic("fixture generation chmod failed")
				}
			},
		},
		{
			name:  "YAML mode before final pass",
			event: protectedEventBeforeFinalChildren,
			mutate: func(fixture protectedBackendFixture) {
				if err := os.Chmod(fixture.yamlPath, 0o400); err != nil {
					panic("fixture YAML chmod failed")
				}
			},
		},
		{
			name:  "HMAC concurrent cap plus one",
			event: protectedEventBeforeChildRead,
			role:  protectedHMAC,
			mutate: func(fixture protectedBackendFixture) {
				writeProtectedFileWithoutModeChange(
					filepath.Join(fixture.generationPath, "hmac"),
					bytes.Repeat([]byte{0xb6}, exactKeyBytes+1),
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newProtectedBackendFixture(t, ReplayMemory)
			mutated := false
			owner, err := loadProtectedObserved(fixture.yamlPath, FlagValues{}, func(event protectedLoadEvent, role protectedFileRole) {
				if !mutated && event == test.event && (test.role == 0 || role == test.role) {
					mutated = true
					test.mutate(fixture)
				}
			})
			if CodeOf(err) == CodeProtectedUnsupported {
				t.Skip("test filesystem is outside the closed production allowlist")
			}
			if owner != nil || err == nil || !mutated {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatalf("metadata mutation returned code %s mutated=%t", CodeOf(err), mutated)
			}
		})
	}
}

// TestProtectedLoadAtomicGenerationReplacementCannotMixChildren proves descriptor binding.
func TestProtectedLoadAtomicGenerationReplacementCannotMixChildren(t *testing.T) {
	fixture := newProtectedBackendFixture(t, ReplayMemory)
	replacement := fixture.generationPath + ".replacement"
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal("mkdir replacement failed")
	}
	writeProtectedTestFile(t, filepath.Join(replacement, "capability"), bytes.Repeat([]byte{0x5a}, exactKeyBytes), 0o600)
	writeProtectedTestFile(t, filepath.Join(replacement, "hmac"), bytes.Repeat([]byte{0x6b}, exactKeyBytes), 0o600)
	sealGeneration(t, replacement)
	replaced := false
	owner, err := loadProtectedObserved(fixture.yamlPath, FlagValues{}, func(event protectedLoadEvent, _ protectedFileRole) {
		if !replaced && event == protectedEventGenerationOpened {
			old := fixture.generationPath + ".old"
			if renameErr := os.Rename(fixture.generationPath, old); renameErr != nil {
				panic("test generation rename failed")
			}
			if renameErr := os.Rename(replacement, fixture.generationPath); renameErr != nil {
				panic("test replacement publish failed")
			}
			replaced = true
		}
	})
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if owner != nil || CodeOf(err) != CodeProtectedAccess || !replaced {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatalf("atomic generation replacement returned code %s replaced=%t", CodeOf(err), replaced)
	}
}

// TestLoadProtectedRejectsDescriptorAndContentViolations covers adjacent fail-closed fixtures.
func TestLoadProtectedRejectsDescriptorAndContentViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, protectedLoaderFixture)
	}{
		{
			name: "generation mode",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				if err := os.Chmod(fixture.generationPath, 0o700); err != nil {
					t.Fatal("chmod generation failed")
				}
			},
		},
		{
			name: "yaml mode",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				if err := os.Chmod(fixture.yamlPath, 0o644); err != nil {
					t.Fatal("chmod yaml failed")
				}
			},
		},
		{
			name: "capability mode",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				if err := os.Chmod(fixture.capabilityPath, 0o644); err != nil {
					t.Fatal("chmod capability failed")
				}
			},
		},
		{
			name: "capability hardlink",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				makeGenerationWritable(t, fixture.generationPath)
				if err := os.Link(fixture.capabilityPath, fixture.capabilityPath+".link"); err != nil {
					t.Fatal("hardlink capability failed")
				}
				sealGeneration(t, fixture.generationPath)
			},
		},
		{
			name: "capability symlink",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				makeGenerationWritable(t, fixture.generationPath)
				target := fixture.capabilityPath + ".target"
				if err := os.Rename(fixture.capabilityPath, target); err != nil {
					t.Fatal("rename capability failed")
				}
				if err := os.Symlink(target, fixture.capabilityPath); err != nil {
					t.Fatal("symlink capability failed")
				}
				sealGeneration(t, fixture.generationPath)
			},
		},
		{
			name: "capability fifo",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				makeGenerationWritable(t, fixture.generationPath)
				if err := os.Remove(fixture.capabilityPath); err != nil {
					t.Fatal("remove capability failed")
				}
				if err := unix.Mkfifo(fixture.capabilityPath, 0o600); err != nil {
					t.Fatal("mkfifo capability failed")
				}
				sealGeneration(t, fixture.generationPath)
			},
		},
		{
			name: "capability socket",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				shortDirectory, err := os.MkdirTemp("/tmp", "d2-")
				if err != nil {
					t.Fatal("mkdir short socket fixture failed")
				}
				t.Cleanup(func() { _ = os.RemoveAll(shortDirectory) })
				shortSocket := filepath.Join(shortDirectory, "s")
				listener, err := net.Listen("unix", shortSocket)
				if err != nil {
					t.Skip("sandbox does not permit unix socket fixture")
				}
				t.Cleanup(func() { _ = listener.Close() })
				makeGenerationWritable(t, fixture.generationPath)
				if err := os.Remove(fixture.capabilityPath); err != nil {
					t.Fatal("remove capability failed")
				}
				if err := os.Rename(shortSocket, fixture.capabilityPath); err != nil {
					t.Skip("socket rename crosses filesystems")
				}
				sealGeneration(t, fixture.generationPath)
			},
		},
		{
			name: "all zero capability",
			mutate: func(t *testing.T, fixture protectedLoaderFixture) {
				t.Helper()
				makeGenerationWritable(t, fixture.generationPath)
				writeProtectedTestFile(t, fixture.capabilityPath, make([]byte, exactKeyBytes), 0o600)
				sealGeneration(t, fixture.generationPath)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
			test.mutate(t, fixture)
			owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
			if owner != nil || err == nil {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatal("LoadProtected() accepted an invalid descriptor fixture")
			}
		})
	}
}

// TestLoadProtectedRejectsWrongUIDAndUntrustedParents freezes one captured authority.
func TestLoadProtectedRejectsWrongUIDAndUntrustedParents(t *testing.T) {
	fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	owner, err := loadProtectedObservedWithUID(
		fixture.yamlPath,
		FlagValues{},
		nil,
		uint32(os.Geteuid()+1),
	)
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("descriptor-native ACL inspection is unavailable")
	}
	if owner != nil || CodeOf(err) != CodeProtectedAccess {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatalf("wrong captured UID returned code %s", CodeOf(err))
	}

	if err := os.Chmod(filepath.Dir(fixture.yamlPath), 0o770); err != nil {
		t.Fatal("chmod fixture parent failed")
	}
	owner, err = LoadProtected(fixture.yamlPath, FlagValues{})
	if owner != nil || CodeOf(err) != CodeProtectedAccess {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatalf("writable parent returned code %s", CodeOf(err))
	}
}

// TestLoadProtectedRejectsSymlinkedParentComponent prevents pathname fallback traversal.
func TestLoadProtectedRejectsSymlinkedParentComponent(t *testing.T) {
	fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	base := filepath.Dir(fixture.yamlPath)
	alias := base + ".alias"
	if err := os.Symlink(base, alias); err != nil {
		t.Fatal("symlink parent fixture failed")
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	owner, err := LoadProtected(filepath.Join(alias, filepath.Base(fixture.yamlPath)), FlagValues{})
	if owner != nil || err == nil {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("symlinked parent component was accepted")
	}
}

// TestProtectedRoleSizeMatrix freezes every independent pre-read byte bound.
func TestProtectedRoleSizeMatrix(t *testing.T) {
	tests := []struct {
		role protectedFileRole
		min  int64
		max  int64
	}{
		{role: protectedYAML, min: 1, max: maxYAMLDocumentBytes},
		{role: protectedCapability, min: exactKeyBytes, max: exactKeyBytes},
		{role: protectedHMAC, min: exactKeyBytes, max: exactKeyBytes},
		{role: protectedApplicationPassword, min: 1, max: maxPasswordBytes},
		{role: protectedAuditorPassword, min: 1, max: maxPasswordBytes},
		{role: protectedCA, min: 1, max: maxCAPEMBytes},
		{role: protectedTracingCA, min: 1, max: maxTracingCAPEMBytes},
	}
	for _, test := range tests {
		for _, size := range []int64{test.min - 1, test.min, test.max, test.max + 1} {
			want := size >= test.min && size <= test.max
			if got := protectedSizeAccepted(test.role, size); got != want {
				t.Fatalf("role=%d size=%d accepted=%t want=%t", test.role, size, got, want)
			}
		}
	}
}

// TestLoadProtectedRejectsPerRoleAdjacentSizeFixtures exercises retained file descriptors end to end.
func TestLoadProtectedRejectsPerRoleAdjacentSizeFixtures(t *testing.T) {
	tests := []struct {
		name    string
		backend ReplayBackend
		path    func(protectedBackendFixture) string
		size    int
	}{
		{
			name: "HMAC minus one", backend: ReplayMemory,
			path: func(fixture protectedBackendFixture) string { return filepath.Join(fixture.generationPath, "hmac") },
			size: exactKeyBytes - 1,
		},
		{
			name: "HMAC plus one", backend: ReplayMemory,
			path: func(fixture protectedBackendFixture) string { return filepath.Join(fixture.generationPath, "hmac") },
			size: exactKeyBytes + 1,
		},
		{
			name: "application empty", backend: ReplayValkey,
			path: func(fixture protectedBackendFixture) string {
				return filepath.Join(fixture.generationPath, "application-password")
			},
			size: 0,
		},
		{
			name: "application plus one", backend: ReplayValkey,
			path: func(fixture protectedBackendFixture) string {
				return filepath.Join(fixture.generationPath, "application-password")
			},
			size: maxPasswordBytes + 1,
		},
		{
			name: "auditor empty", backend: ReplayValkey,
			path: func(fixture protectedBackendFixture) string {
				return filepath.Join(fixture.generationPath, "auditor-password")
			},
			size: 0,
		},
		{
			name: "auditor plus one", backend: ReplayValkey,
			path: func(fixture protectedBackendFixture) string {
				return filepath.Join(fixture.generationPath, "auditor-password")
			},
			size: maxPasswordBytes + 1,
		},
		{
			name: "CA empty", backend: ReplayValkey,
			path: func(fixture protectedBackendFixture) string { return filepath.Join(fixture.generationPath, "ca") },
			size: 0,
		},
		{
			name: "CA plus one", backend: ReplayValkey,
			path: func(fixture protectedBackendFixture) string { return filepath.Join(fixture.generationPath, "ca") },
			size: maxCAPEMBytes + 1,
		},
		{
			name: "YAML empty", backend: ReplayDisabled,
			path: func(fixture protectedBackendFixture) string { return fixture.yamlPath },
			size: 0,
		},
		{
			name: "YAML plus one", backend: ReplayDisabled,
			path: func(fixture protectedBackendFixture) string { return fixture.yamlPath },
			size: maxYAMLDocumentBytes + 1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newProtectedBackendFixture(t, test.backend)
			writeProtectedFileWithoutModeChange(test.path(fixture), bytes.Repeat([]byte{'x'}, test.size))
			owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
			if CodeOf(err) == CodeProtectedUnsupported {
				t.Skip("test filesystem is outside the closed production allowlist")
			}
			if owner != nil || err == nil {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatal("adjacent role size was accepted")
			}
		})
	}
}

// TestValidateGenerationMetadataRejectsUnlinkedAndMixedOwners freezes directory policy.
func TestValidateGenerationMetadataRejectsUnlinkedAndMixedOwners(t *testing.T) {
	valid := descriptorMetadata{
		typeBits:  unix.S_IFDIR,
		uid:       uint32(os.Geteuid()),
		modeBits:  0o500,
		linkCount: 1,
	}
	if err := validateGenerationMetadata(valid, uint32(os.Geteuid())); err != nil {
		t.Fatalf("valid generation metadata rejected with code %s", CodeOf(err))
	}
	for _, mutate := range []func(*descriptorMetadata){
		func(value *descriptorMetadata) { value.linkCount = 0 },
		func(value *descriptorMetadata) { value.uid++ },
		func(value *descriptorMetadata) { value.modeBits = 0o700 },
		func(value *descriptorMetadata) { value.typeBits = unix.S_IFREG },
	} {
		candidate := valid
		mutate(&candidate)
		if err := validateGenerationMetadata(candidate, uint32(os.Geteuid())); CodeOf(err) != CodeProtectedAccess {
			t.Fatalf("invalid generation metadata returned code %s", CodeOf(err))
		}
	}
}

// TestValidateProtectedFileMetadataFreezesRoleLinkAndTypePolicies covers special files and CA links.
func TestValidateProtectedFileMetadataFreezesRoleLinkAndTypePolicies(t *testing.T) {
	valid := descriptorMetadata{
		typeBits:  unix.S_IFREG,
		uid:       uint32(os.Geteuid()),
		modeBits:  0o600,
		linkCount: 1,
		size:      exactKeyBytes,
	}
	if err := validateProtectedFileMetadata(valid, protectedCapability, valid.uid); err != nil {
		t.Fatalf("valid secret metadata rejected with code %s", CodeOf(err))
	}
	for _, specialType := range []uint32{unix.S_IFIFO, unix.S_IFSOCK, unix.S_IFCHR, unix.S_IFBLK, unix.S_IFDIR} {
		candidate := valid
		candidate.typeBits = specialType
		if err := validateProtectedFileMetadata(candidate, protectedCapability, valid.uid); CodeOf(err) != CodeProtectedAccess {
			t.Fatalf("special type %o returned code %s", specialType, CodeOf(err))
		}
	}
	secretLinked := valid
	secretLinked.linkCount = 2
	if err := validateProtectedFileMetadata(secretLinked, protectedHMAC, valid.uid); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("linked secret returned code %s", CodeOf(err))
	}
	ca := valid
	ca.modeBits = 0o644
	ca.size = 1
	ca.linkCount = 2
	if err := validateProtectedFileMetadata(ca, protectedCA, valid.uid); err != nil {
		t.Fatalf("linked CA rejected with code %s", CodeOf(err))
	}
	ca.linkCount = 0
	if err := validateProtectedFileMetadata(ca, protectedCA, valid.uid); CodeOf(err) != CodeProtectedAccess {
		t.Fatalf("unlinked CA returned code %s", CodeOf(err))
	}
	tracingCA := valid
	tracingCA.size = 1
	for _, mode := range []uint32{0o400, 0o600} {
		tracingCA.modeBits = mode
		if err := validateProtectedFileMetadata(
			tracingCA,
			protectedTracingCA,
			valid.uid,
		); err != nil {
			t.Fatalf("tracing CA mode %o returned code %s", mode, CodeOf(err))
		}
	}
	for _, mutate := range []func(*descriptorMetadata){
		func(value *descriptorMetadata) { value.modeBits = 0o440 },
		func(value *descriptorMetadata) { value.linkCount = 2 },
	} {
		candidate := tracingCA
		mutate(&candidate)
		if err := validateProtectedFileMetadata(
			candidate,
			protectedTracingCA,
			valid.uid,
		); CodeOf(err) != CodeProtectedAccess {
			t.Fatalf("invalid tracing CA metadata returned code %s", CodeOf(err))
		}
	}
}

// TestOpenPreclassifiedChildRejectsDevice verifies descriptor-relative device preclassification.
func TestOpenPreclassifiedChildRejectsDevice(t *testing.T) {
	descriptor, err := openPreclassifiedChild(unix.AT_FDCWD, os.DevNull, false)
	if descriptor.fd >= 0 {
		_ = descriptor.close()
		t.Fatal("device preclassification returned an owned descriptor")
	}
	if CodeOf(err) != CodeProtectedPath {
		t.Fatalf("device preclassification returned code %s", CodeOf(err))
	}
}

// TestLoadProtectedEnforcesExactCapabilityReadBounds covers cap-minus/exact/plus-one bytes.
func TestLoadProtectedEnforcesExactCapabilityReadBounds(t *testing.T) {
	for _, size := range []int{exactKeyBytes - 1, exactKeyBytes, exactKeyBytes + 1} {
		size := size
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, size))
			owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
			if CodeOf(err) == CodeProtectedUnsupported {
				t.Skip("test filesystem is outside the closed production allowlist")
			}
			if size == exactKeyBytes {
				if err != nil {
					t.Fatalf("exact capability rejected with code %s", CodeOf(err))
				}
				_ = owner.Close()
				return
			}
			if owner != nil || err == nil {
				t.Fatal("non-exact capability size accepted")
			}
		})
	}
}

// TestOpenProtectedChildRemainsBoundToTheOpenedGeneration proves path replacement cannot mix generations.
func TestOpenProtectedChildRemainsBoundToTheOpenedGeneration(t *testing.T) {
	fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	generation, err := openProtectedPath(fixture.generationPath, true)
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("openProtectedPath() failed with code %s", CodeOf(err))
	}
	defer func() { _ = generation.close() }()
	replacement := fixture.generationPath + ".replacement"
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal("mkdir replacement failed")
	}
	writeProtectedTestFile(t, filepath.Join(replacement, "capability"), bytes.Repeat([]byte{0x5a}, exactKeyBytes), 0o600)
	if err := os.Chmod(replacement, 0o500); err != nil {
		t.Fatal("seal replacement failed")
	}
	old := fixture.generationPath + ".old"
	if err := os.Rename(fixture.generationPath, old); err != nil {
		t.Fatal("rename original generation failed")
	}
	if err := os.Rename(replacement, fixture.generationPath); err != nil {
		t.Fatal("publish replacement generation failed")
	}
	child, err := openProtectedChild(generation.fd, "capability")
	if err != nil {
		t.Fatalf("openProtectedChild() failed with code %s", CodeOf(err))
	}
	defer func() { _ = child.close() }()
	data, err := readProtectedDescriptor(child.fd, exactKeyBytes)
	if err != nil {
		t.Fatalf("readProtectedDescriptor() failed with code %s", CodeOf(err))
	}
	if !bytes.Equal(data, bytes.Repeat([]byte{0xa5}, exactKeyBytes)) {
		t.Fatal("opened generation descriptor mixed replacement child content")
	}
}

// TestProtectedDescriptorOpenFlags proves read-only, nonblocking, and close-on-exec state.
func TestProtectedDescriptorOpenFlags(t *testing.T) {
	fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	generation, err := openProtectedPath(fixture.generationPath, true)
	if CodeOf(err) == CodeProtectedUnsupported {
		t.Skip("test filesystem is outside the closed production allowlist")
	}
	if err != nil {
		t.Fatalf("open generation failed with code %s", CodeOf(err))
	}
	defer func() { _ = generation.close() }()
	child, err := openProtectedChild(generation.fd, "capability")
	if err != nil {
		t.Fatalf("open child failed with code %s", CodeOf(err))
	}
	defer func() { _ = child.close() }()
	descriptorFlags, err := unix.FcntlInt(uintptr(child.fd), unix.F_GETFD, 0)
	if err != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("protected child lacks close-on-exec")
	}
	statusFlags, err := unix.FcntlInt(uintptr(child.fd), unix.F_GETFL, 0)
	if err != nil ||
		statusFlags&unix.O_ACCMODE != unix.O_RDONLY ||
		statusFlags&unix.O_NONBLOCK == 0 {
		t.Fatal("protected child lacks read-only nonblocking status")
	}
}

// TestProtectedPathComponentsEnforcesExactBounds freezes lexical traversal limits.
func TestProtectedPathComponentsEnforcesExactBounds(t *testing.T) {
	valid := "/" + strings.Repeat("a", maxProtectedComponentBytes) + "/file"
	if _, err := protectedPathComponents(valid); err != nil {
		t.Fatalf("exact component bound rejected with code %s", CodeOf(err))
	}
	for _, path := range []string{
		"relative/file",
		"/a/../file",
		"/a/\x00/file",
		"/" + strings.Repeat("a", maxProtectedComponentBytes+1) + "/file",
		"/" + strings.Repeat("a/", maxProtectedPathComponents) + "file",
		strings.Repeat("/a", maxProtectedPathBytes),
	} {
		if _, err := protectedPathComponents(path); CodeOf(err) != CodeProtectedPath {
			t.Fatalf("invalid protected path returned code %s", CodeOf(err))
		}
	}
	exactComponents := "/" + strings.Join(makeRepeatedComponents(64, "a"), "/")
	if _, err := protectedPathComponents(exactComponents); err != nil {
		t.Fatalf("exact component-count bound rejected with code %s", CodeOf(err))
	}
	overComponents := "/" + strings.Join(makeRepeatedComponents(65, "a"), "/")
	if _, err := protectedPathComponents(overComponents); CodeOf(err) != CodeProtectedPath {
		t.Fatalf("over component-count bound returned code %s", CodeOf(err))
	}
	exactPathParts := makeRepeatedComponents(16, strings.Repeat("a", 255))
	exactPath := "/" + strings.Join(exactPathParts, "/")
	if len(exactPath) != maxProtectedPathBytes {
		t.Fatal("exact path fixture length is wrong")
	}
	if _, err := protectedPathComponents(exactPath); err != nil {
		t.Fatalf("exact path byte bound rejected with code %s", CodeOf(err))
	}
	overPathParts := append(
		makeRepeatedComponents(15, strings.Repeat("a", 255)),
		strings.Repeat("b", 254),
		"c",
	)
	overPath := "/" + strings.Join(overPathParts, "/")
	if len(overPath) != maxProtectedPathBytes+1 {
		t.Fatal("over path fixture length is wrong")
	}
	if _, err := protectedPathComponents(overPath); CodeOf(err) != CodeProtectedPath {
		t.Fatalf("over path byte bound returned code %s", CodeOf(err))
	}
}

// makeRepeatedComponents returns one independent path-component fixture.
func makeRepeatedComponents(count int, value string) []string {
	components := make([]string, count)
	for index := range components {
		components[index] = value
	}
	return components
}

// TestLoadProtectedRejectsYAMLInsideGenerationAncestry covers direct and nested descendants.
func TestLoadProtectedRejectsYAMLInsideGenerationAncestry(t *testing.T) {
	for _, nested := range []bool{false, true} {
		nested := nested
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			fixture := newProtectedLoaderFixture(t, bytes.Repeat([]byte{0xa5}, exactKeyBytes))
			makeGenerationWritable(t, fixture.generationPath)
			destinationDirectory := fixture.generationPath
			if nested {
				destinationDirectory = filepath.Join(fixture.generationPath, "nested")
				if err := os.Mkdir(destinationDirectory, 0o700); err != nil {
					t.Fatal("mkdir nested YAML directory failed")
				}
			}
			destination := filepath.Join(destinationDirectory, "dkim2d.yaml")
			if err := os.Rename(fixture.yamlPath, destination); err != nil {
				t.Fatal("move YAML into generation failed")
			}
			sealGeneration(t, fixture.generationPath)
			owner, err := LoadProtected(destination, FlagValues{})
			if CodeOf(err) == CodeProtectedUnsupported {
				t.Skip("descriptor-native ACL inspection is unavailable")
			}
			if owner != nil || CodeOf(err) != CodeProtectedPath {
				if owner != nil {
					_ = owner.Close()
				}
				t.Fatalf("generation-descendant YAML returned code %s", CodeOf(err))
			}
		})
	}
}

// TestDescriptorAncestryContainsRejectsAliasIdentity freezes bind-alias-equivalent matching.
func TestDescriptorAncestryContainsRejectsAliasIdentity(t *testing.T) {
	ancestry := [][2]uint64{{1, 2}, {3, 4}, {5, 6}}
	if !descriptorAncestryContains(ancestry, descriptorMetadata{device: 3, inode: 4}) {
		t.Fatal("descriptor ancestry missed an alias identity")
	}
	if descriptorAncestryContains(ancestry, descriptorMetadata{device: 3, inode: 7}) {
		t.Fatal("descriptor ancestry matched a distinct inode")
	}
}

// TestOwnedDescriptorCloseReportsFailureOnce freezes no-retry close semantics.
func TestOwnedDescriptorCloseReportsFailureOnce(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal("Open() failed")
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		t.Fatal("Dup() failed")
	}
	if err := file.Close(); err != nil {
		t.Fatal("file Close() failed")
	}
	descriptor := ownedDescriptor{fd: fd}
	if err := unix.Close(fd); err != nil {
		t.Fatal("fixture Close() failed")
	}
	if err := descriptor.close(); CodeOf(err) != CodeProtectedIO {
		t.Fatalf("owned close failure returned code %s", CodeOf(err))
	}
	if err := descriptor.close(); err != nil {
		t.Fatalf("second owned close retried with code %s", CodeOf(err))
	}
}

// TestOwnedDescriptorCloseInjectionWithholdsSuccessAndNeverRetries proves close ownership.
func TestOwnedDescriptorCloseInjectionWithholdsSuccessAndNeverRetries(t *testing.T) {
	calls := 0
	descriptor := ownedDescriptor{
		fd: 42,
		closeFn: func(int) error {
			calls++
			return unix.EINTR
		},
	}
	if err := descriptor.close(); CodeOf(err) != CodeProtectedIO {
		t.Fatalf("injected close failure returned code %s", CodeOf(err))
	}
	if err := descriptor.close(); err != nil || calls != 1 {
		t.Fatalf("close retried: calls=%d code=%s", calls, CodeOf(err))
	}
	owner := &Prebootstrap{state: &protectedState{phase: protectedOwnedByPrebootstrap}}
	var resultErr error
	applyProtectedClose(&owner, &resultErr, newError(CodeProtectedIO))
	if owner != nil || CodeOf(resultErr) != CodeProtectedIO {
		t.Fatal("close ambiguity did not withhold successful ownership")
	}
}

// TestCloseRetainedFilesAttemptsEveryOwnerOnce freezes aggregate cleanup behavior.
func TestCloseRetainedFilesAttemptsEveryOwnerOnce(t *testing.T) {
	calls := make([]int, 3)
	files := make([]*retainedProtectedFile, len(calls))
	for index := range files {
		index := index
		files[index] = &retainedProtectedFile{descriptor: ownedDescriptor{
			fd: index + 10,
			closeFn: func(int) error {
				calls[index]++
				if index < 2 {
					return unix.EIO
				}
				return nil
			},
		}}
	}
	if err := closeRetainedFiles(files); CodeOf(err) != CodeProtectedIO {
		t.Fatalf("aggregate close returned code %s", CodeOf(err))
	}
	for index, count := range calls {
		if count != 1 {
			t.Fatalf("close owner %d called %d times", index, count)
		}
	}
	if err := closeRetainedFiles(files); err != nil {
		t.Fatalf("second aggregate close returned code %s", CodeOf(err))
	}
	for index, count := range calls {
		if count != 1 {
			t.Fatalf("close owner %d retried to %d calls", index, count)
		}
	}
}

// TestReadProtectedDescriptorWithHandlesPartialEINTRAndExactCap freezes read semantics.
func TestReadProtectedDescriptorWithHandlesPartialEINTRAndExactCap(t *testing.T) {
	source := []byte("abcdef")
	offset := 0
	calls := 0
	data, err := readProtectedDescriptorWith(len(source), func(destination []byte) (int, error) {
		calls++
		if calls == 1 {
			destination[0] = source[0]
			offset = 1
			return 1, unix.EINTR
		}
		if offset == len(source) {
			return 0, nil
		}
		count := min(2, len(destination), len(source)-offset)
		copy(destination, source[offset:offset+count])
		offset += count
		return count, nil
	})
	if err != nil || !bytes.Equal(data, source) {
		t.Fatalf("partial/EINTR read failed with code %s", CodeOf(err))
	}
	over := append(append([]byte(nil), source...), 'g')
	offset = 0
	data, err = readProtectedDescriptorWith(len(source), func(destination []byte) (int, error) {
		if offset == len(over) {
			return 0, nil
		}
		count := copy(destination, over[offset:])
		offset += count
		return count, nil
	})
	if data != nil || CodeOf(err) != CodeProtectedContent {
		t.Fatalf("cap-plus-one read returned code %s", CodeOf(err))
	}
	_, err = readProtectedDescriptorWith(8, func([]byte) (int, error) {
		return 0, errors.New("toxic read error")
	})
	if CodeOf(err) != CodeProtectedIO || strings.Contains(err.Error(), "toxic") {
		t.Fatal("raw reader failure escaped content-free mapping")
	}
	_, err = readProtectedDescriptorWith(8, func(destination []byte) (int, error) {
		return len(destination) + 1, nil
	})
	if CodeOf(err) != CodeProtectedIO {
		t.Fatalf("oversized injected count returned code %s", CodeOf(err))
	}
}

// TestDescriptorOpenAndStatRetriesHandleEINTRAndMapTerminalErrors.
func TestDescriptorOpenAndStatRetriesHandleEINTRAndMapTerminalErrors(t *testing.T) {
	openCalls := 0
	fd, err := retryOpenatWith(func() (int, error) {
		openCalls++
		if openCalls < 3 {
			return -1, unix.EINTR
		}
		return 42, nil
	})
	if err != nil || fd != 42 || openCalls != 3 {
		t.Fatalf("open retry failed: fd=%d calls=%d code=%s", fd, openCalls, CodeOf(err))
	}
	if _, err := retryOpenatWith(func() (int, error) {
		return -1, errors.New("toxic open failure")
	}); CodeOf(err) != CodeProtectedIO || strings.Contains(err.Error(), "toxic") {
		t.Fatal("terminal open error escaped stable mapping")
	}

	for _, operationName := range []string{"fstat", "fstatat"} {
		calls := 0
		err := retryDescriptorOperation(func() error {
			calls++
			if calls < 3 {
				return unix.EINTR
			}
			return nil
		})
		if err != nil || calls != 3 {
			t.Fatalf("%s retry failed: calls=%d code=%s", operationName, calls, CodeOf(err))
		}
		err = retryDescriptorOperation(func() error {
			return errors.New("toxic stat failure")
		})
		if CodeOf(err) != CodeProtectedIO || strings.Contains(err.Error(), "toxic") {
			t.Fatalf("%s terminal error escaped stable mapping", operationName)
		}
	}
}

type protectedLoaderFixture struct {
	yamlPath       string
	generationPath string
	capabilityPath string
}

type protectedBackendFixture struct {
	yamlPath       string
	yamlBytes      []byte
	generationPath string
	capabilityPath string
}

// newProtectedBackendFixture creates one complete backend-conditional generation.
func newProtectedBackendFixture(t *testing.T, backend ReplayBackend) protectedBackendFixture {
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
	var document string
	switch backend {
	case ReplayDisabled:
		document = disabledYAML()
	case ReplayMemory:
		document = memoryYAML("1", "capability")
		writeProtectedTestFile(t, filepath.Join(generationPath, "hmac"), bytes.Repeat([]byte{0xb6}, exactKeyBytes), 0o600)
	case ReplayValkey:
		document = valkeyYAML()
		writeProtectedTestFile(t, filepath.Join(generationPath, "hmac"), bytes.Repeat([]byte{0xb6}, exactKeyBytes), 0o600)
		writeProtectedTestFile(t, filepath.Join(generationPath, "application-password"), []byte("application-password"), 0o600)
		writeProtectedTestFile(t, filepath.Join(generationPath, "auditor-password"), []byte("auditor-password"), 0o600)
		certificate := testProtectedCertificateDER(t, 400, true, 0)
		writeProtectedTestFile(
			t,
			filepath.Join(generationPath, "ca"),
			pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificate}),
			0o644,
		)
	default:
		t.Fatal("unsupported test backend")
	}
	document = strings.ReplaceAll(document, "/secure/"+testGeneration, generationPath)
	yamlBytes := []byte(document)
	yamlPath := filepath.Join(base, "dkim2d.yaml")
	writeProtectedTestFile(t, yamlPath, yamlBytes, 0o600)
	sealGeneration(t, generationPath)
	return protectedBackendFixture{
		yamlPath:       yamlPath,
		yamlBytes:      yamlBytes,
		generationPath: generationPath,
		capabilityPath: capabilityPath,
	}
}

// newProtectedLoaderFixture creates one descriptor-policy-correct disabled bundle.
func newProtectedLoaderFixture(t *testing.T, capability []byte) protectedLoaderFixture {
	t.Helper()
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
	writeProtectedTestFile(t, capabilityPath, capability, 0o600)
	if err := os.Chmod(generationPath, 0o500); err != nil {
		t.Fatal("seal generation failed")
	}
	yamlPath := filepath.Join(base, "dkim2d.yaml")
	document := strings.Replace(
		disabledYAML(),
		"/secure/"+testGeneration+"/capability",
		capabilityPath,
		1,
	)
	writeProtectedTestFile(t, yamlPath, []byte(document), 0o600)
	return protectedLoaderFixture{
		yamlPath:       yamlPath,
		generationPath: generationPath,
		capabilityPath: capabilityPath,
	}
}

// makeGenerationWritable temporarily opens one synthetic generation for fixture mutation.
func makeGenerationWritable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal("open generation failed")
	}
}

// sealGeneration restores the exact immutable generation-directory mode.
func sealGeneration(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal("seal generation failed")
	}
}

// writeProtectedTestFile writes one synthetic protected fixture with an exact mode.
func writeProtectedTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal("WriteFile() failed")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("Chmod() failed")
	}
}

// writeProtectedFileWithoutModeChange rewrites one retained fixture inode in place.
func writeProtectedFileWithoutModeChange(path string, data []byte) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		panic("protected fixture rewrite open failed")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		panic("protected fixture rewrite failed")
	}
	if err := file.Close(); err != nil {
		panic("protected fixture rewrite close failed")
	}
}

// FuzzProtectedPathComponents exercises only lexical bounds without opening fuzzed paths.
func FuzzProtectedPathComponents(f *testing.F) {
	f.Add("/secure/file")
	f.Add("/a/\x00/file")
	f.Add("relative")
	f.Add("TOXIC_PATH_MARKER")
	f.Fuzz(func(t *testing.T, path string) {
		components, err := protectedPathComponents(path)
		if err != nil {
			if CodeOf(err) != CodeProtectedPath ||
				strings.Contains(path, "TOXIC_PATH_MARKER") &&
					strings.Contains(err.Error(), "TOXIC_PATH_MARKER") {
				t.Fatalf("lexical path error was unstable or exposed input")
			}
			return
		}
		if len(path) == 0 || len(path) > maxProtectedPathBytes ||
			len(components) == 0 || len(components) > maxProtectedPathComponents {
			t.Fatal("accepted path escaped aggregate bounds")
		}
		for _, component := range components {
			if len(component) == 0 || len(component) > maxProtectedComponentBytes {
				t.Fatal("accepted path escaped component bounds")
			}
		}
	})
}
