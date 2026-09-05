//go:build linux || darwin

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadProtectedAcceptsPropagationOnlyGeneration proves a protected
// generation whose only route capability is the propagation capability loads
// without an unused originator or delivery-status signing capability.
func TestLoadProtectedAcceptsPropagationOnlyGeneration(t *testing.T) {
	fixture := newProtectedSigningFixture(t)
	generationPath := filepath.Dir(fixture.signCapabilityPath)
	propagateCapability := bytes.Repeat([]byte{0xe9}, exactKeyBytes)
	makeGenerationWritable(t, generationPath)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "dsn-propagate-capability"),
		propagateCapability, 0o600,
	)
	writeProtectedTestFile(
		t, filepath.Join(generationPath, "hmac"),
		bytes.Repeat([]byte{0x5a}, exactKeyBytes), 0o600,
	)
	sealGeneration(t, generationPath)
	document := protectedSigningDocument(t, fixture.yamlPath)
	document = removeYAMLField(document, "  sign_capability_file:")
	document = removeYAMLField(document, "  revise_capability_file:")
	document = removeYAMLField(document, "  dsn_sign_capability_file:")
	document = strings.Replace(
		document,
		"  capability_file: "+filepath.Join(generationPath, "capability")+"\n",
		"  capability_file: "+filepath.Join(generationPath, "capability")+"\n"+
			"  dsn_propagate_capability_file: "+
			filepath.Join(generationPath, "dsn-propagate-capability")+"\n",
		1,
	)
	document = strings.Replace(
		document,
		"replay:\n  backend: disabled\n",
		"replay:\n  backend: memory\n  hmac_key_file: "+
			filepath.Join(generationPath, "hmac")+"\n  epoch: 1\n",
		1,
	)
	writeProtectedTestFile(t, fixture.yamlPath, []byte(document), 0o600)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if err != nil {
		t.Fatalf("LoadProtected(propagation only) failed with code %s", CodeOf(err))
	}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime(propagation only) failed with code %s", CodeOf(err))
	}
	if preparation.SigningStore() == nil {
		t.Fatal("propagation-only generation withheld the signing store")
	}
	capability := preparation.DSNPropagateCapability()
	signCapability := preparation.SignCapability()
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime(propagation only) failed with code %s", CodeOf(err))
	}
	if !capability.Equal(propagateCapability) {
		t.Fatal("propagation-only generation lost its dedicated capability")
	}
	if signCapability.Equal(fixture.signCapability) {
		t.Fatal("propagation-only generation published an originator capability")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close(propagation only) failed with code %s", CodeOf(err))
	}
}

// TestLoadProtectedAcceptsLocalityOnlyGeneration proves a protected
// generation with no route capability loads when the locality tenant of the
// process route consumes the datasource, and stays refused without it.
func TestLoadProtectedAcceptsLocalityOnlyGeneration(t *testing.T) {
	fixture := newProtectedSigningFixture(t)
	document := protectedSigningDocument(t, fixture.yamlPath)
	document = removeYAMLField(document, "  sign_capability_file:")
	document = removeYAMLField(document, "  revise_capability_file:")
	document = removeYAMLField(document, "  dsn_sign_capability_file:")
	writeProtectedTestFile(t, fixture.yamlPath, []byte(document), 0o600)
	if owner, err := LoadProtected(fixture.yamlPath, FlagValues{}); owner != nil ||
		CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("generation without any consumer returned code %s", CodeOf(err))
	}
	writeProtectedTestFile(
		t, fixture.yamlPath,
		[]byte(document+"process:\n  default_tenant: "+testTenant+"\n"), 0o600,
	)
	owner, err := LoadProtected(fixture.yamlPath, FlagValues{})
	if err != nil {
		t.Fatalf("LoadProtected(locality only) failed with code %s", CodeOf(err))
	}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime(locality only) failed with code %s", CodeOf(err))
	}
	if preparation.SigningStore() == nil {
		t.Fatal("locality-only generation withheld the read-only signing store")
	}
	signCapability := preparation.SignCapability()
	dsnSignCapability := preparation.DSNSignCapability()
	propagateCapability := preparation.DSNPropagateCapability()
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime(locality only) failed with code %s", CodeOf(err))
	}
	if signCapability.Equal(fixture.signCapability) ||
		dsnSignCapability.Equal(fixture.dsnSignCapability) ||
		propagateCapability.Equal(bytes.Repeat([]byte{0xe9}, exactKeyBytes)) {
		t.Fatal("locality-only generation published a signing route capability")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close(locality only) failed with code %s", CodeOf(err))
	}
}

// protectedSigningDocument reads back the fixture document under test.
func protectedSigningDocument(t *testing.T, path string) string {
	t.Helper()
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(document)
}
