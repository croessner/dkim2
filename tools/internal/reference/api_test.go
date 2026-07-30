package reference

import (
	"bytes"
	"strings"
	"testing"
)

// TestGenerateAPIManifestIsDeterministic verifies exact repeated output.
func TestGenerateAPIManifestIsDeterministic(t *testing.T) {
	first, firstCount, err := GenerateAPIManifest(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	second, secondCount, err := GenerateAPIManifest(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if firstCount == 0 || firstCount != secondCount || !bytes.Equal(first, second) {
		t.Fatal("API manifest changed for identical sources")
	}
}

// TestGenerateAPIManifestIncludesModuleAndDocumentationSurface freezes the complete public boundary.
func TestGenerateAPIManifestIncludesModuleAndDocumentationSurface(t *testing.T) {
	manifest, _, err := GenerateAPIManifest(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"module: github.com/croessner/dkim2\n",
		"go: 1.26\n",
		"// ObservationEvent is the immutable closed library observation value.",
	} {
		if !strings.Contains(string(manifest), required) {
			t.Fatalf("API manifest omitted %q", required)
		}
	}
}
