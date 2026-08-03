package datasourceadmin

import (
	"strings"
	"testing"

	"github.com/croessner/dkim2/provider"
)

// TestHandleDeclarationUsesCanonicalDatasetValidation freezes the existing provider seam.
func TestHandleDeclarationUsesCanonicalDatasetValidation(t *testing.T) {
	if err := ValidateHandleDeclaration("handle.valid-1"); err != nil {
		t.Fatal("canonical handle declaration rejected")
	}
	for _, value := range []string{"", "Uppercase", "contains space"} {
		if err := ValidateHandleDeclaration(value); err == nil {
			t.Fatal("noncanonical handle declaration accepted")
		}
	}
	maximum := provider.DefaultLimits().MaxIdentifierBytes
	if err := ValidateHandleDeclaration(strings.Repeat("h", maximum)); err != nil {
		t.Fatal("exact maximum-length handle declaration rejected")
	}
	if err := ValidateHandleDeclaration(strings.Repeat("h", maximum+1)); err == nil {
		t.Fatal("one-over maximum handle declaration accepted")
	}
}
