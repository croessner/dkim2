//nolint:goconst // Independent object-class tests intentionally repeat exact engine vocabulary.
package containerownership

import (
	"encoding/json"
	"testing"
)

// TestValidateInspectAcceptsOnlyExactRunOwnedObjects freezes cleanup authority.
func TestValidateInspectAcceptsOnlyExactRunOwnedObjects(t *testing.T) {
	for _, kind := range []string{"container", "image", "volume"} {
		content, err := marshalFixture(kind, "object-identity", "run-identity")
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateInspect(kind, "object-identity", "run-identity", content); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInspect(kind, "foreign-identity", "run-identity", content); err == nil {
			t.Fatalf("%s identity collision was accepted", kind)
		}
		if err := ValidateInspect(kind, "object-identity", "foreign-run", content); err == nil {
			t.Fatalf("%s ownership loss was accepted", kind)
		}
	}
}

// TestValidateSourceImageRequiresExactConfigAndUniqueTag freezes offline image cleanup.
func TestValidateSourceImageRequiresExactConfigAndUniqueTag(t *testing.T) {
	content, err := json.Marshal([]engineObject{{
		ID:       "sha256:config",
		RepoTags: []string{"dkim2-runtime:local"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceImage("sha256:config", "dkim2-runtime:local", content); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceImage("sha256:foreign", "dkim2-runtime:local", content); err == nil {
		t.Fatal("foreign config was accepted")
	}
	if err := ValidateSourceImage("sha256:config", "foreign:local", content); err == nil {
		t.Fatal("foreign tag was accepted")
	}
}

// TestValidateInspectRejectsPartialAndDuplicateDocuments freezes partial-create cleanup.
func TestValidateInspectRejectsPartialAndDuplicateDocuments(t *testing.T) {
	partial := []byte(`[{"Id":"object-identity","Config":{"Labels":{"com.croessner.dkim2.project":"runtime-test"}}}]`)
	if err := ValidateInspect("container", "object-identity", "run-identity", partial); err == nil {
		t.Fatal("partial labels were accepted")
	}
	duplicate := []byte(`[{"Id":"object-identity","Id":"foreign","Config":{"Labels":{"com.croessner.dkim2.runtime-run":"run-identity","com.croessner.dkim2.project":"runtime-test"}}}]`)
	if err := ValidateInspect("image", "object-identity", "run-identity", duplicate); err == nil {
		t.Fatal("duplicate identity was accepted")
	}
}
