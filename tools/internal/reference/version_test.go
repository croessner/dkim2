package reference

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseRCVersionAcceptsCanonicalValues proves all numeric fields are bounded.
func TestParseRCVersionAcceptsCanonicalValues(t *testing.T) {
	for _, value := range []string{"v0.1.0-rc.1", "v1.2.3-rc.0", "v9999999999.0.7-rc.42"} {
		if _, err := ParseRCVersion(value); err != nil {
			t.Fatalf("ParseRCVersion(%q) error = %v", value, err)
		}
	}
}

// TestParseRCVersionRejectsAliasesAndNoncanonicalForms protects publication separation.
func TestParseRCVersionRejectsAliasesAndNoncanonicalForms(t *testing.T) {
	values := []string{
		"", "0.1.0-rc.1", "v0.1.0", "v0.1-rc.1", "v0.1.0-RC.1",
		"v0.1.0-rc", "v0.1.0-rc.01", "v00.1.0-rc.1",
		"v0.1.0-rc.1+build", "v0.1.0-rc.1.2", "v0.1.0-beta.1",
		"latest", "v0", "v0.1", "v0.1.0-rc.-1",
	}
	for _, value := range values {
		if _, err := ParseRCVersion(value); err == nil {
			t.Fatalf("ParseRCVersion(%q) accepted hostile value", value)
		}
	}
}

// TestCheckReleasePlanAcceptsRepositoryPlan validates exact module and publication state.
func TestCheckReleasePlanAcceptsRepositoryPlan(t *testing.T) {
	if err := CheckReleasePlan(repositoryRoot(t)); err != nil {
		t.Fatalf("CheckReleasePlan() error = %v", err)
	}
}

// FuzzLoadReleasePlan proves hostile plan bytes remain bounded and panic-free.
func FuzzLoadReleasePlan(f *testing.F) {
	content, err := os.ReadFile(filepath.Join(repositoryRootForFuzz(), releasePlanPath))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(content)
	f.Add([]byte(`{"schema":"dkim2.release-plan.v1"}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if int64(len(input)) > maxReleasePlanBytes+1 {
			input = input[:maxReleasePlanBytes+1]
		}
		_, _ = LoadReleasePlan(input)
	})
}
