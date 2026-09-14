package reference

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionSeparationRejectsPublicationBypasses exercises the current tag-push workflow boundary.
func TestVersionSeparationRejectsPublicationBypasses(t *testing.T) {
	root := repositoryRoot(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	openapi, err := os.ReadFile(filepath.Join(root, "docs/specs/openapi/dkim2d.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"valid_workflow", "", ""},
		{"trigger", `tags: ["v*"]`, `branches: ["main"]`},
		{"version", `\.(0|[1-9][0-9]*)$`, `\.(0|[1-9][0-9]*)(-rc.1)?$`},
		{"annotation", `git cat-file -t`, `git cat-file -s`},
		{"commit", `test "$revision" = "$(git rev-parse HEAD)"`, `true`},
		{"image_alias", `tags: ${{ steps.image.outputs.repository }}:${{ needs.quality.outputs.version }}`, `tags: example.invalid/image:latest`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, path := range []string{".github/workflows", "docs/specs/openapi"} {
				if err := os.MkdirAll(filepath.Join(dir, path), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			content := string(workflow)
			if tc.old != "" {
				if !strings.Contains(content, tc.old) {
					t.Fatal("mutation missing")
				}
				content = strings.Replace(content, tc.old, tc.replacement, 1)
			}
			if err := os.WriteFile(filepath.Join(dir, ".github/workflows/release.yml"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "docs/specs/openapi/dkim2d.yaml"), openapi, 0o600); err != nil {
				t.Fatal(err)
			}
			err := checkVersionSeparation(dir)
			if (err == nil) != (tc.name == "valid_workflow") {
				t.Fatalf("unexpected workflow admission: %v", err)
			}
		})
	}
}

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
