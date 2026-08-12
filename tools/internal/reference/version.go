//nolint:goconst // Exact module paths and environment values stay explicit in release policy.
package reference

import (
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/interop"
	"github.com/croessner/dkim2/tools/internal/strictjson"
	"golang.org/x/mod/modfile"
)

const (
	releasePlanSchemaName = "dkim2.release-plan.v1"
	releasePlanPath       = "testdata/reference/release-plan.json"
	releasePlanSchemaPath = "testdata/reference/schemas/release-plan.schema.json"
	candidateVersion      = "v0.1.0-rc.1"
	candidateBaseRevision = "8716654e2a8cbee4c2f2ebc8a1960335eb27e417"
	maxReleasePlanBytes   = int64(1 << 20)
)

var plannedCandidateTags = []string{
	"cmd/dkim2-milter/v0.1.0-rc.1",
	"cmd/dkim2-exim/v0.1.0-rc.1",
	"cmd/dkim2ctl/v0.1.0-rc.1",
	"cmd/dkim2d/v0.1.0-rc.1",
	"lib/v0.1.0-rc.1",
	"v0.1.0-rc.1",
}

// RCVersion is one canonical release-candidate semantic version.
type RCVersion struct {
	Major     uint64
	Minor     uint64
	Patch     uint64
	Candidate uint64
}

// ReleasePlan freezes intended versions, tags, modules, and authority.
type ReleasePlan struct {
	Schema         string            `json:"schema"`
	ProductVersion string            `json:"product_version"`
	OpenAPIVersion string            `json:"openapi_version"`
	WireVersion    string            `json:"wire_version"`
	PlannedTags    []string          `json:"planned_tags"`
	Modules        []ReleaseModule   `json:"modules"`
	Publication    PublicationPlan   `json:"publication"`
	Capabilities   ReleaseCapability `json:"capabilities"`
}

// ReleaseModule binds one nested module to its exact future tag.
type ReleaseModule struct {
	Path      string `json:"path"`
	Directory string `json:"directory"`
	Tag       string `json:"tag"`
}

// PublicationPlan explicitly removes all publication authority from preparation.
type PublicationPlan struct {
	RealTagsCreated       bool     `json:"real_tags_created"`
	StableWorkflowAllowed bool     `json:"stable_workflow_allowed"`
	Aliases               []string `json:"aliases"`
	CredentialsAllowed    bool     `json:"credentials_allowed"`
}

// ReleaseCapability preserves closed candidate capability-status values.
type ReleaseCapability struct {
	Exim             string `json:"exim"`
	LDAPSQLMigration string `json:"ldap_sql_migration"`
}

// ParseRCVersion accepts only canonical vMAJOR.MINOR.PATCH-rc.NUMBER values.
func ParseRCVersion(value string) (RCVersion, error) {
	if len(value) < len("v0.0.0-rc.0") || len(value) > 48 ||
		!strings.HasPrefix(value, "v") || strings.Count(value, "-rc.") != 1 {
		return RCVersion{}, errors.New("version_syntax")
	}
	stable, candidateText, found := strings.Cut(value[1:], "-rc.")
	if !found || strings.Contains(candidateText, ".") {
		return RCVersion{}, errors.New("version_syntax")
	}
	fields := strings.Split(stable, ".")
	if len(fields) != 3 {
		return RCVersion{}, errors.New("version_syntax")
	}
	values := make([]uint64, 0, 4)
	for _, field := range append(fields, candidateText) {
		if !canonicalDecimal(field) {
			return RCVersion{}, errors.New("version_syntax")
		}
		number, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return RCVersion{}, errors.New("version_range")
		}
		values = append(values, number)
	}
	return RCVersion{
		Major: values[0], Minor: values[1], Patch: values[2], Candidate: values[3],
	}, nil
}

// LoadReleasePlan strictly decodes one bounded durable release plan.
func LoadReleasePlan(content []byte) (ReleasePlan, error) {
	if len(content) == 0 || int64(len(content)) > maxReleasePlanBytes {
		return ReleasePlan{}, errors.New("release_plan_size")
	}
	var plan ReleasePlan
	if err := strictjson.Decode(content, &plan, 16, 4096); err != nil {
		return ReleasePlan{}, errors.New("release_plan_json")
	}
	if plan.Schema != releasePlanSchemaName {
		return ReleasePlan{}, errors.New("release_plan_identity")
	}
	return plan, nil
}

// CheckReleasePlan proves the exact version, module, and no-publication contract.
func CheckReleasePlan(root string) error {
	content, err := artifactpath.ReadFile(root, releasePlanPath, maxReleasePlanBytes)
	if err != nil {
		return errors.New("release_plan_read")
	}
	plan, err := LoadReleasePlan(content)
	if err != nil {
		return err
	}
	if err := conformance.ValidateRepositoryJSONSchema(
		root, releasePlanSchemaPath, releasePlanPath, maxReleasePlanBytes,
	); err != nil {
		return errors.New("release_plan_schema")
	}
	if _, err := ParseRCVersion(plan.ProductVersion); err != nil ||
		plan.ProductVersion != candidateVersion ||
		plan.OpenAPIVersion != strings.TrimPrefix(candidateVersion, "v") ||
		plan.WireVersion != "v1" ||
		!slices.Equal(plan.PlannedTags, plannedCandidateTags) ||
		plan.Publication.RealTagsCreated || plan.Publication.StableWorkflowAllowed ||
		plan.Publication.CredentialsAllowed || len(plan.Publication.Aliases) != 0 ||
		plan.Capabilities.Exim != "qualified_linux" ||
		plan.Capabilities.LDAPSQLMigration != "implemented" {
		return errors.New("release_plan_contract")
	}
	if err := checkModulePlans(root, plan.Modules); err != nil {
		return err
	}
	if err := checkVersionSeparation(root); err != nil {
		return err
	}
	return checkCandidateTagsAbsent(root)
}

// ReleasePlanDigest returns the validated plan identity.
func ReleasePlanDigest(root string) (string, error) {
	if err := CheckReleasePlan(root); err != nil {
		return "", err
	}
	content, err := artifactpath.ReadFile(root, releasePlanPath, maxReleasePlanBytes)
	if err != nil {
		return "", errors.New("release_plan_read")
	}
	return interop.SHA256(content), nil
}

// canonicalDecimal accepts a bounded decimal without noncanonical leading zeros.
func canonicalDecimal(value string) bool {
	if value == "" || len(value) > 10 || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// checkModulePlans validates exact module tags, requirements, and replacements.
func checkModulePlans(root string, modules []ReleaseModule) error {
	expected := []ReleaseModule{
		{Path: "github.com/croessner/dkim2", Directory: "lib", Tag: "lib/" + candidateVersion},
		{Path: "github.com/croessner/dkim2/cmd/dkim2-milter", Directory: "cmd/dkim2-milter", Tag: "cmd/dkim2-milter/" + candidateVersion},
		{Path: "github.com/croessner/dkim2/cmd/dkim2-exim", Directory: "cmd/dkim2-exim", Tag: "cmd/dkim2-exim/" + candidateVersion},
		{Path: "github.com/croessner/dkim2/cmd/dkim2ctl", Directory: "cmd/dkim2ctl", Tag: "cmd/dkim2ctl/" + candidateVersion},
		{Path: "github.com/croessner/dkim2/cmd/dkim2d", Directory: "cmd/dkim2d", Tag: "cmd/dkim2d/" + candidateVersion},
	}
	if !slices.Equal(modules, expected) {
		return errors.New("release_plan_modules")
	}
	for _, modulePlan := range modules {
		content, err := artifactpath.ReadFile(
			root, filepath.ToSlash(filepath.Join(modulePlan.Directory, "go.mod")), 1<<20,
		)
		if err != nil {
			return errors.New("release_module_read")
		}
		moduleFile, err := modfile.Parse("go.mod", content, nil)
		if err != nil || moduleFile.Module == nil || moduleFile.Module.Mod.Path != modulePlan.Path ||
			len(moduleFile.Replace) != 0 {
			return errors.New("release_module_contract")
		}
		if modulePlan.Directory == "cmd/dkim2d" &&
			!requiresExact(moduleFile, "github.com/croessner/dkim2", candidateVersion) {
			return errors.New("release_module_requirement")
		}
	}
	toolsContent, err := artifactpath.ReadFile(root, "tools/go.mod", 1<<20)
	if err != nil {
		return errors.New("release_module_read")
	}
	toolsFile, err := modfile.Parse("go.mod", toolsContent, nil)
	if err != nil || !requiresExact(toolsFile, "github.com/croessner/dkim2", candidateVersion) ||
		len(toolsFile.Replace) != 0 {
		return errors.New("release_module_requirement")
	}
	work, err := artifactpath.ReadFile(root, "go.work", 1<<20)
	if err != nil || strings.Contains(string(work), "replace ") ||
		strings.Contains(string(work), "v0.0.0") {
		return errors.New("release_workspace_bootstrap")
	}
	return nil
}

// requiresExact reports whether one module requirement has the exact version.
func requiresExact(file *modfile.File, path, version string) bool {
	for _, requirement := range file.Require {
		if requirement.Mod.Path == path {
			return requirement.Mod.Version == version
		}
	}
	return false
}

// checkVersionSeparation proves product RC metadata cannot enter stable publication.
func checkVersionSeparation(root string) error {
	openapi, err := artifactpath.ReadFile(root, "docs/specs/openapi/dkim2d.yaml", 4<<20)
	if err != nil || !strings.Contains(string(openapi), "version: 0.1.0-rc.1") ||
		!strings.Contains(string(openapi), "api_version:") ||
		!strings.Contains(string(openapi), "- v1") {
		return errors.New("release_openapi_version")
	}
	workflow, err := artifactpath.ReadFile(root, ".github/workflows/release.yml", 1<<20)
	if err != nil || !strings.Contains(
		string(workflow), "github.event.release.prerelease == false",
	) || !strings.Contains(string(workflow), "git cat-file -t") ||
		!strings.Contains(string(workflow), "git rev-parse \"$RELEASE_TAG^{commit}\"") ||
		strings.Contains(string(workflow), "github.ref_protected") ||
		strings.Contains(string(workflow), "latest") {
		return errors.New("release_stable_workflow")
	}
	return nil
}

// checkCandidateTagsAbsent proves preparation did not create any planned Git tag.
func checkCandidateTagsAbsent(root string) error {
	arguments := append([]string{"-C", root, "tag", "--list"}, plannedCandidateTags...)
	command := exec.Command("git", arguments...)
	command.Env = []string{
		"HOME=" + filepath.Join(root, ".artifacts", "reference", "git-home"),
		"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin",
	}
	output, err := command.Output()
	if err != nil || len(output) != 0 {
		return errors.New("release_real_tag")
	}
	return nil
}
