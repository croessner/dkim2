//nolint:goconst // Hostile report fixtures intentionally repeat exact field names.
package reference

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/interop"
)

// TestLoadCandidateReportRejectsDuplicateAndIncompleteInput proves strict decoding.
func TestLoadCandidateReportRejectsDuplicateAndIncompleteInput(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`{"schema":"dkim2.reference-candidate-report.v1"}`),
		[]byte(`{"schema":"dkim2.reference-candidate-report.v1","schema":"duplicate"}`),
		[]byte(`[]`),
	} {
		if _, err := LoadCandidateReport(content); err == nil {
			t.Fatal("hostile candidate report was accepted")
		}
	}
}

// TestCandidateReportRenderingIsDeterministicAndContentFree proves stable output.
func TestCandidateReportRenderingIsDeterministicAndContentFree(t *testing.T) {
	report := CandidateReport{
		ProductVersion:          candidateVersion,
		BaseRevision:            "3803d52c5279f65f5e659fefe996548adfe6d41d",
		CandidateSnapshotSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExternalAvailability:    "eligible_not_runnable", ExternalCases: 6,
		ModuleProxySHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ModuleCount:       42, Overall: "pass",
		Criteria: []CandidateCriterion{{ID: "modules", State: "pass"}},
	}
	first := renderCandidateReport(report)
	second := renderCandidateReport(report)
	if !bytes.Equal(first, second) || bytes.Contains(first, []byte("private")) ||
		bytes.Contains(first, []byte("recipient")) {
		t.Fatal("human report was nondeterministic or admitted protected content")
	}
}

// TestValidateEvidenceProjectionRejectsStaleAndFailedEvidence proves candidate binding.
func TestValidateEvidenceProjectionRejectsStaleAndFailedEvidence(t *testing.T) {
	revision := "3803d52c5279f65f5e659fefe996548adfe6d41d"
	candidate := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	valid := map[string]any{
		"base_revision": revision, "candidate_snapshot_sha256": candidate, "overall": "pass",
	}
	if err := validateEvidenceProjection(valid, revision, candidate); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []map[string]any{
		{"base_revision": "stale"},
		{"base_revision": json.Number("1")},
		{"candidate_snapshot_sha256": "stale"},
		{"candidate_snapshot_sha256": true},
		{"overall": "fail"},
		{"overall": nil},
		{"state": "fail"},
	} {
		if err := validateEvidenceProjection(hostile, revision, candidate); err == nil {
			t.Fatal("stale or failed evidence was accepted")
		}
	}
	if err := validateRequiredEvidenceProjection(map[string]any{
		"schema": "dkim2.security-report.v1",
	}); err == nil {
		t.Fatal("schema-only evidence was accepted as candidate-bound PASS")
	}
}

// TestEvidenceSchemaCannotLaunderHostileMarkers freezes the closed evidence classes.
func TestEvidenceSchemaCannotLaunderHostileMarkers(t *testing.T) {
	value := map[string]any{"schema": "marker-private-key"}
	path := ".artifacts/security/report.json"
	if got := evidenceSchema(value); got == reportEvidenceSchemas[path] {
		t.Fatal("hostile schema marker entered a closed report class")
	}
	if len(reportEvidenceSchemas) != len(reportEvidencePaths) {
		t.Fatal("evidence schema inventory is not closed over every report path")
	}
}

// TestDatasourceIntegrationEvidenceSchemaTracksV2Producer reproduces the
// collector rejection caused by the stale v1 schema declaration.
func TestDatasourceIntegrationEvidenceSchemaTracksV2Producer(t *testing.T) {
	const path = ".artifacts/datasource-integration/report.json"
	if reportEvidenceSchemas[path] != "dkim2.datasource-integration-report.v2" {
		t.Fatal("datasource integration v2 producer is rejected by the collector")
	}
}

// TestDatasourceIntegrationReportV2AcceptsOnlyTheClosedCrossProduct freezes
// producer, semantic collector, and JSON Schema agreement.
func TestDatasourceIntegrationReportV2AcceptsOnlyTheClosedCrossProduct(t *testing.T) {
	revision := strings.Repeat("a", 40)
	candidate := strings.Repeat("b", 64)
	valid := validDatasourceIntegrationReportFixture(revision, candidate)
	content, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDatasourceIntegrationReport(
		repositoryRoot(t), content, revision, candidate,
	); err != nil {
		t.Fatal("closed datasource integration v2 report was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*datasourceIntegrationReport)
	}{
		{"v1", func(report *datasourceIntegrationReport) { report.Schema = "dkim2.datasource-integration-report.v1" }},
		{"wrong base", func(report *datasourceIntegrationReport) { report.BaseRevision = strings.Repeat("c", 40) }},
		{"wrong candidate", func(report *datasourceIntegrationReport) { report.CandidateSnapshotSHA256 = strings.Repeat("d", 64) }},
		{"wrong runs", func(report *datasourceIntegrationReport) { report.RuntimeQualificationRuns = 3 }},
		{"missing check", func(report *datasourceIntegrationReport) { report.Checks = report.Checks[:len(report.Checks)-1] }},
		{"duplicate check", func(report *datasourceIntegrationReport) { report.Checks[len(report.Checks)-1] = report.Checks[0] }},
		{"unknown check", func(report *datasourceIntegrationReport) { report.Checks[len(report.Checks)-1] = "unknown" }},
		{"missing result", func(report *datasourceIntegrationReport) { report.Results = report.Results[:len(report.Results)-1] }},
		{"duplicate result", func(report *datasourceIntegrationReport) { report.Results[len(report.Results)-1] = report.Results[0] }},
		{"wrong backend image", func(report *datasourceIntegrationReport) {
			for index := range report.Results {
				if report.Results[index].Backend == "ldap" {
					report.Results[index].Image = datasourceMySQLImage
					return
				}
			}
		}},
		{"failed result", func(report *datasourceIntegrationReport) { report.Results[0].Result = "fail" }},
		{"failed overall", func(report *datasourceIntegrationReport) { report.Overall = "fail" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hostile := validDatasourceIntegrationReportFixture(revision, candidate)
			test.mutate(&hostile)
			encoded, encodeErr := json.Marshal(hostile)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if validateDatasourceIntegrationReport(
				repositoryRoot(t), encoded, revision, candidate,
			) == nil {
				t.Fatal("hostile datasource integration report was accepted")
			}
		})
	}

	var extra map[string]any
	if err := json.Unmarshal(content, &extra); err != nil {
		t.Fatal(err)
	}
	extra["unexpected"] = true
	encoded, err := json.Marshal(extra)
	if err != nil {
		t.Fatal(err)
	}
	if validateDatasourceIntegrationReport(
		repositoryRoot(t), encoded, revision, candidate,
	) == nil {
		t.Fatal("extra datasource integration field was accepted")
	}
}

// validDatasourceIntegrationReportFixture builds one exact v2 semantic corpus.
func validDatasourceIntegrationReportFixture(
	revision string,
	candidate string,
) datasourceIntegrationReport {
	checks := make([]string, 0, len(datasourceIntegrationChecks))
	for check := range datasourceIntegrationChecks {
		checks = append(checks, check)
	}
	results := make([]datasourceIntegrationResult, 0, datasourceIntegrationResultCount)
	for backend, image := range datasourceIntegrationImages {
		for _, check := range datasourceIntegrationResultChecks {
			results = append(results, datasourceIntegrationResult{
				Image: image, Backend: backend, Check: check, Result: "pass",
			})
		}
	}
	return datasourceIntegrationReport{
		Schema: datasourceIntegrationReportSchema, BaseRevision: revision,
		CandidateSnapshotSHA256: candidate,
		LDAPImage:               datasourceLDAPImage, PostgreSQLImage: datasourcePostgreSQLImage,
		MySQLImage: datasourceMySQLImage, MariaDBImage: datasourceMariaDBImage,
		RuntimeQualificationRuns: datasourceIntegrationQualificationRuns,
		Checks:                   checks, Results: results, Overall: "pass",
	}
}

// TestDatasourceRunnerInvalidatesStalePassBeforeNonSuccessExit proves
// preflight, injected failure, and atomic-install failure cannot retain PASS.
func TestDatasourceRunnerInvalidatesStalePassBeforeNonSuccessExit(t *testing.T) {
	root := repositoryRoot(t)
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(validDatasourceIntegrationReportFixture(
		revision, snapshot.SHA256,
	))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "test-datasource-services.sh")
	for _, test := range []struct {
		mode        string
		wantSuccess bool
	}{
		{mode: "preflight", wantSuccess: true},
		{mode: "failure", wantSuccess: false},
		{mode: "atomic_failure", wantSuccess: false},
	} {
		t.Run(test.mode, func(t *testing.T) {
			work := t.TempDir()
			final := filepath.Join(
				work, ".artifacts", "datasource-integration", "report.json",
			)
			if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(final, content, 0o600); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(work, "candidate.json")
			if err := os.WriteFile(source, content, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("sh", script)
			command.Dir = work
			command.Env = append(
				os.Environ(),
				"DKIM2_REPORT_LIFECYCLE_TEST="+test.mode,
				"DKIM2_REPORT_LIFECYCLE_SOURCE="+source,
				"GOCACHE=/tmp/dkim2-go-build-cache",
			)
			runErr := command.Run()
			if (runErr == nil) != test.wantSuccess {
				t.Fatal("report lifecycle mode returned the wrong bounded status")
			}
			if _, err := os.Lstat(final); !os.IsNotExist(err) {
				t.Fatal("non-success lifecycle retained final PASS evidence")
			}
			partials, err := filepath.Glob(filepath.Join(filepath.Dir(final), ".report.*"))
			if err != nil || len(partials) != 0 {
				t.Fatal("non-success lifecycle retained a partial report")
			}
		})
	}
}

// TestCollectOpenAPIIdentitiesBindsClosedGeneratedInventory freezes every release boundary.
func TestCollectOpenAPIIdentitiesBindsClosedGeneratedInventory(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		"docs/specs/openapi/dkim2d.yaml",
		"cmd/dkim2-dsn-propagator/internal/daemon/generated/client.gen.go",
		"cmd/dkim2-dsn-propagator/internal/integration/generated/server.gen.go",
		"cmd/dkim2-exim/internal/daemon/generated/client.gen.go",
		"cmd/dkim2-exim/internal/integration/generated/server.gen.go",
		"cmd/dkim2-milter/internal/daemon/generated/client.gen.go",
		"cmd/dkim2-milter/internal/integration/generated/server.gen.go",
		"cmd/dkim2ctl/internal/testclient/generated/client.gen.go",
		"cmd/dkim2d/internal/httpjson/generated/server.gen.go",
	}
	for _, path := range paths {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	identities, err := collectOpenAPIIdentities(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != len(paths) || len(generatedOpenAPIPaths) != len(paths)-1 {
		t.Fatalf("OpenAPI identity inventory is not closed over nine artifacts: got %d", len(identities))
	}
	for index, path := range paths {
		identity := identities[index]
		if identity.Path != path || identity.Schema != "openapi_source_or_generated" ||
			identity.SHA256 != interop.SHA256([]byte(path)) {
			t.Fatalf("unexpected OpenAPI identity at %d: %+v", index, identity)
		}
	}
}

// TestValidateImageReleaseReportRejectsMissingOrChangedChildren prevents stale image evidence laundering.
func TestValidateImageReleaseReportRejectsMissingOrChangedChildren(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, ".artifacts", "image-evidence")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	product := "dkim2d"
	paths := []string{
		".artifacts/image-evidence/dkim2d.oci.json",
		".artifacts/image-evidence/dkim2d.provenance.json",
		".artifacts/image-evidence/runtime-policy.json",
		".artifacts/image-evidence/trivy-database.json",
		".artifacts/image-evidence/dkim2d.amd64.sbom-binding.json",
		".artifacts/image-evidence/dkim2d.amd64.trivy-binding.json",
		".artifacts/image-evidence/dkim2d.arm64.sbom-binding.json",
		".artifacts/image-evidence/dkim2d.arm64.trivy-binding.json",
	}
	artifacts := make([]imageReleaseArtifact, 0, len(paths))
	for _, path := range paths {
		content := []byte(path)
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, imageReleaseArtifact{
			Path: path, SHA256: interop.SHA256(content),
		})
	}
	report := imageReleaseReport{
		Schema:                  "dkim2-image-release-report-v1",
		BaseRevision:            "3803d52c5279f65f5e659fefe996548adfe6d41d",
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		Product:                 product,
		OCI:                     artifacts[0],
		Provenance:              artifacts[1],
		RuntimePolicy:           artifacts[2],
		VulnerabilityDatabase:   artifacts[3],
		SBOMBindings:            []imageReleaseArtifact{artifacts[4], artifacts[6]},
		VulnerabilityBindings:   []imageReleaseArtifact{artifacts[5], artifacts[7]},
		State:                   "pass",
	}
	content, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := ".artifacts/image-evidence/dkim2d.release.json"
	if err := validateImageReleaseReport(
		root,
		reportPath,
		content,
		report.BaseRevision,
		report.CandidateSnapshotSHA256,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, filepath.FromSlash(paths[4])),
		[]byte("changed"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateImageReleaseReport(
		root,
		reportPath,
		content,
		report.BaseRevision,
		report.CandidateSnapshotSHA256,
	); err == nil {
		t.Fatal("changed SBOM binding remained accepted")
	}
}

// FuzzLoadCandidateReport proves arbitrary bounded report bytes remain panic-free.
func FuzzLoadCandidateReport(f *testing.F) {
	f.Add([]byte(`{"schema":"dkim2.reference-candidate-report.v1"}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if int64(len(input)) > maxCandidateReportBytes+1 {
			input = input[:maxCandidateReportBytes+1]
		}
		_, _ = LoadCandidateReport(input)
	})
}
