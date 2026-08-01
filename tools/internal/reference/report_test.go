//nolint:goconst // Hostile report fixtures intentionally repeat exact field names.
package reference

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// TestCollectOpenAPIIdentitiesBindsClosedGeneratedInventory freezes every release boundary.
func TestCollectOpenAPIIdentitiesBindsClosedGeneratedInventory(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		"docs/specs/openapi/dkim2d.yaml",
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
		t.Fatalf("OpenAPI identity inventory is not closed over seven artifacts: got %d", len(identities))
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
