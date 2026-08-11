//nolint:goconst // Evidence paths and schema classes remain explicit in the closed merge.
package reference

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/interop"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	candidateReportSchema     = "dkim2.reference-candidate-report.v1"
	candidateReportJSONPath   = ".artifacts/reference/candidate-report.json"
	candidateReportMarkdown   = ".artifacts/reference/candidate-report.md"
	candidateReportSchemaPath = "testdata/reference/schemas/candidate-report.schema.json"
	maxCandidateReportBytes   = int64(4 << 20)
)

var reportEvidencePaths = []string{
	".artifacts/conformance-full/report.json",
	".artifacts/conformance-portable/report.json",
	".artifacts/security/fuzz.json",
	".artifacts/security/race.json",
	".artifacts/security/report.json",
	".artifacts/security/vulnerability.json",
	".artifacts/privacy-evidence/report.json",
	".artifacts/image-evidence/dkim2-milter.release.json",
	".artifacts/image-evidence/dkim2ctl.release.json",
	".artifacts/image-evidence/dkim2d.release.json",
	".artifacts/image-evidence/dkim2-milter.oci.json",
	".artifacts/image-evidence/dkim2-milter.provenance.json",
	".artifacts/image-evidence/dkim2ctl.oci.json",
	".artifacts/image-evidence/dkim2ctl.provenance.json",
	".artifacts/image-evidence/dkim2d.oci.json",
	".artifacts/image-evidence/dkim2d.provenance.json",
	".artifacts/postfix-deployment/run-1/report.json",
	".artifacts/postfix-deployment/run-2/report.json",
	".artifacts/datasource-integration/report.json",
}

var reportEvidenceSchemas = map[string]string{
	".artifacts/conformance-full/report.json":                "dkim2.conformance-report.v1",
	".artifacts/conformance-portable/report.json":            "dkim2.conformance-report.v1",
	".artifacts/security/fuzz.json":                          "dkim2.security-fuzz-report.v1",
	".artifacts/security/race.json":                          "dkim2.security-race-report.v1",
	".artifacts/security/report.json":                        "dkim2.security-report.v1",
	".artifacts/security/vulnerability.json":                 "dkim2.security-vulnerability-report.v1",
	".artifacts/privacy-evidence/report.json":                "dkim2-deployment-privacy-evidence-v1",
	".artifacts/image-evidence/dkim2-milter.release.json":    "dkim2-image-release-report-v1",
	".artifacts/image-evidence/dkim2ctl.release.json":        "dkim2-image-release-report-v1",
	".artifacts/image-evidence/dkim2d.release.json":          "dkim2-image-release-report-v1",
	".artifacts/image-evidence/dkim2-milter.oci.json":        "dkim2-oci-policy-v1",
	".artifacts/image-evidence/dkim2-milter.provenance.json": "https://in-toto.io/Statement/v1",
	".artifacts/image-evidence/dkim2ctl.oci.json":            "dkim2-oci-policy-v1",
	".artifacts/image-evidence/dkim2ctl.provenance.json":     "https://in-toto.io/Statement/v1",
	".artifacts/image-evidence/dkim2d.oci.json":              "dkim2-oci-policy-v1",
	".artifacts/image-evidence/dkim2d.provenance.json":       "https://in-toto.io/Statement/v1",
	".artifacts/postfix-deployment/run-1/report.json":        "dkim2.postfix-deployment-report.v1",
	".artifacts/postfix-deployment/run-2/report.json":        "dkim2.postfix-deployment-report.v1",
	".artifacts/datasource-integration/report.json":          datasourceIntegrationReportSchema,
}

var generatedOpenAPIPaths = []string{
	"cmd/dkim2-exim/internal/daemon/generated/client.gen.go",
	"cmd/dkim2-exim/internal/integration/generated/server.gen.go",
	"cmd/dkim2-milter/internal/daemon/generated/client.gen.go",
	"cmd/dkim2-milter/internal/integration/generated/server.gen.go",
	"cmd/dkim2ctl/internal/testclient/generated/client.gen.go",
	"cmd/dkim2d/internal/httpjson/generated/server.gen.go",
}

// CandidateReport is the content-free merge of exact candidate evidence.
type CandidateReport struct {
	Schema                   string               `json:"schema"`
	BaseRevision             string               `json:"base_revision"`
	CandidateSnapshotSHA256  string               `json:"candidate_snapshot_sha256"`
	ProductVersion           string               `json:"product_version"`
	MessageDraft             string               `json:"message_draft"`
	DNSDraft                 string               `json:"dns_draft"`
	ReleasePlanSHA256        string               `json:"release_plan_sha256"`
	APISHA256                string               `json:"api_sha256"`
	APIDeclarations          int                  `json:"api_declarations"`
	OpenAPI                  []ArtifactIdentity   `json:"openapi"`
	IssueLogSHA256           string               `json:"issue_log_sha256"`
	IssueCount               int                  `json:"issue_count"`
	ExternalEvidenceSHA256   string               `json:"external_evidence_sha256"`
	ExternalComparisonSHA256 string               `json:"external_comparison_sha256"`
	ExternalAvailability     string               `json:"external_availability"`
	ExternalCases            int                  `json:"external_cases"`
	ModuleProofSHA256        string               `json:"module_proof_sha256"`
	ModuleProxySHA256        string               `json:"module_proxy_sha256"`
	ModuleCount              int                  `json:"module_count"`
	Evidence                 []ArtifactIdentity   `json:"evidence"`
	Capabilities             ReleaseCapability    `json:"capabilities"`
	Criteria                 []CandidateCriterion `json:"criteria"`
	Overall                  string               `json:"overall"`
}

// ArtifactIdentity records only a path, schema class, and byte identity.
type ArtifactIdentity struct {
	Path   string `json:"path"`
	Schema string `json:"schema"`
	SHA256 string `json:"sha256"`
}

// CandidateCriterion records one closed release-candidate acceptance decision.
type CandidateCriterion struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type imageReleaseArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type imageReleaseReport struct {
	Schema                  string                 `json:"schema"`
	BaseRevision            string                 `json:"base_revision"`
	CandidateSnapshotSHA256 string                 `json:"candidate_snapshot_sha256"`
	Product                 string                 `json:"product"`
	OCI                     imageReleaseArtifact   `json:"oci"`
	Provenance              imageReleaseArtifact   `json:"provenance"`
	RuntimePolicy           imageReleaseArtifact   `json:"runtime_policy"`
	VulnerabilityDatabase   imageReleaseArtifact   `json:"vulnerability_database"`
	SBOMBindings            []imageReleaseArtifact `json:"sbom_bindings"`
	VulnerabilityBindings   []imageReleaseArtifact `json:"vulnerability_bindings"`
	State                   string                 `json:"state"`
}

// GenerateCandidateReport validates and merges the current ignored evidence.
func GenerateCandidateReport(root string, now time.Time) (CandidateReport, []byte, []byte, error) {
	if err := CheckReleasePlan(root); err != nil {
		return CandidateReport{}, nil, nil, err
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil ||
		conformance.IsRevisionAncestor(root, candidateBaseRevision, revision) != nil {
		return CandidateReport{}, nil, nil, errors.New("report_base")
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_candidate")
	}
	planDigest, err := ReleasePlanDigest(root)
	if err != nil {
		return CandidateReport{}, nil, nil, err
	}
	apiContent, apiDeclarations, err := GenerateAPIManifest(root)
	if err != nil || CheckAPI(root) != nil {
		return CandidateReport{}, nil, nil, errors.New("report_api")
	}
	issueContent, err := artifactpath.ReadFile(root, issuePath, maxIssueBytes)
	if err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_issues")
	}
	issues, err := checkIssueContent(root, issueContent)
	if err != nil {
		return CandidateReport{}, nil, nil, err
	}
	issueDigest := interop.SHA256(issueContent)
	currentExternal, err := interop.LoadCurrentEvidenceSet(root, now)
	if err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_external")
	}
	external := currentExternal.Discovery
	comparison := currentExternal.Comparison
	if err := checkExternalIssueClosure(issues, comparison); err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_issues")
	}
	moduleBytes, err := artifactpath.ReadFile(root, moduleProofPath, maxCandidateReportBytes)
	if err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_module")
	}
	moduleProof, err := loadCurrentModuleProof(root, moduleBytes)
	if err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_module")
	}
	openAPI, err := collectOpenAPIIdentities(root)
	if err != nil {
		return CandidateReport{}, nil, nil, err
	}
	evidence, err := collectReportEvidence(root, revision, snapshot.SHA256)
	if err != nil {
		return CandidateReport{}, nil, nil, err
	}
	report := CandidateReport{
		Schema: candidateReportSchema, BaseRevision: revision,
		CandidateSnapshotSHA256: snapshot.SHA256, ProductVersion: candidateVersion,
		MessageDraft: interop.MessageDraft, DNSDraft: interop.DNSDraft,
		ReleasePlanSHA256: planDigest, APISHA256: interop.SHA256(apiContent),
		APIDeclarations: apiDeclarations, OpenAPI: openAPI,
		IssueLogSHA256: issueDigest, IssueCount: len(issues.Issues),
		ExternalEvidenceSHA256:   interop.SHA256(currentExternal.DiscoveryJSON),
		ExternalComparisonSHA256: interop.SHA256(currentExternal.ComparisonJSON),
		ExternalAvailability:     external.Availability, ExternalCases: len(comparison.Cases),
		ModuleProofSHA256: interop.SHA256(moduleBytes),
		ModuleProxySHA256: moduleProof.ProxySHA256, ModuleCount: len(moduleProof.Modules),
		Evidence: evidence,
		Capabilities: ReleaseCapability{
			Exim:             "qualified_linux",
			LDAPSQLMigration: "implemented",
		},
		Criteria: []CandidateCriterion{
			{ID: "api", State: "pass"},
			{ID: "conformance", State: "pass"},
			{ID: "deployment", State: "pass"},
			{ID: "datasources", State: "pass"},
			{ID: "external", State: "pass"},
			{ID: "images", State: "pass"},
			{ID: "issues", State: "pass"},
			{ID: "modules", State: "pass"},
			{ID: "security", State: "pass"},
			{ID: "version", State: "pass"},
		},
		Overall: "pass",
	}
	machine, err := canonicalCandidateReport(report)
	if err != nil {
		return CandidateReport{}, nil, nil, err
	}
	if err := conformance.ValidateJSONSchema(
		root, candidateReportSchemaPath, machine, maxCandidateReportBytes,
	); err != nil {
		return CandidateReport{}, nil, nil, errors.New("report_schema")
	}
	human := renderCandidateReport(report)
	return report, machine, human, nil
}

// WriteCandidateReport writes deterministic ignored machine and human reports.
func WriteCandidateReport(root string, now time.Time) (CandidateReport, error) {
	_, machine, human, err := GenerateCandidateReport(root, now)
	if err != nil {
		return CandidateReport{}, err
	}
	if err := writePrivateArtifact(root, candidateReportJSONPath, machine); err != nil {
		return CandidateReport{}, err
	}
	if err := writePrivateArtifact(root, candidateReportMarkdown, human); err != nil {
		return CandidateReport{}, err
	}
	current, err := ReadCurrentCandidateReport(root)
	if err != nil {
		return CandidateReport{}, err
	}
	currentHuman, err := artifactpath.ReadFile(root, candidateReportMarkdown, maxCandidateReportBytes)
	if err != nil || !bytes.Equal(currentHuman, renderCandidateReport(current)) {
		return CandidateReport{}, errors.New("report_markdown")
	}
	return current, nil
}

// LoadCandidateReport strictly validates one bounded machine report.
func LoadCandidateReport(content []byte) (CandidateReport, error) {
	if len(content) == 0 || int64(len(content)) > maxCandidateReportBytes {
		return CandidateReport{}, errors.New("report_size")
	}
	var report CandidateReport
	if err := strictjson.Decode(content, &report, 24, 131072); err != nil {
		return CandidateReport{}, errors.New("report_json")
	}
	if report.Schema != candidateReportSchema || report.ProductVersion != candidateVersion ||
		report.MessageDraft != interop.MessageDraft || report.DNSDraft != interop.DNSDraft ||
		report.Overall != "pass" || len(report.Criteria) != 10 || len(report.Evidence) != len(reportEvidencePaths) {
		return CandidateReport{}, errors.New("report_contract")
	}
	return report, nil
}

// canonicalCandidateReport renders one stable newline-terminated report.
func canonicalCandidateReport(report CandidateReport) ([]byte, error) {
	content, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, errors.New("report_encode")
	}
	return append(content, '\n'), nil
}

// renderCandidateReport renders a deterministic content-free operator summary.
func renderCandidateReport(report CandidateReport) []byte {
	var output bytes.Buffer
	fmt.Fprintln(&output, "# DKIM2 Reference Candidate Report")
	fmt.Fprintln(&output)
	fmt.Fprintf(&output, "- Product: `%s`\n", report.ProductVersion)
	fmt.Fprintf(&output, "- Base: `%s`\n", report.BaseRevision)
	fmt.Fprintf(&output, "- Candidate: `%s`\n", report.CandidateSnapshotSHA256)
	fmt.Fprintf(&output, "- Result: `%s`\n", strings.ToUpper(report.Overall))
	fmt.Fprintf(&output, "- External availability: `%s` (%d cases)\n", report.ExternalAvailability, report.ExternalCases)
	fmt.Fprintf(&output, "- Module proxy: `%s` (%d identities)\n", report.ModuleProxySHA256, report.ModuleCount)
	fmt.Fprintln(&output, "- Exim: `qualified_linux`")
	fmt.Fprintln(&output, "- LDAP/PostgreSQL migration: `implemented`")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "## Criteria")
	fmt.Fprintln(&output)
	for _, criterion := range report.Criteria {
		fmt.Fprintf(&output, "- `%s`: `%s`\n", criterion.ID, criterion.State)
	}
	return output.Bytes()
}

// collectOpenAPIIdentities binds the source and all generated boundary artifacts.
func collectOpenAPIIdentities(root string) ([]ArtifactIdentity, error) {
	paths := append([]string{"docs/specs/openapi/dkim2d.yaml"}, generatedOpenAPIPaths...)
	identities := make([]ArtifactIdentity, 0, len(paths))
	for _, path := range paths {
		content, err := artifactpath.ReadFile(root, path, 16<<20)
		if err != nil {
			return nil, errors.New("report_openapi")
		}
		identities = append(identities, ArtifactIdentity{
			Path: path, Schema: "openapi_source_or_generated", SHA256: interop.SHA256(content),
		})
	}
	return identities, nil
}

// collectReportEvidence validates candidate identity and hashes exact evidence bytes.
func collectReportEvidence(root, revision, candidate string) ([]ArtifactIdentity, error) {
	identities := make([]ArtifactIdentity, 0, len(reportEvidencePaths))
	for _, path := range reportEvidencePaths {
		content, err := artifactpath.ReadFile(root, path, 64<<20)
		if err != nil || strictjson.Validate(content, 64, 1<<20) != nil {
			return nil, errors.New("report_evidence")
		}
		var value map[string]any
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("report_evidence")
		}
		if err := validateEvidenceProjection(value, revision, candidate); err != nil {
			return nil, err
		}
		schema := evidenceSchema(value)
		if expected := reportEvidenceSchemas[path]; expected == "" || schema != expected {
			return nil, errors.New("report_evidence_schema")
		}
		if schema == datasourceIntegrationReportSchema &&
			validateDatasourceIntegrationReport(root, content, revision, candidate) != nil {
			return nil, errors.New("report_evidence_schema")
		}
		if schema != "dkim2-oci-policy-v1" &&
			schema != "https://in-toto.io/Statement/v1" &&
			validateRequiredEvidenceProjection(value) != nil {
			return nil, errors.New("report_evidence_identity")
		}
		if schema == "dkim2-image-release-report-v1" &&
			validateImageReleaseReport(root, path, content, revision, candidate) != nil {
			return nil, errors.New("report_image_evidence")
		}
		identities = append(identities, ArtifactIdentity{
			Path: path, Schema: schema, SHA256: interop.SHA256(content),
		})
	}
	if !slices.IsSortedFunc(identities, func(left, right ArtifactIdentity) int {
		return strings.Compare(left.Path, right.Path)
	}) {
		slices.SortFunc(identities, func(left, right ArtifactIdentity) int {
			return strings.Compare(left.Path, right.Path)
		})
	}
	return identities, nil
}

// validateRequiredEvidenceProjection requires an exact subject and successful state.
func validateRequiredEvidenceProjection(value map[string]any) error {
	_, hasBase, baseErr := evidenceString(value, "base_revision")
	_, hasSource, sourceErr := evidenceString(value, "source_revision")
	_, hasCandidate, candidateErr := evidenceString(value, "candidate_snapshot_sha256")
	_, hasOverall, overallErr := evidenceString(value, "overall")
	_, hasState, stateErr := evidenceString(value, "state")
	if baseErr != nil || sourceErr != nil || candidateErr != nil ||
		overallErr != nil || stateErr != nil ||
		(!hasBase && !hasSource) || !hasCandidate || (!hasOverall && !hasState) {
		return errors.New("report_evidence_identity")
	}
	return nil
}

// validateImageReleaseReport rebinds one derived image report to every exact child artifact.
func validateImageReleaseReport(
	root string,
	path string,
	content []byte,
	revision string,
	candidate string,
) error {
	var report imageReleaseReport
	if err := strictjson.Decode(content, &report, 16, 4096); err != nil {
		return errors.New("image_release_json")
	}
	product := strings.TrimSuffix(strings.TrimPrefix(
		path,
		".artifacts/image-evidence/",
	), ".release.json")
	if report.Schema != "dkim2-image-release-report-v1" ||
		report.BaseRevision != revision ||
		report.CandidateSnapshotSHA256 != candidate ||
		report.Product != product ||
		report.State != "pass" ||
		len(report.SBOMBindings) != 2 ||
		len(report.VulnerabilityBindings) != 2 {
		return errors.New("image_release_identity")
	}
	expected := []imageReleaseArtifact{
		{
			Path:   ".artifacts/image-evidence/" + product + ".oci.json",
			SHA256: report.OCI.SHA256,
		},
		{
			Path:   ".artifacts/image-evidence/" + product + ".provenance.json",
			SHA256: report.Provenance.SHA256,
		},
		{
			Path:   ".artifacts/image-evidence/runtime-policy.json",
			SHA256: report.RuntimePolicy.SHA256,
		},
		{
			Path:   ".artifacts/image-evidence/trivy-database.json",
			SHA256: report.VulnerabilityDatabase.SHA256,
		},
	}
	for index, architecture := range []string{"amd64", "arm64"} {
		expected = append(expected,
			imageReleaseArtifact{
				Path: ".artifacts/image-evidence/" + product + "." +
					architecture + ".sbom-binding.json",
				SHA256: report.SBOMBindings[index].SHA256,
			},
			imageReleaseArtifact{
				Path: ".artifacts/image-evidence/" + product + "." +
					architecture + ".trivy-binding.json",
				SHA256: report.VulnerabilityBindings[index].SHA256,
			},
		)
	}
	actual := []imageReleaseArtifact{
		report.OCI,
		report.Provenance,
		report.RuntimePolicy,
		report.VulnerabilityDatabase,
		report.SBOMBindings[0],
		report.VulnerabilityBindings[0],
		report.SBOMBindings[1],
		report.VulnerabilityBindings[1],
	}
	for index := range expected {
		if actual[index].Path != expected[index].Path ||
			actual[index].SHA256 != expected[index].SHA256 ||
			!validReportDigest(actual[index].SHA256) {
			return errors.New("image_release_binding")
		}
		child, err := artifactpath.ReadFile(root, actual[index].Path, 64<<20)
		if err != nil || interop.SHA256(child) != actual[index].SHA256 {
			return errors.New("image_release_binding")
		}
	}
	return nil
}

// validReportDigest accepts one canonical lowercase SHA-256 identity.
func validReportDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// validateEvidenceProjection rejects stale or failing candidate evidence.
func validateEvidenceProjection(value map[string]any, revision, candidate string) error {
	base, present, err := evidenceString(value, "base_revision")
	if err != nil || (present && base != revision) {
		return errors.New("report_evidence_base")
	}
	source, present, err := evidenceString(value, "source_revision")
	if err != nil || (present && source != revision) {
		return errors.New("report_evidence_base")
	}
	snapshot, present, err := evidenceString(value, "candidate_snapshot_sha256")
	if err != nil || (present && snapshot != candidate) {
		return errors.New("report_evidence_candidate")
	}
	overall, present, err := evidenceString(value, "overall")
	if err != nil || (present && overall != "pass") {
		return errors.New("report_evidence_state")
	}
	state, present, err := evidenceString(value, "state")
	if err != nil || (present && state != "pass") {
		return errors.New("report_evidence_state")
	}
	return nil
}

// evidenceString reads one optional string and rejects type laundering.
func evidenceString(value map[string]any, key string) (string, bool, error) {
	raw, present := value[key]
	if !present {
		return "", false, nil
	}
	found, ok := raw.(string)
	if !ok || found == "" {
		return "", true, errors.New("report_evidence_type")
	}
	return found, true, nil
}

// evidenceSchema returns one bounded schema or document-class marker.
func evidenceSchema(value map[string]any) string {
	if schema, present, err := evidenceString(value, "schema"); err == nil &&
		present && len(schema) <= 128 {
		return schema
	}
	if kind, present, err := evidenceString(value, "_type"); err == nil &&
		present && len(kind) <= 128 {
		return kind
	}
	return "json-evidence"
}

// ReadCurrentCandidateReport validates the ignored report against current bytes.
func ReadCurrentCandidateReport(root string) (CandidateReport, error) {
	content, err := artifactpath.ReadFile(root, candidateReportJSONPath, maxCandidateReportBytes)
	if err != nil {
		return CandidateReport{}, errors.New("report_read")
	}
	report, err := LoadCandidateReport(content)
	if err != nil {
		return CandidateReport{}, err
	}
	snapshot, err := conformance.ProduceSnapshot(root, report.BaseRevision)
	if err != nil || snapshot.SHA256 != report.CandidateSnapshotSHA256 {
		return CandidateReport{}, errors.New("report_candidate")
	}
	current, machine, _, err := GenerateCandidateReport(root, time.Now())
	if err != nil || !bytes.Equal(content, machine) {
		return CandidateReport{}, errors.New("report_current")
	}
	return current, nil
}
