// Package conformance owns repository-wide evidence indexing and reporting.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	// MessageDraft is the exact DKIM2 behavior baseline.
	MessageDraft = "draft-ietf-dkim-dkim2-spec-05"
	// DNSDraft is the exact DNS behavior baseline.
	DNSDraft = "draft-chuang-dkim2-dns-04"
	// ManifestSchema identifies the repository manifest format.
	ManifestSchema = "dkim2.conformance-manifest.v1"
	// ReportSchema identifies the machine report format.
	ReportSchema = "dkim2.conformance-report.v1"
	// SnapshotSchema identifies the candidate snapshot framing.
	SnapshotSchema = "dkim2.candidate-snapshot.v1"
	// EximUnqualifiedDraft05 identifies the evidence-free Draft-05 adapter surface.
	EximUnqualifiedDraft05 = "unqualified_draft05"
	maxJSONDepth           = 16
)

var (
	knownClasses = stringSet(
		"draft_normative", "rfc_normative", "documented_interpretation",
		"local_security_policy", "openapi_contract", "adapter_contract",
	)
	knownRunners = stringSet(
		"portable_vector", "openapi_fixture", "milter_fixture",
		"postfix_qualification",
	)
	knownPlatforms = stringSet("portable", "linux")
	knownOutcomes  = stringSet("pass", "fail", "not_run", "not_applicable")
)

const (
	statePass              = "pass"
	stateFail              = "fail"
	stateNotRun            = "not_run"
	stateNotApplicable     = "not_applicable"
	profilePortable        = "portable"
	profileFull            = "full"
	platformLinux          = "linux"
	classAdapter           = "adapter_contract"
	moduleConformance      = "testdata/conformance"
	capLibrary             = "library"
	capDaemon              = "daemon"
	capMilter              = "milter"
	capPostfix             = "postfix"
	capExim                = "exim"
	supportedCapability    = "supported"
	partialCapability      = "partial"
	partialLinuxCapability = "partial_linux"
)

// Manifest is the closed repository-wide conformance index.
type Manifest struct {
	Schema       string            `json:"schema"`
	MessageDraft string            `json:"message_draft"`
	DNSDraft     string            `json:"dns_draft"`
	SuiteVersion string            `json:"suite_version"`
	Suites       []string          `json:"suites"`
	Capabilities map[string]string `json:"capabilities"`
	Artifacts    []Artifact        `json:"artifacts"`
	Cases        []ManifestCase    `json:"cases"`
}

// Artifact binds one stable identity to exact immutable repository bytes.
type Artifact struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Module string `json:"module"`
}

// ManifestCase binds one exact case to one or more hashed artifacts.
type ManifestCase struct {
	Suite            string   `json:"suite"`
	CaseID           string   `json:"case_id"`
	Class            string   `json:"class"`
	Authority        []string `json:"authority"`
	Provenance       string   `json:"provenance"`
	Runner           string   `json:"runner"`
	RequiredPlatform string   `json:"required_platform"`
	ExpectedOutcome  string   `json:"expected_outcome"`
	Artifacts        []string `json:"artifacts"`
	Producer         string   `json:"producer"`
}

// Report is a deterministic, content-free conformance result.
type Report struct {
	Schema                  string            `json:"schema"`
	MessageDraft            string            `json:"message_draft"`
	DNSDraft                string            `json:"dns_draft"`
	ManifestSchema          string            `json:"manifest_schema"`
	ManifestSHA256          string            `json:"manifest_sha256"`
	BaseRevision            string            `json:"base_revision"`
	CandidateSnapshotSHA256 string            `json:"candidate_snapshot_sha256"`
	Profile                 string            `json:"profile"`
	Platform                string            `json:"platform"`
	Capabilities            map[string]string `json:"capabilities"`
	Tools                   []ToolIdentity    `json:"tools"`
	Cases                   []CaseResult      `json:"cases"`
	Counts                  []ClassCount      `json:"counts"`
	Overall                 string            `json:"overall"`
}

// ToolIdentity records one bounded producer identity.
type ToolIdentity struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// CaseResult records one stable case outcome without mail content.
type CaseResult struct {
	Suite          string   `json:"suite"`
	CaseID         string   `json:"case_id"`
	Class          string   `json:"class"`
	State          string   `json:"state"`
	ArtifactSHA256 []string `json:"artifact_sha256"`
	Producer       string   `json:"producer,omitempty"`
	ProducerSHA256 string   `json:"producer_sha256,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// ClassCount records stable totals for one class and state.
type ClassCount struct {
	Class string `json:"class"`
	State string `json:"state"`
	Count int    `json:"count"`
}

// NewReport constructs one report from a validated manifest and ordered outcomes.
func NewReport(
	manifest Manifest,
	manifestDigest, baseRevision, snapshotDigest, profile, platform string,
	tools []ToolIdentity,
	results []CaseResult,
) (Report, error) {
	report := Report{
		Schema: ReportSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		ManifestSchema: ManifestSchema, ManifestSHA256: manifestDigest,
		BaseRevision: baseRevision, CandidateSnapshotSHA256: snapshotDigest,
		Profile: profile, Platform: platform, Capabilities: cloneMap(manifest.Capabilities),
		Tools: append([]ToolIdentity(nil), tools...), Cases: append([]CaseResult(nil), results...),
	}
	sort.Slice(report.Tools, func(i, j int) bool { return report.Tools[i].Name < report.Tools[j].Name })
	sort.Slice(report.Cases, func(i, j int) bool {
		return report.Cases[i].Suite < report.Cases[j].Suite ||
			report.Cases[i].Suite == report.Cases[j].Suite &&
				report.Cases[i].CaseID < report.Cases[j].CaseID
	})
	report.Counts = countCases(report.Cases)
	report.Overall = statePass
	for _, result := range report.Cases {
		if result.State == stateFail || result.State == stateNotRun {
			report.Overall = stateFail
		}
	}
	if err := report.Validate(manifest); err != nil {
		return Report{}, err
	}
	return report, nil
}

// Validate enforces the closed report contract and required-case policy.
func (r Report) Validate(manifest Manifest) error {
	if err := r.validateIdentityAndTools(manifest); err != nil {
		return err
	}
	if err := r.validateCases(manifest); err != nil {
		return err
	}
	return r.validateDerived()
}

// validateIdentityAndTools checks report identity, capabilities, and producers.
func (r Report) validateIdentityAndTools(manifest Manifest) error {
	if r.Schema != ReportSchema || r.MessageDraft != MessageDraft ||
		r.DNSDraft != DNSDraft || r.ManifestSchema != ManifestSchema {
		return errors.New("report_identity")
	}
	if !isSHA256(r.ManifestSHA256) || !isSHA256(r.CandidateSnapshotSHA256) ||
		!isRevision(r.BaseRevision) || (r.Profile != profilePortable && r.Profile != profileFull) ||
		(r.Platform != profilePortable && r.Platform != platformLinux) {
		return errors.New("report_identity")
	}
	if r.Profile == profilePortable != (r.Platform == profilePortable) {
		return errors.New("report_identity")
	}
	if !equalMap(r.Capabilities, manifest.Capabilities) {
		return errors.New("report_capabilities")
	}
	for _, suite := range manifest.Suites {
		if suite == capExim {
			return errors.New("report_exim_suite")
		}
	}
	if len(r.Tools) == 0 || len(r.Tools) > 64 {
		return errors.New("report_tools")
	}
	previousTool := ""
	for _, tool := range r.Tools {
		if !caseIDPattern.MatchString(tool.Name) || tool.Name <= previousTool || !isSHA256(tool.Digest) {
			return errors.New("report_tools")
		}
		previousTool = tool.Name
	}
	return nil
}

// validateCases checks exact case inventory, artifact binding, and state correlation.
func (r Report) validateCases(manifest Manifest) error {
	cases := make(map[string]ManifestCase, len(manifest.Cases))
	for _, manifestCase := range manifest.Cases {
		if manifestCase.Suite == capExim {
			return errors.New("report_exim_suite")
		}
		cases[manifestCase.Suite+"\x00"+manifestCase.CaseID] = manifestCase
	}
	seen := make(map[string]struct{}, len(r.Cases))
	toolDigests := make(map[string]string, len(r.Tools))
	for _, tool := range r.Tools {
		toolDigests[tool.Name] = tool.Digest
	}
	previous := ""
	for _, result := range r.Cases {
		if result.Suite == capExim {
			return errors.New("report_exim_suite")
		}
		key := result.Suite + "\x00" + result.CaseID
		if key <= previous {
			return errors.New("report_case_order")
		}
		previous = key
		manifestCase, ok := cases[key]
		if !ok || result.Class != manifestCase.Class || !knownOutcomes[result.State] {
			return errors.New("report_case")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("report_case")
		}
		seen[key] = struct{}{}
		if result.Error != "" && !knownErrorClass(result.Error) {
			return errors.New("report_error")
		}
		expectedDigests := manifestCaseDigests(manifest, manifestCase)
		if !equalStrings(result.ArtifactSHA256, expectedDigests) {
			return errors.New("report_artifacts")
		}
		if result.State == statePass &&
			(result.Producer != manifestCase.Producer ||
				toolDigests[result.Producer] != result.ProducerSHA256 ||
				!isSHA256(result.ProducerSHA256)) ||
			result.State != statePass &&
				(result.ProducerSHA256 != "" || result.Producer != "") {
			return errors.New("report_producer")
		}
		if (result.State == statePass ||
			result.State == stateNotApplicable) != (result.Error == "") {
			return errors.New("report_error")
		}
		switch {
		case manifestCase.RequiredPlatform == platformLinux && r.Profile == profilePortable:
			if result.State != stateNotApplicable {
				return errors.New("report_platform_state")
			}
		default:
			if result.State != statePass {
				return errors.New("report_required_case")
			}
		}
	}
	if len(seen) != len(cases) {
		return errors.New("report_missing_case")
	}
	return nil
}

// validateDerived checks counts and overall only from exact case results.
func (r Report) validateDerived() error {
	expectedCounts := countCases(r.Cases)
	if !equalCounts(r.Counts, expectedCounts) {
		return errors.New("report_counts")
	}
	expectedOverall := statePass
	for _, result := range r.Cases {
		if result.State == stateFail || result.State == stateNotRun {
			expectedOverall = stateFail
		}
	}
	if r.Overall != expectedOverall {
		return errors.New("report_overall")
	}
	return nil
}

// manifestCaseDigests resolves exact sorted artifact digests for one case.
func manifestCaseDigests(manifest Manifest, manifestCase ManifestCase) []string {
	byID := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		byID[artifact.ID] = artifact.SHA256
	}
	digests := make([]string, 0, len(manifestCase.Artifacts))
	for _, identifier := range manifestCase.Artifacts {
		digests = append(digests, byID[identifier])
	}
	return digests
}

// equalStrings compares exact string array order and values.
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// RenderJSON returns canonical repository JSON with one trailing LF.
func (r Report) RenderJSON() ([]byte, error) {
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, errors.New("report_encode")
	}
	return append(encoded, '\n'), nil
}

// RenderText returns a stable content-free human summary.
func (r Report) RenderText() []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# DKIM2 Conformance Report\n\n")
	fmt.Fprintf(&output, "- Message draft: `%s`\n", r.MessageDraft)
	fmt.Fprintf(&output, "- DNS draft: `%s`\n", r.DNSDraft)
	fmt.Fprintf(&output, "- Base revision: `%s`\n", r.BaseRevision)
	fmt.Fprintf(&output, "- Candidate snapshot: `%s`\n", r.CandidateSnapshotSHA256)
	fmt.Fprintf(&output, "- Profile: `%s`\n", r.Profile)
	fmt.Fprintf(&output, "- Platform: `%s`\n", r.Platform)
	fmt.Fprintf(&output, "- Overall: `%s`\n\n", r.Overall)
	output.WriteString("## Scope\n\n")
	fmt.Fprintf(
		&output,
		"- Supported surfaces: library `%s`; daemon `%s`; Milter `%s`; Postfix `%s`; Exim `%s`.\n",
		r.Capabilities[capLibrary], r.Capabilities[capDaemon], r.Capabilities[capMilter],
		r.Capabilities[capPostfix], r.Capabilities[capExim],
	)
	suites := make([]string, 0, len(r.Cases))
	seenSuites := make(map[string]struct{}, len(r.Cases))
	for _, result := range r.Cases {
		if _, exists := seenSuites[result.Suite]; exists {
			continue
		}
		seenSuites[result.Suite] = struct{}{}
		suites = append(suites, result.Suite)
	}
	sort.Strings(suites)
	fmt.Fprintf(&output, "- Tested suites: `%s`.\n", strings.Join(suites, "`, `"))
	output.WriteString("- Claim limit: results apply only to the exact base revision, candidate snapshot, pinned drafts, manifest, producers, profile, and case inventory shown by this report.\n")
	output.WriteString("- A pass is not a claim of original SMTP-wire fidelity, external interoperability, DNSSEC validation, or unexecuted platform behavior.\n\n")
	output.WriteString("## Results\n\n")
	output.WriteString("| Class | State | Count |\n| --- | --- | ---: |\n")
	for _, count := range r.Counts {
		fmt.Fprintf(&output, "| `%s` | `%s` | %d |\n", count.Class, count.State, count.Count)
	}
	output.WriteString("\n## Limitations and interpretations\n\n")
	output.WriteString("- Milter evidence uses byte-exact callback reconstruction, not an original SMTP wire image. Postfix prepends its own `Received` field outside Milter-visible message bytes.\n")
	output.WriteString("- Postfix execution is Linux-only and covers the pinned qualification image, explicit Milter-v6 timeouts, SMTP intake, and simulated non-SMTP callbacks.\n")
	output.WriteString("- Replay detection is a restrictive local security policy layered after protocol verification; it is not a DKIM2 cryptographic result.\n")
	output.WriteString("- Exim is `unqualified_draft05`; this report admits no Exim qualification case or imported evidence.\n")
	output.WriteString("- Draft-05 architecture references, EAI considerations, IANA considerations, and security considerations remain `TBA`; implemented interpretations are reported separately from normative claims.\n\n")
	output.WriteString("## Reproduce\n\n```text\nmake check-conformance\nmake conformance\n")
	if r.Profile == profileFull {
		output.WriteString("make conformance-postfix\nmake conformance-all\n")
	}
	output.WriteString("```\n")
	return []byte(output.String())
}

// DecodeStrictJSON rejects duplicate members, excessive depth, unknown members,
// trailing values, BOM input, and inputs larger than the supplied bound.
func DecodeStrictJSON(input []byte, limit int64, target any) error {
	if int64(len(input)) > limit || !json.Valid(input) || bytes.HasPrefix(input, []byte{0xef, 0xbb, 0xbf}) {
		return errors.New("invalid_json")
	}
	if err := rejectDuplicateMembers(input); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid_json")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid_json")
	}
	return nil
}

// SHA256 returns the lowercase SHA-256 of exact bytes.
func SHA256(input []byte) string {
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}

// rejectDuplicateMembers walks the token stream and rejects duplicate object keys.
func rejectDuplicateMembers(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	var stack []frame
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("invalid_json")
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				if len(stack) >= maxJSONDepth {
					return errors.New("json_depth")
				}
				stack = append(stack, frame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				if len(stack) >= maxJSONDepth {
					return errors.New("json_depth")
				}
				stack = append(stack, frame{})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("invalid_json")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				current := &stack[len(stack)-1]
				if _, exists := current.keys[value]; exists {
					return errors.New("duplicate_member")
				}
				current.keys[value] = struct{}{}
				current.expectKey = false
			} else if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		}
	}
}

// countCases returns stable class/state counts.
func countCases(cases []CaseResult) []ClassCount {
	counts := make(map[string]int)
	for _, result := range cases {
		counts[result.Class+"\x00"+result.State]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make([]ClassCount, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		output = append(output, ClassCount{Class: parts[0], State: parts[1], Count: counts[key]})
	}
	return output
}

// equalCounts compares exact derived count records.
func equalCounts(left, right []ClassCount) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// knownErrorClass reports whether the stable error belongs to the closed vocabulary.
func knownErrorClass(value string) bool {
	return stringSet(
		"fixture_invalid", "artifact_tampered", "runner_failure", "timeout",
		"service_unavailable", "contract_violation", "privacy_violation",
	)[value]
}

// stableInt returns one nonnegative canonical decimal integer.

// stringSet constructs a read-only membership map.
func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

// isSHA256 reports whether value is one lowercase hexadecimal SHA-256.
func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

// isRevision reports whether value is a full lowercase Git object identifier.
func isRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

// cloneMap returns an independent string map.
func cloneMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

// equalMap compares exact map content.
func equalMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
