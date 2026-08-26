// Package reference owns release-reference closure and candidate reporting.
package reference

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/draftsection"
	"github.com/croessner/dkim2/tools/internal/interop"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	issueSchemaName = "dkim2.draft-issues.v1"
	issuePath       = "testdata/reference/draft-issues.json"
	issueSchemaPath = "testdata/reference/schemas/draft-issues.schema.json"
	issueMarkdown   = "docs/reference/draft-issues.md"
	maxIssueBytes   = int64(1 << 20)
)

var claimClasses = stringSet(
	"adapter_contract", "documented_interpretation", "draft_normative",
	"external_observation", "local_security_policy", "release_policy",
)

var issueLocalStatuses = stringSet(
	"open_blocks_candidate", "implemented_interpretation", "not_implemented",
	"not_applicable", "superseded_by_baseline", "resolved_local_defect",
)

var issueUpstreamStatuses = stringSet(
	"not_reported", "reporting_requires_authorization", "reported",
	"acknowledged", "resolved_in_later_draft", "not_upstream_issue",
)

// IssueLog is the strict machine-readable draft issue owner.
type IssueLog struct {
	Schema       string  `json:"schema"`
	MessageDraft string  `json:"message_draft"`
	DNSDraft     string  `json:"dns_draft"`
	Issues       []Issue `json:"issues"`
}

// Issue separates local behavior, upstream status, tests, and public effect.
type Issue struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Sections            []string `json:"sections"`
	Class               string   `json:"class"`
	LocalStatus         string   `json:"local_status"`
	UpstreamStatus      string   `json:"upstream_status"`
	BehaviorOwner       string   `json:"behavior_owner"`
	ConformanceCases    []string `json:"conformance_cases"`
	TestRefs            []string `json:"test_refs"`
	ExternalCases       []string `json:"external_cases"`
	PublicEffect        string   `json:"public_effect"`
	ResolutionCriterion string   `json:"resolution_criterion"`
	ClaimClasses        []string `json:"claim_classes"`
	UpstreamReference   string   `json:"upstream_reference,omitempty"`
	ObservationDate     string   `json:"observation_date,omitempty"`
}

// CheckIssues proves TBA, interpretation, test, and public-claim closure.
func CheckIssues(root string) error {
	content, err := artifactpath.ReadFile(root, issuePath, maxIssueBytes)
	if err != nil {
		return errors.New("issues_read")
	}
	_, err = checkIssueContent(root, content)
	return err
}

// checkIssueContent validates one exact issue-log byte sequence and its repository closure.
//
//nolint:gocyclo // Bidirectional issue closure is intentionally visible in one audit owner.
func checkIssueContent(root string, content []byte) (IssueLog, error) {
	log, err := LoadIssueLog(content)
	if err != nil {
		return IssueLog{}, err
	}
	if err := conformance.ValidateJSONSchema(
		root, issueSchemaPath, content, maxIssueBytes,
	); err != nil {
		return IssueLog{}, errors.New("issues_schema")
	}
	manifest, _, err := conformance.LoadManifest(root, "testdata/conformance/manifest.json")
	if err != nil {
		return IssueLog{}, errors.New("issues_manifest")
	}
	markdown, err := artifactpath.ReadFile(root, issueMarkdown, maxIssueBytes)
	if err != nil {
		return IssueLog{}, errors.New("issues_markdown")
	}
	expectedCases := make(map[string]bool)
	for _, manifestCase := range manifest.Cases {
		if manifestCase.Class == "documented_interpretation" {
			expectedCases[manifestCase.Suite+"/"+manifestCase.CaseID] = false
		}
	}
	expectedTBA := map[string]bool{
		"Draft-05 Section 1.1":  false,
		"Draft-05 Section 10.3": false,
		"Draft-05 Section 14":   false,
		"Draft-05 Section 15":   false,
		"Draft-05 Section 16":   false,
	}
	for index, issue := range log.Issues {
		expectedID := fmt.Sprintf("DKIM2-ISSUE-%04d", index+1)
		if issue.ID != expectedID || !strings.Contains(string(markdown), issue.ID) {
			return IssueLog{}, errors.New("issues_ids")
		}
		if !issueLocalStatuses[issue.LocalStatus] ||
			!issueUpstreamStatuses[issue.UpstreamStatus] {
			return IssueLog{}, errors.New("issues_status")
		}
		if !slices.IsSorted(issue.Sections) || hasDuplicate(issue.Sections) ||
			!slices.IsSorted(issue.ConformanceCases) || hasDuplicate(issue.ConformanceCases) ||
			!slices.IsSorted(issue.TestRefs) || hasDuplicate(issue.TestRefs) ||
			!slices.IsSorted(issue.ExternalCases) || hasDuplicate(issue.ExternalCases) ||
			!slices.IsSorted(issue.ClaimClasses) || hasDuplicate(issue.ClaimClasses) {
			return IssueLog{}, errors.New("issues_order")
		}
		for _, class := range issue.ClaimClasses {
			if !claimClasses[class] {
				return IssueLog{}, errors.New("issues_claim_class")
			}
		}
		if issue.LocalStatus == "not_implemented" && issue.Class == "tba" &&
			len(issue.TestRefs) != 0 {
			return IssueLog{}, errors.New("issues_unimplemented")
		}
		if issue.LocalStatus != "not_implemented" && len(issue.TestRefs) == 0 {
			return IssueLog{}, errors.New("issues_tests")
		}
		for _, section := range issue.Sections {
			if _, exists := expectedTBA[section]; exists && issue.Class == "tba" {
				expectedTBA[section] = true
			}
		}
		for _, caseID := range issue.ConformanceCases {
			seen, exists := expectedCases[caseID]
			if !exists || seen {
				return IssueLog{}, errors.New("issues_conformance")
			}
			expectedCases[caseID] = true
		}
		for _, reference := range issue.TestRefs {
			if err := validateTestReference(root, reference); err != nil {
				return IssueLog{}, err
			}
		}
	}
	for _, seen := range expectedCases {
		if !seen {
			return IssueLog{}, errors.New("issues_conformance")
		}
	}
	for _, seen := range expectedTBA {
		if !seen {
			return IssueLog{}, errors.New("issues_tba")
		}
	}
	return log, nil
}

// LoadIssueLog performs bounded strict decoding of one machine issue log.
func LoadIssueLog(content []byte) (IssueLog, error) {
	if len(content) == 0 || int64(len(content)) > maxIssueBytes {
		return IssueLog{}, errors.New("issues_size")
	}
	var log IssueLog
	if err := strictjson.Decode(content, &log, 24, 65536); err != nil {
		return IssueLog{}, errors.New("issues_json")
	}
	if log.Schema != issueSchemaName ||
		log.MessageDraft != interop.MessageDraft || log.DNSDraft != interop.DNSDraft ||
		len(log.Issues) == 0 || len(log.Issues) > 256 {
		return IssueLog{}, errors.New("issues_identity")
	}
	for _, issue := range log.Issues {
		for _, section := range issue.Sections {
			if !draftsection.CitationValid(section) {
				return IssueLog{}, errors.New("issues_section")
			}
		}
	}
	return log, nil
}

// CheckCurrentIssueEvidence binds every external mismatch to one stable issue.
func CheckCurrentIssueEvidence(root string, now time.Time) error {
	content, err := artifactpath.ReadFile(root, issuePath, maxIssueBytes)
	if err != nil {
		return errors.New("issues_read")
	}
	log, err := checkIssueContent(root, content)
	if err != nil {
		return err
	}
	_, comparison, err := interop.ReadCurrentEvidence(root, now)
	if err != nil {
		return errors.New("issues_current")
	}
	return checkExternalIssueClosure(log, comparison)
}

// checkExternalIssueClosure proves every current mismatch has exactly one durable issue owner.
func checkExternalIssueClosure(log IssueLog, comparison interop.ComparisonReport) error {
	required := make(map[string]bool)
	for _, result := range comparison.Cases {
		if result.State == "unsupported" || result.State == "disagreement" {
			required[result.CandidateID+"/"+result.CaseID] = false
		}
	}
	for _, issue := range log.Issues {
		for _, externalCase := range issue.ExternalCases {
			seen, exists := required[externalCase]
			if !exists || seen {
				return errors.New("issues_external")
			}
			required[externalCase] = true
		}
	}
	for _, seen := range required {
		if !seen {
			return errors.New("issues_external")
		}
	}
	return nil
}

// IssueDigest returns the validated strict issue-log identity.
func IssueDigest(root string) (string, error) {
	content, err := artifactpath.ReadFile(root, issuePath, maxIssueBytes)
	if err != nil {
		return "", errors.New("issues_read")
	}
	if _, err := checkIssueContent(root, content); err != nil {
		return "", err
	}
	return interop.SHA256(content), nil
}

// validateTestReference proves both the file and named Go test exist.
func validateTestReference(root, reference string) error {
	path, symbol, found := strings.Cut(reference, "#")
	if !found || path == "" || symbol == "" {
		return errors.New("issues_test_ref")
	}
	content, err := artifactpath.ReadFile(root, path, 16<<20)
	if err != nil {
		return errors.New("issues_test_ref")
	}
	if !strings.Contains(string(content), "func "+symbol+"(") {
		return errors.New("issues_test_ref")
	}
	return nil
}

// hasDuplicate reports adjacent duplicates in one sorted string list.
func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

// stringSet constructs one immutable membership set.
func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
