package reference

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/tools/internal/interop"
)

// TestDraft05IssueIdentityAndClassBijection freezes current issue identity and manifest linkage.
func TestDraft05IssueIdentityAndClassBijection(t *testing.T) {
	const draft05 = "draft-ietf-dkim-dkim2-spec-05"
	root := repositoryRoot(t)
	content, err := os.ReadFile(filepath.Join(root, issuePath))
	if err != nil {
		t.Fatal(err)
	}
	log, err := checkIssueContent(root, content)
	if err != nil {
		t.Fatal(err)
	}
	if log.MessageDraft != draft05 {
		t.Fatalf("issue message_draft = %q, want %q", log.MessageDraft, draft05)
	}
}

// TestLoadIssueLogRejectsUnknownDraft05Section proves issue authorities cannot
// cite a section outside the pinned Draft-05 structure.
func TestLoadIssueLogRejectsUnknownDraft05Section(t *testing.T) {
	root := repositoryRoot(t)
	content, err := os.ReadFile(filepath.Join(root, issuePath))
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(
		string(content),
		"Draft-05 Section 1.1",
		"Draft-05 Section 5.3",
		1,
	)
	if _, err := LoadIssueLog([]byte(mutated)); err == nil || err.Error() != "issues_section" {
		t.Fatalf("issue section error = %v, want issues_section", err)
	}
}

// TestDraft05MigrationIssueAuthorityBindings freezes the issue authority and
// exact interpretation-case bijection for recipe-less Draft-05 history.
func TestDraft05MigrationIssueAuthorityBindings(t *testing.T) {
	root := repositoryRoot(t)
	content, err := os.ReadFile(filepath.Join(root, issuePath))
	if err != nil {
		t.Fatal(err)
	}
	log, err := LoadIssueLog(content)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range log.Issues {
		if issue.ID != "DKIM2-ISSUE-0017" {
			continue
		}
		if !slices.Equal(issue.Sections, []string{"Draft-05 Sections 7.2, 9.1, and 11.2"}) ||
			!slices.Equal(issue.ConformanceCases, []string{
				"verification/draft05-recipe-less-unchanged",
				"verification/draft05-recipe-less-unknown-only",
			}) {
			t.Fatalf("DKIM2-ISSUE-0017 authority/bijection = %q/%q", issue.Sections, issue.ConformanceCases)
		}
		return
	}
	t.Fatal("DKIM2-ISSUE-0017 is missing")
}

// TestCheckIssuesAcceptsRepositoryClosure verifies the durable issue inventory.
func TestCheckIssuesAcceptsRepositoryClosure(t *testing.T) {
	if err := CheckIssues(repositoryRoot(t)); err != nil {
		t.Fatalf("CheckIssues() error = %v", err)
	}
}

// TestValidateTestReferenceRejectsMissingOwner proves issue tests name real symbols.
func TestValidateTestReferenceRejectsMissingOwner(t *testing.T) {
	if err := validateTestReference(
		repositoryRoot(t),
		"lib/internal/signature/parser_test.go#TestDoesNotExist",
	); err == nil {
		t.Fatal("validateTestReference accepted an absent test")
	}
}

// TestCheckIssuesRejectsStatusVocabularyOutsideTheDurableContract prevents local/upstream state laundering.
func TestCheckIssuesRejectsStatusVocabularyOutsideTheDurableContract(t *testing.T) {
	if issueLocalStatuses["implemented_restrictive"] ||
		issueUpstreamStatuses["open_unfiled"] {
		t.Fatal("legacy issue status vocabulary remained accepted")
	}
}

// TestCheckExternalIssueClosureRejectsUnownedMismatch freezes report-level mismatch ownership.
func TestCheckExternalIssueClosureRejectsUnownedMismatch(t *testing.T) {
	log := IssueLog{Issues: []Issue{{
		ExternalCases: []string{"peer-a/case-a"},
	}}}
	comparison := interop.ComparisonReport{Cases: []interop.ComparisonCase{{
		CandidateID: "peer-a",
		CaseID:      "case-a",
		State:       "unsupported",
	}}}
	if err := checkExternalIssueClosure(log, comparison); err != nil {
		t.Fatal(err)
	}
	comparison.Cases = append(comparison.Cases, interop.ComparisonCase{
		CandidateID: "peer-b",
		CaseID:      "case-b",
		State:       "disagreement",
	})
	if err := checkExternalIssueClosure(log, comparison); err == nil {
		t.Fatal("unowned current mismatch was accepted")
	}
}

// FuzzLoadIssueLog proves hostile issue bytes remain bounded and panic-free.
func FuzzLoadIssueLog(f *testing.F) {
	content, err := os.ReadFile(filepath.Join(repositoryRootForFuzz(), issuePath))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(content)
	f.Add([]byte(`{"schema":"dkim2.draft-issues.v1","issues":[]}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if int64(len(input)) > maxIssueBytes+1 {
			input = input[:maxIssueBytes+1]
		}
		_, _ = LoadIssueLog(input)
	})
}

// repositoryRoot locates the workspace root from this package.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// repositoryRootForFuzz locates the workspace root without a testing handle.
func repositoryRootForFuzz() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
