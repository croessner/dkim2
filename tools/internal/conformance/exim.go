package conformance

import (
	"errors"
	"slices"
)

const eximQualificationProfile = "exim"

// EximQualificationSummary is the bounded import boundary for verified Linux evidence.
type EximQualificationSummary struct {
	Schema                  string                 `json:"schema"`
	MessageDraft            string                 `json:"message_draft"`
	DNSDraft                string                 `json:"dns_draft"`
	BaseRevision            string                 `json:"base_revision"`
	CandidateSnapshotSHA256 string                 `json:"candidate_snapshot_sha256"`
	ManifestSHA256          string                 `json:"manifest_sha256"`
	Profile                 string                 `json:"profile"`
	Platform                string                 `json:"platform"`
	ProducerSHA256          string                 `json:"producer_sha256"`
	State                   string                 `json:"state"`
	RunID                   string                 `json:"run_id"`
	RunManifestSHA256       string                 `json:"run_manifest_sha256"`
	Rows                    []EximQualificationRow `json:"rows"`
	TotalCases              int                    `json:"total_cases"`
	PrivacyScan             string                 `json:"privacy_scan"`
}

// EximQualificationRow records one content-free matrix row result.
type EximQualificationRow struct {
	Name         string `json:"name"`
	EximVersion  string `json:"exim_version"`
	ResultSHA256 string `json:"result_sha256"`
	CaseCount    int    `json:"case_count"`
	State        string `json:"state"`
}

// ValidateEximQualificationSummary enforces exact candidate binding and matrix closure.
func ValidateEximQualificationSummary(
	summary EximQualificationSummary,
	manifestDigest, revision, snapshotDigest, producerDigest string,
) error {
	if summary.Schema != "dkim2.exim-linux-qualification.v1" ||
		summary.MessageDraft != MessageDraft ||
		summary.DNSDraft != DNSDraft ||
		summary.BaseRevision != revision ||
		summary.CandidateSnapshotSHA256 != snapshotDigest ||
		summary.ManifestSHA256 != manifestDigest ||
		summary.Profile != eximQualificationProfile ||
		summary.Platform != platformLinux ||
		summary.ProducerSHA256 != producerDigest ||
		summary.State != statePass ||
		!isSHA256(summary.RunID) ||
		!isSHA256(summary.RunManifestSHA256) ||
		summary.TotalCases != 215 ||
		summary.PrivacyScan != "passed" {
		return errors.New("runner_identity")
	}
	expectedNames := []string{
		"debian-4.98.2-1+deb13u3",
		"debian-4.98.2-1+deb13u4",
		"ubuntu-4.99.1-1ubuntu1.3",
		"ubuntu-4.99.1-1ubuntu1.4",
		"upstream-4.99.5",
	}
	expectedVersions := []string{
		"4.98.2-1+deb13u3",
		"4.98.2-1+deb13u4",
		"4.99.1-1ubuntu1.3",
		"4.99.1-1ubuntu1.4",
		"4.99.5",
	}
	if len(summary.Rows) != len(expectedNames) {
		return errors.New("runner_missing_case")
	}
	names := make([]string, 0, len(summary.Rows))
	for index, row := range summary.Rows {
		names = append(names, row.Name)
		if row.Name != expectedNames[index] ||
			row.EximVersion != expectedVersions[index] ||
			!isSHA256(row.ResultSHA256) ||
			row.CaseCount != 43 ||
			row.State != statePass {
			return errors.New("runner_failure")
		}
	}
	if !slices.IsSorted(names) {
		return errors.New("runner_failure")
	}
	return nil
}
