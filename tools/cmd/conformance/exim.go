package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

var eximQualificationRows = []string{
	"debian-4.98.2-1+deb13u3",
	"debian-4.98.2-1+deb13u4",
	"ubuntu-4.99.1-1ubuntu1.3",
	"ubuntu-4.99.1-1ubuntu1.4",
	"upstream-4.99.5",
}

var eximDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var eximFieldPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type eximRunIdentity struct {
	runID         string
	adapterSHA256 string
	daemonSHA256  string
}

// executeEximQualification verifies and imports one external real-Exim matrix.
func executeEximQualification(
	root string,
	definition runnerDefinition,
	binding qualificationBinding,
) (string, []string, []conformance.ToolIdentity, error) {
	if len(definition.cases) != 1 || binding.eximEvidence == "" {
		return "", nil, nil, errors.New("runner_dependency")
	}
	evidenceRoot, err := validateEximEvidenceRoot(binding.eximEvidence)
	if err != nil {
		return "", nil, nil, err
	}
	absoluteRoot, err := absoluteQualificationRoot(root)
	if err != nil {
		return "", nil, nil, err
	}
	verifierPath := filepath.Join(
		absoluteRoot,
		"cmd",
		"dkim2-exim",
		"exim",
		"tests",
		"run-real-matrix.sh",
	)
	producerDigest, err := fileDigest(verifierPath)
	if err != nil {
		return "", nil, nil, err
	}
	identity, err := loadEximRunIdentity(evidenceRoot, binding)
	if err != nil {
		return "", nil, nil, err
	}
	runContext, cancelRun := context.WithTimeout(context.Background(), definition.timeout)
	output := &boundedOutput{limit: 4096}
	command := exec.CommandContext(runContext, verifierPath)
	command.Dir = absoluteRoot
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		environmentHomeTmp,
		environmentLangC,
		environmentLocaleC,
		"DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT=" + evidenceRoot,
		"DKIM2_EXIM_REAL_MATRIX_RUN_ID=" + identity.runID,
		"DKIM2_EXIM_REAL_MATRIX_ADAPTER_SHA256=" + identity.adapterSHA256,
		"DKIM2_EXIM_REAL_MATRIX_DAEMON_SHA256=" + identity.daemonSHA256,
	}
	command.Stdout = output
	command.Stderr = output
	runErr := command.Run()
	contextErr := runContext.Err()
	cancelRun()
	if runErr != nil {
		if errors.Is(contextErr, context.DeadlineExceeded) {
			return "", nil, nil, errors.New("runner_timeout")
		}
		return "", nil, nil, errors.New("runner_failure")
	}
	if strings.TrimSpace(output.String()) !=
		"real Exim matrix result set is fixture-authenticated and case-complete" {
		return "", nil, nil, errors.New("runner_failure")
	}
	summary, err := buildEximQualificationSummary(
		evidenceRoot,
		binding,
		producerDigest,
		identity.runID,
	)
	if err != nil {
		return "", nil, nil, err
	}
	if err := conformance.ValidateEximQualificationSummary(
		summary,
		binding.manifestDigest,
		binding.revision,
		binding.snapshotDigest,
		producerDigest,
	); err != nil {
		return "", nil, nil, err
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", nil, nil, errors.New("runner_failure")
	}
	encoded = append(encoded, '\n')
	if err := conformance.ValidateJSONSchema(
		absoluteRoot,
		eximQualificationSchemaPath,
		encoded,
		1<<20,
	); err != nil {
		return "", nil, nil, err
	}
	outputPath := filepath.Join(absoluteRoot, ".artifacts", "conformance-exim")
	if err := os.MkdirAll(outputPath, 0o700); err != nil {
		return "", nil, nil, errors.New("runner_failure")
	}
	if err := os.WriteFile(filepath.Join(outputPath, "import.json"), encoded, 0o600); err != nil {
		return "", nil, nil, errors.New("runner_failure")
	}
	if current, digestErr := fileDigest(verifierPath); digestErr != nil ||
		current != producerDigest {
		return "", nil, nil, errors.New("runner_unstable")
	}
	tools := []conformance.ToolIdentity{
		{Name: "exim-adapter-binary", Digest: identity.adapterSHA256},
		{Name: "exim-dkim2d-binary", Digest: identity.daemonSHA256},
		{Name: "exim-run-manifest", Digest: summary.RunManifestSHA256},
	}
	return producerDigest, []string{definition.cases[0].key}, tools, nil
}

// loadEximRunIdentity validates the candidate binding and uniform binary identities.
func loadEximRunIdentity(
	evidenceRoot string,
	binding qualificationBinding,
) (eximRunIdentity, error) {
	runFields, err := readEximEvidenceFields(evidenceRoot, "run-v1.txt", 4096)
	if err != nil ||
		runFields["format"] != "dkim2-exim-real-matrix-run-v1" ||
		runFields["base_revision"] != binding.revision ||
		runFields["candidate_snapshot_sha256"] != binding.snapshotDigest ||
		!eximDigestPattern.MatchString(runFields["candidate_snapshot_sha256"]) ||
		len(runFields) != 6 {
		return eximRunIdentity{}, errors.New("runner_failure")
	}
	identity := eximRunIdentity{runID: runFields["run_id"]}
	if !eximDigestPattern.MatchString(identity.runID) {
		return eximRunIdentity{}, errors.New("runner_identity")
	}
	for _, row := range eximQualificationRows {
		fields, readErr := readEximEvidenceFields(
			evidenceRoot,
			filepath.ToSlash(filepath.Join(row, "result-v1.txt")),
			64<<10,
		)
		if readErr != nil || fields["row"] != row || fields["run_id"] != identity.runID {
			return eximRunIdentity{}, errors.New("runner_failure")
		}
		if identity.adapterSHA256 == "" {
			identity.adapterSHA256 = fields["adapter_sha256"]
			identity.daemonSHA256 = fields["daemon_sha256"]
		}
		if fields["adapter_sha256"] != identity.adapterSHA256 ||
			fields["daemon_sha256"] != identity.daemonSHA256 ||
			!eximDigestPattern.MatchString(identity.adapterSHA256) ||
			!eximDigestPattern.MatchString(identity.daemonSHA256) {
			return eximRunIdentity{}, errors.New("runner_identity")
		}
	}
	return identity, nil
}

// validateEximEvidenceRoot accepts one absolute direct non-symlink directory.
func validateEximEvidenceRoot(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("runner_dependency")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("runner_dependency")
	}
	return path, nil
}

// readEximEvidenceFields reads one bounded strict key-value evidence record.
func readEximEvidenceFields(root, path string, limit int64) (map[string]string, error) {
	input, err := conformance.ReadConfinedFile(root, path, limit)
	if err != nil || len(input) == 0 || input[len(input)-1] != '\n' {
		return nil, errors.New("runner_failure")
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(input), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || !eximFieldPattern.MatchString(key) ||
			value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("runner_failure")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("runner_failure")
		}
		fields[key] = value
	}
	return fields, nil
}

// buildEximQualificationSummary binds verified row results to the current candidate.
func buildEximQualificationSummary(
	evidenceRoot string,
	binding qualificationBinding,
	producerDigest, runID string,
) (conformance.EximQualificationSummary, error) {
	runInput, err := conformance.ReadConfinedFile(evidenceRoot, "run-v1.txt", 4096)
	if err != nil {
		return conformance.EximQualificationSummary{}, errors.New("runner_failure")
	}
	rows := make([]conformance.EximQualificationRow, 0, len(eximQualificationRows))
	for _, name := range eximQualificationRows {
		path := filepath.ToSlash(filepath.Join(name, "result-v1.txt"))
		input, readErr := conformance.ReadConfinedFile(evidenceRoot, path, 64<<10)
		fields, fieldsErr := readEximEvidenceFields(evidenceRoot, path, 64<<10)
		if readErr != nil || fieldsErr != nil {
			return conformance.EximQualificationSummary{}, errors.New("runner_failure")
		}
		rows = append(rows, conformance.EximQualificationRow{
			Name:         name,
			EximVersion:  fields["exim_version"],
			ResultSHA256: conformance.SHA256(input),
			CaseCount:    43,
			State:        passState,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return conformance.EximQualificationSummary{
		Schema:                  "dkim2.exim-linux-qualification.v1",
		MessageDraft:            conformance.MessageDraft,
		DNSDraft:                conformance.DNSDraft,
		BaseRevision:            binding.revision,
		CandidateSnapshotSHA256: binding.snapshotDigest,
		ManifestSHA256:          binding.manifestDigest,
		Profile:                 "exim",
		Platform:                linuxPlatform,
		ProducerSHA256:          producerDigest,
		State:                   passState,
		RunID:                   runID,
		RunManifestSHA256:       conformance.SHA256(runInput),
		Rows:                    rows,
		TotalCases:              215,
		PrivacyScan:             "passed",
	}, nil
}
