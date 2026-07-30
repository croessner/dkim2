package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/conformance"
	referencecheck "github.com/croessner/dkim2/tools/internal/reference"
)

const (
	fuzzReportSchema          = "dkim2.security-fuzz-report.v1"
	raceReportSchema          = "dkim2.security-race-report.v1"
	vulnerabilityReportSchema = "dkim2.security-vulnerability-report.v1"
	securityReportSchema      = "dkim2.security-report.v1"
	securityProfile           = "complete"
	passState                 = "pass"
	maxRunnerOutput           = 2 << 20
	fuzzDurationClass         = "at_least_10s"
	racePassState             = "required_pass"
	vulnerabilityDatabase     = "vuln.go.dev"
	evidencePostfixRunOne     = "postfix-run-1"
	evidencePostfixRunTwo     = "postfix-run-2"
	postfixEvidenceProfile    = "postfix"
)

// FuzzResult records one content-free closed-target result.
type FuzzResult struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	DurationClass string `json:"duration_class"`
}

// FuzzReport binds the complete fuzz inventory result to one candidate.
type FuzzReport struct {
	Schema                  string       `json:"schema"`
	BaseRevision            string       `json:"base_revision"`
	CandidateSnapshotSHA256 string       `json:"candidate_snapshot_sha256"`
	InventorySHA256         string       `json:"inventory_sha256"`
	GoVersion               string       `json:"go_version"`
	GOOS                    string       `json:"goos"`
	GOARCH                  string       `json:"goarch"`
	Targets                 []FuzzResult `json:"targets"`
	Overall                 string       `json:"overall"`
}

// VulnerabilityReport binds a clean fixed-module scan to one candidate and tool.
type VulnerabilityReport struct {
	Schema                  string   `json:"schema"`
	BaseRevision            string   `json:"base_revision"`
	CandidateSnapshotSHA256 string   `json:"candidate_snapshot_sha256"`
	Scanner                 string   `json:"scanner"`
	ScannerSHA256           string   `json:"scanner_sha256"`
	Database                string   `json:"database"`
	Modules                 []string `json:"modules"`
	ReachableFindings       int      `json:"reachable_findings"`
	State                   string   `json:"state"`
}

// RaceReport binds full race-detector execution to one candidate.
type RaceReport struct {
	Schema                  string   `json:"schema"`
	BaseRevision            string   `json:"base_revision"`
	CandidateSnapshotSHA256 string   `json:"candidate_snapshot_sha256"`
	GoVersion               string   `json:"go_version"`
	GOOS                    string   `json:"goos"`
	GOARCH                  string   `json:"goarch"`
	Modules                 []string `json:"modules"`
	State                   string   `json:"state"`
}

// EvidenceDigest binds one existing deterministic report by relative path and digest.
type EvidenceDigest struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// FindingCounts records unresolved security findings by bounded severity.
type FindingCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Report is the deterministic content-free security evidence envelope.
type Report struct {
	Schema                  string           `json:"schema"`
	MessageDraft            string           `json:"message_draft"`
	DNSDraft                string           `json:"dns_draft"`
	BaseRevision            string           `json:"base_revision"`
	CandidateSnapshotSHA256 string           `json:"candidate_snapshot_sha256"`
	Profile                 string           `json:"profile"`
	InventorySHA256         string           `json:"inventory_sha256"`
	GoVersion               string           `json:"go_version"`
	GOOS                    string           `json:"goos"`
	GOARCH                  string           `json:"goarch"`
	Race                    string           `json:"race"`
	FuzzTargets             int              `json:"fuzz_targets"`
	FuzzState               string           `json:"fuzz_state"`
	VulnerabilityState      string           `json:"vulnerability_state"`
	Evidence                []EvidenceDigest `json:"evidence"`
	Findings                FindingCounts    `json:"unresolved_findings"`
	Exim                    string           `json:"exim"`
	Overall                 string           `json:"overall"`
}

// RunFuzz executes every closed first-party target for the required minimum duration.
func RunFuzz(root, outputPath string) (FuzzReport, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return FuzzReport{}, errors.New("security_root")
	}
	if err := ValidateInventory(root); err != nil {
		return FuzzReport{}, err
	}
	goExecutable, goDigest, err := resolveGoExecutable()
	if err != nil {
		return FuzzReport{}, err
	}
	if err := cleanFuzzCache(root, goExecutable); err != nil {
		return FuzzReport{}, err
	}
	snapshot, err := currentSnapshot(root)
	if err != nil {
		return FuzzReport{}, err
	}
	results := make([]FuzzResult, 0, len(Targets()))
	for index, target := range Targets() {
		if err := runFuzzTarget(root, goExecutable, target); err != nil {
			return FuzzReport{}, fmt.Errorf("%s_%03d", err.Error(), index+1)
		}
		results = append(results, FuzzResult{
			ID: target.ID, State: passState, DurationClass: fuzzDurationClass,
		})
	}
	if err := candidateUnchanged(root, snapshot); err != nil {
		return FuzzReport{}, err
	}
	if finalDigest, err := digestRegularFile(goExecutable); err != nil || finalDigest != goDigest {
		return FuzzReport{}, errors.New("security_go_dependency")
	}
	report := FuzzReport{
		Schema: fuzzReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: snapshot.SHA256,
		InventorySHA256:         InventorySHA256(), GoVersion: runtime.Version(),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Targets: results, Overall: passState,
	}
	if err := report.Validate(); err != nil {
		return FuzzReport{}, err
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/fuzz-report.schema.json",
		report,
		8<<20,
	); err != nil {
		return FuzzReport{}, err
	}
	if err := writeJSONAtomic(root, outputPath, report, 8<<20); err != nil {
		return FuzzReport{}, err
	}
	return report, nil
}

// RunVulnerabilityScan executes govulncheck over every fixed workspace module.
func RunVulnerabilityScan(root, outputPath string) (VulnerabilityReport, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return VulnerabilityReport{}, errors.New("security_root")
	}
	snapshot, err := currentSnapshot(root)
	if err != nil {
		return VulnerabilityReport{}, err
	}
	scanner, err := exec.LookPath("govulncheck")
	if err != nil {
		return VulnerabilityReport{}, errors.New("vulnerability_dependency")
	}
	scannerDigest, err := digestRegularFile(scanner)
	if err != nil {
		return VulnerabilityReport{}, err
	}
	version, err := scannerVersion(scanner)
	if err != nil {
		return VulnerabilityReport{}, err
	}
	modules := workspaceModules()
	for index, module := range modules {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		command := exec.CommandContext(
			ctx,
			scanner,
			"-db=https://vuln.go.dev",
			"-scan=symbol",
			"./...",
		)
		command.Dir = filepath.Join(root, module)
		command.Env = appendClosedGoEnvironment(os.Environ(), root)
		output := &boundedOutput{limit: maxRunnerOutput}
		command.Stdout = output
		command.Stderr = output
		runErr := command.Run()
		contextErr := ctx.Err()
		cancel()
		if runErr != nil {
			if errors.Is(contextErr, context.DeadlineExceeded) {
				return VulnerabilityReport{}, errors.New("vulnerability_timeout")
			}
			return VulnerabilityReport{}, fmt.Errorf("vulnerability_failure_%02d", index+1)
		}
	}
	finalScannerDigest, err := digestRegularFile(scanner)
	if err != nil || finalScannerDigest != scannerDigest {
		return VulnerabilityReport{}, errors.New("vulnerability_dependency")
	}
	finalVersion, err := scannerVersion(scanner)
	if err != nil || finalVersion != version {
		return VulnerabilityReport{}, errors.New("vulnerability_dependency")
	}
	if err := candidateUnchanged(root, snapshot); err != nil {
		return VulnerabilityReport{}, err
	}
	report := VulnerabilityReport{
		Schema: vulnerabilityReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: snapshot.SHA256, Scanner: version,
		ScannerSHA256: scannerDigest, Database: vulnerabilityDatabase,
		Modules: modules, ReachableFindings: 0, State: passState,
	}
	if err := report.Validate(); err != nil {
		return VulnerabilityReport{}, err
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/vulnerability-report.schema.json",
		report,
		1<<20,
	); err != nil {
		return VulnerabilityReport{}, err
	}
	if err := writeJSONAtomic(root, outputPath, report, 1<<20); err != nil {
		return VulnerabilityReport{}, err
	}
	return report, nil
}

// RunRace executes the race detector over every fixed workspace module.
func RunRace(root, outputPath string) (RaceReport, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return RaceReport{}, errors.New("security_root")
	}
	snapshot, err := currentSnapshot(root)
	if err != nil {
		return RaceReport{}, err
	}
	goExecutable, goDigest, err := resolveGoExecutable()
	if err != nil {
		return RaceReport{}, err
	}
	proxyProof, proxyRoot, cleanupProxy, err := referencecheck.BuildPrivateProxy(root)
	if err != nil || proxyProof.CandidateSnapshotSHA256 != snapshot.SHA256 {
		return RaceReport{}, errors.New("race_dependency")
	}
	defer func() {
		_ = cleanupProxy()
	}()
	modules := workspaceModules()
	for index, module := range modules {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		command := exec.CommandContext(ctx, goExecutable, "test", "-race", "./...")
		command.Dir = filepath.Join(root, module)
		command.Env = appendRaceEnvironment(os.Environ(), root, proxyRoot)
		output := &boundedOutput{limit: maxRunnerOutput}
		command.Stdout = output
		command.Stderr = output
		runErr := command.Run()
		contextErr := ctx.Err()
		cancel()
		if runErr != nil {
			if errors.Is(contextErr, context.DeadlineExceeded) {
				return RaceReport{}, errors.New("race_timeout")
			}
			return RaceReport{}, fmt.Errorf("race_failure_%02d", index+1)
		}
	}
	if err := candidateUnchanged(root, snapshot); err != nil {
		return RaceReport{}, err
	}
	if finalDigest, err := digestRegularFile(goExecutable); err != nil || finalDigest != goDigest {
		return RaceReport{}, errors.New("security_go_dependency")
	}
	report := RaceReport{
		Schema: raceReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: snapshot.SHA256,
		GoVersion:               runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Modules: modules, State: passState,
	}
	if err := report.Validate(); err != nil {
		return RaceReport{}, err
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/race-report.schema.json",
		report,
		1<<20,
	); err != nil {
		return RaceReport{}, err
	}
	if err := writeJSONAtomic(root, outputPath, report, 1<<20); err != nil {
		return RaceReport{}, err
	}
	return report, nil
}

// BuildReport validates fuzz, race, vulnerability, conformance, Valkey, and Postfix evidence.
func BuildReport(root, fuzzPath, racePath, vulnerabilityPath, outputPath string) (Report, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Report{}, errors.New("security_root")
	}
	if err := ValidateInventory(root); err != nil {
		return Report{}, err
	}
	snapshot, err := currentSnapshot(root)
	if err != nil {
		return Report{}, err
	}
	local, err := loadLocalEvidence(
		root,
		fuzzPath,
		racePath,
		vulnerabilityPath,
		snapshot.SHA256,
	)
	if err != nil {
		return Report{}, err
	}
	evidence, err := collectExternalEvidence(root, snapshot.SHA256)
	if err != nil {
		return Report{}, err
	}
	evidence, err = appendLocalEvidenceDigests(
		root,
		evidence,
		fuzzPath,
		racePath,
		vulnerabilityPath,
	)
	if err != nil {
		return Report{}, err
	}
	slices.SortFunc(evidence, func(left, right EvidenceDigest) int {
		return strings.Compare(left.ID, right.ID)
	})
	report := Report{
		Schema: securityReportSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision: BaseRevision, CandidateSnapshotSHA256: snapshot.SHA256,
		Profile: securityProfile, InventorySHA256: InventorySHA256(),
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Race: racePassState, FuzzTargets: len(local.fuzz.Targets), FuzzState: passState,
		VulnerabilityState: passState, Evidence: evidence, Findings: FindingCounts{},
		Exim: conformance.EximDeferred, Overall: passState,
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/report.schema.json",
		report,
		8<<20,
	); err != nil {
		return Report{}, err
	}
	if err := candidateUnchanged(root, snapshot); err != nil {
		return Report{}, err
	}
	if err := writeJSONAtomic(root, outputPath, report, 8<<20); err != nil {
		return Report{}, err
	}
	return report, nil
}

type localEvidence struct {
	fuzz          FuzzReport
	race          RaceReport
	vulnerability VulnerabilityReport
}

// loadLocalEvidence validates strict fuzz, race, and vulnerability reports.
func loadLocalEvidence(
	root, fuzzPath, racePath, vulnerabilityPath, candidate string,
) (localEvidence, error) {
	var result localEvidence
	fuzz := &result.fuzz
	if err := readJSON(root, fuzzPath, 8<<20, fuzz); err != nil ||
		fuzz.Validate() != nil ||
		fuzz.GoVersion != runtime.Version() ||
		fuzz.GOOS != runtime.GOOS ||
		fuzz.GOARCH != runtime.GOARCH ||
		validateSchemaValue(
			root,
			"testdata/security/fuzz-report.schema.json",
			*fuzz,
			8<<20,
		) != nil {
		return localEvidence{}, errors.New("security_fuzz_evidence")
	}
	vulnerability := &result.vulnerability
	if err := readJSON(root, vulnerabilityPath, 1<<20, vulnerability); err != nil ||
		vulnerability.Validate() != nil ||
		validateSchemaValue(
			root,
			"testdata/security/vulnerability-report.schema.json",
			*vulnerability,
			1<<20,
		) != nil {
		return localEvidence{}, errors.New("security_vulnerability_evidence")
	}
	if fuzz.CandidateSnapshotSHA256 != candidate ||
		vulnerability.CandidateSnapshotSHA256 != candidate {
		return localEvidence{}, errors.New("security_candidate")
	}
	race := &result.race
	if err := readJSON(root, racePath, 1<<20, race); err != nil ||
		race.Validate() != nil ||
		race.GoVersion != runtime.Version() ||
		race.GOOS != runtime.GOOS ||
		race.GOARCH != runtime.GOARCH ||
		validateSchemaValue(
			root,
			"testdata/security/race-report.schema.json",
			*race,
			1<<20,
		) != nil ||
		race.CandidateSnapshotSHA256 != candidate {
		return localEvidence{}, errors.New("security_race_evidence")
	}
	return result, nil
}

// collectExternalEvidence validates complete conformance and Postfix reports.
func collectExternalEvidence(root, candidate string) ([]EvidenceDigest, error) {
	evidencePaths := externalEvidenceExpectations()
	manifest, manifestDigest, err := conformance.LoadManifest(
		root,
		"testdata/conformance/manifest.json",
	)
	if err != nil {
		return nil, errors.New("security_external_evidence")
	}
	producerInput, err := conformance.ReadConfinedFile(
		root,
		"contrib/qualification/postfix-milter/run.sh",
		8<<20,
	)
	if err != nil {
		return nil, errors.New("security_external_evidence")
	}
	postfixProducerDigest := conformance.SHA256(producerInput)
	evidence := make([]EvidenceDigest, 0, len(evidencePaths)+3)
	postfixDigest := ""
	for _, current := range evidencePaths {
		var digest string
		switch current.profile {
		case "full", "portable":
			digest, err = validateConformanceReport(
				root,
				current.path,
				current.profile,
				candidate,
				manifest,
				manifestDigest,
			)
		case postfixEvidenceProfile:
			digest, err = validatePostfixReport(
				root,
				current.path,
				candidate,
				manifestDigest,
				postfixProducerDigest,
			)
		default:
			err = errors.New("security_external_evidence")
		}
		if err != nil {
			return nil, err
		}
		if current.id == evidencePostfixRunOne {
			postfixDigest = digest
		}
		if current.id == evidencePostfixRunTwo && digest != postfixDigest {
			return nil, errors.New("security_postfix_repeatability")
		}
		evidence = append(evidence, EvidenceDigest{
			ID: current.id, Path: current.path, SHA256: digest,
		})
	}
	return evidence, nil
}

// appendLocalEvidenceDigests binds the already validated local reports.
func appendLocalEvidenceDigests(
	root string,
	evidence []EvidenceDigest,
	fuzzPath, racePath, vulnerabilityPath string,
) ([]EvidenceDigest, error) {
	for _, current := range localEvidenceExpectations(fuzzPath, racePath, vulnerabilityPath) {
		digest, err := digestRelativeFile(root, current.path, 8<<20)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, EvidenceDigest{
			ID: current.id, Path: current.path, SHA256: digest,
		})
	}
	return evidence, nil
}

// validateSchemaValue checks one generated value against its checked-in strict schema.
func validateSchemaValue(root, schemaPath string, value any, limit int) error {
	input, err := json.Marshal(value)
	if err != nil || len(input) > limit {
		return errors.New("security_schema")
	}
	if err := conformance.ValidateJSONSchema(root, schemaPath, input, int64(limit)); err != nil {
		return errors.New("security_schema")
	}
	return nil
}

// Validate enforces exact fuzz evidence identity and complete target closure.
func (r FuzzReport) Validate() error {
	targets := Targets()
	if r.Schema != fuzzReportSchema || r.BaseRevision != BaseRevision ||
		!isSHA256(r.CandidateSnapshotSHA256) ||
		r.InventorySHA256 != InventorySHA256() ||
		!strings.HasPrefix(r.GoVersion, "go1.26.") ||
		r.GOOS == "" || r.GOARCH == "" || r.Overall != passState ||
		len(r.Targets) != len(targets) {
		return errors.New("fuzz_report_identity")
	}
	for index, result := range r.Targets {
		if result.ID != targets[index].ID || result.State != passState ||
			result.DurationClass != fuzzDurationClass {
			return errors.New("fuzz_report_target")
		}
	}
	return nil
}

// Validate enforces exact vulnerability evidence identity and clean result state.
func (r VulnerabilityReport) Validate() error {
	expectedModules := workspaceModules()
	if r.Schema != vulnerabilityReportSchema || r.BaseRevision != BaseRevision ||
		!isSHA256(r.CandidateSnapshotSHA256) ||
		!strings.HasPrefix(r.Scanner, "govulncheck@v") ||
		!isSHA256(r.ScannerSHA256) || r.Database != vulnerabilityDatabase ||
		!slices.Equal(r.Modules, expectedModules) || r.ReachableFindings != 0 ||
		r.State != passState {
		return errors.New("vulnerability_report")
	}
	return nil
}

// Validate enforces exact full-workspace race evidence identity and clean state.
func (r RaceReport) Validate() error {
	expectedModules := workspaceModules()
	if r.Schema != raceReportSchema || r.BaseRevision != BaseRevision ||
		!isSHA256(r.CandidateSnapshotSHA256) ||
		!strings.HasPrefix(r.GoVersion, "go1.26.") ||
		r.GOOS == "" || r.GOARCH == "" ||
		!slices.Equal(r.Modules, expectedModules) || r.State != passState {
		return errors.New("race_report")
	}
	return nil
}

// Validate enforces exact complete security evidence identity and closure.
func (r Report) Validate() error {
	if r.Schema != securityReportSchema || r.MessageDraft != MessageDraft ||
		r.DNSDraft != DNSDraft || r.BaseRevision != BaseRevision ||
		!isSHA256(r.CandidateSnapshotSHA256) || r.Profile != securityProfile ||
		r.InventorySHA256 != InventorySHA256() ||
		!strings.HasPrefix(r.GoVersion, "go1.26.") ||
		r.GOOS == "" || r.GOARCH == "" || r.Race != racePassState ||
		r.FuzzTargets != len(Targets()) || r.FuzzState != passState ||
		r.VulnerabilityState != passState || r.Findings != (FindingCounts{}) ||
		r.Exim != conformance.EximDeferred || r.Overall != passState ||
		len(r.Evidence) != 7 {
		return errors.New("security_report")
	}
	previous := ""
	expectedEvidence := expectedEvidenceIdentities()
	for index, evidence := range r.Evidence {
		if evidence.ID <= previous || evidence.ID != expectedEvidence[index].ID ||
			evidence.Path != expectedEvidence[index].Path || !isSHA256(evidence.SHA256) {
			return errors.New("security_report_evidence")
		}
		previous = evidence.ID
	}
	return nil
}

// externalEvidenceExpectations returns the fixed conformance and Postfix inputs.
func externalEvidenceExpectations() []struct {
	id      string
	path    string
	profile string
} {
	return []struct {
		id      string
		path    string
		profile string
	}{
		{id: "conformance-full", path: ".artifacts/conformance-full/report.json", profile: "full"},
		{id: "conformance-portable", path: ".artifacts/conformance-portable/report.json", profile: "portable"},
		{id: evidencePostfixRunOne, path: ".artifacts/conformance-postfix/run-1/report.json", profile: postfixEvidenceProfile},
		{id: evidencePostfixRunTwo, path: ".artifacts/conformance-postfix/run-2/report.json", profile: postfixEvidenceProfile},
	}
}

// localEvidenceExpectations returns the fixed security-runner inputs.
func localEvidenceExpectations(fuzzPath, racePath, vulnerabilityPath string) []struct {
	id   string
	path string
} {
	return []struct {
		id   string
		path string
	}{
		{id: "fuzz", path: fuzzPath},
		{id: "race", path: racePath},
		{id: "vulnerability", path: vulnerabilityPath},
	}
}

// expectedEvidenceIdentities returns the exact sorted final evidence identity set.
func expectedEvidenceIdentities() []EvidenceDigest {
	result := make([]EvidenceDigest, 0, 7)
	for _, current := range externalEvidenceExpectations() {
		result = append(result, EvidenceDigest{ID: current.id, Path: current.path})
	}
	for _, current := range localEvidenceExpectations(
		".artifacts/security/fuzz.json",
		".artifacts/security/race.json",
		".artifacts/security/vulnerability.json",
	) {
		result = append(result, EvidenceDigest{ID: current.id, Path: current.path})
	}
	slices.SortFunc(result, func(left, right EvidenceDigest) int {
		return strings.Compare(left.ID, right.ID)
	})
	return result
}

// appendRaceEnvironment binds race subprocesses to the proof-owned offline module proxy.
func appendRaceEnvironment(environment []string, root, proxyRoot string) []string {
	filtered := make([]string, 0, len(environment)+4)
	for _, current := range appendClosedGoEnvironment(environment, root) {
		key, _, _ := strings.Cut(current, "=")
		if key == "GOPROXY" || key == "GOSUMDB" || key == "GONOSUMDB" ||
			key == "GONOPROXY" || key == "GOPRIVATE" {
			continue
		}
		filtered = append(filtered, current)
	}
	return append(
		filtered,
		"GOPROXY=file://"+filepath.ToSlash(proxyRoot),
		"GOSUMDB=off",
		"GONOSUMDB=*",
		"GONOPROXY=",
		"GOPRIVATE=",
	)
}

// runFuzzTarget executes one fixed package and exact function without caller selection.
func runFuzzTarget(root, goExecutable string, target FuzzTarget) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	arguments := fuzzArguments(target)
	command := exec.CommandContext(ctx, goExecutable, arguments...)
	command.Dir = filepath.Join(root, target.Module)
	command.Env = appendClosedGoEnvironment(os.Environ(), root)
	output := &boundedOutput{limit: maxRunnerOutput}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("fuzz_timeout")
		}
		return classifyFuzzFailure(err, output.String())
	}
	return nil
}

// cleanFuzzCache removes unversioned discoveries from earlier candidates
// before the closed inventory starts while preserving the shared build cache.
func cleanFuzzCache(root, goExecutable string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, goExecutable, fuzzCacheArguments()...)
	command.Dir = root
	command.Env = appendClosedGoEnvironment(os.Environ(), root)
	output := &boundedOutput{limit: 4096}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || ctx.Err() != nil ||
		strings.TrimSpace(output.String()) != "" {
		return errors.New("fuzz_cache")
	}
	return nil
}

// fuzzCacheArguments returns the exact non-extensible Go cache operation.
func fuzzCacheArguments() []string {
	return []string{"clean", "-fuzzcache"}
}

// classifyFuzzFailure maps process and test failures to content-free diagnostics.
func classifyFuzzFailure(runErr error, output string) error {
	switch {
	case strings.Contains(output, "Failing input written to"),
		strings.Contains(output, "panic:"):
		return errors.New("fuzz_crash")
	case strings.Contains(output, "resource temporarily unavailable"),
		strings.Contains(output, "no space left on device"),
		strings.Contains(output, "failed to create new OS thread"),
		strings.Contains(output, "fatal error: out of memory"),
		strings.Contains(output, "signal: killed"):
		return errors.New("fuzz_resource")
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) && exitError.ExitCode() < 0 {
		return errors.New("fuzz_process")
	}
	return errors.New("fuzz_failure")
}

// fuzzArguments returns the exact non-extensible go test invocation for one target.
func fuzzArguments(target FuzzTarget) []string {
	return []string{
		"test", target.Package,
		"-run=^$",
		"-fuzz=^" + target.Function + "$",
		"-fuzztime=" + FuzzDuration,
		"-parallel=1",
	}
}

// appendClosedGoEnvironment removes caller fuzz knobs and selects private cache paths.
func appendClosedGoEnvironment(environment []string, root string) []string {
	filtered := make([]string, 0, len(environment)+9)
	for _, current := range environment {
		key, _, _ := strings.Cut(current, "=")
		if key == "GOCACHE" ||
			key == "GOMODCACHE" ||
			key == "GOFLAGS" ||
			key == "GOWORK" ||
			key == "GOENV" ||
			key == "GOTOOLCHAIN" ||
			key == "GOVULNDB" ||
			key == "GOOS" ||
			key == "GOARCH" ||
			key == "GOEXPERIMENT" ||
			key == "LANG" ||
			key == "LC_ALL" {
			continue
		}
		filtered = append(filtered, current)
	}
	return append(
		filtered,
		"GOCACHE=/tmp/dkim2-security-go-cache",
		"GOMODCACHE=/tmp/dkim2-security-module-cache",
		"GOFLAGS=",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOVULNDB=https://vuln.go.dev",
		"GOWORK="+filepath.Join(root, "go.work"),
		"LANG=C",
		"LC_ALL=C",
	)
}

// resolveGoExecutable binds the child toolchain to the runner's exact Go identity.
func resolveGoExecutable() (string, string, error) {
	executable, err := exec.LookPath("go")
	if err != nil {
		return "", "", errors.New("security_go_dependency")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return "", "", errors.New("security_go_dependency")
	}
	digest, err := digestRegularFile(executable)
	if err != nil {
		return "", "", errors.New("security_go_dependency")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "version")
	output := &boundedOutput{limit: 4096}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || ctx.Err() != nil {
		return "", "", errors.New("security_go_dependency")
	}
	expected := "go version " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	if strings.TrimSpace(output.String()) != expected {
		return "", "", errors.New("security_go_dependency")
	}
	return executable, digest, nil
}

// scannerVersion returns the bounded scanner identity without database URL material.
func scannerVersion(scanner string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, scanner, "-version")
	output := &boundedOutput{limit: 4096}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return "", errors.New("vulnerability_dependency")
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "Scanner: govulncheck@v") &&
			len(line) <= 64 {
			return strings.TrimPrefix(line, "Scanner: "), nil
		}
	}
	return "", errors.New("vulnerability_dependency")
}

// validateConformanceReport proves one complete strict conformance report.
func validateConformanceReport(
	root, path, profile, candidate string,
	manifest conformance.Manifest,
	manifestDigest string,
) (string, error) {
	input, err := conformance.ReadConfinedFile(root, path, 8<<20)
	if err != nil {
		return "", errors.New("security_external_evidence")
	}
	var report conformance.Report
	if err := conformance.DecodeStrictJSON(input, 8<<20, &report); err != nil ||
		report.Validate(manifest) != nil ||
		report.BaseRevision != BaseRevision ||
		report.CandidateSnapshotSHA256 != candidate ||
		report.ManifestSHA256 != manifestDigest ||
		report.Profile != profile ||
		report.Overall != passState {
		return "", errors.New("security_external_evidence")
	}
	if err := conformance.ValidateJSONSchema(
		root,
		"testdata/conformance/schemas/report.schema.json",
		input,
		8<<20,
	); err != nil {
		return "", errors.New("security_external_evidence")
	}
	return conformance.SHA256(input), nil
}

// validatePostfixReport proves one complete strict real-Postfix report.
func validatePostfixReport(
	root, path, candidate, manifestDigest, producerDigest string,
) (string, error) {
	input, err := conformance.ReadConfinedFile(root, path, 1<<20)
	if err != nil {
		return "", errors.New("security_external_evidence")
	}
	var report conformance.PostfixQualificationReport
	if err := conformance.DecodeStrictJSON(input, 1<<20, &report); err != nil ||
		conformance.ValidatePostfixQualificationReport(
			report,
			manifestDigest,
			BaseRevision,
			candidate,
			producerDigest,
		) != nil {
		return "", errors.New("security_external_evidence")
	}
	return conformance.SHA256(input), nil
}

// readRegularFileBounded charges a stable regular file before allocating its contents.
func readRegularFileBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("security_file")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("security_file")
	}
	input, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(input)) > limit {
		return nil, errors.New("security_file")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() {
		return nil, errors.New("security_file")
	}
	return input, nil
}

// currentSnapshot returns the exact empty-index durable candidate.
func currentSnapshot(root string) (conformance.Snapshot, error) {
	revision, err := conformance.CurrentRevision(root)
	if err != nil || revision != BaseRevision {
		return conformance.Snapshot{}, errors.New("security_base")
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return conformance.Snapshot{}, errors.New("security_snapshot")
	}
	return snapshot, nil
}

// candidateUnchanged rejects evidence spanning two durable candidate states.
func candidateUnchanged(root string, expected conformance.Snapshot) error {
	current, err := currentSnapshot(root)
	if err != nil || current.SHA256 != expected.SHA256 {
		return errors.New("security_candidate")
	}
	return nil
}

// readJSON decodes one bounded strict JSON object from an ignored report path.
func readJSON(root, relative string, limit int64, destination any) error {
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		strings.HasPrefix(relative, "..") {
		return errors.New("security_path")
	}
	input, err := conformance.ReadConfinedFile(root, relative, limit)
	if err != nil {
		return errors.New("security_evidence")
	}
	if err := conformance.DecodeStrictJSON(input, limit, destination); err != nil {
		return errors.New("security_evidence")
	}
	return nil
}

// writeJSONAtomic writes deterministic evidence below an ignored output directory.
func writeJSONAtomic(root, relative string, value any, limit int) error {
	if !strings.HasPrefix(filepath.ToSlash(relative), ".artifacts/security/") ||
		filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return errors.New("security_output")
	}
	input, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(input)+1 > limit {
		return errors.New("security_output")
	}
	input = append(input, '\n')
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("security_output")
	}
	defer func() { _ = rootHandle.Close() }()
	directory := filepath.ToSlash(filepath.Dir(relative))
	if err := createConfinedDirectories(rootHandle, directory); err != nil {
		return errors.New("security_output")
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return errors.New("security_output")
	}
	temporaryPath := filepath.ToSlash(filepath.Join(
		directory,
		".security-report-"+hex.EncodeToString(random[:]),
	))
	temporary, err := rootHandle.OpenFile(
		filepath.FromSlash(temporaryPath),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return errors.New("security_output")
	}
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = rootHandle.Remove(filepath.FromSlash(temporaryPath))
		}
	}()
	if _, err := temporary.Write(input); err != nil || temporary.Sync() != nil ||
		temporary.Close() != nil {
		return errors.New("security_output")
	}
	if err := rootHandle.Rename(
		filepath.FromSlash(temporaryPath),
		filepath.FromSlash(relative),
	); err != nil {
		return errors.New("security_output")
	}
	ok = true
	return nil
}

// createConfinedDirectories creates real private directories without following symlinks.
func createConfinedDirectories(root *os.Root, relative string) error {
	if relative == "." {
		return nil
	}
	current := ""
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("security_output")
		}
		current = filepath.ToSlash(filepath.Join(current, component))
		info, err := root.Lstat(filepath.FromSlash(current))
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return errors.New("security_output")
			}
		case errors.Is(err, os.ErrNotExist):
			if err := root.Mkdir(filepath.FromSlash(current), 0o700); err != nil {
				return errors.New("security_output")
			}
		default:
			return errors.New("security_output")
		}
	}
	return nil
}

// digestRelativeFile hashes one bounded regular evidence file.
func digestRelativeFile(root, relative string, limit int64) (string, error) {
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		strings.HasPrefix(relative, "..") {
		return "", errors.New("security_path")
	}
	input, err := conformance.ReadConfinedFile(root, relative, limit)
	if err != nil {
		return "", errors.New("security_evidence")
	}
	return conformance.SHA256(input), nil
}

// digestRegularFile hashes one stable scanner executable.
func digestRegularFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("vulnerability_dependency")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > 256<<20 {
		return "", errors.New("vulnerability_dependency")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", errors.New("vulnerability_dependency")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() {
		return "", errors.New("vulnerability_dependency")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// isSHA256 reports whether value is exact lowercase hexadecimal SHA-256.
func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

// Write captures bounded process output and aborts on overflow.
func (o *boundedOutput) Write(input []byte) (int, error) {
	if o.buffer.Len()+len(input) > o.limit {
		return 0, errors.New("security_output")
	}
	return o.buffer.Write(input)
}

// String returns captured bounded output for closed scanner identity parsing.
func (o *boundedOutput) String() string {
	return o.buffer.String()
}
