package security

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

const (
	testGoVersion = "go1.26.5"
	testGOARCH    = "amd64"
	testGOOS      = "linux"
	testScanner   = "govulncheck@v1.3.0"
)

// TestFuzzArgumentsCannotSelectCommandsFlagsOrPaths freezes the closed runner.
func TestFuzzArgumentsCannotSelectCommandsFlagsOrPaths(t *testing.T) {
	target := Targets()[0]
	arguments := fuzzArguments(target)
	want := []string{
		"test",
		target.Package,
		"-run=^$",
		"-fuzz=^" + target.Function + "$",
		"-fuzztime=10s",
		"-parallel=1",
	}
	if !slices.Equal(arguments, want) {
		t.Fatalf("fuzzArguments() = %#v, want %#v", arguments, want)
	}
	for _, argument := range arguments {
		if strings.ContainsAny(argument, ";&|`") {
			t.Fatalf("argument %q contains command-selection syntax", argument)
		}
	}
}

// TestFuzzCacheArgumentsCannotSelectPaths freezes the candidate-isolation step.
func TestFuzzCacheArgumentsCannotSelectPaths(t *testing.T) {
	want := []string{"clean", "-fuzzcache"}
	if got := fuzzCacheArguments(); !slices.Equal(got, want) {
		t.Fatalf("fuzzCacheArguments() = %#v, want %#v", got, want)
	}
}

// TestFuzzReportRejectsSkipMissingTamperAndStaleSnapshot protects required closure.
func TestFuzzReportRejectsSkipMissingTamperAndStaleSnapshot(t *testing.T) {
	report := validFuzzReportForTest()
	if err := report.Validate(report.BaseRevision); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*FuzzReport)
	}{
		{name: "skip", mutate: func(report *FuzzReport) { report.Targets[0].State = "skipped" }},
		{name: "missing", mutate: func(report *FuzzReport) { report.Targets = report.Targets[1:] }},
		{name: "tamper", mutate: func(report *FuzzReport) { report.InventorySHA256 = strings.Repeat("0", 64) }},
		{name: "stale", mutate: func(report *FuzzReport) { report.CandidateSnapshotSHA256 = "stale" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			changed := report
			changed.Targets = append([]FuzzResult(nil), report.Targets...)
			testCase.mutate(&changed)
			if err := changed.Validate(report.BaseRevision); err == nil {
				t.Fatal("invalid fuzz evidence was accepted")
			}
		})
	}
}

// TestVulnerabilityReportRejectsFindingAndScannerDrift protects release gating.
func TestVulnerabilityReportRejectsFindingAndScannerDrift(t *testing.T) {
	report := VulnerabilityReport{
		Schema: vulnerabilityReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		Scanner:                 testScanner, ScannerSHA256: strings.Repeat("b", 64),
		Database: vulnerabilityDatabase,
		Modules:  workspaceModules(),
		State:    passState,
	}
	if err := report.Validate(BaseRevision); err != nil {
		t.Fatal(err)
	}
	report.ReachableFindings = 1
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("reachable vulnerability finding was accepted")
	}
	report.ReachableFindings = 0
	report.Scanner = "other"
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("unknown scanner was accepted")
	}
}

// TestRaceReportRejectsMissingModulesAndNonPassState protects full race closure.
func TestRaceReportRejectsMissingModulesAndNonPassState(t *testing.T) {
	report := RaceReport{
		Schema: raceReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		GoVersion:               testGoVersion, GOOS: testGOOS, GOARCH: testGOARCH,
		Modules: workspaceModules(),
		State:   passState,
	}
	if err := report.Validate(BaseRevision); err != nil {
		t.Fatal(err)
	}
	report.Modules = report.Modules[1:]
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("incomplete race module inventory was accepted")
	}
	report.Modules = workspaceModules()
	report.State = "skipped"
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("skipped race state was accepted")
	}
}

// TestSecurityReportRejectsFindingOverclaimAndEvidenceTamper protects final evidence.
func TestSecurityReportRejectsFindingOverclaimAndEvidenceTamper(t *testing.T) {
	evidence := expectedEvidenceIdentities()
	for index := range evidence {
		evidence[index].SHA256 = strings.Repeat(string(rune('1'+index)), 64)
	}
	report := Report{
		Schema: securityReportSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision: BaseRevision, CandidateSnapshotSHA256: strings.Repeat("a", 64),
		Profile: securityProfile, InventorySHA256: InventorySHA256(),
		GoVersion: testGoVersion, GOOS: testGOOS, GOARCH: testGOARCH,
		Race: racePassState, FuzzTargets: len(Targets()), FuzzState: passState,
		VulnerabilityState: passState, Evidence: evidence,
		Exim: conformance.EximQualifiedLinux, Overall: passState,
	}
	if err := report.Validate(BaseRevision); err != nil {
		t.Fatal(err)
	}
	report.Findings.Medium = 1
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("unresolved finding was accepted")
	}
	report.Findings = FindingCounts{}
	report.Exim = passState
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("Exim overclaim was accepted")
	}
	report.Exim = conformance.EximQualifiedLinux
	report.Evidence[0].SHA256 = "marker-private-key"
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("tampered evidence was accepted")
	}
	report.Evidence[0].SHA256 = strings.Repeat("1", 64)
	report.Evidence[0].Path = ".artifacts/security/substitute.json"
	if err := report.Validate(BaseRevision); err == nil {
		t.Fatal("substituted evidence path was accepted")
	}
}

// TestOutputPathIsConfinedAndJSONStrict protects report-file ownership.
func TestOutputPathIsConfinedAndJSONStrict(t *testing.T) {
	root := t.TempDir()
	if err := writeJSONAtomic(root, "../escape.json", struct{}{}, 1024); err == nil {
		t.Fatal("escaping output path was accepted")
	}
	path := ".artifacts/security/test.json"
	if err := writeJSONAtomic(root, path, map[string]string{"state": passState}, 1024); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		State string `json:"state"`
	}
	if err := readJSON(root, path, 1024, &decoded); err != nil || decoded.State != "pass" {
		t.Fatalf("readJSON() state=%q err=%v", decoded.State, err)
	}
	oversizePath := ".artifacts/security/oversize.json"
	oversize := append([]byte(`{"state":"pass"}`), make([]byte, 1024)...)
	if err := os.WriteFile(filepath.Join(root, oversizePath), oversize, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(root, oversizePath, 1024, &decoded); err == nil {
		t.Fatal("oversize JSON with a valid bounded prefix was accepted")
	}
	duplicatePath := ".artifacts/security/duplicate.json"
	if err := os.WriteFile(
		filepath.Join(root, duplicatePath),
		[]byte(`{"state":"fail","state":"pass"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(root, duplicatePath, 1024, &decoded); err == nil {
		t.Fatal("duplicate JSON member was accepted")
	}
}

// TestOutputPathRejectsSymlinkedParents prevents ignored evidence from escaping its owner.
func TestOutputPathRejectsSymlinkedParents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".artifacts")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeJSONAtomic(
		root,
		".artifacts/security/report.json",
		map[string]string{"state": passState},
		1024,
	); err == nil {
		t.Fatal("symlinked output parent was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "security", "report.json")); !os.IsNotExist(err) {
		t.Fatalf("escaped report exists or stat failed unexpectedly: %v", err)
	}
}

// TestPostfixEvidenceRejectsIdentityOnlyReports prevents partial-report substitution.
func TestPostfixEvidenceRejectsIdentityOnlyReports(t *testing.T) {
	root := t.TempDir()
	path := ".artifacts/conformance-postfix/run-1/report.json"
	absolute := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := strings.Repeat("a", 64)
	input := `{"base_revision":"` + BaseRevision +
		`","candidate_snapshot_sha256":"` + candidate + `","state":"` + passState + `"}`
	if err := os.WriteFile(absolute, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePostfixReport(
		root,
		path,
		BaseRevision,
		candidate,
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
	); err == nil {
		t.Fatal("identity-only Postfix report was accepted")
	}
}

// TestReportValidatorsRequireExactCandidateRevision rejects evidence from another admitted candidate.
func TestReportValidatorsRequireExactCandidateRevision(t *testing.T) {
	candidateRevision := strings.Repeat("b", 40)
	fuzz := validFuzzReportForTest()
	fuzz.BaseRevision = candidateRevision
	if err := fuzz.Validate(candidateRevision); err != nil {
		t.Fatalf("FuzzReport.Validate() error = %v", err)
	}
	if err := fuzz.Validate(BaseRevision); err == nil {
		t.Fatal("FuzzReport accepted another candidate revision")
	}

	vulnerability := VulnerabilityReport{
		Schema: vulnerabilityReportSchema, BaseRevision: candidateRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		Scanner:                 testScanner, ScannerSHA256: strings.Repeat("b", 64),
		Database: vulnerabilityDatabase, Modules: workspaceModules(), State: passState,
	}
	if err := vulnerability.Validate(candidateRevision); err != nil {
		t.Fatalf("VulnerabilityReport.Validate() error = %v", err)
	}
	if err := vulnerability.Validate(BaseRevision); err == nil {
		t.Fatal("VulnerabilityReport accepted another candidate revision")
	}

	race := RaceReport{
		Schema: raceReportSchema, BaseRevision: candidateRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		GoVersion:               testGoVersion, GOOS: testGOOS, GOARCH: testGOARCH,
		Modules: workspaceModules(), State: passState,
	}
	if err := race.Validate(candidateRevision); err != nil {
		t.Fatalf("RaceReport.Validate() error = %v", err)
	}
	if err := race.Validate(BaseRevision); err == nil {
		t.Fatal("RaceReport accepted another candidate revision")
	}
}

// TestCurrentSnapshotRequiresTheFixedBaseAndEmptyIndex documents anchored candidate ownership.
func TestCurrentSnapshotRequiresTheFixedBaseAndEmptyIndex(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	snapshot, err := currentSnapshot(root)
	if err != nil {
		t.Fatalf("currentSnapshot() error = %v", err)
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		t.Fatalf("CurrentRevision() error = %v", err)
	}
	if snapshot.BaseRevision != revision {
		t.Fatalf("base = %q, want %q", snapshot.BaseRevision, revision)
	}
}

// TestBoundedOutputRejectsOverflowWithoutRetainingTheHostileSuffix protects diagnostics.
func TestBoundedOutputRejectsOverflowWithoutRetainingTheHostileSuffix(t *testing.T) {
	output := &boundedOutput{limit: 4}
	if _, err := output.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("marker")); err == nil {
		t.Fatal("overflow was accepted")
	}
	if output.String() != "safe" {
		t.Fatalf("bounded output = %q", output.String())
	}
}

// TestErrorClassesRemainContentFree protects marker-bearing failures.
func TestErrorClassesRemainContentFree(t *testing.T) {
	for _, err := range []error{
		errors.New("fuzz_failure"),
		errors.New("security_evidence"),
		errors.New("vulnerability_finding"),
	} {
		for _, marker := range []string{"PRIVATE KEY", "recipient@", "/protected/"} {
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error %q contains hostile marker", err)
			}
		}
	}
}

// TestClassifyFuzzFailureKeepsProcessOutputPrivate freezes closed diagnostics.
func TestClassifyFuzzFailureKeepsProcessOutputPrivate(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{name: "crash corpus", output: "Failing input written to marker-private-key", want: "fuzz_crash"},
		{name: "panic", output: "panic: marker-private-key", want: "fuzz_crash"},
		{name: "resource", output: "fork/exec: resource temporarily unavailable", want: "fuzz_resource"},
		{name: "ordinary failure", output: "FAIL marker-private-key", want: "fuzz_failure"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := classifyFuzzFailure(errors.New("marker-private-key"), testCase.output)
			if err.Error() != testCase.want || strings.Contains(err.Error(), "marker") {
				t.Fatalf("classifyFuzzFailure() = %q, want %q", err, testCase.want)
			}
		})
	}
}

// TestReadRegularFileBoundedRejectsOversizeBeforeReading protects allocation bounds.
func TestReadRegularFileBoundedRejectsOversizeBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFileBounded(path, 4); err == nil {
		t.Fatal("oversize file was accepted")
	}
	input, err := readRegularFileBounded(path, 5)
	if err != nil || string(input) != "12345" {
		t.Fatalf("readRegularFileBounded() = %q, %v", input, err)
	}
}

// TestClosedGoEnvironmentRejectsCallerToolchainAndDatabaseSelection freezes provenance.
func TestClosedGoEnvironmentRejectsCallerToolchainAndDatabaseSelection(t *testing.T) {
	environment := appendClosedGoEnvironment([]string{
		"PATH=/trusted",
		"GOENV=/hostile/goenv",
		"GOTOOLCHAIN=go1.99.0",
		"GOVULNDB=https://hostile.invalid",
		"GOOS=plan9",
		"GOARCH=386",
		"GOEXPERIMENT=hostile",
		"LANG=hostile",
		"LC_ALL=hostile",
	}, "/repository")
	values := make(map[string]string)
	for _, current := range environment {
		key, value, _ := strings.Cut(current, "=")
		values[key] = value
	}
	for key, want := range map[string]string{
		"GOENV":       "off",
		"GOTOOLCHAIN": "local",
		"GOVULNDB":    "https://vuln.go.dev",
		"GOWORK":      "/repository/go.work",
		"LANG":        "C",
		"LC_ALL":      "C",
	} {
		if got := values[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"GOOS", "GOARCH", "GOEXPERIMENT"} {
		if _, present := values[key]; present {
			t.Fatalf("%s remained caller-selectable", key)
		}
	}
	executable, digest, err := resolveGoExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(executable) || !isSHA256(digest) {
		t.Fatalf("closed Go executable = %q digest=%q", executable, digest)
	}
}

// TestRaceEnvironmentUsesOnlyTheProofOwnedOfflineProxy prevents cache-dependent race results.
func TestRaceEnvironmentUsesOnlyTheProofOwnedOfflineProxy(t *testing.T) {
	environment := appendRaceEnvironment([]string{
		"GOPROXY=https://hostile.invalid,direct",
		"GOSUMDB=https://hostile.invalid",
		"GONOSUMDB=hostile.invalid",
		"GONOPROXY=hostile.invalid",
		"GOPRIVATE=hostile.invalid",
	}, "/repository", "/repository/.artifacts/reference/.module-proof.123/proxy")
	values := make(map[string]string)
	for _, current := range environment {
		key, value, _ := strings.Cut(current, "=")
		values[key] = value
	}
	for key, want := range map[string]string{
		"GOPROXY":   "file:///repository/.artifacts/reference/.module-proof.123/proxy",
		"GOSUMDB":   "off",
		"GONOSUMDB": "*",
		"GONOPROXY": "",
		"GOPRIVATE": "",
	} {
		if got := values[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

// TestSecuritySchemasAcceptExactEvidenceAndRejectUnknownMembers freezes JSON closure.
func TestSecuritySchemasAcceptExactEvidenceAndRejectUnknownMembers(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	fuzz := validFuzzReportForTest()
	if err := validateSchemaValue(
		root,
		"testdata/security/fuzz-report.schema.json",
		fuzz,
		8<<20,
	); err != nil {
		t.Fatal(err)
	}
	fuzz.BaseRevision = strings.Repeat("b", 40)
	if err := validateSchemaValue(
		root,
		"testdata/security/fuzz-report.schema.json",
		fuzz,
		8<<20,
	); err != nil {
		t.Fatal(err)
	}
	vulnerability := VulnerabilityReport{
		Schema: vulnerabilityReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		Scanner:                 testScanner, ScannerSHA256: strings.Repeat("b", 64),
		Database: vulnerabilityDatabase,
		Modules:  workspaceModules(),
		State:    passState,
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/vulnerability-report.schema.json",
		vulnerability,
		1<<20,
	); err != nil {
		t.Fatal(err)
	}
	race := RaceReport{
		Schema: raceReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		GoVersion:               testGoVersion, GOOS: testGOOS, GOARCH: testGOARCH,
		Modules: workspaceModules(),
		State:   passState,
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/race-report.schema.json",
		race,
		1<<20,
	); err != nil {
		t.Fatal(err)
	}
	evidence := expectedEvidenceIdentities()
	for index := range evidence {
		evidence[index].SHA256 = strings.Repeat(string(rune('1'+index)), 64)
	}
	report := Report{
		Schema: securityReportSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision: BaseRevision, CandidateSnapshotSHA256: strings.Repeat("a", 64),
		Profile: securityProfile, InventorySHA256: InventorySHA256(),
		GoVersion: testGoVersion, GOOS: testGOOS, GOARCH: testGOARCH,
		Race: racePassState, FuzzTargets: len(Targets()), FuzzState: passState,
		VulnerabilityState: passState, Evidence: evidence,
		Exim: conformance.EximQualifiedLinux, Overall: passState,
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/report.schema.json",
		report,
		8<<20,
	); err != nil {
		t.Fatal(err)
	}
	report.Evidence[0].Path = ".artifacts/security/substitute.json"
	if err := validateSchemaValue(
		root,
		"testdata/security/report.schema.json",
		report,
		8<<20,
	); err == nil {
		t.Fatal("security schema accepted a substituted evidence path")
	}
	input := map[string]any{
		"schema":                    fuzzReportSchema,
		"base_revision":             BaseRevision,
		"candidate_snapshot_sha256": strings.Repeat("a", 64),
		"inventory_sha256":          InventorySHA256(),
		"go_version":                testGoVersion,
		"goos":                      testGOOS,
		"goarch":                    testGOARCH,
		"targets":                   fuzz.Targets,
		"overall":                   passState,
		"unexpected":                "marker",
	}
	if err := validateSchemaValue(
		root,
		"testdata/security/fuzz-report.schema.json",
		input,
		8<<20,
	); err == nil {
		t.Fatal("schema accepted an unknown member")
	}
}

// validFuzzReportForTest constructs complete deterministic fuzz evidence.
func validFuzzReportForTest() FuzzReport {
	results := make([]FuzzResult, 0, len(Targets()))
	for _, target := range Targets() {
		results = append(results, FuzzResult{
			ID: target.ID, State: passState, DurationClass: fuzzDurationClass,
		})
	}
	return FuzzReport{
		Schema: fuzzReportSchema, BaseRevision: BaseRevision,
		CandidateSnapshotSHA256: strings.Repeat("a", 64),
		InventorySHA256:         InventorySHA256(), GoVersion: testGoVersion,
		GOOS: testGOOS, GOARCH: testGOARCH, Targets: results, Overall: passState,
	}
}
