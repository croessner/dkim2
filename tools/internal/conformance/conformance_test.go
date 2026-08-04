package conformance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	codeKey             = "code"
	digestKey           = "digest"
	dispositionKey      = "disposition"
	draftNormativeClass = "draft_normative"
	expectedKey         = "expected"
	inputKey            = "input"
	manualProvenance    = "manual_derivation"
	stateKey            = "state"
	testAuthority       = "test authority"
	fixtureCaseID       = "case"
	fixtureModule       = "testdata/conformance"
	fixtureOnePath      = "one.json"
	fixtureRunner       = "milter_fixture"
	fixtureSuite        = "suite"
	runnerName          = "runner"
	verificationSuite   = "verification"
	verifyArtifactID    = "verify"
)

// TestStrictJSONRejectsDuplicateUnknownAndDeepInput freezes the closed JSON boundary.
func TestStrictJSONRejectsDuplicateUnknownAndDeepInput(t *testing.T) {
	var target struct {
		Value string `json:"value"`
	}
	for _, input := range []string{
		`{"value":"a","value":"b"}`,
		`{"value":"a","unknown":true}`,
		strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1),
		"\xef\xbb\xbf{}",
		`{"value":"a"} true`,
	} {
		if err := DecodeStrictJSON([]byte(input), 1024, &target); err == nil {
			t.Fatalf("DecodeStrictJSON(%q) succeeded", input)
		}
	}
}

// TestSchemaClosureRejectsNoCheckedInOpenShapes proves the durable schema oracle.
func TestSchemaClosureRejectsNoCheckedInOpenShapes(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if err := ValidateSchemaClosure(root); err != nil {
		t.Fatalf("ValidateSchemaClosure() error = %v", err)
	}
}

// TestManifestSchemaMatchesCanonicalManifest proves the durable schema is executable.
func TestManifestSchemaMatchesCanonicalManifest(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if err := ValidateRepositoryJSONSchema(
		root,
		"testdata/conformance/schemas/manifest.schema.json",
		"testdata/conformance/manifest.json",
		maxManifestBytes,
	); err != nil {
		t.Fatalf("ValidateRepositoryJSONSchema() error = %v", err)
	}
}

// TestJSONSchemaRejectsExternalResources freezes offline schema evaluation.
func TestJSONSchemaRejectsExternalResources(t *testing.T) {
	root := t.TempDir()
	schema := []byte(`{
	  "$schema":"https://json-schema.org/draft/2020-12/schema",
	  "$ref":"file:///etc/passwd"
	}`)
	if err := os.WriteFile(filepath.Join(root, "schema.json"), schema, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJSONSchema(root, "schema.json", []byte(`{}`), 1024); err == nil {
		t.Fatal("ValidateJSONSchema accepted an external schema resource")
	}
}

// TestCaseRejectsNestedUnknownAndMultipleOperations freezes exact operation closure.
func TestCaseRejectsNestedUnknownAndMultipleOperations(t *testing.T) {
	base := `{
	  "schema":"dkim2.conformance-case.v1",
	  "case_id":"closed-case",
	  "message_draft":"draft-ietf-dkim-dkim2-spec-04",
	  "dns_draft":"draft-chuang-dkim2-dns-04",
	  "class":"draft_normative",
	  "authority":["draft-ietf-dkim-dkim2-spec-04 Section 4"],
	  "provenance":"manual_derivation",
	  "verify":{"input":{"message_b64":"","reverse_path_b64":"","forward_paths_b64":[]%s},"expected":{"code":"pass","state":"pass"}}%s
	}`
	if _, err := ValidateCaseBytes([]byte(strings.ReplaceAll(
		strings.ReplaceAll(base, "%s", `,"unexpected":true`),
		`%s`, "",
	))); err == nil {
		t.Fatal("ValidateCaseBytes accepted a nested unknown member")
	}
	second := `,"sign":{"input":{"message_b64":"","reverse_path_b64":"","forward_paths_b64":[]},"expected":{"code":"pass","state":"pass"}}`
	input := strings.Replace(base, "%s", "", 1)
	input = strings.Replace(input, "%s", second, 1)
	if _, err := ValidateCaseBytes([]byte(input)); err == nil {
		t.Fatal("ValidateCaseBytes accepted multiple operations")
	}
}

// TestCaseSchemaMatchesGoValidation freezes operation-specific schema parity.
func TestCaseSchemaMatchesGoValidation(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	digest := strings.Repeat("0", 64)
	mailInput := map[string]any{
		"message_b64": "", "reverse_path_b64": "", "forward_paths_b64": []string{},
	}
	cases := map[string]map[string]any{
		operationVerify: {
			inputKey: mailInput, expectedKey: map[string]any{
				codeKey: statePass, stateKey: statePassUpper, digestKey: digest,
			},
		},
		operationSign: {
			inputKey: mailInput, expectedKey: map[string]any{
				codeKey: statePass, stateKey: "signed", digestKey: digest, dispositionKey: dispositionContinue,
			},
		},
		operationRevise: {
			inputKey: mailInput, expectedKey: map[string]any{
				codeKey: statePass, stateKey: "revised", digestKey: digest, dispositionKey: dispositionContinue,
			},
		},
		operationOpenAPI: {
			inputKey: mailInput, expectedKey: map[string]any{
				codeKey: statePass, stateKey: "contract_match", dispositionKey: noMutationState,
			},
		},
		operationMilter: {
			inputKey: mailInput, expectedKey: map[string]any{
				codeKey: statePass, stateKey: stateAccept, dispositionKey: stateAccept,
			},
		},
		operationRecipeApply: {
			"recipe_b64": "", "current_message_b64": "",
			expectedKey: map[string]any{codeKey: statePass, stateKey: "applied", digestKey: digest},
		},
		operationRecipeGenerate: {
			"before_message_b64": "", "after_message_b64": "", "body_policy": "available",
			expectedKey: map[string]any{codeKey: statePass, stateKey: "generated", digestKey: digest},
		},
		operationDNS: {
			"record_b64": "", "algorithm": "ed25519-sha256",
			expectedKey: map[string]any{codeKey: statePass, stateKey: "found"},
		},
		operationPolicy: {
			"verification_state": statePassUpper, "mode": "strict",
			expectedKey: map[string]any{
				codeKey: statePass, stateKey: stateAccept, dispositionKey: stateAccept,
			},
		},
		operationReplay: {
			"identity_b64": "", "clock_unix": 0,
			expectedKey: map[string]any{codeKey: codeFirstSeen, stateKey: codeFirstSeen},
		},
	}
	for operation, value := range cases {
		t.Run(operation, func(t *testing.T) {
			instance := map[string]any{
				"schema": "dkim2.conformance-case.v1", "case_id": operation,
				"message_draft": MessageDraft, "dns_draft": DNSDraft,
				"class":      draftNormativeClass,
				"authority":  []string{MessageDraft + " Section 1"},
				"provenance": manualProvenance, operation: value,
			}
			input, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			assertCaseParity(t, root, input, true)
			value[expectedKey].(map[string]any)[stateKey] = "invalid-correlation"
			invalid, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			assertCaseParity(t, root, invalid, false)
		})
	}
}

// assertCaseParity requires the checked-in schema and Go model to reach one decision.
func assertCaseParity(t *testing.T, root string, input []byte, want bool) {
	t.Helper()
	schemaErr := ValidateJSONSchema(
		root, "testdata/conformance/schemas/case.schema.json", input, maxVectorBytes,
	)
	_, goErr := ValidateCaseBytes(input)
	if (schemaErr == nil) != want || (goErr == nil) != want {
		t.Fatalf("schema error = %v, Go error = %v, want acceptance %t", schemaErr, goErr, want)
	}
}

// TestEximQualificationSummaryRejectsStaleCandidateBinding freezes the import boundary.
func TestEximQualificationSummaryRejectsStaleCandidateBinding(t *testing.T) {
	summary := validEximQualificationSummaryForTest()
	if err := ValidateEximQualificationSummary(
		summary,
		strings.Repeat("a", 64),
		strings.Repeat("b", 40),
		strings.Repeat("c", 64),
		strings.Repeat("d", 64),
	); err != nil {
		t.Fatalf("ValidateEximQualificationSummary() error = %v", err)
	}
	summary.CandidateSnapshotSHA256 = strings.Repeat("e", 64)
	if err := ValidateEximQualificationSummary(
		summary,
		strings.Repeat("a", 64),
		strings.Repeat("b", 40),
		strings.Repeat("c", 64),
		strings.Repeat("d", 64),
	); err == nil {
		t.Fatal("ValidateEximQualificationSummary accepted stale candidate binding")
	}
}

// validEximQualificationSummaryForTest returns one exact synthetic matrix import.
func validEximQualificationSummaryForTest() EximQualificationSummary {
	names := []string{
		"debian-4.98.2-1+deb13u3",
		"debian-4.98.2-1+deb13u4",
		"ubuntu-4.99.1-1ubuntu1.3",
		"ubuntu-4.99.1-1ubuntu1.4",
		"upstream-4.99.5",
	}
	versions := []string{
		"4.98.2-1+deb13u3",
		"4.98.2-1+deb13u4",
		"4.99.1-1ubuntu1.3",
		"4.99.1-1ubuntu1.4",
		"4.99.5",
	}
	rows := make([]EximQualificationRow, 0, len(names))
	for index := range names {
		rows = append(rows, EximQualificationRow{
			Name: names[index], EximVersion: versions[index],
			ResultSHA256: strings.Repeat("f", 64), CaseCount: 43, State: statePass,
		})
	}
	return EximQualificationSummary{
		Schema:       "dkim2.exim-linux-qualification.v1",
		MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision:            strings.Repeat("b", 40),
		CandidateSnapshotSHA256: strings.Repeat("c", 64),
		ManifestSHA256:          strings.Repeat("a", 64),
		Profile:                 eximQualificationProfile, Platform: platformLinux,
		ProducerSHA256: strings.Repeat("d", 64), State: statePass,
		RunID: strings.Repeat("e", 64), RunManifestSHA256: strings.Repeat("f", 64),
		Rows: rows, TotalCases: 215, PrivacyScan: "passed",
	}
}

// TestManifestRejectsIntermediateSymlinkEscape reproduces descriptor-escape risk.
func TestManifestRejectsIntermediateSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWriteFile(t, filepath.Join(outside, "fixture.json"), []byte("{}"))
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(Artifact{
		ID: fixtureCaseID, Path: "linked/fixture.json", SHA256: SHA256([]byte("{}")),
		Module: fixtureModule,
	})
	if err := manifest.Validate(root); err == nil {
		t.Fatal("Validate accepted an intermediate symlink")
	}
}

// TestManifestRejectsHardLinkAmbiguity reproduces one inode under two artifact names.
func TestManifestRejectsHardLinkAmbiguity(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, fixtureOnePath), []byte("{}"))
	if err := os.Link(filepath.Join(root, fixtureOnePath), filepath.Join(root, "two.json")); err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(
		Artifact{
			ID: "a", Path: fixtureOnePath, SHA256: SHA256([]byte("{}")),
			Module: fixtureModule,
		},
		Artifact{
			ID: "b", Path: "two.json", SHA256: SHA256([]byte("{}")),
			Module: fixtureModule,
		},
	)
	if err := manifest.Validate(root); err == nil {
		t.Fatal("Validate accepted hard-linked artifacts")
	}
}

// TestManifestRejectsDuplicateExactArtifactPath freezes one identity per path.
func TestManifestRejectsDuplicateExactArtifactPath(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, fixtureOnePath), []byte("{}"))
	manifest := testManifest(
		Artifact{ID: "a", Path: fixtureOnePath, SHA256: SHA256([]byte("{}")), Module: fixtureModule},
		Artifact{ID: "b", Path: fixtureOnePath, SHA256: SHA256([]byte("{}")), Module: fixtureModule},
	)
	if err := manifest.Validate(root); err == nil {
		t.Fatal("Validate accepted duplicate artifact paths")
	}
}

// TestManifestAllowsMultipleCasesToShareOneArtifact freezes independent inventories.
func TestManifestAllowsMultipleCasesToShareOneArtifact(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "shared.json"), []byte("{}"))
	manifest := testManifest(Artifact{
		ID: "shared", Path: "shared.json", SHA256: SHA256([]byte("{}")),
		Module: fixtureModule,
	})
	manifest.Cases = append(manifest.Cases, ManifestCase{
		Suite: fixtureSuite, CaseID: "zsecond", Class: classAdapter,
		Authority: []string{testAuthority}, Provenance: manualProvenance,
		Runner: fixtureRunner, RequiredPlatform: profilePortable,
		ExpectedOutcome: statePass, Artifacts: []string{"shared"},
		Producer: "test-runner",
	})
	if err := manifest.Validate(root); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// TestManifestRejectsOrphanAndUnknownArtifactReferences freezes graph closure.
func TestManifestRejectsOrphanAndUnknownArtifactReferences(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, fixtureOnePath), []byte("{}"))
	base := testManifest(Artifact{
		ID: "one", Path: fixtureOnePath, SHA256: SHA256([]byte("{}")),
		Module: fixtureModule,
	})
	base.Cases[0].Artifacts = []string{"missing"}
	if err := base.Validate(root); err == nil {
		t.Fatal("Validate accepted an unknown artifact reference")
	}
	base = testManifest(Artifact{
		ID: "one", Path: fixtureOnePath, SHA256: SHA256([]byte("{}")),
		Module: fixtureModule,
	})
	base.Cases = nil
	if err := base.Validate(root); err == nil {
		t.Fatal("Validate accepted an orphan artifact")
	}
}

// TestReportRejectsSelfAssertedCountsAndToolIdentity freezes derived report facts.
func TestReportRejectsSelfAssertedCountsAndToolIdentity(t *testing.T) {
	manifest := testManifest(Artifact{
		ID: "case", Path: "unused", SHA256: strings.Repeat("0", 64),
		Module: fixtureModule,
	})
	report := Report{
		Schema: ReportSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		ManifestSchema: ManifestSchema, ManifestSHA256: strings.Repeat("1", 64),
		BaseRevision: strings.Repeat("2", 40), CandidateSnapshotSHA256: strings.Repeat("3", 64),
		Profile: profilePortable, Platform: profilePortable, Capabilities: cloneMap(manifest.Capabilities),
		Tools: []ToolIdentity{{Name: runnerName, Digest: "not-a-digest"}},
		Cases: []CaseResult{{
			Suite: fixtureSuite, CaseID: fixtureCaseID, Class: classAdapter, State: statePass,
			ArtifactSHA256: []string{strings.Repeat("0", 64)},
			ProducerSHA256: strings.Repeat("4", 64),
		}},
		Counts:  []ClassCount{{Class: classAdapter, State: statePass, Count: 99}},
		Overall: statePass,
	}
	if err := report.Validate(manifest); err == nil {
		t.Fatal("Validate accepted self-asserted counts and invalid tool identity")
	}
}

// TestSnapshotHandlesTrackedDeletion freezes current-tree deletion semantics.
func TestSnapshotHandlesTrackedDeletion(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "DKIM2 Test")
	runGit(t, root, "config", "user.email", "test@example.test")
	mustWriteFile(t, filepath.Join(root, "kept"), []byte("kept"))
	mustWriteFile(t, filepath.Join(root, "deleted"), []byte("deleted"))
	runGit(t, root, "add", "kept", "deleted")
	runGit(t, root, "commit", "-m", "fixture")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	if err := os.Remove(filepath.Join(root, "deleted")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ProduceSnapshot(root, base)
	if err != nil {
		t.Fatalf("ProduceSnapshot() error = %v", err)
	}
	for _, entry := range snapshot.Entries {
		if entry.Path == "deleted" {
			t.Fatal("deleted path entered current-tree snapshot")
		}
	}
}

// TestIsRevisionAncestorRejectsDescendantAndMalformedRevisions freezes the trust-anchor check.
func TestIsRevisionAncestorRejectsDescendantAndMalformedRevisions(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "DKIM2 Test")
	runGit(t, root, "config", "user.email", "test@example.test")
	mustWriteFile(t, filepath.Join(root, "one"), []byte("one"))
	runGit(t, root, "add", "one")
	runGit(t, root, "commit", "-m", "first")
	first := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	mustWriteFile(t, filepath.Join(root, "two"), []byte("two"))
	runGit(t, root, "add", "two")
	runGit(t, root, "commit", "-m", "second")
	second := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	if err := IsRevisionAncestor(root, first, second); err != nil {
		t.Fatalf("IsRevisionAncestor() error = %v", err)
	}
	if err := IsRevisionAncestor(root, second, first); err == nil {
		t.Fatal("IsRevisionAncestor accepted a descendant as an ancestor")
	}
	if err := IsRevisionAncestor(root, "not-a-revision", second); err == nil {
		t.Fatal("IsRevisionAncestor accepted a malformed revision")
	}
}

// testManifest returns the minimal closed manifest around artifacts.
func testManifest(artifacts ...Artifact) Manifest {
	cases := make([]ManifestCase, 0, len(artifacts))
	for _, artifact := range artifacts {
		cases = append(cases, ManifestCase{
			Suite: fixtureSuite, CaseID: artifact.ID, Class: classAdapter,
			Authority: []string{testAuthority}, Provenance: manualProvenance,
			Runner: fixtureRunner, RequiredPlatform: profilePortable,
			ExpectedOutcome: statePass, Artifacts: []string{artifact.ID},
			Producer: "test-runner",
		})
	}
	return Manifest{
		Schema: ManifestSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		SuiteVersion: "1", Suites: []string{fixtureSuite},
		Capabilities: map[string]string{
			capLibrary: supportedCapability, capDaemon: supportedCapability,
			capMilter: partialCapability, capPostfix: partialLinuxCapability,
			capExim: EximQualifiedLinux,
		},
		Artifacts: artifacts, Cases: cases,
	}
}

// mustWriteFile writes one test file and creates its parent.
func mustWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runGit runs one test-local Git command and returns stdout.
func runGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}

// TestReportJSONIsDeterministic proves stable encoding.
func TestReportJSONIsDeterministic(t *testing.T) {
	report := Report{
		Schema: ReportSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		Capabilities: map[string]string{"exim": EximQualifiedLinux},
	}
	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(report)
	if err != nil || string(first) != string(second) {
		t.Fatal("report encoding was not deterministic")
	}
}

// TestHumanReportGolden freezes deterministic public claim rendering.
func TestHumanReportGolden(t *testing.T) {
	manifest := Manifest{
		Schema: ManifestSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		SuiteVersion: "1", Suites: []string{capExim, verificationSuite},
		Capabilities: map[string]string{
			capLibrary: supportedCapability, capDaemon: supportedCapability,
			capMilter: partialCapability, capPostfix: partialLinuxCapability,
			capExim: EximQualifiedLinux,
		},
		Artifacts: []Artifact{
			{ID: capExim, SHA256: strings.Repeat("5", 64)},
			{ID: verifyArtifactID, SHA256: strings.Repeat("6", 64)},
		},
		Cases: []ManifestCase{
			{
				Suite: capExim, CaseID: "linux-real-matrix", Class: classAdapter,
				Authority: []string{testAuthority}, Provenance: manualProvenance,
				Runner: runnerExim, RequiredPlatform: platformLinux,
				ExpectedOutcome: statePass, Artifacts: []string{capExim}, Producer: "exim-runner",
			},
			{
				Suite: verificationSuite, CaseID: "public", Class: "draft_normative",
				Authority: []string{testAuthority}, Provenance: "cross_primitive",
				Runner: "portable_vector", RequiredPlatform: profilePortable,
				ExpectedOutcome: statePass, Artifacts: []string{verifyArtifactID}, Producer: runnerName,
			},
		},
	}
	report, err := NewReport(
		manifest, strings.Repeat("1", 64), strings.Repeat("2", 40),
		strings.Repeat("3", 64), profilePortable, profilePortable,
		[]ToolIdentity{{Name: runnerName, Digest: strings.Repeat("4", 64)}},
		[]CaseResult{
			{
				Suite: verificationSuite, CaseID: "public", Class: "draft_normative",
				State: statePass, ArtifactSHA256: []string{strings.Repeat("6", 64)},
				Producer: runnerName, ProducerSHA256: strings.Repeat("4", 64),
			},
			{
				Suite: capExim, CaseID: "linux-real-matrix", Class: classAdapter,
				State: stateNotApplicable, ArtifactSHA256: []string{strings.Repeat("5", 64)},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	golden, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "testdata", "conformance", "report-golden", "portable.md",
	))
	if err != nil {
		t.Fatal(err)
	}
	if got := report.RenderText(); string(got) != string(golden) {
		t.Fatalf("RenderText() drifted:\n%s", got)
	}
	report.Cases[1].State = stateNotApplicable
	report.Cases[1].Producer = ""
	report.Cases[1].ProducerSHA256 = ""
	report.Counts = countCases(report.Cases)
	if err := report.Validate(manifest); err == nil {
		t.Fatal("Validate accepted platform state for an ordinary portable case")
	}
}
