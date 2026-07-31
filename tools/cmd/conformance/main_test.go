package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

const (
	testFixtureArtifact = "fixture"
	testPortableRunner  = "portable_vector"
)

// TestPublicFailureDiagnosticRejectsHostileContent freezes content-free diagnostics.
func TestPublicFailureDiagnosticRejectsHostileContent(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want string
	}{
		{name: "closed", err: errors.New("runner_failure:closed-producer"), want: "runner_failure:closed-producer"},
		{name: "raw error", err: errors.New("runner failure /protected/marker"), want: unknownDiagnostic},
		{name: "nil", err: nil, want: unknownDiagnostic},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := publicFailureDiagnostic(testCase.err); got != testCase.want {
				t.Fatalf("publicFailureDiagnostic() = %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestPostfixQualificationReportValidation proves every merge identity and
// required real-process observation is checked before full-profile admission.
func TestPostfixQualificationReportValidation(t *testing.T) {
	report := validPostfixQualificationReportForTest()
	if err := validatePostfixQualificationReport(
		report,
		strings.Repeat("b", 64),
		strings.Repeat("c", 40),
		strings.Repeat("d", 64),
		strings.Repeat("e", 64),
	); err != nil {
		t.Fatalf("validatePostfixQualificationReport() error = %v", err)
	}
	report.RuntimeIdentity.Executables["dkim2d"] = strings.Repeat("f", 63)
	if err := validatePostfixQualificationReport(
		report,
		strings.Repeat("b", 64),
		strings.Repeat("c", 40),
		strings.Repeat("d", 64),
		strings.Repeat("e", 64),
	); err == nil {
		t.Fatal("validatePostfixQualificationReport accepted a malformed daemon identity")
	}
}

// FuzzPostfixQualificationReportDecoding exercises bounded strict merge input decoding.
func FuzzPostfixQualificationReportDecoding(f *testing.F) {
	seed, err := json.Marshal(validPostfixQualificationReportForTest())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema":"dkim2.postfix-qualification-report.v1"}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if len(input) > 1<<20+1 {
			input = input[:1<<20+1]
		}
		var report postfixQualificationReport
		_ = conformance.DecodeStrictJSON(input, 1<<20, &report)
	})
}

// validPostfixQualificationReportForTest returns one synthetic closed report.
func validPostfixQualificationReportForTest() postfixQualificationReport {
	digest := strings.Repeat("a", 64)
	return postfixQualificationReport{
		Schema:                  "dkim2.postfix-qualification-report.v1",
		MessageDraft:            conformance.MessageDraft,
		DNSDraft:                conformance.DNSDraft,
		BaseRevision:            strings.Repeat("c", 40),
		CandidateSnapshotSHA256: strings.Repeat("d", 64),
		ManifestSHA256:          strings.Repeat("b", 64),
		Profile:                 postfixProfile,
		Platform:                linuxPlatform,
		ProducerSHA256:          strings.Repeat("e", 64),
		State:                   passState,
		ImageIdentities: map[string]string{
			"debian":  "debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e",
			"golang":  "golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6",
			"postfix": "chrroessner/postfix@sha256:13cd39ff85a2edece32bdf3a4cdaa123c1a7d91db0e296f840c3ffe3d9121a4d",
		},
		RuntimeIdentity: postfixQualificationRuntimeIdentity{
			Schema: "dkim2.postfix-qualification-identity.v1", PostfixVersion: "3.11.5",
			Executables: map[string]string{
				"dkim2-milter": digest, "dkim2d": digest, "qualify": digest,
			},
		},
		Fragments: []postfixQualificationReportFragment{
			{
				Schema: postfixFragmentSchema, State: passState,
				Cases: []string{
					"daemon_loopback_topology",
					"inbound_cryptographic_pass",
					"local_sendmail_signing",
					"postfix_received_visibility",
					"smtp_origin_signing",
				},
			},
			{
				Schema: postfixFragmentSchema, State: passState,
				Cases: []string{"daemon_unavailable_fixed_tempfail"},
			},
			{
				Schema: postfixFragmentSchema, State: passState,
				Cases: []string{
					"non_smtp_milter_unavailable_tempfail",
					"smtp_milter_unavailable_tempfail",
				},
			},
		},
		Topology: postfixQualificationTopology{
			ComposeHostPorts: 0, DaemonHTTP: "canonical_loopback_only",
			MilterTransport: "owned_unix_sockets_only", PostfixProtocol: 6,
			PostfixDefaultAction: "tempfail",
			MilterConnectTimeout: "2s", MilterCommandTimeout: "5s",
			MilterContentTimeout: "5s",
		},
		Cleanup: "project_scoped_pass",
	}
}

// TestQualificationDockerHostEnvironmentAllowsOnlyAbsoluteUnixSockets freezes
// the one Docker context value admitted into the isolated child environment.
func TestQualificationDockerHostEnvironmentAllowsOnlyAbsoluteUnixSockets(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	environment, err := qualificationDockerHostEnvironment()
	if err != nil || environment != nil {
		t.Fatalf("empty Docker host environment = %v, %v", environment, err)
	}
	t.Setenv("DOCKER_HOST", "unix:///tmp/docker.sock")
	environment, err = qualificationDockerHostEnvironment()
	if err != nil ||
		!slices.Equal(environment, []string{"DOCKER_HOST=unix:///tmp/docker.sock"}) {
		t.Fatalf("Unix Docker host environment = %v, %v", environment, err)
	}
	for _, value := range []string{
		"tcp://127.0.0.1:2375",
		"unix://relative/docker.sock",
		"unix:///tmp/../docker.sock",
		"unix:///tmp/docker.sock?secret=value",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DOCKER_HOST", value)
			if _, err := qualificationDockerHostEnvironment(); err == nil {
				t.Fatal("unsafe Docker host environment was accepted")
			}
		})
	}
}

// TestAbsoluteQualificationRootResolvesExecutableBase proves the Makefile's
// relative root cannot be applied a second time after setting the child Dir.
func TestAbsoluteQualificationRootResolvesExecutableBase(t *testing.T) {
	root, err := absoluteQualificationRoot(filepath.Join("..", "..", ".."))
	if err != nil || !filepath.IsAbs(root) {
		t.Fatalf("absoluteQualificationRoot() = %q, %v", root, err)
	}
	script := filepath.Join(
		root,
		"contrib",
		"qualification",
		"postfix-milter",
		"run.sh",
	)
	info, err := os.Stat(script)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("resolved qualification script = %q, %v", script, err)
	}
}

// TestRepositoryCheckValid proves schema and artifact closure for the checked-in suite.
func TestRepositoryCheckValid(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if err := check(root); err != nil {
		t.Fatalf("check() error = %v", err)
	}
}

// TestCandidateMutationAfterRunnerIsRejected reproduces stale-snapshot report evidence.
func TestCandidateMutationAfterRunnerIsRejected(t *testing.T) {
	root := t.TempDir()
	runGitCommand(t, root, "init")
	runGitCommand(t, root, "config", "user.name", "DKIM2 Test")
	runGitCommand(t, root, "config", "user.email", "test@example.test")
	path := filepath.Join(root, testFixtureArtifact)
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitCommand(t, root, "add", testFixtureArtifact)
	runGitCommand(t, root, "commit", "-m", testFixtureArtifact)
	revision := strings.TrimSpace(runGitCommand(t, root, "rev-parse", "HEAD"))
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed during runner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateUnchanged(root, revision, snapshot.SHA256); err == nil {
		t.Fatal("verifyCandidateUnchanged accepted a post-runner mutation")
	}
}

// TestRunnerInventoryRejectsUnexecutedManifestCase freezes exact per-case evidence.
func TestRunnerInventoryRejectsUnexecutedManifestCase(t *testing.T) {
	var cases []conformance.ManifestCase
	for _, definition := range portableDefinitions {
		for _, runnerCase := range definition.cases {
			parts := strings.SplitN(runnerCase.key, "\x00", 2)
			cases = append(cases, conformance.ManifestCase{
				Suite: parts[0], CaseID: parts[1], Class: "draft_normative",
				Authority: []string{"test authority"}, Provenance: "manual_derivation",
				Runner: testPortableRunner, RequiredPlatform: portableProfile,
				ExpectedOutcome: passState, Artifacts: runnerCase.artifacts,
				Producer: definition.name,
			})
		}
	}
	cases = append(cases, conformance.ManifestCase{
		Suite: "verification", CaseID: "unexecuted", Class: "draft_normative",
		Authority: []string{"test authority"}, Provenance: "manual_derivation",
		Runner: testPortableRunner, RequiredPlatform: portableProfile,
		ExpectedOutcome: passState, Artifacts: []string{testFixtureArtifact},
		Producer: "missing-runner",
	})
	if _, _, err := executeRunners(
		t.TempDir(), conformance.Manifest{Cases: cases}, portableProfile, qualificationBinding{},
	); err == nil {
		t.Fatal("executeRunners accepted an unexecuted manifest case")
	}
}

// TestRunnerInventoryRejectsWrongArtifactBinding prevents unrelated evidence substitution.
func TestRunnerInventoryRejectsWrongArtifactBinding(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	manifest, _, err := conformance.LoadManifest(root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Cases[0].Artifacts = []string{"canonical-header"}
	if _, _, err := executeRunners(
		t.TempDir(), manifest, portableProfile, qualificationBinding{},
	); err == nil ||
		err.Error() != "runner_artifact_binding" {
		t.Fatalf("executeRunners() error = %v, want runner_artifact_binding", err)
	}
}

// TestRunnerFailureIdentifiesOnlyTheClosedProducer freezes bounded root-cause diagnostics.
func TestRunnerFailureIdentifiesOnlyTheClosedProducer(t *testing.T) {
	original := portableDefinitions
	t.Cleanup(func() { portableDefinitions = original })
	portableDefinitions = []runnerDefinition{{
		name: "closed-producer", module: "missing-module", pkg: ".",
		timeout: time.Second,
		cases: []runnerCase{{
			key: "suite\x00case", artifacts: []string{testFixtureArtifact},
		}},
	}}
	manifest := conformance.Manifest{Cases: []conformance.ManifestCase{{
		Suite: "suite", CaseID: "case", Class: "local_security_policy",
		Authority: []string{"repository policy"}, Provenance: "direct_observation",
		Runner: testPortableRunner, RequiredPlatform: portableProfile,
		ExpectedOutcome: passState, Artifacts: []string{testFixtureArtifact},
		Producer: "closed-producer",
	}}}
	_, _, err := executeRunners(
		t.TempDir(), manifest, portableProfile, qualificationBinding{},
	)
	if err == nil || err.Error() != "runner_build:closed-producer" {
		t.Fatalf("executeRunners() error = %v, want runner_build:closed-producer", err)
	}
}

// TestConfiguredRunnersEmitExactEvidence proves every configured case has one producer.
func TestConfiguredRunnersEmitExactEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	if err := listener.Close(); err != nil {
		t.Fatal("close loopback capability probe")
	}
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	manifest, _, err := conformance.LoadManifest(root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _, err := executeRunners(
		root, manifest, portableProfile, qualificationBinding{},
	)
	if err != nil {
		t.Fatalf("executeRunners() error = %v", err)
	}
	if len(evidence) != 57 {
		t.Fatalf("executeRunners() evidence count = %d, want 57", len(evidence))
	}
}

// TestFullProfileRejectsMissingEximEvidence freezes the mandatory import boundary.
func TestFullProfileRejectsMissingEximEvidence(t *testing.T) {
	_, _, err := executeRunners(
		t.TempDir(),
		conformance.Manifest{Cases: []conformance.ManifestCase{{
			Suite: "exim", CaseID: "linux-real-matrix",
			Class: "adapter_contract", Authority: []string{"Exim adapter contract"},
			Provenance: "independent_oracle", Runner: eximRunner,
			RequiredPlatform: linuxPlatform, ExpectedOutcome: passState,
			Artifacts: []string{
				"exim-qualification-contract",
				"exim-qualification-executor",
				"exim-qualification-helper",
				"exim-qualification-schema",
				"exim-qualification-verifier",
			},
			Producer: eximRunnerName,
		}}},
		fullProfile,
		qualificationBinding{},
	)
	if err == nil || err.Error() != "runner_dependency:exim-qualification-verifier" {
		t.Fatalf("executeRunners() error = %v", err)
	}
}

// TestEximQualificationImportsVerifiedEvidence exercises the opt-in real-matrix import boundary.
func TestEximQualificationImportsVerifiedEvidence(t *testing.T) {
	evidenceRoot := os.Getenv("DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT")
	if evidenceRoot == "" {
		t.Skip("set DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT to verified real-matrix evidence")
	}
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	_, manifestDigest, err := conformance.LoadManifest(root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		t.Fatal(err)
	}
	var definition runnerDefinition
	for _, candidate := range portableDefinitions {
		if candidate.name == eximRunnerName {
			definition = candidate
			break
		}
	}
	if definition.name == "" {
		t.Fatal("Exim qualification runner definition is missing")
	}
	binding := qualificationBinding{
		manifestDigest: manifestDigest,
		revision:       revision,
		snapshotDigest: snapshot.SHA256,
		eximEvidence:   evidenceRoot,
	}
	producerDigest, passed, identities, err := executeEximQualification(
		root,
		definition,
		binding,
	)
	if err != nil {
		t.Fatalf("executeEximQualification() error = %v", err)
	}
	if len(passed) != 1 || passed[0] != "exim\x00linux-real-matrix" ||
		len(identities) != 3 {
		t.Fatalf(
			"executeEximQualification() passed=%v identities=%v",
			passed,
			identities,
		)
	}
	input, err := os.ReadFile(filepath.Join(root, ".artifacts", "conformance-exim", "import.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary conformance.EximQualificationSummary
	if err := conformance.DecodeStrictJSON(input, 1<<20, &summary); err != nil {
		t.Fatal(err)
	}
	if err := conformance.ValidateEximQualificationSummary(
		summary,
		manifestDigest,
		revision,
		snapshot.SHA256,
		producerDigest,
	); err != nil {
		t.Fatal(err)
	}
	if expected := os.Getenv("DKIM2_EXIM_REAL_MATRIX_RUN_ID"); expected != "" &&
		summary.RunID != expected {
		t.Fatalf("imported run ID = %q, want %q", summary.RunID, expected)
	}
}

// TestValkeyRunnerOwnsExactBinariesAndCleanup proves the opt-in full-profile harness.
func TestValkeyRunnerOwnsExactBinariesAndCleanup(t *testing.T) {
	if os.Getenv("DKIM2_RUN_VALKEY_HARNESS") != "1" {
		t.Skip("set DKIM2_RUN_VALKEY_HARNESS=1 for the hermetic Valkey integration")
	}
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	for _, definition := range portableDefinitions {
		if definition.name != valkeyRunnerName {
			continue
		}
		digest, passed, identities, err := executeValkeyHarness(root, definition)
		if err != nil {
			t.Fatalf("executeValkeyHarness() error = %v", err)
		}
		if len(digest) != 64 || len(passed) != 1 || len(identities) != 2 {
			t.Fatalf(
				"executeValkeyHarness() digest=%q passed=%d identities=%d",
				digest, len(passed), len(identities),
			)
		}
		return
	}
	t.Fatal("valkey runner definition is missing")
}

// runGitCommand executes one test-local Git command.
func runGitCommand(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}
