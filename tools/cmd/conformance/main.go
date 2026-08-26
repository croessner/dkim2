// Command conformance validates and renders the closed DKIM2 evidence suite.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

const manifestPath = "testdata/conformance/manifest.json"

const (
	unknownDiagnostic           = "unknown"
	portableProfile             = "portable"
	fullProfile                 = "full"
	linuxPlatform               = "linux"
	passState                   = "pass"
	runnerFailureClass          = "runner_failure"
	libraryModule               = "lib"
	daemonModule                = "cmd/dkim2d"
	manifestSchemaPath          = "testdata/conformance/schemas/manifest.schema.json"
	caseSchemaPath              = "testdata/conformance/schemas/case.schema.json"
	reportSchemaPath            = "testdata/conformance/schemas/report.schema.json"
	signingFacadeArtifact       = "signing-facade-source"
	signingProvenanceArtifact   = "signing-provenance"
	signingPublicArtifact       = "signing-public"
	signingTestKeyArtifact      = "signing-test-key"
	daemonReplayArtifact        = "daemon-replay-source"
	milterNegativeArtifact      = "milter-negative-source"
	openAPINegativeArtifact     = "openapi-negative-source"
	openAPIOperationArtifact    = "openapi-operation-source"
	openAPIProcessFixture       = "openapi-process-report-fixture"
	openAPIReviseFixture        = "openapi-revise-fixture"
	openAPISignFixture          = "openapi-sign-fixture"
	postfixRunnerName           = "postfix-qualification-runner"
	postfixProfile              = "postfix"
	postfixFragmentSchema       = "dkim2.postfix-qualification-fragment.v1"
	milterPublicPeerArtifact    = "milter-public-peer-source"
	canonicalHeaderArtifact     = "canonical-header-source"
	instanceDraft05Artifact     = "instance-draft05-source"
	signatureNegativeArtifact   = "signature-negative-source"
	verificationDraft05Artifact = "verification-draft05-source"
	postfixComposeArtifact      = "postfix-qualification-compose"
	postfixDockerfileArtifact   = "postfix-qualification-dockerfile"
	postfixRuntimeArtifact      = "postfix-qualification-runtime"
	valkeyRunnerName            = "valkey-tests"
	environmentHomeTmp          = "HOME=/tmp"
	environmentLangC            = "LANG=C"
	environmentLocaleC          = "LC_ALL=C"
	verificationGoldenTest      = "TestPublicDraft05GoldenVectors"
	verificationPublicArtifact  = "verification-public"
)

// main executes one closed conformance operation.
func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "conformance failed:", publicFailureDiagnostic(err))
		os.Exit(1)
	}
}

// publicFailureDiagnostic admits only bounded closed error and producer identities.
func publicFailureDiagnostic(err error) string {
	if err == nil {
		return unknownDiagnostic
	}
	value := err.Error()
	if len(value) > 128 || !publicFailurePattern.MatchString(value) {
		return unknownDiagnostic
	}
	return value
}

// run validates trusted command arguments and dispatches a closed operation.
func run(arguments []string) error {
	flags := flag.NewFlagSet("conformance", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	profile := flags.String("profile", portableProfile, "portable or full")
	eximEvidence := flags.String(
		"exim-evidence",
		"",
		"reserved; Draft-05 rejects imported Exim qualification evidence",
	)
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 {
		return errors.New("arguments")
	}
	if *eximEvidence != "" {
		return errors.New("exim_evidence_forbidden")
	}
	switch flags.Arg(0) {
	case "check":
		return check(*root)
	case "refresh-manifest":
		return refreshManifest(*root)
	case "snapshot":
		revision, err := conformance.CurrentRevision(*root)
		if err != nil {
			return err
		}
		snapshot, err := conformance.ProduceSnapshot(*root, revision)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(snapshot)
	case "report":
		if *profile != portableProfile && *profile != fullProfile {
			return errors.New("arguments")
		}
		return report(*root, *profile, *eximEvidence)
	default:
		return errors.New("arguments")
	}
}

// refreshManifest recomputes every artifact digest and atomically writes the validated manifest.
func refreshManifest(root string) error {
	input, err := conformance.ReadConfinedFile(root, manifestPath, 1<<20)
	if err != nil {
		return err
	}
	var manifest conformance.Manifest
	if err := conformance.DecodeStrictJSON(input, 1<<20, &manifest); err != nil {
		return err
	}
	for index := range manifest.Artifacts {
		content, readErr := conformance.ReadConfinedFile(root, manifest.Artifacts[index].Path, 16<<20)
		if readErr != nil {
			return errors.New("artifact_read")
		}
		manifest.Artifacts[index].SHA256 = conformance.SHA256(content)
	}
	if err := manifest.Validate(root); err != nil {
		return err
	}
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("manifest_encode")
	}
	content = append(content, '\n')
	repository, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("manifest_root")
	}
	defer func() { _ = repository.Close() }()
	if err := atomicWrite(repository, manifestPath, content); err != nil {
		return err
	}
	if err := repository.Chmod(manifestPath, 0o644); err != nil {
		return errors.New("output")
	}
	return nil
}

// check validates strict schemas, manifest closure, and artifact bindings.
func check(root string) error {
	if err := conformance.ValidateSchemaClosure(root); err != nil {
		return err
	}
	if err := conformance.ValidateRepositoryJSONSchema(
		root, manifestSchemaPath, manifestPath, 1<<20,
	); err != nil {
		return err
	}
	manifest, _, err := conformance.LoadManifest(root, manifestPath)
	if err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		input, readErr := conformance.LoadArtifactBytes(root, artifact)
		if readErr != nil {
			return errors.New("artifact_read")
		}
		switch {
		case filepath.Ext(artifact.Path) == ".json" &&
			len(artifact.Path) >= len(".case.json") &&
			artifact.Path[len(artifact.Path)-len(".case.json"):] == ".case.json":
			if validateErr := conformance.ValidateJSONSchema(
				root, caseSchemaPath, input, 24<<20,
			); validateErr != nil {
				return validateErr
			}
			if _, validateErr := conformance.ValidateCaseBytes(input); validateErr != nil {
				return validateErr
			}
		}
	}
	return nil
}

// report renders one profile only after the same candidate passes closure.
func report(root, profile, eximEvidence string) error {
	if eximEvidence != "" {
		return errors.New("exim_evidence_forbidden")
	}
	if err := check(root); err != nil {
		return err
	}
	manifest, manifestDigest, err := conformance.LoadManifest(root, manifestPath)
	if err != nil {
		return err
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		return err
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return err
	}
	runnerEvidence, runnerTools, err := executeRunners(
		root,
		manifest,
		profile,
		qualificationBinding{eximEvidence: eximEvidence},
	)
	if err != nil {
		return err
	}
	results := make([]conformance.CaseResult, 0, len(manifest.Cases))
	for _, manifestCase := range manifest.Cases {
		state := "not_run"
		errorClass := runnerFailureClass
		producer := conformance.ToolIdentity{}
		if profile == portableProfile && manifestCase.RequiredPlatform == linuxPlatform {
			state = "not_applicable"
			errorClass = ""
		} else if evidence := runnerEvidence[caseKey(manifestCase.Suite, manifestCase.CaseID)]; evidence.Digest != "" {
			state = passState
			errorClass = ""
			producer = evidence
		}
		results = append(results, conformance.CaseResult{
			Suite: manifestCase.Suite, CaseID: manifestCase.CaseID,
			Class: manifestCase.Class, State: state,
			ArtifactSHA256: caseArtifactDigests(manifest, manifestCase),
			Producer:       producer.Name, ProducerSHA256: producer.Digest, Error: errorClass,
		})
	}
	platform := portableProfile
	if profile == fullProfile {
		platform = linuxPlatform
	}
	producerDigest, err := executableDigest()
	if err != nil {
		return err
	}
	runnerTools = append(runnerTools, conformance.ToolIdentity{
		Name: "conformance-runner", Digest: producerDigest,
	})
	machine, err := conformance.NewReport(
		manifest, manifestDigest, revision, snapshot.SHA256, profile, platform,
		runnerTools,
		results,
	)
	if err != nil {
		return err
	}
	machineJSON, err := machine.RenderJSON()
	if err != nil {
		return err
	}
	if err := conformance.ValidateJSONSchema(root, reportSchemaPath, machineJSON, 8<<20); err != nil {
		return err
	}
	if err := check(root); err != nil {
		return err
	}
	if err := verifyCandidateUnchanged(root, revision, snapshot.SHA256); err != nil {
		return err
	}
	if err := writeReports(root, profile, machine); err != nil {
		return err
	}
	if machine.Overall != passState {
		return errors.New("suite_failed")
	}
	return nil
}

// verifyCandidateUnchanged rejects evidence produced across different repository candidates.
func verifyCandidateUnchanged(root, revision, digest string) error {
	currentRevision, err := conformance.CurrentRevision(root)
	if err != nil || currentRevision != revision {
		return errors.New("candidate_changed")
	}
	current, err := conformance.ProduceSnapshot(root, revision)
	if err != nil || current.SHA256 != digest {
		return errors.New("candidate_changed")
	}
	return nil
}

type runnerDefinition struct {
	name    string
	module  string
	pkg     string
	timeout time.Duration
	cases   []runnerCase
}

type runnerCase struct {
	key       string
	testName  string
	artifacts []string
}

type qualificationBinding struct {
	eximEvidence string
}

var portableDefinitions = []runnerDefinition{
	{
		name: "canonical-tests", module: libraryModule, pkg: "./internal/canonical",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "canonical\x00body-hash-input", testName: "TestGoldenBodyCanonicalizationFixtures", artifacts: []string{"canonical-body"}},
			{key: "canonical\x00draft04-to-draft05-header-boundary", testName: "TestDraft04SignatureFailsUnderDraft05HeaderRules", artifacts: []string{canonicalHeaderArtifact}},
			{key: "canonical\x00draft05-digest-algorithms", testName: "TestSHA512DigestHashesCanonicalInput", artifacts: []string{"canonical-digest-source"}},
			{key: "canonical\x00draft05-header-exclusions", testName: "TestHeaderRelevanceDraft05UnsignedSet", artifacts: []string{canonicalHeaderArtifact}},
			{key: "canonical\x00draft05-to-draft04-header-boundary", testName: "TestDraft05SignatureFailsUnderDraft04HeaderRules", artifacts: []string{canonicalHeaderArtifact}},
			{key: "canonical\x00header-hash-input", testName: "TestGoldenHeaderCanonicalizationFixture", artifacts: []string{"canonical-header"}},
			{key: "canonical\x00signature-input", testName: "TestGoldenSignatureCanonicalizationFixture", artifacts: []string{"canonical-signature"}},
		},
	},
	{
		name: "instance-tests", module: libraryModule, pkg: "./internal/instance",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "instance\x00draft05-dual-hash", testName: "TestHashSetAcceptsMixedSupportedAlgorithmsInWireOrder", artifacts: []string{instanceDraft05Artifact}},
			{key: "instance\x00draft05-duplicate-extension-hash", testName: "TestHashSetRejectsDuplicateExtensionName", artifacts: []string{instanceDraft05Artifact}},
			{key: "instance\x00draft05-duplicate-hash", testName: "TestParseRejectsDuplicateHashAlgorithms", artifacts: []string{instanceDraft05Artifact}},
			{key: "instance\x00draft05-sha512-uppercase", testName: "TestHashSetAcceptsSHA512", artifacts: []string{instanceDraft05Artifact}},
		},
	},
	{
		name: "library-facade-tests", module: libraryModule, pkg: ".",
		timeout: 4 * time.Minute,
		cases: []runnerCase{
			{key: "dns\x00dns-negative-record-states", testName: "TestDNSPublicKeyProviderMapsResolverOutcomes", artifacts: []string{"dns-negative-source"}},
			{key: "dns\x00dns-records", testName: "TestDNSDraft04PublicPassVectors", artifacts: []string{"dns-records"}},
			{key: "policy\x00draft05-invalid-recipe-json", testName: "TestMalformedHistoriedMessageFailsClosedAcrossServiceAndFacade", artifacts: []string{"policy-invalid-recipe-source"}},
			{key: "policy\x00projection-modes", testName: "TestEvaluatePolicySelectedFourStateModeMatrix", artifacts: []string{"policy-positive-source"}},
			{key: "signing\x00envelope-facade", testName: "TestPublicEnvelopeSnapshotsAndOrderedGroupMatching", artifacts: []string{signingFacadeArtifact, signingProvenanceArtifact, signingPublicArtifact, signingTestKeyArtifact}},
			{key: "signing\x00next-domain-facade", testName: "TestPublicNextDomainCreationReleaseAndCompletion", artifacts: []string{signingFacadeArtifact, signingProvenanceArtifact, signingPublicArtifact, signingTestKeyArtifact}},
			{key: "signing\x00origin-facade", testName: "TestPublicOriginatorSigningAlgorithmsAndImmutableBytes", artifacts: []string{signingFacadeArtifact, signingProvenanceArtifact, signingPublicArtifact, signingTestKeyArtifact}},
			{key: "signing\x00restricted-release", testName: "TestPublicLocalOnlyReleaseIsExactAtomicAndNilOnDenial", artifacts: []string{signingFacadeArtifact, signingProvenanceArtifact, signingPublicArtifact, "signing-release-source", signingTestKeyArtifact}},
			{key: "signing\x00revision-facade", testName: "TestPublicExistingSigningDerivesForwarderAndReviser", artifacts: []string{signingFacadeArtifact, signingProvenanceArtifact, signingPublicArtifact, signingTestKeyArtifact}},
			{key: "signing\x00limits-negative", testName: "TestPublicSigningMessageLimitExactAndOneOver", artifacts: []string{"signing-limits-source"}},
			{key: "verification\x00negative-crypto-dns", testName: verificationGoldenTest, artifacts: []string{verificationPublicArtifact}},
			{key: "verification\x00negative-envelope", testName: verificationGoldenTest, artifacts: []string{verificationPublicArtifact}},
			{key: "verification\x00negative-hash", testName: verificationGoldenTest, artifacts: []string{verificationPublicArtifact}},
			{key: "verification\x00negative-structure", testName: verificationGoldenTest, artifacts: []string{verificationPublicArtifact}},
			{key: "verification\x00negative-time", testName: verificationGoldenTest, artifacts: []string{verificationPublicArtifact}},
			{key: "verification\x00public-facade", testName: verificationGoldenTest, artifacts: []string{verificationPublicArtifact}},
		},
	},
	{
		name: "raw-message-tests", module: libraryModule, pkg: "./internal/rawmsg",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "raw-message\x00strict-bytes", testName: "TestParseStrictCRLFMessagePreservesHeadersAndBody", artifacts: []string{"rawmsg-positive-source"}},
			{key: "raw-message\x00utf8-binary", testName: "TestParsePreservesValidUTF8HeaderAndArbitraryBodyBytes", artifacts: []string{"rawmsg-positive-source"}},
		},
	},
	{
		name: "crypto-golden-tests", module: libraryModule, pkg: "./internal/cryptodkim2",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "signing\x00custody-cryptography", testName: "TestDraft05CryptoVerificationGoldenVectors", artifacts: []string{"signing-custody", signingProvenanceArtifact}},
			{key: "signing\x00custody-key-policy", testName: "TestCryptoPublicKeyPolicyBoundaryGoldenVectors", artifacts: []string{"signing-custody", signingProvenanceArtifact}},
		},
	},
	{
		name: "recipe-tests", module: libraryModule, pkg: "./internal/recipe",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "recipe\x00application", testName: "TestGoldenRecipeApplicationDraft05", artifacts: []string{"recipe-application"}},
			{key: "recipe\x00draft05-lowercase-recipe", testName: "TestParserAcceptsEscapedLowercaseHeaderKey", artifacts: []string{"recipe-draft05-source"}},
			{key: "recipe\x00draft05-nonlowercase-recipe", testName: "TestParserRejectsNonLowercaseHeaderKey", artifacts: []string{"recipe-draft05-source"}},
			{key: "recipe\x00generation", testName: "TestSerializeGenerationPlanMatchesDraft05Goldens", artifacts: []string{"recipe-generation"}},
			{key: "recipe\x00limit-boundaries", testName: "TestEveryRecipeHardMaximumAcceptsExactAndRejectsOneOver", artifacts: []string{"recipe-limits-source"}},
			{key: "recipe\x00parser-negative", testName: "TestParserAdditionalDraftAndRFC8259Vectors", artifacts: []string{"recipe-negative-source"}},
		},
	},
	{
		name: "replay-memory-tests", module: libraryModule, pkg: "./internal/replay",
		timeout: 3 * time.Minute,
		cases: []runnerCase{
			{key: "replay\x00concurrent-duplicate", testName: "TestMemoryStoreConcurrentSameKeyHasOneWinner", artifacts: []string{"replay-memory-source"}},
			{key: "replay\x00identity-draft05-epoch", testName: "TestDraft05IdentitySeparatesEpoch", artifacts: []string{"replay-deriver-source"}},
			{key: "replay\x00identity-separation", testName: "TestDeriverChangesEveryBoundFact", artifacts: []string{"replay-deriver-source"}},
			{key: "replay\x00memory-expiry", testName: "TestMemoryStoreFirstSeenReplayExpiryAndNoExtension", artifacts: []string{"replay-memory-source"}},
			{key: "replay\x00retention-edge", testName: "TestRetentionCheckedAdditionPreservesExactExpiry", artifacts: []string{"replay-retention-source"}},
		},
	},
	{
		name: "daemon-replay-tests", module: daemonModule, pkg: "./internal/app",
		timeout: 4 * time.Minute,
		cases: []runnerCase{
			{key: "replay\x00aggregate-states", testName: "TestReplayCoordinatorAggregateMatrix", artifacts: []string{daemonReplayArtifact}},
			{key: "replay\x00disabled", testName: "TestReplayCoordinatorGateAndDisabledPerformNoWork", artifacts: []string{daemonReplayArtifact}},
			{key: "replay\x00privacy", testName: "TestReplayCoordinatorPrivacyAndConcurrentReuse", artifacts: []string{daemonReplayArtifact}},
			{key: "replay\x00provider-failures", testName: "TestReplayCoordinatorContinuesEveryOrdinaryFailure", artifacts: []string{daemonReplayArtifact}},
		},
	},
	{
		name: "dkim2d-openapi-integration-tests", module: daemonModule, pkg: "./internal/httpjson",
		timeout: 4 * time.Minute,
		cases: []runnerCase{
			{key: "openapi\x00draft05-invalid-json-diagnostics", testName: "TestJSONPreflightRejectsMalformedTexts", artifacts: []string{"openapi-invalid-json-source"}},
			{
				key:      "openapi\x00real-daemon-generated-boundary",
				testName: "TestDKIM2ctlGeneratedClientAgainstProductionBoundary",
				artifacts: []string{
					"openapi-daemon-boundary-source", openAPIProcessFixture,
					openAPIReviseFixture, openAPISignFixture,
					"openapi-wire-response-source",
				},
			},
		},
	},
	{
		name: "dkim2ctl-negative-tests", module: "cmd/dkim2ctl", pkg: "./internal/testclient",
		timeout: 3 * time.Minute,
		cases: []runnerCase{
			{key: "openapi\x00negative-request-contract", testName: "TestNegativeBuilderFreezesClosedMutationShapes", artifacts: []string{openAPINegativeArtifact}},
			{key: "openapi\x00negative-response-contract", testName: "TestNegativeResponseRejectsMalformedAndContradictoryContracts", artifacts: []string{openAPINegativeArtifact}},
			{key: "openapi\x00negative-response-headers", testName: "TestNegativeResponseRequiresStatusSpecificHeaders", artifacts: []string{openAPINegativeArtifact}},
			{key: "openapi\x00privacy-negative", testName: "TestCallNegativeClassifiesTypedErrorAndKeepsMarkersPrivate", artifacts: []string{openAPINegativeArtifact}},
		},
	},
	{
		name: "dkim2ctl-operation-tests", module: "cmd/dkim2ctl", pkg: "./internal/testclient",
		timeout: 4 * time.Minute,
		cases: []runnerCase{
			{
				key:       "openapi\x00generated-operation-boundary",
				testName:  "TestGeneratedSignAndReviseRequestsPreserveDistinctFacts",
				artifacts: []string{openAPIOperationArtifact},
			},
			{
				key:      "openapi\x00independent-socket-fixtures",
				testName: "TestIndependentSocketOracleGeneratedOperationMatrix",
				artifacts: []string{
					"openapi-independent-oracle-source", "openapi-process-negative-fixture",
					openAPIProcessFixture, openAPIReviseFixture,
					"openapi-route-negative-fixture", openAPISignFixture,
				},
			},
			{
				key:      "openapi\x00offline-operation-validation",
				testName: "TestOfflineOperationValidationDoesNotAcquireCapabilitiesOrRuntime",
				artifacts: []string{
					openAPIOperationArtifact, openAPIProcessFixture,
					openAPIReviseFixture, openAPISignFixture,
				},
			},
			{
				key:       "openapi\x00operation-response-closure",
				testName:  "TestOperationResponseMatrixRejectsContradictions",
				artifacts: []string{openAPIOperationArtifact},
			},
		},
	},
	{
		name: "milter-public-fixture-tests", module: "cmd/dkim2-milter", pkg: "./internal/integration",
		timeout: 5 * time.Minute,
		cases: []runnerCase{
			{
				key:       "milter\x00abort-reuse",
				testName:  "TestExecutableAbortReuseAndMalformedDisconnect",
				artifacts: []string{milterPublicPeerArtifact},
			},
			{
				key:       "milter\x00envelope-domain-originator",
				testName:  "TestOriginatorEnvelopeSenderDomainSelectionRunsThroughPublicSocket",
				artifacts: []string{milterPublicPeerArtifact},
			},
			{
				key:       "milter\x00overload-disconnect",
				testName:  "TestExecutableOverloadAndSlowDisconnect",
				artifacts: []string{milterPublicPeerArtifact},
			},
			{
				key:       "milter\x00protocol-v6-fixture-matrix",
				testName:  "TestExecutableStrictMilterFixtureMatrix",
				artifacts: []string{"milter-fixture-data", "milter-fixture-source"},
			},
			{
				key:       "milter\x00public-failure-outcomes",
				testName:  "TestExecutableFailurePolicyMatrix",
				artifacts: []string{milterPublicPeerArtifact},
			},
		},
	},
	{
		name: "milter-negative-tests", module: "cmd/dkim2-milter", pkg: "./internal/milter",
		timeout: 3 * time.Minute,
		cases: []runnerCase{
			{key: "milter\x00callback-order-negative", testName: "TestIllegalCallbackOrderFailsClosed", artifacts: []string{milterNegativeArtifact}},
			{key: "milter\x00frame-limit-negative", testName: "TestReadFrameEnforcesDefaultAndCommandSpecificCaps", artifacts: []string{milterNegativeArtifact}},
			{key: "milter\x00partial-mutation-negative", testName: "TestWriteFramesClassifiesWriterPanicAsIndeterminate", artifacts: []string{milterNegativeArtifact}},
			{key: "milter\x00pre-mail-abort-helo-reuse", testName: "TestAbortBeforeMailAllowsPostfixConnectionReuse", artifacts: []string{milterNegativeArtifact}},
			{key: "milter\x00timeout-privacy-negative", testName: "TestHandlerDeadlineMapsToFixedTempfail", artifacts: []string{milterNegativeArtifact}},
		},
	},
	{
		name: "postfix-policy-tests", module: "tools", pkg: ".",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{
				key:       "postfix\x00static-isolation-policy",
				testName:  "TestPostfixQualificationComposePolicy",
				artifacts: []string{postfixComposeArtifact, "postfix-qualification-policy-source"},
			},
			{
				key:       "postfix\x00supply-chain-cleanup-policy",
				testName:  "TestPostfixQualificationPinsBuildInputsAndCleanup",
				artifacts: []string{postfixDockerfileArtifact, "postfix-qualification-policy-source", postfixRunnerName, postfixRuntimeArtifact},
			},
		},
	},
	{
		name: postfixRunnerName, timeout: 20 * time.Minute,
		cases: []runnerCase{
			{
				key:       "postfix\x00failure-cleanup",
				artifacts: []string{postfixComposeArtifact, postfixDockerfileArtifact, postfixRunnerName, postfixRuntimeArtifact},
			},
			{
				key:       "postfix\x00smtp-nonsmtp-inbound",
				artifacts: []string{postfixComposeArtifact, postfixDockerfileArtifact, postfixRunnerName, postfixRuntimeArtifact},
			},
		},
	},
	{
		name: valkeyRunnerName, module: daemonModule, pkg: "./internal/replay/valkey",
		timeout: 4 * time.Minute,
		cases: []runnerCase{
			{key: "replay\x00valkey-set-nx-px", testName: "TestRealValkeyHarness", artifacts: []string{"valkey-harness-script", "valkey-replay-source"}},
		},
	},
	{
		name: "signing-golden-tests", module: libraryModule, pkg: "./internal/signing",
		timeout: 3 * time.Minute,
		cases: []runnerCase{
			{key: "signing\x00local-sha256-output-policy", testName: "TestSignerMayEmitSHA256FromSHA512OnlyHistory", artifacts: []string{"signing-revision-source"}},
			{key: "signing\x00public-facade", testName: "TestDraft05SigningGoldenVectors", artifacts: []string{signingProvenanceArtifact, signingPublicArtifact}},
			{key: "signing\x00unchanged-no-redundant-instance", testName: "TestHashPlanOriginatorAndExistingRoles", artifacts: []string{"signing-plan-source"}},
		},
	},
	{
		name: "signature-tests", module: libraryModule, pkg: "./internal/signature",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "signing\x00custody-transitions", testName: "TestDraft05CustodyGoldenVectors", artifacts: []string{"custody-positive-source", signingProvenanceArtifact}},
			{key: "signing\x00draft05-duplicate-selector", testName: "TestParseRejectsDuplicateSelectors", artifacts: []string{signatureNegativeArtifact}},
			{key: "signing\x00draft05-same-algorithm-pair", testName: "TestParseAllowsTwoSameAlgorithmDifferentSelectors", artifacts: []string{signatureNegativeArtifact}},
			{key: "signing\x00draft05-third-same-algorithm", testName: "TestParseRejectsThirdSameAlgorithm", artifacts: []string{signatureNegativeArtifact}},
			{key: "signing\x00signature-grammar-negative", testName: "TestParseRejectsSharedTagSyntaxErrors", artifacts: []string{signatureNegativeArtifact}},
			{key: "signing\x00tag-case-interpretation", testName: "TestParseAcceptsInteropFWSAndMixedCaseTags", artifacts: []string{signatureNegativeArtifact}},
		},
	},
	{
		name: "service-draft05-tests", module: libraryModule, pkg: "./internal/service",
		timeout: 2 * time.Minute,
		cases: []runnerCase{
			{key: "verification\x00draft05-diagnostics", testName: "TestDraft05ProtocolInfractionsMapToDistinctPermanentReasons", artifacts: []string{"service-draft05-source"}},
		},
	},
	{
		name: "verification-draft05-tests", module: libraryModule, pkg: "./internal/verify",
		timeout: 3 * time.Minute,
		cases: []runnerCase{
			{key: "verification\x00draft05-dual-mismatch", testName: "TestVerifierRejectsOneMismatchingSupportedTuple", artifacts: []string{verificationDraft05Artifact}},
			{key: "verification\x00draft05-recipe-less-unchanged", testName: "TestHistoryAcceptsRecipeLessUnchangedTransitionMatrix", artifacts: []string{verificationDraft05Artifact}},
			{key: "verification\x00draft05-recipe-less-unknown-only", testName: "TestHistoryAcceptsRecipeLessUnchangedTransitionMatrix", artifacts: []string{verificationDraft05Artifact}},
			{key: "verification\x00draft05-same-algorithm-positional", testName: "TestVerifierChecksSameAlgorithmSignaturesPositionally", artifacts: []string{"verification-multisignature-source"}},
			{key: "verification\x00draft05-sha512-only", testName: "TestVerifierAcceptsSHA512Only", artifacts: []string{verificationDraft05Artifact}},
		},
	},
}

var publicFailurePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?::[a-z][a-z0-9_-]*)?$`)
var semanticVersionPattern = regexp.MustCompile(`^[0-9]+[.][0-9]+[.][0-9]+$`)

type ciToolchainVersionManifest struct {
	Schema   string `json:"schema"`
	Fixtures struct {
		Valkey struct {
			Version string `json:"version"`
		} `json:"valkey"`
	} `json:"fixtures"`
}

type postfixQualificationReport = conformance.PostfixQualificationReport
type postfixQualificationRuntimeIdentity = conformance.PostfixQualificationRuntimeIdentity
type postfixQualificationReportFragment = conformance.PostfixQualificationFragment
type postfixQualificationTopology = conformance.PostfixQualificationTopology

// executeRunners builds exact test binaries and returns per-case producer evidence.
func executeRunners(
	root string,
	manifest conformance.Manifest,
	profile string,
	binding qualificationBinding,
) (map[string]conformance.ToolIdentity, []conformance.ToolIdentity, error) {
	required := make(map[string]struct{})
	manifestCases := make(map[string]conformance.ManifestCase)
	for _, manifestCase := range manifest.Cases {
		key := caseKey(manifestCase.Suite, manifestCase.CaseID)
		manifestCases[key] = manifestCase
		if profile != portableProfile || manifestCase.RequiredPlatform != linuxPlatform {
			required[key] = struct{}{}
		}
	}
	if binding.eximEvidence != "" {
		return nil, nil, errors.New("exim_evidence_forbidden")
	}
	defined := make(map[string]struct{})
	for _, definition := range portableDefinitions {
		for _, runnerCase := range definition.cases {
			if _, selected := required[runnerCase.key]; !selected {
				continue
			}
			if _, duplicate := defined[runnerCase.key]; duplicate {
				return nil, nil, errors.New("runner_duplicate_case")
			}
			manifestCase, ok := manifestCases[runnerCase.key]
			if !ok || manifestCase.Producer != definition.name ||
				!slices.Equal(manifestCase.Artifacts, runnerCase.artifacts) {
				return nil, nil, errors.New("runner_artifact_binding")
			}
			defined[runnerCase.key] = struct{}{}
		}
	}
	for key := range required {
		if _, ok := defined[key]; !ok {
			return nil, nil, errors.New("runner_inventory")
		}
	}
	for key := range defined {
		if _, ok := required[key]; !ok {
			return nil, nil, errors.New("runner_inventory")
		}
	}
	directory, err := os.MkdirTemp("", ".dkim2-conformance-runners-")
	if err != nil {
		return nil, nil, errors.New("runner_build")
	}
	defer func() { _ = os.RemoveAll(directory) }()
	evidence := make(map[string]conformance.ToolIdentity, len(required))
	tools := make([]conformance.ToolIdentity, 0, len(portableDefinitions))
	for _, definition := range portableDefinitions {
		selected := definition
		selected.cases = make([]runnerCase, 0, len(definition.cases))
		for _, runnerCase := range definition.cases {
			if _, ok := required[runnerCase.key]; ok {
				selected.cases = append(selected.cases, runnerCase)
			}
		}
		if len(selected.cases) == 0 {
			continue
		}
		var (
			digest      string
			passedCases []string
			extraTools  []conformance.ToolIdentity
			runErr      error
		)
		switch selected.name {
		case valkeyRunnerName:
			digest, passedCases, extraTools, runErr = executeValkeyHarness(root, selected)
		case postfixRunnerName:
			digest, passedCases, extraTools, runErr = executePostfixQualification(
				root,
				selected,
			)
		default:
			digest, passedCases, runErr = executeTestBinary(root, directory, selected)
		}
		if runErr != nil {
			return nil, nil, fmt.Errorf("%w:%s", runErr, selected.name)
		}
		tools = append(tools, conformance.ToolIdentity{Name: definition.name, Digest: digest})
		tools = append(tools, extraTools...)
		for _, key := range passedCases {
			if evidence[key].Digest != "" {
				return nil, nil, errors.New("runner_duplicate_case")
			}
			evidence[key] = conformance.ToolIdentity{Name: definition.name, Digest: digest}
		}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return evidence, tools, nil
}

// executePostfixQualification runs the closed Docker matrix and validates its
// identity-bound, repeated, content-free report before admitting case evidence.
func executePostfixQualification(
	root string,
	definition runnerDefinition,
) (string, []string, []conformance.ToolIdentity, error) {
	if len(definition.cases) != 2 {
		return "", nil, nil, errors.New("runner_inventory")
	}
	absoluteRoot, err := absoluteQualificationRoot(root)
	if err != nil {
		return "", nil, nil, err
	}
	root = absoluteRoot
	scriptPath := filepath.Join(
		root,
		"contrib",
		"qualification",
		"postfix-milter",
		"run.sh",
	)
	producerDigest, err := fileDigest(scriptPath)
	if err != nil {
		return "", nil, nil, err
	}
	outputRelative := filepath.Join(".artifacts", "postfix-conformance-runner")
	runContext, cancelRun := context.WithTimeout(context.Background(), definition.timeout)
	output := &boundedOutput{limit: 2 << 20}
	command := exec.CommandContext(runContext, scriptPath, outputRelative)
	command.Dir = root
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		environmentHomeTmp,
		"TMPDIR=/tmp",
		"GOCACHE=/tmp/dkim2-conformance-go-cache",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		environmentLangC,
		environmentLocaleC,
	}
	dockerHost, err := qualificationDockerHostEnvironment()
	if err != nil {
		cancelRun()
		return "", nil, nil, err
	}
	command.Env = append(command.Env, dockerHost...)
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
	reportRelative := filepath.ToSlash(filepath.Join(outputRelative, "run-1", "report.json"))
	reportInput, err := conformance.ReadConfinedFile(root, reportRelative, 1<<20)
	if err != nil || len(reportInput) == 0 {
		return "", nil, nil, errors.New("runner_failure")
	}
	var report postfixQualificationReport
	if err := conformance.DecodeStrictJSON(reportInput, 1<<20, &report); err != nil {
		return "", nil, nil, errors.New("runner_failure")
	}
	_, manifestDigest, err := conformance.LoadManifest(root, manifestPath)
	if err != nil {
		return "", nil, nil, errors.New("runner_failure")
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		return "", nil, nil, err
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return "", nil, nil, err
	}
	if err := validatePostfixQualificationReport(
		report,
		manifestDigest,
		revision,
		snapshot.SHA256,
		producerDigest,
	); err != nil {
		return "", nil, nil, err
	}
	if current, digestErr := fileDigest(scriptPath); digestErr != nil || current != producerDigest {
		return "", nil, nil, errors.New("runner_unstable")
	}
	passed := make([]string, 0, len(definition.cases))
	for _, runnerCase := range definition.cases {
		passed = append(passed, runnerCase.key)
	}
	tools := []conformance.ToolIdentity{
		{Name: "debian-image", Digest: strings.TrimPrefix(report.ImageIdentities["debian"], "debian@sha256:")},
		{Name: "dkim2-milter-binary", Digest: report.RuntimeIdentity.Executables["dkim2-milter"]},
		{Name: "dkim2d-binary", Digest: report.RuntimeIdentity.Executables["dkim2d"]},
		{Name: "golang-image", Digest: strings.TrimPrefix(report.ImageIdentities["golang"], "golang@sha256:")},
		{Name: "postfix-image", Digest: strings.TrimPrefix(report.ImageIdentities["postfix"], "chrroessner/postfix@sha256:")},
		{Name: "qualify-binary", Digest: report.RuntimeIdentity.Executables["qualify"]},
	}
	return producerDigest, passed, tools, nil
}

// absoluteQualificationRoot resolves a caller-relative repository root before
// it is reused as both a child working directory and an executable base.
func absoluteQualificationRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", errors.New("runner_build")
	}
	return absolute, nil
}

// qualificationDockerHostEnvironment resolves and preserves only an absolute
// Unix socket endpoint for rootless or desktop Docker contexts.
func qualificationDockerHostEnvironment() ([]string, error) {
	value, present := os.LookupEnv("DOCKER_HOST")
	if present && value == "" {
		return nil, nil
	}
	if !present {
		context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(
			context,
			"docker",
			"context",
			"inspect",
			"--format",
			"{{.Endpoints.docker.Host}}",
		)
		output := &boundedOutput{limit: 4096}
		command.Stdout = output
		command.Stderr = io.Discard
		if err := command.Run(); err != nil || context.Err() != nil {
			return nil, errors.New("runner_dependency")
		}
		value = strings.TrimSpace(output.String())
	}
	endpoint, err := url.Parse(value)
	if err != nil ||
		endpoint.Scheme != "unix" ||
		endpoint.Host != "" ||
		endpoint.User != nil ||
		endpoint.RawQuery != "" ||
		endpoint.Fragment != "" ||
		!filepath.IsAbs(endpoint.Path) ||
		filepath.Clean(endpoint.Path) != endpoint.Path {
		return nil, errors.New("runner_dependency")
	}
	return []string{"DOCKER_HOST=" + value}, nil
}

// validatePostfixQualificationReport enforces exact runtime identities,
// topology, cases, cleanup, and current-candidate binding.
func validatePostfixQualificationReport(
	report postfixQualificationReport,
	manifestDigest, revision, snapshotDigest, producerDigest string,
) error {
	return conformance.ValidatePostfixQualificationReport(
		report,
		manifestDigest,
		revision,
		snapshotDigest,
		producerDigest,
	)
}

// executeValkeyHarness owns exact server startup, authenticated execution, and cleanup evidence.
func executeValkeyHarness(
	root string,
	definition runnerDefinition,
) (string, []string, []conformance.ToolIdentity, error) {
	if len(definition.cases) != 1 {
		return "", nil, nil, errors.New("runner_inventory")
	}
	expectedVersion, err := loadValkeyVersion(root)
	if err != nil {
		return "", nil, nil, err
	}
	sourceServerPath, err := exec.LookPath("valkey-server")
	if err != nil {
		return "", nil, nil, errors.New("runner_dependency")
	}
	directory, err := os.MkdirTemp("/tmp", ".dkim2-valkey-runner-")
	if err != nil {
		return "", nil, nil, errors.New("runner_build")
	}
	defer func() { _ = os.RemoveAll(directory) }()
	serverPath := filepath.Join(directory, "valkey-server")
	if err := copyExecutable(sourceServerPath, serverPath); err != nil {
		return "", nil, nil, err
	}
	serverDigest, err := fileDigest(serverPath)
	if err != nil {
		return "", nil, nil, err
	}
	testBinary := filepath.Join(directory, "valkey-integration.test")
	buildContext, cancelBuild := context.WithTimeout(context.Background(), definition.timeout)
	build := exec.CommandContext(
		buildContext,
		"go", "test", "-tags=valkeyintegration", "-c", "-o", testBinary, definition.pkg,
	)
	build.Dir = filepath.Join(root, definition.module)
	build.Stdout = io.Discard
	build.Stderr = io.Discard
	buildErr := build.Run()
	buildContextErr := buildContext.Err()
	cancelBuild()
	if buildErr != nil || buildContextErr != nil {
		return "", nil, nil, errors.New("runner_build")
	}
	testDigest, err := fileDigest(testBinary)
	if err != nil {
		return "", nil, nil, err
	}
	versionContext, cancelVersion := context.WithTimeout(context.Background(), 10*time.Second)
	versionOutput := &boundedOutput{limit: 1024}
	version := exec.CommandContext(versionContext, serverPath, "--version")
	version.Stdout = versionOutput
	version.Stderr = versionOutput
	versionErr := version.Run()
	versionContextErr := versionContext.Err()
	cancelVersion()
	if versionErr != nil || versionContextErr != nil ||
		!matchesValkeyVersion(versionOutput.String(), expectedVersion) {
		return "", nil, nil, errors.New("runner_dependency")
	}
	sourceScriptPath := filepath.Join(root, "scripts", "test-valkey.sh")
	scriptPath := filepath.Join(directory, "test-valkey.sh")
	if err := copyExecutable(sourceScriptPath, scriptPath); err != nil {
		return "", nil, nil, err
	}
	scriptDigest, err := fileDigest(scriptPath)
	if err != nil {
		return "", nil, nil, err
	}
	before, err := filepath.Glob("/tmp/dkim2-valkey-integration.*")
	if err != nil {
		return "", nil, nil, errors.New("runner_cleanup")
	}
	sort.Strings(before)
	runContext, cancelRun := context.WithTimeout(context.Background(), definition.timeout)
	output := &boundedOutput{limit: 1 << 20}
	command := exec.CommandContext(runContext, "/bin/sh", scriptPath, serverPath, testBinary)
	command.Dir = root
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		environmentHomeTmp,
		"TMPDIR=/tmp",
		"GOCACHE=/tmp/dkim2-conformance-go-cache",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		environmentLangC,
		environmentLocaleC,
	}
	command.Stdout = output
	command.Stderr = output
	runErr := command.Run()
	contextErr := runContext.Err()
	cancelRun()
	after, globErr := filepath.Glob("/tmp/dkim2-valkey-integration.*")
	sort.Strings(after)
	if globErr != nil || !slices.Equal(before, after) {
		return "", nil, nil, errors.New("runner_cleanup")
	}
	if runErr != nil {
		if errors.Is(contextErr, context.DeadlineExceeded) {
			return "", nil, nil, errors.New("runner_timeout")
		}
		return "", nil, nil, errors.New("runner_failure")
	}
	if !strings.Contains(
		output.String(), "--- PASS: "+definition.cases[0].testName+" ",
	) {
		return "", nil, nil, errors.New("runner_missing_case")
	}
	currentServerDigest, serverErr := fileDigest(serverPath)
	currentScriptDigest, scriptErr := fileDigest(scriptPath)
	currentTestDigest, testErr := fileDigest(testBinary)
	if serverErr != nil || scriptErr != nil || testErr != nil ||
		currentServerDigest != serverDigest ||
		currentScriptDigest != scriptDigest ||
		currentTestDigest != testDigest {
		return "", nil, nil, errors.New("runner_unstable")
	}
	return testDigest, []string{definition.cases[0].key}, []conformance.ToolIdentity{
		{Name: "valkey-harness-script", Digest: scriptDigest},
		{Name: "valkey-server-" + expectedVersion, Digest: serverDigest},
	}, nil
}

// loadValkeyVersion reads the only approved Valkey version from the central CI manifest.
func loadValkeyVersion(root string) (string, error) {
	input, err := conformance.ReadConfinedFile(root, "build/ci/toolchain.json", 1<<16)
	if err != nil {
		return "", errors.New("runner_dependency")
	}
	var manifest ciToolchainVersionManifest
	if err := json.Unmarshal(input, &manifest); err != nil ||
		manifest.Schema != "dkim2-ci-toolchain-v1" ||
		!semanticVersionPattern.MatchString(manifest.Fixtures.Valkey.Version) {
		return "", errors.New("runner_dependency")
	}
	return manifest.Fixtures.Valkey.Version, nil
}

// matchesValkeyVersion validates the bounded official banner against the manifest version.
func matchesValkeyVersion(output, expectedVersion string) bool {
	if !semanticVersionPattern.MatchString(expectedVersion) {
		return false
	}
	pattern := regexp.MustCompile(
		`^Valkey server v=` + regexp.QuoteMeta(expectedVersion) +
			` sha=[0-9a-f]{8,64}:[01] malloc=[A-Za-z0-9._+-]+ bits=(32|64) build=[0-9a-f]{8,64}\n?$`,
	)
	return pattern.MatchString(output)
}

// executeTestBinary builds, hashes, and executes one exact test producer.
func executeTestBinary(
	root, directory string,
	definition runnerDefinition,
) (string, []string, error) {
	binary := filepath.Join(directory, definition.name)
	buildContext, cancelBuild := context.WithTimeout(context.Background(), definition.timeout)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, "go", "test", "-c", "-o", binary, definition.pkg)
	build.Dir = filepath.Join(root, definition.module)
	build.Stdout = io.Discard
	build.Stderr = io.Discard
	if err := build.Run(); err != nil {
		return "", nil, errors.New("runner_build")
	}
	digest, err := fileDigest(binary)
	if err != nil {
		return "", nil, err
	}
	passed := make([]string, 0, len(definition.cases))
	for _, runnerCase := range definition.cases {
		runContext, cancelRun := context.WithTimeout(context.Background(), definition.timeout)
		output := &boundedOutput{limit: 1 << 20}
		run := exec.CommandContext(
			runContext, binary, "-test.count=1", "-test.timeout="+definition.timeout.String(),
			"-test.run=^"+runnerCase.testName+"$", "-test.v",
		)
		run.Dir = filepath.Join(root, definition.module)
		if definition.pkg != "." {
			run.Dir = filepath.Join(run.Dir, strings.TrimPrefix(definition.pkg, "./"))
		}
		run.Stdout = output
		run.Stderr = output
		runErr := run.Run()
		contextErr := runContext.Err()
		cancelRun()
		if runErr != nil {
			if errors.Is(contextErr, context.DeadlineExceeded) {
				return "", nil, runnerCaseFailure("runner_timeout", runnerCase.key)
			}
			return "", nil, runnerCaseFailure(
				classifyTestFailure(output.String()), runnerCase.key,
			)
		}
		text := output.String()
		if !strings.Contains(text, "=== RUN   "+runnerCase.testName+"\n") ||
			!strings.Contains(text, "--- PASS: "+runnerCase.testName+" ") {
			return "", nil, runnerCaseFailure("runner_missing_case", runnerCase.key)
		}
		passed = append(passed, runnerCase.key)
	}
	return digest, passed, nil
}

// runnerCaseFailure identifies a closed manifest case without exposing test output.
func runnerCaseFailure(class, key string) error {
	_, caseID, ok := strings.Cut(key, "\x00")
	if !ok || caseID == "" {
		return errors.New(class)
	}
	return errors.New(class + "_" + strings.ReplaceAll(caseID, "-", "_"))
}

// classifyTestFailure maps bounded test output to fixed content-free phases.
func classifyTestFailure(output string) string {
	for _, candidate := range []struct {
		marker string
		class  string
	}{
		{marker: "trusted fixture root failed", class: "runner_failure_fixture_root"},
		{marker: "integration configuration failed preflight", class: "runner_failure_config_preflight"},
		{marker: "integration capability failed preflight", class: "runner_failure_capability_preflight"},
		{marker: "adapter socket was not ready", class: "runner_failure_socket_startup"},
		{marker: "zero-length public frame did not terminate", class: "runner_failure_malformed_disconnect"},
		{marker: "reused transaction response", class: "runner_failure_abort_reuse"},
		{marker: "daemon calls after abort/reuse", class: "runner_failure_abort_accounting"},
		{marker: "adapter did not stop within its shutdown budget", class: "runner_failure_shutdown"},
	} {
		if strings.Contains(output, candidate.marker) {
			return candidate.class
		}
	}
	return "runner_failure"
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

// Write captures bounded test protocol output and stops the producer on overflow.
func (o *boundedOutput) Write(input []byte) (int, error) {
	if o.buffer.Len()+len(input) > o.limit {
		return 0, errors.New("runner_output")
	}
	return o.buffer.Write(input)
}

// String returns the bounded captured test protocol output.
func (o *boundedOutput) String() string {
	return o.buffer.String()
}

// caseKey returns the unambiguous internal suite/case identity.
func caseKey(suite, identifier string) string {
	return suite + "\x00" + identifier
}

// caseArtifactDigests resolves exact artifact digests in manifest reference order.
func caseArtifactDigests(manifest conformance.Manifest, manifestCase conformance.ManifestCase) []string {
	byID := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		byID[artifact.ID] = artifact.SHA256
	}
	result := make([]string, 0, len(manifestCase.Artifacts))
	for _, identifier := range manifestCase.Artifacts {
		result = append(result, byID[identifier])
	}
	return result
}

// executableDigest hashes the exact running producer binary.
func executableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", errors.New("producer")
	}
	return fileDigest(path)
}

// fileDigest hashes one exact regular file through a stable descriptor.
func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("producer")
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", errors.New("producer")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// copyExecutable freezes one stable regular executable into a private runner directory.
func copyExecutable(sourcePath, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return errors.New("producer")
	}
	defer func() { _ = source.Close() }()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("producer")
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return errors.New("producer")
	}
	ok := false
	defer func() {
		_ = destination.Close()
		if !ok {
			_ = os.Remove(destinationPath)
		}
	}()
	if _, err := io.Copy(destination, source); err != nil {
		return errors.New("producer")
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return errors.New("runner_unstable")
	}
	if err := destination.Sync(); err != nil {
		return errors.New("producer")
	}
	if err := destination.Close(); err != nil {
		return errors.New("producer")
	}
	ok = true
	return nil
}

// writeReports confines generated reports to an ignored descriptor-rooted tree.
func writeReports(root, profile string, report conformance.Report) error {
	repository, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("output")
	}
	defer func() { _ = repository.Close() }()
	if err := ensureDirectory(repository, ".artifacts"); err != nil {
		return err
	}
	artifacts, err := repository.OpenRoot(".artifacts")
	if err != nil {
		return errors.New("output")
	}
	defer func() { _ = artifacts.Close() }()
	directory := "conformance-" + profile
	if err := ensureDirectory(artifacts, directory); err != nil {
		return err
	}
	output, err := artifacts.OpenRoot(directory)
	if err != nil {
		return errors.New("output")
	}
	defer func() { _ = output.Close() }()
	machine, err := report.RenderJSON()
	if err != nil {
		return err
	}
	if err := atomicWrite(output, "report.json", machine); err != nil {
		return err
	}
	return atomicWrite(output, "report.md", report.RenderText())
}

// ensureDirectory creates or validates one non-symlink directory.
func ensureDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil {
			return errors.New("output")
		}
		info, err = root.Lstat(name)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output")
	}
	return nil
}

// atomicWrite fsyncs one fixed regular artifact before descriptor-rooted rename.
func atomicWrite(root *os.Root, name string, content []byte) error {
	if info, err := root.Lstat(name); err == nil &&
		(!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("output")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("output")
	}
	temporary := name + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("output")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return errors.New("output")
	}
	if err := file.Sync(); err != nil {
		return errors.New("output")
	}
	if err := file.Close(); err != nil {
		return errors.New("output")
	}
	if err := root.Rename(temporary, name); err != nil {
		return errors.New("output")
	}
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("output")
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return errors.New("output")
	}
	ok = true
	return nil
}
