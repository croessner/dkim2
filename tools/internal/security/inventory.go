// Package security owns the closed repository security-test inventory and evidence.
//
//nolint:goconst // The auditable inventory repeats dimension names at their owning entry.
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	// MessageDraft is the exact DKIM2 behavior baseline used by security evidence.
	MessageDraft = "draft-ietf-dkim-dkim2-spec-05"
	// DNSDraft is the exact historical DNS behavior baseline used by security evidence.
	DNSDraft = "draft-chuang-dkim2-dns-04"
	// BaseRevision is the fixed trusted implementation anchor for candidate admission.
	BaseRevision = "f30fecbd35ae3afd1b590ddfe55ee45f0cf6555a"
	// FuzzDuration is the minimum unchanged-candidate duration for each target.
	FuzzDuration = "10s"

	moduleMilter          = "cmd/dkim2-milter"
	moduleExim            = "cmd/dkim2-exim"
	moduleControl         = "cmd/dkim2ctl"
	moduleDaemon          = "cmd/dkim2d"
	moduleLibrary         = "lib"
	moduleTools           = "tools"
	dimensionEnvelopeByte = "envelope_bytes"
	dimensionJSONDepth    = "json_depth"
	dimensionWaiters      = "waiters"
)

var (
	closedClasses = stringSet(
		"adapter_contract",
		"documented_interpretation",
		"draft_normative",
		"local_security_policy",
		"openapi_contract",
		"rfc_normative",
	)
	identifierPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	sourcePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*_test\.go$`)
)

// FuzzTarget binds one first-party fuzz function to its closed security owner.
type FuzzTarget struct {
	ID               string   `json:"id"`
	Module           string   `json:"module"`
	Package          string   `json:"package"`
	Function         string   `json:"function"`
	Source           string   `json:"source"`
	Boundary         string   `json:"boundary"`
	Class            string   `json:"class"`
	SeedSource       string   `json:"seed_source"`
	Properties       []string `json:"properties"`
	BoundingStrategy string   `json:"bounding_strategy"`
	ExternalIO       string   `json:"external_io"`
	RegressionOwner  string   `json:"regression_owner"`
	Duration         string   `json:"duration"`
}

// ResourceOwner records one production limit family and its deterministic proofs.
type ResourceOwner struct {
	ID         string   `json:"id"`
	Owner      string   `json:"owner"`
	Dimensions []string `json:"dimensions"`
	Proofs     []string `json:"proofs"`
}

// Targets returns the immutable closed first-party fuzz inventory.
func Targets() []FuzzTarget {
	targets := []FuzzTarget{
		target("cmd/dkim2-exim/internal/config/config_test.go", "FuzzDecode", "Exim adapter configuration", "local_security_policy", "bounded strict adapter configuration decoding"),
		target("cmd/dkim2-exim/internal/daemon/admission_test.go", "FuzzOperationAdmission", "Exim daemon operation admission", "openapi_contract", "bounded closed operation request admission"),
		target("cmd/dkim2-exim/internal/daemon/mapping_test.go", "FuzzMapTransportFilterMessage", "Exim transport message projection", "adapter_contract", "bounded byte-preserving CRLF reconstruction"),
		target("cmd/dkim2-exim/internal/evidence/manifest_test.go", "FuzzStoreManifest", "Exim evidence manifest", "local_security_policy", "bounded strict durable manifest decoding"),
		target("cmd/dkim2-exim/internal/evidence/readiness_test.go", "FuzzDecodeReadiness", "Exim evidence readiness", "local_security_policy", "bounded strict readiness decoding"),
		target("cmd/dkim2-exim/internal/evidence/record_test.go", "FuzzDecode", "Exim evidence record", "adapter_contract", "bounded authenticated record decoding"),
		target("cmd/dkim2-exim/internal/filter/input_test.go", "FuzzInvocationParsing", "Exim filter invocation", "adapter_contract", "bounded exact direct argument admission"),
		target("cmd/dkim2-exim/internal/filter/rewrite_test.go", "FuzzTransform", "Exim filter rewriting", "adapter_contract", "bounded complete message transformation"),
		target("cmd/dkim2-exim/internal/ipc/codec_test.go", "FuzzRequestCodec", "Exim IPC request", "adapter_contract", "bounded framed request decoding"),
		target("cmd/dkim2-exim/internal/ipc/codec_test.go", "FuzzResponseCodec", "Exim IPC response", "adapter_contract", "bounded framed response decoding"),
		target("cmd/dkim2-milter/internal/config/config_test.go", "FuzzConfigurationManifestParsingNeverPanics", "protected Milter configuration", "local_security_policy", "strict bounded YAML and protected-file validation"),
		target("cmd/dkim2-milter/internal/daemon/handler_behavior_test.go", "FuzzRawDaemonResponseAndActionAdmissionNeverPanics", "Milter daemon response", "openapi_contract", "bounded response and closed action admission"),
		target("cmd/dkim2-milter/internal/integration/milter_fixture_test.go", "FuzzMilterFixtureDecoding", "portable Milter fixture", "adapter_contract", "bounded strict fixture decoding"),
		target("cmd/dkim2-milter/internal/milter/actions_test.go", "FuzzActionPlanAdmissionNeverPanics", "Milter action plan", "adapter_contract", "prevalidate count bytes and action vocabulary"),
		target("cmd/dkim2-milter/internal/milter/state_matrix_test.go", "FuzzCallbackStateMachineNeverPanics", "Milter callback state", "adapter_contract", "bounded transition sequence"),
		target("cmd/dkim2-milter/internal/milter/state_matrix_test.go", "FuzzEnvelopeAndESMTPValidationNeverPanics", "SMTP envelope callbacks", "rfc_normative", "bounded path and ESMTP argument validation"),
		target("cmd/dkim2-milter/internal/milter/state_matrix_test.go", "FuzzHeaderValidationNeverPanics", "Milter header callbacks", "adapter_contract", "bounded field and message accounting"),
		target("cmd/dkim2-milter/internal/milter/state_matrix_test.go", "FuzzReadFrameNeverAllocatesBeyondTheFixedCap", "Milter wire frames", "adapter_contract", "fixed frame cap before allocation"),
		target("cmd/dkim2ctl/internal/testclient/fuzz_test.go", "FuzzFixtureDecoding", "generated-client fixture", "openapi_contract", "strict bounded offline decoding"),
		target("cmd/dkim2ctl/internal/testclient/fuzz_test.go", "FuzzNegativeMutationConstruction", "negative HTTP mutation", "openapi_contract", "closed mutation vocabulary"),
		target("cmd/dkim2ctl/internal/testclient/fuzz_test.go", "FuzzOutputPrivacy", "CLI output", "local_security_policy", "bounded redacted record projection"),
		target("cmd/dkim2ctl/internal/testclient/fuzz_test.go", "FuzzResponseClassification", "generated-client response", "openapi_contract", "closed response and error classification"),
		target("cmd/dkim2d/internal/app/replay_test.go", "FuzzReplayCheckClassification", "daemon replay result", "local_security_policy", "closed result error and state matrix"),
		target("cmd/dkim2d/internal/config/config_test.go", "FuzzLoadStrict", "daemon configuration", "local_security_policy", "strict bounded typed configuration"),
		target("cmd/dkim2d/internal/config/protected_loader_test.go", "FuzzProtectedPathComponents", "protected path", "local_security_policy", "confined component and descriptor checks"),
		target("cmd/dkim2d/internal/config/protected_parse_test.go", "FuzzProtectedContentParsers", "protected content", "local_security_policy", "bounded strict PEM JSON and secret parsing"),
		target("cmd/dkim2d/internal/config/yaml_test.go", "FuzzExpandPlaceholders", "configuration placeholders", "local_security_policy", "bounded scalar-only expansion"),
		target("cmd/dkim2d/internal/config/yaml_test.go", "FuzzPreflightYAML", "configuration YAML", "local_security_policy", "node depth count and scalar caps"),
		target("cmd/dkim2d/internal/httpjson/http_boundary_matrix_test.go", "FuzzHTTPBoundaryPrecedence", "raw HTTP request", "openapi_contract", "bounded lexical preflight before admission"),
		target("cmd/dkim2d/internal/httpjson/json_preflight_test.go", "FuzzJSONPreflight", "HTTP JSON", "openapi_contract", "token depth member and byte caps"),
		target("cmd/dkim2d/internal/httpjson/request_test.go", "FuzzDecodeCanonicalBase64", "OpenAPI message encoding", "openapi_contract", "encoded and decoded caps before allocation"),
		target("cmd/dkim2d/internal/httpjson/request_test.go", "FuzzMapProcessRequest", "OpenAPI process request", "openapi_contract", "closed generated DTO mapping"),
		target("cmd/dkim2d/internal/httpjson/response_snapshot_test.go", "FuzzResponseSnapshotMappers", "OpenAPI response snapshot", "openapi_contract", "immutable bounded action response mapping"),
		target("cmd/dkim2d/internal/migration/inventory_test.go", "FuzzLegacyInventoryNeverPanicsOrRequestsPrivateKeys", "legacy OpenDKIM inventory", "local_security_policy", "bounded read-only projection without private key attributes"),
		target("cmd/dkim2d/internal/observability/fuzz_test.go", "FuzzMetricLabels", "Prometheus labels", "local_security_policy", "closed low-cardinality vocabulary"),
		target("cmd/dkim2d/internal/observability/fuzz_test.go", "FuzzOTLPProjection", "OTLP projection", "local_security_policy", "bounded allowlisted trace fields"),
		target("cmd/dkim2d/internal/observability/fuzz_test.go", "FuzzSlogAdmission", "structured logging", "local_security_policy", "bounded allowlisted log fields"),
		target("cmd/dkim2d/internal/replay/valkey/fuzz_test.go", "FuzzValkeyResultMapping", "Valkey replay response", "local_security_policy", "bounded RESP and closed mutation authority"),
		target("cmd/dkim2d/internal/signingstore/manifest_fuzz_test.go", "FuzzPrivateManifestParsingNeverPanics", "private signing manifest", "local_security_policy", "strict bounded same-generation parsing"),
		target("cmd/dkim2d/internal/signingstore/registry_test.go", "FuzzImportedPrivateKeyNeverLeaksOrPanics", "protected legacy private-key import", "local_security_policy", "bounded exact PKCS8 algorithm and strength validation"),
		target("lib/dns_provider_fuzz_test.go", "FuzzDNSPublicProvider", "public DNS provider", "draft_normative", "bounded typed resolver projection"),
		target("lib/dns_provider_fuzz_test.go", "FuzzDNSPublicVerifier", "public DNS verification", "draft_normative", "bounded provider and verification composition"),
		target("lib/internal/canonical/fuzz_test.go", "FuzzBodyHashInput", "body hash input", "draft_normative", "bounded byte-preserving canonicalization"),
		target("lib/internal/canonical/fuzz_test.go", "FuzzHeaderHashInput", "header hash input", "draft_normative", "bounded occurrence-preserving canonicalization"),
		target("lib/internal/canonical/fuzz_test.go", "FuzzSignatureInput", "signature input", "draft_normative", "bounded deterministic signature framing"),
		target("lib/internal/datasource/flatfile/fuzz_test.go", "FuzzCrossReferences", "flat-file cross references", "local_security_policy", "bounded exact same-generation resolution"),
		target("lib/internal/datasource/flatfile/fuzz_test.go", "FuzzProviderParity", "flat-file provider parity", "local_security_policy", "closed storage-neutral projection"),
		target("lib/internal/datasource/flatfile/fuzz_test.go", "FuzzStrictJSON", "flat-file JSON", "local_security_policy", "strict bounded duplicate-free decoding"),
		target("lib/internal/datasource/fuzz_test.go", "FuzzIdentifierAndLookupFacts", "datasource identifiers", "local_security_policy", "bounded exact lookup facts"),
		target("lib/internal/datasource/memory/fuzz_test.go", "FuzzSnapshotMapping", "memory datasource snapshot", "local_security_policy", "immutable generation projection"),
		target("lib/internal/datasource/signingprofile/fuzz_test.go", "FuzzSigningProjection", "signing profile projection", "local_security_policy", "opaque handle and public key coherence"),
		target("lib/internal/dsn/parser_test.go", "FuzzParse", "delivery status notification parser", "rfc_normative", "bounded multipart parsing without caller-byte mutation"),
		target("lib/internal/instance/fuzz_test.go", "FuzzParseMessageInstance", "Message-Instance parser", "draft_normative", "bounded strict tag and Base64 parsing"),
		target("lib/internal/instance/render_fuzz_test.go", "FuzzMessageInstanceRender", "Message-Instance rendering", "draft_normative", "bounded deterministic field rendering"),
		target("lib/internal/keyresolver/fuzz_test.go", "FuzzDNSKeyRecord", "DNS key record", "draft_normative", "bounded strict DNS-04 tag parsing"),
		target("lib/internal/keyresolver/fuzz_test.go", "FuzzKeyDecodingCoherence", "DNS public key", "draft_normative", "bounded algorithm and key-shape coherence"),
		target("lib/internal/keyresolver/fuzz_test.go", "FuzzOwnerConstruction", "DNS owner name", "draft_normative", "label count and owner byte caps"),
		target("lib/internal/keyresolver/fuzz_test.go", "FuzzTXTLookupTraversal", "DNS TXT response", "local_security_policy", "RR count byte and cancellation caps"),
		target("lib/internal/observability/fuzz_test.go", "FuzzObservationEventValidation", "library observation event", "local_security_policy", "closed bounded event vocabulary"),
		target("lib/internal/policy/fuzz_test.go", "FuzzSealedPolicyEvaluation", "sealed policy evidence", "documented_interpretation", "bounded immutable finding projection"),
		target("lib/internal/rawmsg/fuzz_test.go", "FuzzParseSmallInputs", "raw RFC 5322 message", "rfc_normative", "total line field and header caps"),
		target("lib/internal/rawmsg/insertion_fuzz_test.go", "FuzzSignedMessageInsertion", "signed message insertion", "draft_normative", "bounded atomic header insertion"),
		target("lib/internal/recipe/apply_body_fuzz_test.go", "FuzzApplyBody", "recipe body application", "draft_normative", "bounded lines ranges literals output and work"),
		target("lib/internal/recipe/apply_header_fuzz_test.go", "FuzzApplyHeader", "recipe header application", "draft_normative", "bounded names occurrences output and work"),
		target("lib/internal/recipe/generation_fuzz_test.go", "FuzzGenerateRecipe", "recipe generation", "documented_interpretation", "bounded candidates comparisons steps and proof"),
		target("lib/internal/recipe/generation_fuzz_test.go", "FuzzGeneratedRecipeRoundTrip", "recipe round trip", "documented_interpretation", "bounded generate parse apply self-proof"),
		target("lib/internal/recipe/parser_fuzz_test.go", "FuzzParseRecipe", "recipe JSON", "draft_normative", "strict depth member string step and byte caps"),
		target("lib/internal/replay/fuzz_test.go", "FuzzMemoryStateSequence", "memory replay lifecycle", "local_security_policy", "bounded entry and prune accounting"),
		target("lib/internal/replay/fuzz_test.go", "FuzzReplayIdentityAndKey", "replay identity", "local_security_policy", "framed bounded privacy-preserving derivation"),
		target("lib/internal/replay/fuzz_test.go", "FuzzReplayResultPair", "replay result pair", "local_security_policy", "closed result error and state combinations"),
		target("lib/internal/replay/fuzz_test.go", "FuzzReplayRetention", "replay retention", "local_security_policy", "overflow-safe millisecond retention"),
		target("lib/internal/signature/fuzz_test.go", "FuzzParseDKIM2Signature", "DKIM2-Signature parser", "draft_normative", "bounded strict tags Base64 and numeric fields"),
		target("lib/internal/signature/rendering_fuzz_test.go", "FuzzCustodyTransitions", "custody transition", "draft_normative", "closed bounded sequence state machine"),
		target("lib/internal/signature/rendering_fuzz_test.go", "FuzzDKIM2SignatureRender", "DKIM2-Signature rendering", "draft_normative", "bounded deterministic field rendering"),
		target("lib/internal/signature/rendering_fuzz_test.go", "FuzzUnsignedSignatureTarget", "unsigned signature target", "draft_normative", "bounded exact empty-signature framing"),
		target("lib/internal/signing/signing_fuzz_test.go", "FuzzHashGate", "signing hash gate", "draft_normative", "bounded exact previous-instance hash"),
		target("lib/internal/signing/signing_fuzz_test.go", "FuzzSigningRequest", "signing request", "draft_normative", "bounded immutable signing plan"),
		target("lib/internal/tagvalue/fuzz_test.go", "FuzzScanTagList", "DKIM2 tag list", "draft_normative", "bounded duplicate-aware lexical scanner"),
		target("lib/internal/verify/fuzz_test.go", "FuzzVerifyStaticKeyRequest", "static-key verification", "draft_normative", "bounded immutable verification request"),
		target("lib/internal/verify/history_fuzz_test.go", "FuzzHistoryWalk", "historical reconstruction", "draft_normative", "iterative bounded depth state output and work"),
		target("lib/policy_fuzz_test.go", "FuzzEvaluatePolicySealedResults", "public policy facade", "documented_interpretation", "bounded immutable sealed-result projection"),
		target("lib/signing_fuzz_test.go", "FuzzSigningFacade", "public signing facade", "draft_normative", "bounded immutable signing and revision request"),
		target("lib/verification_fuzz_test.go", "FuzzPublicVerify", "public verification facade", "draft_normative", "bounded immutable message envelope and provider work"),
		target("tools/cmd/conformance/main_test.go", "FuzzPostfixQualificationReportDecoding", "Postfix qualification report", "local_security_policy", "strict bounded content-free report decoding"),
		target("tools/cmd/deploymentfixture/main_test.go", "FuzzDeploymentFixtureDNSNeverPanicsOrChangesClassification", "Postfix deployment DNS fixture", "local_security_policy", "fixed datagram record and label bounds before deterministic response construction"),
		target("tools/cmd/ocipolicy/main_test.go", "FuzzReadLayoutArchive", "OCI image layout", "local_security_policy", "bounded non-extracting tar and descriptor validation"),
		target("tools/internal/interop/archive_test.go", "FuzzInspectArchive", "external source archive", "local_security_policy", "bounded non-extracting tar path type collision mode and content validation"),
		target("tools/internal/interop/model_test.go", "FuzzLoadRegistry", "interoperability discovery registry", "local_security_policy", "strict depth token source URL query and retrieval policy limits"),
		target("tools/internal/reference/issues_test.go", "FuzzLoadIssueLog", "draft issue log", "local_security_policy", "strict bounded duplicate-free issue evidence decoding"),
		target("tools/internal/reference/proxy_test.go", "FuzzLoadModuleProof", "standalone module proof", "local_security_policy", "strict bounded candidate-bound module evidence decoding"),
		target("tools/internal/reference/report_test.go", "FuzzLoadCandidateReport", "reference candidate report", "local_security_policy", "strict bounded candidate-bound aggregate evidence decoding"),
		target("tools/internal/reference/version_test.go", "FuzzLoadReleasePlan", "release-candidate plan", "local_security_policy", "strict bounded canonical version and publication policy decoding"),
		target("tools/internal/strictjson/decode_test.go", "FuzzDecodeNeverPanicsOrChangesClassification", "release evidence JSON", "local_security_policy", "shared depth token duplicate unknown and trailing-document limits"),
		target("tools/postfix_qualification_policy_test.go", "FuzzPostfixQualificationComposeDecoding", "Postfix qualification configuration", "local_security_policy", "bounded static topology decoding"),
	}
	slices.SortFunc(targets, func(left, right FuzzTarget) int {
		return strings.Compare(left.ID, right.ID)
	})
	return targets
}

// ResourceOwners returns the closed cross-boundary production limit inventory.
func ResourceOwners() []ResourceOwner {
	return []ResourceOwner{
		resource("config", "cmd/dkim2d/internal/config and cmd/dkim2-milter/internal/config", []string{"file_bytes", "nodes", "depth", "scalars", "placeholders", "path_components", "pem_blocks", "read_attempts"}, "cmd/dkim2d/internal/config/yaml_test.go#TestPreflightYAMLEnforcesResourceBounds", "cmd/dkim2d/internal/config/protected_loader_test.go#TestProtectedRoleSizeMatrix"),
		resource("conformance", "tools/internal/conformance", []string{"manifest_bytes", "artifacts", "artifact_bytes", "paths", "report_bytes", "captured_output"}, "tools/internal/conformance/conformance_test.go#TestManifestRejectsDuplicateExactArtifactPath", "tools/internal/conformance/conformance_test.go#TestStrictJSONRejectsDuplicateUnknownAndDeepInput"),
		resource("datasource", "lib/internal/datasource and cmd/dkim2d/internal/datasource and cmd/dkim2d/internal/migration", []string{"identifier_bytes", "records", "profiles", "policies", "handles", "generations", "json_bytes", dimensionJSONDepth, "backend_bytes", "pages", "responses", "connections", "report_bytes"}, "lib/internal/datasource/limits_test.go#TestLimitsAllowNarrowingAndRejectZeroNegativeOrWidenedValues", "lib/internal/datasource/limits_test.go#TestUsageRejectsOneOverNegativeOverflowAndInconsistentValues", "cmd/dkim2d/internal/migration/inventory_test.go#TestDryRunNeverRequestsKeysOrPublishesIdentity"),
		resource("deployment", "tools/cmd/deploymentfixture", []string{"dns_query_bytes", "dns_labels", "dns_options", "dns_record_bytes", "smtp_reply_bytes", "queue_identifier_bytes", "captured_message_bytes"}, "tools/cmd/deploymentfixture/main_test.go#TestAnswerDNSBoundsQueriesAndReturnsOnlyBoundTXT", "tools/cmd/deploymentfixture/main_test.go#TestSMTPReplyRequiresExactQueuedAcceptance"),
		resource("dns", "lib/internal/keyresolver", []string{"owner_bytes", "labels", "rr_count", "txt_bytes", "key_bytes", "lookups", "cache_entries", "flights", dimensionWaiters}, "lib/internal/keyresolver/limits_test.go#TestDefaultLimitsMatchClosedDNSBounds", "lib/internal/keyresolver/flight_test.go#TestFlightWaiterLimitAllowsExactAndRejectsOneOver"),
		resource("exim", "cmd/dkim2-exim", []string{"message_bytes", "header_bytes", "header_fields", "recipients", "envelope_bytes", "ipc_frame_bytes", "evidence_records", "evidence_bytes"}, "cmd/dkim2-exim/internal/filter/input_test.go#TestBuildRequestValidatesMessageBeforeEvidence", "cmd/dkim2-exim/internal/ipc/codec_test.go#TestRequestRejectsHeaderAggregateBeforeNextAllocation"),
		resource("http", "cmd/dkim2d/internal/httpjson", []string{"request_line_bytes", "header_bytes", "body_bytes", dimensionJSONDepth, "json_tokens", "decoded_message_bytes", dimensionEnvelopeByte, "in_flight", dimensionWaiters, "response_bytes"}, "cmd/dkim2d/internal/httpjson/http_boundary_matrix_test.go#TestHTTPBoundaryRawMethodTargetAndHeadLimits", "cmd/dkim2d/internal/httpjson/body_preflight_test.go#TestReadProcessBodyAcceptsExactLimitAndRejectsOneOver"),
		resource("interop", "tools/internal/interop", []string{"registry_bytes", "json_depth", "json_tokens", "sources", "response_bytes", "redirects", "files", "file_bytes", "total_bytes", "path_bytes", "tree_depth", "timeout", "candidates", "operations", "comparison_cases"}, "tools/internal/interop/model_test.go#TestRegistryRejectsCommandAuthorityAndUnsafeURLs", "tools/internal/interop/model_test.go#TestDiscoveryOutageCannotBecomeCandidateAbsence"),
		resource("milter", "cmd/dkim2-milter/internal/milter", []string{"frame_bytes", "connections", "messages", "buffered_bytes", "headers", "recipients", "actions", "daemon_response_bytes", "timeouts"}, "cmd/dkim2-milter/internal/milter/state_matrix_test.go#TestReadFrameEnforcesDefaultAndCommandSpecificCaps", "cmd/dkim2-milter/internal/milter/state_matrix_test.go#TestSessionLimitInvariantsFailAtConstruction"),
		resource("observability", "lib/internal/observability and cmd/dkim2d/internal/observability", []string{"record_bytes", "attributes", "events", "batch", "queue", "labels", "buckets"}, "cmd/dkim2d/internal/observability/logging_test.go#TestBoundedLoggerRejectsUnknownAndHostileValues", "cmd/dkim2d/internal/observability/metrics_test.go#TestMetricsRejectArbitraryLabels"),
		resource("packaging", "tools/cmd/buildmeta tools/cmd/ocipolicy tools/cmd/dbguard and repository scripts", []string{"archive_bytes", "archive_entries", "entry_bytes", "platforms", "manifests", "layers", "filesystem_entries", "labels", "candidate_files", "candidate_bytes", "publication_subjects", "publication_tool_bytes", "scanner_database_bytes", "scanner_database_files", "scanner_database_reads", "scanner_layout_bytes", "scanner_layout_entries", "scanner_snapshot_files", "scanner_output_bytes", "scanner_diagnostic_bytes", "scanner_duration", "scanner_clock_skew", "scanner_database_age"}, "tools/cmd/buildmeta/main_test.go#TestMaterializeCandidateRejectsHardlinksAndWritesExactPrivateBytes", "tools/cmd/ocipolicy/main_test.go#TestReadLayoutRejectsDuplicateAndLinkEntries", "tools/cmd/ocipolicy/main_test.go#TestStrictJSONRejectsTrailingDocuments", "tools/cmd/dbguard/main_test.go#TestBuildSnapshotRejectsOversizeSymlinkAndHardlinkDatabase", "tools/cmd/dbguard/main_test.go#TestGuardDatabaseFilesRejectsConcurrentWrite", "tools/cmd/dbguard/main_test.go#TestAddSnapshotFileSurvivesTransientSourceSwap", "tools/cmd/dbguard/main_test.go#TestBoundedWriterRejectsOversizeOutput", "tools/cmd/dbguard/main_test.go#TestValidateMetadataAtRejectsExpiredStaleAndFutureState", "tools/cmd/dbguard/main_test.go#TestParseScanTimeRejectsCallerClockDrift"),
		resource("raw-message", "lib/internal/rawmsg", []string{"total_bytes", "header_bytes", "header_fields", "line_bytes", "field_bytes", "body_lines"}, "lib/internal/rawmsg/body_test.go#TestBodyLineCountHardLimitAcceptsExactAndRejectsOneOver", "lib/internal/rawmsg/parser_test.go#TestParseRejectsHeaderResourceLimitViolations"),
		resource("recipe", "lib/internal/recipe", []string{"json_bytes", dimensionJSONDepth, "members", "names", "steps", "ranges", "literals", "state_bytes", "output_bytes", "candidates", "comparisons", "work_units", "history_depth"}, "lib/internal/recipe/limits_test.go#TestEveryRecipeHardMaximumAcceptsExactAndRejectsOneOver", "lib/internal/recipe/generation_limits_test.go#TestEveryGenerationHardMaximumAcceptsExactAndRejectsOneOver"),
		resource("replay", "lib/internal/replay and cmd/dkim2d/internal/replay/valkey", []string{"identity_bytes", "key_bytes", "value_bytes", "retention", "entries", "prune_budget", "in_flight", dimensionWaiters, "wire_bytes"}, "lib/internal/replay/retention_test.go#TestRetentionCheckedAdditionPreservesExactExpiry", "cmd/dkim2d/internal/replay/valkey/config_test.go#TestClientConfigAdmissionLimitsApplyExactDefaultsAndHardBounds"),
		resource("rotation", "cmd/dkim2d/internal/rotationadmin", []string{"work_items", "dns_records", "dns_batch_records", "dns_batches", "journal_bytes", "proof_age"}, "cmd/dkim2d/internal/rotationadmin/campaign_test.go#TestNormalCampaignPreparesOneCompleteCandidateOnce", "cmd/dkim2d/internal/rotationadmin/journal_test.go#TestJournalRequiresDeterministicCompleteFreshDNSProgress"),
		resource("signing", "lib/internal/signing and lib", []string{"message_bytes", dimensionEnvelopeByte, "profiles", "routes", "signatures", "callbacks", "fields", "output_bytes"}, "lib/signing_limits_test.go#TestPublicSigningMessageLimitExactAndOneOver", "lib/signing_limits_test.go#TestSigningLimitsRejectEveryWideningAndAcceptZeroDefaults"),
		resource("tag-fields", "lib/internal/tagvalue lib/internal/instance lib/internal/signature", []string{"field_bytes", "tags", "base64_encoded_bytes", "base64_decoded_bytes", "numeric_values", "signature_sets"}, "lib/internal/tagvalue/scanner_test.go#TestScanRejectsConfiguredLimitViolations", "lib/internal/tagvalue/base64_test.go#TestParseBase64StringRejectsDecodedLimit"),
		resource("verification", "lib/internal/verify and lib", []string{"message_bytes", "envelope_bytes", "signatures", "history_depth", "facts", "provider_calls", "output_facts"}, "lib/verification_abuse_test.go#TestPublicHardLimitBoundaries", "lib/facade_limits_test.go#TestFacadeAcceptsExactPublicLimitBoundaries"),
	}
}

// ValidateInventory compares the closed inventory with independently parsed source.
func ValidateInventory(root string) error {
	targets := Targets()
	if err := validateTargetRecords(targets); err != nil {
		return err
	}
	discovered, err := discoverFuzzTargets(root)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(targets, discovered, func(left, right FuzzTarget) bool {
		return left.Source == right.Source && left.Function == right.Function
	}) {
		return errors.New("fuzz_inventory_drift")
	}
	if err := validateResourceOwners(ResourceOwners()); err != nil {
		return err
	}
	testFunctions, err := discoverTestFunctions(root)
	if err != nil {
		return err
	}
	for _, owner := range ResourceOwners() {
		for _, proof := range owner.Proofs {
			if _, ok := testFunctions[proof]; !ok {
				return errors.New("resource_inventory_proof")
			}
		}
	}
	return nil
}

// InventorySHA256 hashes the normalized closed inventory without production limits.
func InventorySHA256() string {
	hasher := sha256.New()
	for _, current := range Targets() {
		_, _ = fmt.Fprintf(
			hasher,
			"%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00",
			current.ID,
			current.Module,
			current.Package,
			current.Function,
			current.Source,
			current.Boundary,
			current.Class,
			current.SeedSource,
			strings.Join(current.Properties, "\x1f"),
			current.BoundingStrategy,
			current.Duration,
		)
	}
	for _, current := range ResourceOwners() {
		_, _ = fmt.Fprintf(
			hasher,
			"%s\x00%s\x00%s\x00%s\x00",
			current.ID,
			current.Owner,
			strings.Join(current.Dimensions, "\x1f"),
			strings.Join(current.Proofs, "\x1f"),
		)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// target constructs an explicit target and derives its closed module/package identity.
func target(source, function, boundary, class, bounding string) FuzzTarget {
	module, pkg := moduleAndPackage(source)
	return FuzzTarget{
		ID:     module + ":" + strings.TrimPrefix(pkg, "./") + ":" + function,
		Module: module, Package: pkg, Function: function, Source: source,
		Boundary: boundary, Class: class,
		SeedSource: source + "#f.Add",
		Properties: []string{
			"deterministic_classification",
			"no_panic",
			"no_partial_publication",
			"secret_safe_diagnostics",
		},
		BoundingStrategy: bounding,
		ExternalIO:       "forbidden_or_deterministic_fake",
		RegressionOwner:  source,
		Duration:         FuzzDuration,
	}
}

// resource constructs one resource-owner inventory record.
func resource(id, owner string, dimensions []string, proofs ...string) ResourceOwner {
	return ResourceOwner{ID: id, Owner: owner, Dimensions: dimensions, Proofs: proofs}
}

// moduleAndPackage maps a repository source path to its exact workspace target.
func moduleAndPackage(source string) (string, string) {
	for _, module := range workspaceModules() {
		prefix := module + "/"
		if strings.HasPrefix(source, prefix) {
			directory := filepath.ToSlash(filepath.Dir(strings.TrimPrefix(source, prefix)))
			if directory == "." {
				return module, "."
			}
			return module, "./" + directory
		}
	}
	return "", ""
}

// workspaceModules returns the fixed ordered workspace module inventory.
func workspaceModules() []string {
	return []string{moduleExim, moduleMilter, moduleControl, moduleDaemon, moduleLibrary, moduleTools}
}

// validateTargetRecords rejects duplicate, malformed, command-selecting, or incomplete targets.
func validateTargetRecords(targets []FuzzTarget) error {
	seenID := make(map[string]struct{}, len(targets))
	seenSourceFunction := make(map[string]struct{}, len(targets))
	previous := ""
	for _, current := range targets {
		key := current.Source + "\x00" + current.Function
		if current.ID <= previous || current.Module == "" || current.Package == "" ||
			!sourcePattern.MatchString(current.Source) ||
			!identifierPattern.MatchString(current.Function) ||
			!strings.HasPrefix(current.Function, "Fuzz") ||
			current.Boundary == "" || !closedClasses[current.Class] ||
			current.SeedSource != current.Source+"#f.Add" ||
			current.Duration != FuzzDuration ||
			current.ExternalIO != "forbidden_or_deterministic_fake" ||
			current.RegressionOwner != current.Source ||
			len(current.Properties) == 0 || current.BoundingStrategy == "" {
			return errors.New("fuzz_inventory_record")
		}
		if _, duplicate := seenID[current.ID]; duplicate {
			return errors.New("fuzz_inventory_duplicate")
		}
		if _, duplicate := seenSourceFunction[key]; duplicate {
			return errors.New("fuzz_inventory_duplicate")
		}
		seenID[current.ID] = struct{}{}
		seenSourceFunction[key] = struct{}{}
		previous = current.ID
	}
	if len(targets) == 0 {
		return errors.New("fuzz_inventory_missing")
	}
	return nil
}

// discoverFuzzTargets parses every first-party Go source file outside vendor.
func discoverFuzzTargets(root string) ([]FuzzTarget, error) {
	var discovered []FuzzTarget
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("fuzz_inventory_source")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("fuzz_inventory_source")
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if relative == ".git" || relative == "vendor" || relative == "temp" ||
				relative == ".artifacts" || strings.HasPrefix(relative, ".git/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(relative, ".go") {
			return nil
		}
		input, err := readRegularFileBounded(path, 8<<20)
		if err != nil {
			return errors.New("fuzz_inventory_source")
		}
		file, err := parser.ParseFile(token.NewFileSet(), relative, input, 0)
		if err != nil {
			return errors.New("fuzz_inventory_source")
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(function.Name.Name, "Fuzz") {
				continue
			}
			discovered = append(discovered, FuzzTarget{
				Source: relative, Function: function.Name.Name,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(discovered, func(left, right int) bool {
		leftModule, leftPackage := moduleAndPackage(discovered[left].Source)
		rightModule, rightPackage := moduleAndPackage(discovered[right].Source)
		leftID := leftModule + ":" + strings.TrimPrefix(leftPackage, "./") + ":" + discovered[left].Function
		rightID := rightModule + ":" + strings.TrimPrefix(rightPackage, "./") + ":" + discovered[right].Function
		return leftID < rightID
	})
	return discovered, nil
}

// discoverTestFunctions independently indexes first-party proof paths and names.
func discoverTestFunctions(root string) (map[string]struct{}, error) {
	functions := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("resource_inventory_source")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("resource_inventory_source")
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if relative == ".git" || relative == "vendor" || relative == "temp" ||
				relative == ".artifacts" || strings.HasPrefix(relative, ".git/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(relative, "_test.go") {
			return nil
		}
		input, err := readRegularFileBounded(path, 8<<20)
		if err != nil {
			return errors.New("resource_inventory_source")
		}
		file, err := parser.ParseFile(token.NewFileSet(), relative, input, 0)
		if err != nil {
			return errors.New("resource_inventory_source")
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && strings.HasPrefix(function.Name.Name, "Test") {
				functions[relative+"#"+function.Name.Name] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return functions, nil
}

// validateResourceOwners rejects missing, duplicate, unordered, or duplicated dimensions.
func validateResourceOwners(owners []ResourceOwner) error {
	previous := ""
	seen := make(map[string]struct{}, len(owners))
	for _, owner := range owners {
		if owner.ID <= previous || owner.Owner == "" || len(owner.Dimensions) == 0 ||
			len(owner.Proofs) == 0 {
			return errors.New("resource_inventory_record")
		}
		if _, duplicate := seen[owner.ID]; duplicate {
			return errors.New("resource_inventory_duplicate")
		}
		seen[owner.ID] = struct{}{}
		previous = owner.ID
		dimensions := append([]string(nil), owner.Dimensions...)
		sort.Strings(dimensions)
		for index := 1; index < len(dimensions); index++ {
			if dimensions[index] == dimensions[index-1] {
				return errors.New("resource_inventory_duplicate")
			}
		}
		for _, proof := range owner.Proofs {
			source, function, found := strings.Cut(proof, "#")
			if !found || !sourcePattern.MatchString(source) ||
				!strings.HasPrefix(function, "Test") ||
				!identifierPattern.MatchString(function) {
				return errors.New("resource_inventory_record")
			}
		}
	}
	return nil
}

// stringSet constructs an immutable membership set.
func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
