//nolint:goconst // Closed test fixtures intentionally repeat exact wire vocabulary.
package interop

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestRegistryRejectsCommandAuthorityAndUnsafeURLs proves the registry cannot select execution.
func TestRegistryRejectsCommandAuthorityAndUnsafeURLs(t *testing.T) {
	registry := validRegistryForTest()
	tests := []struct {
		name   string
		mutate func(*Registry)
	}{
		{name: "unknown field is rejected by decoding", mutate: nil},
		{name: "url credentials", mutate: func(value *Registry) {
			value.Sources[0].URL = "https://user@example.test/source"
		}},
		{name: "url query", mutate: func(value *Registry) {
			value.Sources[0].URL = "https://github.com/source?ref=main"
		}},
		{name: "unsafe query", mutate: func(value *Registry) {
			value.Sources[0].Query = "run command from result"
		}},
		{name: "optional outage source", mutate: func(value *Registry) {
			value.Sources[0].Required = false
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.mutate == nil {
				content := []byte(`{"schema":"dkim2.interop-discovery-registry.v1","command":"sh"}`)
				if _, err := LoadRegistry(content); err == nil {
					t.Fatal("LoadRegistry accepted execution authority")
				}
				return
			}
			changed := registry
			changed.Sources = append([]DiscoverySource(nil), registry.Sources...)
			testCase.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("Validate accepted hostile registry input")
			}
		})
	}
}

// TestDiscoveryOutageCannotBecomeCandidateAbsence freezes the required outage state.
func TestDiscoveryOutageCannotBecomeCandidateAbsence(t *testing.T) {
	registry := validRegistryForTest()
	evidence := validEvidenceForTest(registry)
	evidence.Sources[0].State = "unavailable"
	evidence.Sources[0].ResponseSHA256 = ""
	evidence.Sources[0].NormalizedSHA256 = ""
	evidence.Availability = "no_eligible_candidate"
	if err := evidence.Validate(registry, testNow()); err == nil {
		t.Fatal("Validate accepted outage as no eligible candidate")
	}
	evidence.Availability = "discovery_unavailable"
	if err := evidence.Validate(registry, testNow()); err != nil {
		t.Fatalf("Validate rejected closed outage: %v", err)
	}
	evidence = validEvidenceForTest(registry)
	evidence.Sources[0].State = "invalid"
	evidence.Sources[0].ResponseSHA256 = ""
	evidence.Sources[0].NormalizedSHA256 = ""
	if err := evidence.Validate(registry, testNow()); err == nil {
		t.Fatal("Validate accepted invalid required evidence as candidate absence")
	}
	evidence.Availability = "evidence_invalid"
	if err := evidence.Validate(registry, testNow()); err != nil {
		t.Fatalf("Validate rejected closed invalid evidence state: %v", err)
	}
}

// TestEligibleCandidateRequiresImmutableLicensedOverlap freezes eligibility evidence.
func TestEligibleCandidateRequiresImmutableLicensedOverlap(t *testing.T) {
	registry := validRegistryForTest()
	evidence := validEvidenceForTest(registry)
	evidence.Candidates = []Candidate{{
		ID: "peer", CanonicalLocation: "https://github.com/example/peer",
		State: "eligible_runnable", Reason: "reviewed-runtime",
		EvidenceSources: []string{registry.Sources[0].ID},
	}}
	evidence.Availability = "eligible_not_runnable"
	if err := evidence.Validate(registry, testNow()); err == nil {
		t.Fatal("Validate accepted unbound eligible candidate")
	}
	evidence.Candidates[0].Revision = strings.Repeat("a", 40)
	evidence.Candidates[0].SourceSHA256 = testDigest
	evidence.Candidates[0].BuildSHA256 = testDigest
	evidence.Candidates[0].License = "Apache-2.0"
	evidence.Candidates[0].Operations = []string{"signature-parse"}
	if err := evidence.Validate(registry, testNow()); err != nil {
		t.Fatalf("Validate rejected bound eligible candidate: %v", err)
	}
}

// TestComparisonRequiresRuntimeAgreementBeforeCompared freezes availability claims.
func TestComparisonRequiresRuntimeAgreementBeforeCompared(t *testing.T) {
	registry := validRegistryForTest()
	evidence := validEvidenceForTest(registry)
	evidence.Candidates = []Candidate{{
		ID: "peer", CanonicalLocation: "https://github.com/example/peer",
		Revision: strings.Repeat("a", 40), SourceSHA256: testDigest,
		License: "Apache-2.0", Operations: []string{"signature-parse"},
		State: "eligible_runnable", Reason: "reviewed-runtime",
		EvidenceSources: []string{registry.Sources[0].ID},
	}}
	report := ComparisonReport{
		Schema: ComparisonSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision: evidence.BaseRevision, CandidateSnapshotSHA256: evidence.CandidateSnapshotSHA256,
		RegistrySHA256: evidence.RegistrySHA256, EvidenceSHA256: testDigest,
		ObservationCutoff: evidence.ObservationCutoff, Availability: "compared",
	}
	if err := report.Validate(evidence); err == nil {
		t.Fatal("Validate accepted compared without runtime agreement")
	}
	report.Cases = []ComparisonCase{{
		CandidateID: "peer", CaseID: "case-one", Operation: "signature-parse",
		ClaimClass: "external_observation", FixtureSHA256: testDigest,
		LocalProducer: testDigest, ExternalProducer: testDigest, State: "agreement",
	}}
	if err := report.Validate(evidence); err != nil {
		t.Fatalf("Validate rejected exact runtime agreement: %v", err)
	}
}

// TestCanonicalJSONIsDeterministic freezes normalized evidence encoding.
func TestCanonicalJSONIsDeterministic(t *testing.T) {
	registry := validRegistryForTest()
	first, err := CanonicalJSON(registry)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalJSON(registry)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualCanonical(first, second) {
		t.Fatal("CanonicalJSON changed identical input")
	}
}

// TestPeerContainerArgumentsEnforceTheClosedSandbox prevents external runner privilege drift.
func TestPeerContainerArgumentsEnforceTheClosedSandbox(t *testing.T) {
	arguments := peerContainerArguments("/safe/peer.test", "^TestPeer$")
	for _, required := range []string{
		"--pull", "never", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "32", "--memory", "256m", "--cpus", "1",
		"--ulimit", "nofile=64:64", "fsize=16777216:16777216",
		"--user", "65534:65534", "--entrypoint", "/peer.test",
		peerRunnerImage,
	} {
		if !slices.Contains(arguments, required) {
			t.Fatalf("peer container arguments omitted %q", required)
		}
	}
	joined := strings.Join(arguments, " ")
	for _, forbidden := range []string{"--privileged", "/var/run/docker.sock", "--network host"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("peer container arguments admitted %q", forbidden)
		}
	}
}

// TestPeerBuildArgumentsEnforceTheClosedSandbox prevents source-build isolation drift.
func TestPeerBuildArgumentsEnforceTheClosedSandbox(t *testing.T) {
	arguments := peerBuildArguments(
		"/safe/root",
		"/safe/output",
		"/safe/source.tar.gz",
		"/safe/harness_test.go",
		currentPeer{
			id: "peer", sourceDirectory: "peer-source", packagePath: ".",
			moduleCache: ".artifacts/cache", expectedBuildSHA256: testDigest,
			expectedDependencyID: testDigest,
		},
	)
	for _, required := range []string{
		"--pull", "never", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "65534:65534", "GOPROXY=off", "GOSUMDB=off",
		"--ulimit", "nofile=64:64", "fsize=134217728:134217728",
		"GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64",
		peerRunnerImage,
	} {
		if !slices.Contains(arguments, required) {
			t.Fatalf("peer build arguments omitted %q", required)
		}
	}
	joined := strings.Join(arguments, " ")
	for _, required := range []string{
		"sha256sum -c", "go mod verify", "go test -c -vet=off",
		"src=/safe/source.tar.gz,dst=/source.tar.gz,readonly",
		"src=/safe/harness_test.go,dst=/harness_test.go,readonly",
		"src=/safe/root/.artifacts/cache,dst=/gopath/pkg/mod,readonly",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("peer build command omitted %q", required)
		}
	}
	for _, forbidden := range []string{"--privileged", "/var/run/docker.sock", "--network host"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("peer build arguments admitted %q", forbidden)
		}
	}
}

// TestBoundedPeerOutputRejectsOverflow contains hostile external diagnostics.
func TestBoundedPeerOutputRejectsOverflow(t *testing.T) {
	output := &boundedPeerOutput{}
	if _, err := output.Write(make([]byte, maxPeerOutputBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte{0}); err == nil {
		t.Fatal("bounded peer output accepted overflow")
	}
}

// FuzzLoadRegistry proves hostile registry bytes remain bounded and panic-free.
func FuzzLoadRegistry(f *testing.F) {
	content, err := CanonicalJSON(validRegistryForTest())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(content)
	f.Add([]byte(`{"schema":"dkim2.interop-discovery-registry.v1","sources":[]}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if len(input) > maxRegistryBytes+1 {
			input = input[:maxRegistryBytes+1]
		}
		_, _ = LoadRegistry(input)
	})
}

// validRegistryForTest constructs one sorted closed registry.
func validRegistryForTest() Registry {
	return Registry{
		Schema: RegistrySchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft, MaxAgeHours: 168,
		RetrievalPolicy: RetrievalPolicy{
			MaxRedirects: 2, MaxResponseBytes: 8192, MaxFiles: 8, MaxFileBytes: 4096,
			MaxTotalBytes: 32768, MaxPathBytes: 256, MaxDepth: 8, TimeoutSeconds: 10,
		},
		Sources: []DiscoverySource{
			{ID: "draft", Kind: "ietf_draft", URL: "https://www.ietf.org/archive/id/spec.txt", Query: "exact", Required: true},
			{ID: "forge", Kind: "source_forge_search", URL: "https://github.com/search", Query: "exact dkim2", Required: true},
			{ID: "mail", Kind: "ietf_mail_archive", URL: "https://mailarchive.ietf.org/arch/browse/ietf-dkim", Query: "exact", Required: true},
			{ID: "repo", Kind: "source_repository", URL: "https://github.com/example/repo", Query: "exact", Required: true},
			{ID: "repo-two", Kind: "source_repository", URL: "https://forge.turscar.ie/example/repo", Query: "exact", Required: true},
		},
	}
}

// validEvidenceForTest constructs complete no-candidate discovery evidence.
func validEvidenceForTest(registry Registry) DiscoveryEvidence {
	observations := make([]SourceObservation, 0, len(registry.Sources))
	for _, source := range registry.Sources {
		observations = append(observations, SourceObservation{
			ID: source.ID, State: "observed", ResponseSHA256: testDigest, NormalizedSHA256: testDigest,
		})
	}
	return DiscoveryEvidence{
		Schema: EvidenceSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision: strings.Repeat("a", 40), CandidateSnapshotSHA256: testDigest,
		RegistrySHA256: testDigest, ObservationCutoff: testNow().Format(time.RFC3339),
		Sources: observations, Availability: "no_eligible_candidate",
	}
}

// testNow returns one stable evidence freshness clock.
func testNow() time.Time {
	return time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
}
