package dkim2

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type publicPolicyFuzzSeed struct {
	result       VerifyResult
	dnsEffective bool
}

// FuzzEvaluatePolicySealedResults exercises real library-created results under restrictive public options.
func FuzzEvaluatePolicySealedResults(f *testing.F) {
	results := fuzzLibraryResults(f)
	for result := range len(results) {
		for mode := range 3 {
			f.Add(result, mode, 127, false)
			f.Add(result, mode, 0, true)
		}
	}
	f.Fuzz(func(t *testing.T, resultSeed, modeSeed, findingSeed int, copyResult bool) {
		runPublicPolicyFuzzCase(t, results, resultSeed, modeSeed, findingSeed, copyResult)
	})
}

// runPublicPolicyFuzzCase mutates accessor copies, evaluates twice, and delegates output checks.
func runPublicPolicyFuzzCase(t *testing.T, results []publicPolicyFuzzSeed, resultSeed, modeSeed, findingSeed int, copyResult bool) {
	t.Helper()
	seed := results[boundedPublicFuzzIndex(resultSeed, len(results))]
	result := seed.result
	if copyResult {
		result = copyFuzzVerifyResult(result)
	}
	before := snapshotPublicResult(result)
	checks, signatures := result.Checks(), result.SignatureSets()
	if len(checks) > 0 {
		checks[0] = CheckFact{}
	}
	if len(signatures) > 0 {
		signatures[0] = SignatureSetFact{}
	}
	if !reflect.DeepEqual(before, snapshotPublicResult(result)) {
		t.Fatal("public accessor mutation changed VerifyResult")
	}
	mode := []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting}[boundedPublicFuzzIndex(modeSeed, 3)]
	findingLimit := boundedPublicFuzzIndex(findingSeed, HardMaxPolicyFindings) + 1
	options := []PolicyOption{WithPolicyMode(mode), WithPolicyMaxFindings(findingLimit), WithPolicyMaxAuthenticatedHops(HardMaxPolicyAuthenticatedHops)}
	decision, err := EvaluatePolicy(result, options...)
	decisionAgain, errAgain := EvaluatePolicy(result, options...)
	if !reflect.DeepEqual(publicPolicyFuzzSnapshot(decision, err), publicPolicyFuzzSnapshot(decisionAgain, errAgain)) {
		t.Fatal("public policy evaluation was nondeterministic")
	}
	if !reflect.DeepEqual(before, snapshotPublicResult(result)) {
		t.Fatal("public policy evaluation mutated VerifyResult")
	}
	assertPublicPolicyFuzzOutcome(t, seed, decision, err, findingLimit)
}

// assertPublicPolicyFuzzOutcome validates error disjointness, bounds, and exact DNS treatment.
func assertPublicPolicyFuzzOutcome(t *testing.T, seed publicPolicyFuzzSeed, decision PolicyDecision, err error, findingLimit int) {
	t.Helper()
	if err != nil {
		if !decision.IsZero() {
			t.Fatal("public policy error returned partial decision")
		}
		var policyErr *PolicyError
		if !errors.As(err, &policyErr) || !policyErr.Code().Known() || len(err.Error()) > 112 {
			t.Fatalf("public policy error escaped closed contract: %v", err)
		}
		return
	}
	result := seed.result
	actions := decision.ActionPlan().Actions()
	if !decision.Valid() || decision.VerificationState() != result.State() || len(actions) != 1 || actions[0].Kind() != PolicyActionKind(decision.Verdict()) || actions[0].Terminal() != (decision.Verdict() != PolicyVerdictContinue) || len(decision.Findings()) > findingLimit || len(decision.Findings()) > HardMaxPolicyFindings {
		t.Fatalf("public policy decision violated contract: %#v", decision)
	}
	if decision.DoNotModifyCompliance() == PolicyComplianceHonored || decision.DoNotExplodeCompliance() == PolicyComplianceHonored {
		t.Fatal("current-only public result produced false honor")
	}
	if decision.DNSTestingEffective() && (result.State() != ResultStatePASS && result.State() != ResultStateFAIL && result.State() != ResultStatePERMERROR || decision.PrimaryReason() != PolicyReasonDNSTestingEffective) {
		t.Fatal("DNS testing widened an ineligible public result")
	}
	if decision.DNSTestingEffective() != seed.dnsEffective {
		t.Fatalf("DNS testing effective = %t, want seeded %t", decision.DNSTestingEffective(), seed.dnsEffective)
	}
	if decision.DNSTestingEffective() && result.State() == ResultStatePASS {
		assertPublicTestingPassSuppressesFlags(t, decision)
	}
}

// assertPublicTestingPassSuppressesFlags rejects public feedback and sequenced findings.
func assertPublicTestingPassSuppressesFlags(t *testing.T, decision PolicyDecision) {
	t.Helper()
	if decision.FeedbackIntent().Requested() || decision.FeedbackIntent().RelayRequired() {
		t.Fatal("testing PASS retained public feedback intent")
	}
	for _, finding := range decision.Findings() {
		if _, sequenced := finding.Sequence(); sequenced {
			t.Fatal("testing PASS emitted public hop-derived finding")
		}
	}
}

// copyFuzzVerifyResult proves ordinary value copies retain sealed provenance.
func copyFuzzVerifyResult(result VerifyResult) VerifyResult { return result }

// fuzzLibraryResult returns one real sealed result spanning every public verification state and target form.
func fuzzLibraryResults(f *testing.F) []publicPolicyFuzzSeed {
	f.Helper()
	corpus := loadPublicGoldenCorpus(f)
	verifyVector := func(name string, provider PublicKeyProvider, options ...VerifierOption) VerifyResult {
		vector := corpus.Vectors[name]
		options = append(options, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
		verifier, err := NewVerifier(provider, options...)
		if err != nil {
			f.Fatalf("NewVerifier(%s) error = %v", name, err)
		}
		result, err := verifier.Verify(context.Background(), NewVerifyRequest(decodeGoldenBytes(f, vector.Raw), decodeGoldenBytes(f, vector.Reverse), decodeGoldenPaths(f, vector.Forward)))
		if err != nil {
			f.Fatalf("Verify(%s) error = %v", name, err)
		}
		return result
	}
	static := func(mode goldenProviderMode) PublicKeyProvider {
		return publicGoldenProvider{mode: mode, rsa: corpus.rsaKey(f), ed: corpus.edKey(f)}
	}
	results := []publicPolicyFuzzSeed{
		{result: verifyVector(goldenVectorRSAPass, static(goldenProviderKeys))},
		{result: verifyVector(goldenVectorEd25519Pass, static(goldenProviderKeys))},
		{result: verifyVector("body_mismatch", static(goldenProviderKeys))},
		{result: verifyVector(goldenVectorRSAPass, static(goldenProviderMissing))},
		{result: verifyVector(goldenVectorRSAPass, static(goldenProviderTemporary))},
		{result: verifyVector(goldenVectorMissingProtocol, static(goldenProviderKeys))},
	}
	flaggedRaw, flaggedKey := signedPublicFlaggedPolicyMessage(f, publicVectorClock)
	flaggedVerifier, err := NewVerifier(publicGoldenProvider{mode: goldenProviderKeys, rsa: flaggedKey}, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		f.Fatalf("NewVerifier(flagged) error = %v", err)
	}
	flagged, err := flaggedVerifier.Verify(context.Background(), NewVerifyRequest(flaggedRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		f.Fatalf("Verify(flagged) error = %v", err)
	}
	results = append(results, publicPolicyFuzzSeed{result: flagged})
	flaggedTestingProvider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return withKeyPolicyMetadata(FoundRSAPublicKey(flaggedKey), newKeyPolicyMetadata(true, false)), nil
	})
	flaggedTestingVerifier, err := NewVerifier(flaggedTestingProvider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		f.Fatalf("NewVerifier(flagged testing) error = %v", err)
	}
	flaggedTesting, err := flaggedTestingVerifier.Verify(context.Background(), NewVerifyRequest(flaggedRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		f.Fatalf("Verify(flagged testing) error = %v", err)
	}
	results = append(results, publicPolicyFuzzSeed{result: flaggedTesting, dnsEffective: true})
	manifest := loadDNSGoldenManifest(f, corpus)
	allTesting := &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorEdOwner {
			return foundPublicTXT(f, manifest.Ed25519LowerTXT+"; t=y", DNSSECStatusUnavailable), nil
		}
		return foundPublicTXT(f, manifest.RSATestingTXT, DNSSECStatusUnavailable), nil
	}}
	results = append(results, publicPolicyFuzzSeed{result: verifyVector("supported_mixed_fail", mustDNSVectorProvider(f, allTesting, DefaultDNSProviderConfig())), dnsEffective: true})
	passTesting := dnsPassTransport(f, manifest.RSATestingTXT, manifest.Ed25519LowerTXT+"; t=y", DNSSECStatusUnavailable)
	results = append(results, publicPolicyFuzzSeed{result: verifyVector(goldenVectorRSAPass, mustDNSVectorProvider(f, passTesting, DefaultDNSProviderConfig())), dnsEffective: true})
	postKeyTesting := dnsPassTransport(f, manifest.RSATestingTXT, manifest.Ed25519LowerTXT+"; t=y", DNSSECStatusUnavailable)
	results = append(results, publicPolicyFuzzSeed{result: verifyVector("age_over", mustDNSVectorProvider(f, postKeyTesting, DefaultDNSProviderConfig())), dnsEffective: true})
	mixedTesting := &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorEdOwner {
			return foundPublicTXT(f, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable), nil
		}
		return foundPublicTXT(f, manifest.RSATestingTXT, DNSSECStatusUnavailable), nil
	}}
	results = append(results, publicPolicyFuzzSeed{result: verifyVector("supported_mixed_fail", mustDNSVectorProvider(f, mixedTesting, DefaultDNSProviderConfig()), WithMaxSignatureFacts(1))})
	return results
}

// boundedPublicFuzzIndex maps arbitrary signed input into a nonnegative closed index.
func boundedPublicFuzzIndex(value, size int) int {
	if value < 0 {
		value = max(-value, 0)
	}
	return value % size
}

// publicPolicyFuzzSnapshot captures closed public decision or error output.
func publicPolicyFuzzSnapshot(decision PolicyDecision, err error) any {
	if err != nil {
		var policyErr *PolicyError
		if errors.As(err, &policyErr) {
			return []any{policyErr.Code(), policyErr.LimitName(), policyErr.ConfiguredLimit(), policyErr.ObservedCount(), err.Error()}
		}
		return []any{"unknown_error", err.Error()}
	}
	return []any{decision.VerificationState(), decision.Mode(), decision.Verdict(), decision.PrimaryReason(), decision.DoNotModifyCompliance(), decision.DoNotExplodeCompliance(), decision.FeedbackIntent(), decision.DNSTestingEffective(), decision.Findings(), decision.ActionPlan().Actions(), fmt.Sprint(decision)}
}
