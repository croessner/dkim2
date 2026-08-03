package domainadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

type proofTransport struct {
	mu     sync.Mutex
	lookup func(context.Context, string) (dkim2.TXTLookupResult, error)
	calls  int
}

// LookupTXT executes one scripted recursive-path answer without retaining the qname.
func (t *proofTransport) LookupTXT(ctx context.Context, owner string) (dkim2.TXTLookupResult, error) {
	t.mu.Lock()
	t.calls++
	lookup := t.lookup
	t.mu.Unlock()
	return lookup(ctx, owner)
}

// TestDNSProofCreatesFreshProviderAndExactLifetimeCapability freezes proof ownership and claims.
func TestDNSProofCreatesFreshProviderAndExactLifetimeCapability(t *testing.T) {
	set, candidate, plan, staged := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	answers := stagedPayloads(t, set)
	factoryCalls := 0
	transport := &proofTransport{lookup: func(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
		payload, found := answers[owner]
		if !found {
			return dkim2.TXTLookupResult{}, errors.New("unexpected proof query")
		}
		return dkim2.NewFoundTXTLookupResult([][]byte{payload}, time.Minute, dkim2.DNSSECStatusUnavailable)
	}}
	completed := time.Unix(1_800_000_000, 0).UTC()
	engine, err := newDNSProofEngine(DefaultLimits(), func() time.Time { return completed }, func(
		context.Context,
		datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		factoryCalls++
		return dkim2.NewDNSPublicKeyProvider(transport)
	})
	if err != nil {
		t.Fatal("construct proof engine")
	}
	proof, err := engine.Prove(t.Context(), set)
	if err != nil || proof == nil || factoryCalls != 1 || transport.calls != 2 {
		t.Fatal("fresh exact resolver-path proof rejected")
	}
	defer proof.Close() //nolint:errcheck // Test cleanup has no recovery.
	if !proof.ValidFor(plan.Digest(), staged, completed) ||
		proof.ValidFor(plan.Digest(), staged, completed.Add(time.Minute)) ||
		proof.ResolverPath() != ResolverPathSystem || proof.CacheResponsibility() != DNSCacheOperatorManaged ||
		proof.ClaimsAuthoritativeServerContact() || proof.ClaimsUpstreamCacheBypass() {
		t.Fatal("proof lifetime or recursive resolver claims overstate the implementation")
	}
	second, err := engine.Prove(t.Context(), set)
	if err != nil || second == nil || factoryCalls != 2 {
		t.Fatal("repeated proof reused a process-local provider")
	}
	_ = second.Close()
}

// TestDNSProofFailureMatrixFreezesMissingAmbiguousMalformedAndDriftOutcomes.
func TestDNSProofFailureMatrix(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	firstPayload := firstStagedPayload(t, set)
	tests := []struct {
		name   string
		lookup func(context.Context, string) (dkim2.TXTLookupResult, error)
		code   ErrorCode
	}{
		{name: "nxdomain", lookup: absentProofLookup(t, dkim2.TXTAbsenceNXDOMAIN), code: CodeDNSMissing},
		{name: "nodata", lookup: absentProofLookup(t, dkim2.TXTAbsenceNODATA), code: CodeDNSMissing},
		{name: "multiple records", lookup: func(context.Context, string) (dkim2.TXTLookupResult, error) {
			return dkim2.NewFoundTXTLookupResult([][]byte{firstPayload, firstPayload}, time.Minute, dkim2.DNSSECStatusUnavailable)
		}, code: CodeDNSAmbiguous},
		{name: "malformed", lookup: foundProofLookup(t, []byte("v=DKIM1; k=rsa; p=%%%")), code: CodeDNSInvalid},
		{name: "revoked", lookup: foundProofLookup(t, []byte("v=DKIM1; k=rsa; p=")), code: CodeDNSInvalid},
		{name: "unsupported", lookup: foundProofLookup(t, []byte("v=DKIM1; k=future; p=QQ==")), code: CodeDNSUnsupported},
		{name: "transport", lookup: func(context.Context, string) (dkim2.TXTLookupResult, error) {
			return dkim2.TXTLookupResult{}, dkim2.NewTemporaryProviderError()
		}, code: CodeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &proofTransport{lookup: tt.lookup}
			engine := proofEngineForTransport(t, transport)
			if proof, err := engine.Prove(t.Context(), set); CodeOf(err) != tt.code || proof != nil {
				t.Fatal("DNS proof failure class drifted")
			}
		})
	}
}

// TestDNSProofRejectsAlgorithmAndSPKIDrift freezes exact staged equality.
func TestDNSProofRejectsAlgorithmAndSPKIDrift(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	answers := stagedPayloads(t, set)
	var rsaPayload, edPayload []byte
	set.mu.Lock()
	for _, record := range set.records {
		if dkim2Algorithm(record.algorithm) == dkim2.AlgorithmRSASHA256 {
			rsaPayload = bytes.Clone(record.payload)
		} else {
			edPayload = bytes.Clone(record.payload)
		}
	}
	set.mu.Unlock()
	defer clear(rsaPayload)
	defer clear(edPayload)
	algorithmMismatch := &proofTransport{lookup: func(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
		payload := answers[owner]
		if bytes.Equal(payload, rsaPayload) {
			payload = edPayload
		} else {
			payload = rsaPayload
		}
		return dkim2.NewFoundTXTLookupResult([][]byte{payload}, 0, dkim2.DNSSECStatusUnavailable)
	}}
	if proof, err := proofEngineForTransport(t, algorithmMismatch).Prove(t.Context(), set); CodeOf(err) != CodeDNSAlgorithmMismatch || proof != nil {
		t.Fatal("DNS algorithm drift was not rejected")
	}

	other, otherCandidate, otherPlan, _ := stagedDNSFixture(t)
	defer other.Close()          //nolint:errcheck // Test cleanup has no recovery.
	defer otherCandidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer otherPlan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	otherByAlgorithm := make(map[dkim2.Algorithm][]byte)
	other.mu.Lock()
	for _, record := range other.records {
		otherByAlgorithm[dkim2Algorithm(record.algorithm)] = bytes.Clone(record.payload)
	}
	other.mu.Unlock()
	defer func() {
		for _, payload := range otherByAlgorithm {
			clear(payload)
		}
	}()
	spkiMismatch := &proofTransport{lookup: func(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
		algorithm := dkim2.AlgorithmEd25519SHA256
		if bytes.Equal(answers[owner], rsaPayload) {
			algorithm = dkim2.AlgorithmRSASHA256
		}
		return dkim2.NewFoundTXTLookupResult([][]byte{otherByAlgorithm[algorithm]}, 0, dkim2.DNSSECStatusUnavailable)
	}}
	if proof, err := proofEngineForTransport(t, spkiMismatch).Prove(t.Context(), set); CodeOf(err) != CodeDNSSPKIMismatch || proof != nil {
		t.Fatal("DNS public key drift was not rejected")
	}
}

// TestDNSProofCancellationAndExpiryFailClosed freezes context and activation-time gates.
func TestDNSProofCancellationAndExpiryFailClosed(t *testing.T) {
	set, candidate, plan, staged := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	factoryCalls := 0
	engine, _ := newDNSProofEngine(DefaultLimits(), time.Now, func(context.Context, datasourceadmin.DNSPolicy) (dkim2.PublicKeyProvider, error) {
		factoryCalls++
		return nil, errors.New("must not run")
	})
	if proof, err := engine.Prove(cancelled, set); CodeOf(err) != CodeUnavailable || proof != nil || factoryCalls != 0 {
		t.Fatal("pre-cancelled proof reached resolver construction")
	}

	answers := stagedPayloads(t, set)
	started := make(chan struct{})
	transport := &proofTransport{lookup: func(ctx context.Context, _ string) (dkim2.TXTLookupResult, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return dkim2.TXTLookupResult{}, ctx.Err()
	}}
	engine = proofEngineForTransport(t, transport)
	inFlight, stop := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := engine.Prove(inFlight, set)
		result <- err
	}()
	<-started
	stop()
	if CodeOf(<-result) != CodeUnavailable {
		t.Fatal("in-flight resolver cancellation advanced proof")
	}

	completed := time.Unix(1_800_000_000, 0).UTC()
	transport = &proofTransport{lookup: func(_ context.Context, owner string) (dkim2.TXTLookupResult, error) {
		return dkim2.NewFoundTXTLookupResult([][]byte{answers[owner]}, 0, dkim2.DNSSECStatusUnavailable)
	}}
	engine, _ = newDNSProofEngine(DefaultLimits(), func() time.Time { return completed }, func(context.Context, datasourceadmin.DNSPolicy) (dkim2.PublicKeyProvider, error) {
		return dkim2.NewDNSPublicKeyProvider(transport)
	})
	proof, err := engine.Prove(t.Context(), set)
	if err != nil {
		t.Fatal("construct expiry proof")
	}
	defer proof.Close() //nolint:errcheck // Test cleanup has no recovery.
	if CodeOf(proof.RequireValidFor(plan.Digest(), staged, completed.Add(time.Minute))) != CodeDNSProofExpired ||
		proof.ValidFor(plan.Digest(), staged, completed.Add(time.Minute)) {
		t.Fatal("expired proof remained usable for activation")
	}
	otherPlanBytes := bytes.Repeat([]byte{0x42}, 32)
	otherPlan, _ := datasourceadmin.ParsePlanDigest(otherPlanBytes)
	clear(otherPlanBytes)
	if CodeOf(proof.RequireValidFor(otherPlan, staged, completed)) != CodeConflict ||
		proof.ValidFor(otherPlan, staged, completed) {
		t.Fatal("proof accepted a different plan digest")
	}
	otherStagedBytes := bytes.Repeat([]byte{0x24}, 32)
	otherStaged, _ := datasourceadmin.ParseStagedEvidence(otherStagedBytes)
	clear(otherStagedBytes)
	if CodeOf(proof.RequireValidFor(plan.Digest(), otherStaged, completed)) != CodeConflict {
		t.Fatal("proof reported staged evidence mismatch as temporal expiry")
	}
}

// TestDNSProofUsesOneOverallBackendDeadline freezes the total multi-record lookup budget.
func TestDNSProofUsesOneOverallBackendDeadline(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	limits := DefaultLimits()
	limits.BackendDeadline = 20 * time.Millisecond
	transport := &proofTransport{lookup: func(ctx context.Context, _ string) (dkim2.TXTLookupResult, error) {
		<-ctx.Done()
		return dkim2.TXTLookupResult{}, ctx.Err()
	}}
	engine, err := newDNSProofEngine(limits, time.Now, func(
		context.Context,
		datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		return dkim2.NewDNSPublicKeyProvider(transport)
	})
	if err != nil {
		t.Fatal("construct deadline proof engine")
	}
	started := time.Now()
	if proof, proveErr := engine.Prove(t.Context(), set); CodeOf(proveErr) != CodeUnavailable || proof != nil {
		t.Fatal("overall DNS proof deadline did not fail closed")
	}
	if time.Since(started) > time.Second {
		t.Fatal("DNS proof exceeded its overall backend deadline")
	}
	if transport.calls != 1 {
		t.Fatal("overall deadline allowed a subsequent credential lookup")
	}
}

// TestDNSProofRejectsExcessLifetimeAndGenericSinks freezes bounded ephemeral proof state.
func TestDNSProofRejectsExcessLifetimeAndGenericSinks(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	set.mu.Lock()
	set.policy.ProofLifetimeSeconds = uint64(DefaultLimits().DNSProofLifetime/time.Second) + 1
	set.mu.Unlock()
	factoryCalls := 0
	engine, _ := newDNSProofEngine(DefaultLimits(), time.Now, func(
		context.Context,
		datasourceadmin.DNSPolicy,
	) (dkim2.PublicKeyProvider, error) {
		factoryCalls++
		return nil, errors.New("must not run")
	})
	if proof, err := engine.Prove(t.Context(), set); CodeOf(err) != CodeInvalidLimits || proof != nil || factoryCalls != 0 {
		t.Fatal("excess proof lifetime reached resolver construction")
	}
	protected := &DNSProof{}
	rendered := fmt.Sprintf("%+v", protected)
	if !strings.Contains(rendered, redacted) {
		t.Fatal("DNS proof reached a formatting sink")
	}
	if _, err := json.Marshal(protected); err == nil {
		t.Fatal("DNS proof reached a generic JSON sink")
	}
}

// TestRecursiveEndpointDialerRejectsInvalidAndNeverUsesDefaultAddress freezes explicit path confinement.
func TestRecursiveEndpointDialerRejectsInvalidAndNeverUsesDefaultAddress(t *testing.T) {
	if dialer, err := newRecursiveEndpointDialer([]string{"missing-port"}); CodeOf(err) != CodeDNSInvalid || dialer != nil {
		t.Fatal("invalid recursive endpoint accepted")
	}
	policy := datasourceadmin.DNSPolicy{ResolverClass: resolverClassSystem, ResolverEndpoints: []string{"127.0.0.1:53"}}
	if providerValue, err := newRecursiveDNSProvider(t.Context(), policy, time.Second); CodeOf(err) != CodeDNSInvalid || providerValue != nil {
		t.Fatal("system resolver accepted explicit endpoint substitution")
	}
	system, err := newResolverForDNSPolicy(datasourceadmin.DNSPolicy{ResolverClass: resolverClassSystem})
	if err != nil || system == nil || system.PreferGo || system.StrictErrors || system.Dial != nil {
		t.Fatal("system path bypassed platform resolver semantics")
	}
	explicit, err := newResolverForDNSPolicy(datasourceadmin.DNSPolicy{
		ResolverClass: resolverClassRecursive, ResolverEndpoints: []string{"127.0.0.1:53"},
	})
	if err != nil || explicit == nil || !explicit.PreferGo || !explicit.StrictErrors || explicit.Dial == nil {
		t.Fatal("explicit recursive path was not confined to its endpoint dialer")
	}
}

// stagedPayloads returns exact absolute-owner to logical-RR mappings.
func stagedPayloads(t *testing.T, set *StagedDNSSet) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	set.mu.Lock()
	defer set.mu.Unlock()
	for _, record := range set.records {
		result[string(record.owner)] = bytes.Clone(record.payload)
	}
	t.Cleanup(func() {
		for _, payload := range result {
			clear(payload)
		}
	})
	return result
}

// firstStagedPayload returns one detached logical RR for negative matrix construction.
func firstStagedPayload(t *testing.T, set *StagedDNSSet) []byte {
	t.Helper()
	set.mu.Lock()
	defer set.mu.Unlock()
	if len(set.records) == 0 {
		t.Fatal("missing staged record fixture")
	}
	value := bytes.Clone(set.records[0].payload)
	t.Cleanup(func() { clear(value) })
	return value
}

// proofEngineForTransport constructs one new provider per attempt over an injected transport.
func proofEngineForTransport(t *testing.T, transport dkim2.TXTTransport) *DNSProofEngine {
	t.Helper()
	engine, err := newDNSProofEngine(DefaultLimits(), func() time.Time {
		return time.Unix(1_800_000_000, 0).UTC()
	}, func(context.Context, datasourceadmin.DNSPolicy) (dkim2.PublicKeyProvider, error) {
		return dkim2.NewDNSPublicKeyProvider(transport)
	})
	if err != nil {
		t.Fatal("construct proof engine fixture")
	}
	return engine
}

// absentProofLookup constructs one exact NXDOMAIN or NODATA answer.
func absentProofLookup(t *testing.T, absence dkim2.TXTAbsenceClass) func(context.Context, string) (dkim2.TXTLookupResult, error) {
	t.Helper()
	return func(context.Context, string) (dkim2.TXTLookupResult, error) {
		return dkim2.NewAbsentTXTLookupResult(absence, time.Minute, dkim2.DNSSECStatusUnavailable)
	}
}

// foundProofLookup constructs one exact unique TXT resource record.
func foundProofLookup(t *testing.T, payload []byte) func(context.Context, string) (dkim2.TXTLookupResult, error) {
	t.Helper()
	return func(context.Context, string) (dkim2.TXTLookupResult, error) {
		return dkim2.NewFoundTXTLookupResult([][]byte{payload}, time.Minute, dkim2.DNSSECStatusUnavailable)
	}
}
