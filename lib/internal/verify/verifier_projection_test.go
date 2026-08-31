package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/recipe"
)

// TestRevisionProofSealsCompleteVerifierProjection locks authenticated chain projection provenance.
func TestRevisionProofSealsCompleteVerifierProjection(t *testing.T) {
	fixture := newNextDomainChainFixture(t, strings.ToUpper(nextHopDomain))
	verifier, err := NewVerifier(providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{
		Message: fixture.message, Envelope: matchingEnvelope(),
	})
	if err != nil || outcome != RevisionProofVerified || !proof.Valid() {
		t.Fatalf("VerifyRevisionProof() = %q/%t/%v", outcome, proof.Valid(), err)
	}
	projection, present := proof.VerifierProjection()
	if !present || !projection.Valid() || projection.Schema() != VerifierProjectionSchema || projection.Draft() != DraftBaseline {
		t.Fatalf("VerifierProjection() = present:%t valid:%t schema:%q draft:%q", present, projection.Valid(), projection.Schema(), projection.Draft())
	}
	hops := projection.Hops()
	if len(hops) != 2 || hops[0].Sequence() != 1 || hops[1].Sequence() != 2 ||
		hops[0].SignerDomain() != testDomain || hops[1].SignerDomain() != nextHopDomain ||
		hops[0].CustodyTransition() != VerifierCustodyOrigin || hops[1].CustodyTransition() != VerifierCustodyNextDomain {
		t.Fatalf("projection hops = %#v", hops)
	}
	for _, hop := range hops {
		algorithms := hop.SignatureAlgorithms()
		if len(algorithms) != 1 || algorithms[0] != AlgorithmRSASHA256 || !hop.Recipe().Valid() || hop.HopBinding() == ([32]byte{}) {
			t.Fatalf("hop = %#v algorithms=%#v", hop, algorithms)
		}
	}
	if projection.Binding() == ([32]byte{}) || hops[0].HopBinding() == hops[1].HopBinding() {
		t.Fatal("projection or hop binding missing/colliding")
	}
	exposed := projection.Hops()
	exposed[0] = VerifierHop{}
	if !projection.Hops()[0].Valid() {
		t.Fatal("projection hop slice was mutable")
	}
}

// TestTerminalNextDomainProofDoesNotExposePermittableProjection locks the OOB authority boundary.
func TestTerminalNextDomainProofDoesNotExposePermittableProjection(t *testing.T) {
	fixture := newHighestNextDomainFixture(t)
	verifier, err := NewVerifier(providerFunc(func(_ context.Context, query KeyQuery) (PublicKey, error) {
		return publicKeyResult(query.Algorithm, fixture.rsaKey, KeyStatusFound), nil
	}), testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message})
	if err != nil || outcome != RevisionProofTerminalNextDomainAuthorizationRequired || !proof.Valid() {
		t.Fatalf("VerifyRevisionProof() = %q/%t/%v", outcome, proof.Valid(), err)
	}
	if projection, present := proof.VerifierProjection(); present || projection.Valid() {
		t.Fatal("terminal nd proof exposed a policy-permittable verifier projection")
	}
}

// TestVerifierProjectionRejectsEveryBoundHopMutation proves exposed semantics cannot drift from bindings.
func TestVerifierProjectionRejectsEveryBoundHopMutation(t *testing.T) {
	descriptor := recipe.UnchangedDescriptor()
	hop := VerifierHop{
		domain: "example.test", algorithms: []Algorithm{AlgorithmRSASHA256}, recipe: descriptor,
		sequence: 1, instance: 1, custody: VerifierCustodyOrigin, recipeMode: VerifierRecipeUnchanged,
		headerState: HistoryDimensionMatched, bodyState: HistoryDimensionMatched,
		bodyAvailable: recipe.BodyAvailabilityKnown, sealed: true,
	}
	projection := VerifierProjection{hops: []VerifierHop{hop}, draft: DraftBaseline, schema: VerifierProjectionSchema, sealed: true}
	projection.binding = verifierProjectionBinding(projection.hops)
	projection.hops[0].binding = verifierBoundHopBinding(projection.binding, projection.hops[0])
	if !projection.Valid() {
		t.Fatal("baseline projection is invalid")
	}
	tests := map[string]func(*VerifierProjection){
		"projection binding": func(p *VerifierProjection) { p.binding[0] ^= 1 },
		"hop binding":        func(p *VerifierProjection) { p.hops[0].binding[0] ^= 1 },
		"sequence":           func(p *VerifierProjection) { p.hops[0].sequence++ },
		"instance":           func(p *VerifierProjection) { p.hops[0].instance++ },
		"domain":             func(p *VerifierProjection) { p.hops[0].domain = "changed.test" },
		"algorithm":          func(p *VerifierProjection) { p.hops[0].algorithms[0] = AlgorithmEd25519SHA256 },
		"custody":            func(p *VerifierProjection) { p.hops[0].custody = VerifierCustodyOrdinary },
		"flag":               func(p *VerifierProjection) { p.hops[0].flags.feedback = true },
		"recipe":             func(p *VerifierProjection) { p.hops[0].recipe = recipe.Descriptor{} },
		"recipe mode":        func(p *VerifierProjection) { p.hops[0].recipeMode = VerifierRecipeApplied },
		"header state":       func(p *VerifierProjection) { p.hops[0].headerState = HistoryDimensionUnsupported },
		"body state":         func(p *VerifierProjection) { p.hops[0].bodyState = HistoryDimensionUnavailable },
		"body availability":  func(p *VerifierProjection) { p.hops[0].bodyAvailable = recipe.BodyAvailabilityUnavailable },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := projection.clone()
			mutate(&candidate)
			if candidate.Valid() {
				t.Fatal("mutated projection remained valid")
			}
		})
	}
}

// FuzzVerifierProjectionBindings exercises deterministic framed hashing under arbitrary bounded text.
func FuzzVerifierProjectionBindings(f *testing.F) {
	f.Add("example.test")
	f.Add("relay.example")
	f.Fuzz(func(t *testing.T, domain string) {
		if len(domain) > 253 {
			domain = domain[:253]
		}
		hop := VerifierHop{
			domain: domain, algorithms: []Algorithm{AlgorithmRSASHA256}, recipe: recipe.UnchangedDescriptor(),
			sequence: 1, instance: 1, custody: VerifierCustodyOrigin, recipeMode: VerifierRecipeUnchanged,
			headerState: HistoryDimensionMatched, bodyState: HistoryDimensionMatched,
			bodyAvailable: recipe.BodyAvailabilityKnown, sealed: true,
		}
		first := verifierHopContentDigest(hop)
		second := verifierHopContentDigest(hop)
		if first != second {
			t.Fatal("hop content digest is nondeterministic")
		}
	})
}
