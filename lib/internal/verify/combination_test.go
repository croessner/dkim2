package verify

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
)

const (
	combinationRSASelector     = "combo-rsa.test"
	combinationRSATwoSelector  = "combo-rsa-two.test"
	combinationEdSelector      = "combo-ed.test"
	combinationUnknownSelector = "combo-future.test"
	combinationUnknownName     = "future-sha999"

	keyModeOK        = "ok"
	keyModeWrong     = "wrong"
	keyModeMissing   = "missing"
	keyModeTemporary = "temporary"

	templateEdOrRSA  = "{ed}|{rsa}"
	templateRSAAndEd = "{rsa},{ed}"
)

// combinationFixture holds one Draft-08 grouped s= target signed by real
// keys over the Section 12.8 unsigned field that keeps the "," and "|"
// separators.
type combinationFixture struct {
	verificationFixture
	rsaKey    *rsa.PublicKey
	rsaTwoKey *rsa.PublicKey
	edKey     ed25519.PublicKey
	wrongEd   ed25519.PublicKey
	signed    string
}

// newCombinationFixture signs a template whose sets are named by selector
// and joined by the given separators. Known algorithms are signed by their
// selector's key; the unknown algorithm carries an opaque value.
func newCombinationFixture(t *testing.T, template string) combinationFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaTwo, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongEd, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	headerDigest, bodyDigest := baseMessageDigests(t)
	render := func(values map[string]string) string {
		return strings.NewReplacer(
			"{rsa}", combinationRSASelector+":"+string(AlgorithmRSASHA256)+":"+values["rsa"],
			"{rsa2}", combinationRSATwoSelector+":"+string(AlgorithmRSASHA256)+":"+values["rsa2"],
			"{ed}", combinationEdSelector+":"+string(AlgorithmEd25519SHA256)+":"+values["ed"],
			"{x}", combinationUnknownSelector+":"+combinationUnknownName+":"+values["x"],
		).Replace(template)
	}
	placeholders := map[string]string{
		"rsa":  base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128)),
		"rsa2": base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128)),
		"ed":   base64.StdEncoding.EncodeToString(bytesOf(0xa5, ed25519.SignatureSize)),
		"x":    base64.StdEncoding.EncodeToString(bytesOf(0x42, 32)),
	}
	unsigned := mustParseVerificationMessage(t, rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, render(placeholders))}))
	digest := signatureDigestForTarget(t, unsigned, 1)
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	rsaTwoSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaTwo, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"rsa":  base64.StdEncoding.EncodeToString(rsaSignature),
		"rsa2": base64.StdEncoding.EncodeToString(rsaTwoSignature),
		"ed":   base64.StdEncoding.EncodeToString(ed25519.Sign(edPrivate, digest)),
		"x":    placeholders["x"],
	}
	signed := render(values)
	parsed, err := parseVerificationFixture(rawWithSignatureFields(headerDigest, bodyDigest, []string{signatureField(1, signed)}))
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	return combinationFixture{verificationFixture: parsed, rsaKey: &rsaKey.PublicKey, rsaTwoKey: &rsaTwo.PublicKey, edKey: edPublic, wrongEd: wrongEd, signed: signed}
}

// combinationKeys selects the published keys: correct, wrong, temporary, or
// absent per selector.
type combinationKeys struct {
	rsa, rsaTwo, ed string
}

// combinationProvider answers lookups from the fixture according to the
// configured per-selector behavior.
type combinationProvider struct {
	fixture combinationFixture
	keys    combinationKeys
	lookups []string
}

// LookupKey returns the configured key, a missing key, or a temporary failure.
func (p *combinationProvider) LookupKey(_ context.Context, query KeyQuery) (PublicKey, error) {
	p.lookups = append(p.lookups, query.Selector)
	mode := map[string]string{combinationRSASelector: p.keys.rsa, combinationRSATwoSelector: p.keys.rsaTwo, combinationEdSelector: p.keys.ed}[query.Selector]
	var material any
	switch {
	case mode == keyModeTemporary:
		return PublicKey{}, NewProviderFailure(ProviderFailureTemporary)
	case mode == "" || mode == keyModeMissing:
		return PublicKey{Algorithm: query.Algorithm, Metadata: KeyMetadata{Status: KeyStatusMissing}}, missingKeyError(query.Algorithm)
	case query.Selector == combinationRSASelector:
		material = p.fixture.rsaKey
	case query.Selector == combinationRSATwoSelector:
		material = p.fixture.rsaTwoKey
	case mode == keyModeWrong:
		material = p.fixture.wrongEd
	default:
		material = p.fixture.edKey
	}
	return PublicKey{Algorithm: query.Algorithm, Material: material, Metadata: KeyMetadata{Status: KeyStatusFound}}, nil
}

// verifyCombination runs current verification of the fixture against one
// provider behavior and optional verifier options.
func verifyCombination(t *testing.T, fixture combinationFixture, keys combinationKeys, options ...Option) (Result, *combinationProvider) {
	t.Helper()
	provider := &combinationProvider{fixture: fixture, keys: keys}
	verifier, err := NewVerifier(provider, append([]Option{testClockOption()}, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.VerifyCurrent(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil {
		t.Fatalf("VerifyCurrent() error = %v", err)
	}
	return result, provider
}

// TestDraft08SignatureCombinationReproducers pins the Section 14.6 algebra on
// real signed targets. Each case names the Draft-08 rule it proves.
func TestDraft08SignatureCombinationReproducers(t *testing.T) {
	tests := []struct {
		name     string
		template string
		keys     combinationKeys
		want     TargetStatus
	}{
		{"a|b with a FAIL and b PASS passes", templateEdOrRSA, combinationKeys{rsa: keyModeOK, ed: keyModeWrong}, TargetStatusPass},
		{"a,b with b unknown is PERMERROR", "{rsa},{x}", combinationKeys{rsa: keyModeOK}, TargetStatusUnsupported},
		{"a|b with b unknown and a PASS passes", "{rsa}|{x}", combinationKeys{rsa: keyModeOK}, TargetStatusPass},
		{"a,b with b key-missing and a PASS is PERMERROR", templateRSAAndEd, combinationKeys{rsa: keyModeOK, ed: keyModeMissing}, TargetStatusUnsupported},
		{"a|b with a key-missing and b PASS passes", templateEdOrRSA, combinationKeys{rsa: keyModeOK, ed: keyModeMissing}, TargetStatusPass},
		{"sig-all PERMERROR,TEMPERROR is PERMERROR", "{ed},{rsa}", combinationKeys{rsa: keyModeTemporary, ed: keyModeMissing}, TargetStatusUnsupported},
		{"sig-all PASS,TEMPERROR is TEMPERROR", templateRSAAndEd, combinationKeys{rsa: keyModeOK, ed: keyModeTemporary}, TargetStatusIndeterminate},
		{"sig-any FAIL|TEMPERROR is TEMPERROR", templateEdOrRSA, combinationKeys{rsa: keyModeTemporary, ed: keyModeWrong}, TargetStatusIndeterminate},
		{"sig-any FAIL|PERMERROR is FAIL", templateEdOrRSA, combinationKeys{rsa: keyModeMissing, ed: keyModeWrong}, TargetStatusFail},
		{"a,b|c with the all group failing and c passing", "{rsa},{ed}|{rsa2}", combinationKeys{rsa: keyModeOK, ed: keyModeWrong, rsaTwo: keyModeOK}, TargetStatusPass},
		{"two same-algorithm signatures in one group pass", "{rsa},{rsa2}", combinationKeys{rsa: keyModeOK, rsaTwo: keyModeOK}, TargetStatusPass},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCombinationFixture(t, test.template)
			result, provider := verifyCombination(t, fixture, test.keys)
			if result.Status() != test.want {
				t.Fatalf("Status() = %q, want %q; sets=%#v", result.Status(), test.want, result.SignatureSets())
			}
			for _, selector := range provider.lookups {
				if selector == combinationUnknownSelector {
					t.Fatal("an unknown algorithm triggered a key lookup")
				}
			}
			if len(result.SignatureSets()) != fixture.signatures[0].SignatureLayout().Sets() {
				t.Fatalf("per-set results = %d, want one per set", len(result.SignatureSets()))
			}
		})
	}
}

// TestDraft08SeparatorIsSignedByteExactly proves the Section 12.8 unsigned
// target carries the "," and "|" separators: a signer-shaped target
// verifies, and swapping one separator invalidates every signature.
func TestDraft08SeparatorIsSignedByteExactly(t *testing.T) {
	for _, swap := range []struct{ template, from, to string }{
		{"{rsa}|{ed}", "|", ","},
		{templateRSAAndEd, ",", "|"},
	} {
		fixture := newCombinationFixture(t, swap.template)
		keys := combinationKeys{rsa: keyModeOK, ed: keyModeOK}
		if result, _ := verifyCombination(t, fixture, keys); result.Status() != TargetStatusPass {
			t.Fatalf("%s: untampered Status() = %q", swap.template, result.Status())
		}
		index := strings.Index(fixture.raw, fixture.signed)
		if index < 0 {
			t.Fatal("fixture lacks the signed s= value")
		}
		tamperedSets := strings.Replace(fixture.signed, swap.from, swap.to, 1)
		tampered, err := fixture.withRawResult(fixture.raw[:index] + tamperedSets + fixture.raw[index+len(fixture.signed):])
		if err != nil {
			t.Fatal(err)
		}
		fixture.verificationFixture = tampered
		result, _ := verifyCombination(t, fixture, keys)
		if result.Status() != TargetStatusFail {
			t.Fatalf("%s: tampered separator Status() = %q, want fail", swap.template, result.Status())
		}
		for _, set := range result.SignatureSets() {
			if set.Status != SignatureSetStatusFail {
				t.Fatalf("%s: tampered separator left set %d as %q", swap.template, set.Index, set.Status)
			}
		}
	}
}

// TestDisabledAlgorithmIsLocallyRejectedPermerror is the reproducer for the
// policy-disabled algorithm: it is a PERMERROR intermediate decided without
// a key lookup, and its key status names the local disabling rather than a
// key-policy rejection.
func TestDisabledAlgorithmIsLocallyRejectedPermerror(t *testing.T) {
	policy := DefaultAlgorithmPolicy()
	policy.AllowedAlgorithms = []Algorithm{AlgorithmRSASHA256}
	fixture := newCombinationFixture(t, "{ed}")
	result, provider := verifyCombination(t, fixture, combinationKeys{ed: keyModeOK}, WithAlgorithmPolicy(policy))
	sets := result.SignatureSets()
	if len(provider.lookups) != 0 || len(sets) != 1 || sets[0].Status != SignatureSetStatusDisabledAlgorithm || sets[0].KeyStatus != KeyStatusDisabledAlgorithm {
		t.Fatalf("disabled set = %#v lookups=%d", sets, len(provider.lookups))
	}
	if result.Status() != TargetStatusUnsupported {
		t.Fatalf("Status() = %q, want unsupported", result.Status())
	}
	alternative := newCombinationFixture(t, templateEdOrRSA)
	if result, _ := verifyCombination(t, alternative, combinationKeys{rsa: keyModeOK, ed: keyModeOK}, WithAlgorithmPolicy(policy)); result.Status() != TargetStatusPass {
		t.Fatalf("disabled alternative beside a pass Status() = %q", result.Status())
	}
}

// TestDraft08RevisionProofUsesSignatureAlgebra proves the all-hop revision
// proof combines inherited sets with the shared Section 14.6 algebra: a key
// error in a losing "|" group still yields a verified proof with an
// alternative-not-passed fact, and a key error inside the only sig-all group
// keeps its specific missing_key reason.
func TestDraft08RevisionProofUsesSignatureAlgebra(t *testing.T) {
	verifyProof := func(template string, keys combinationKeys) (RevisionProofOutcome, RevisionProof) {
		t.Helper()
		fixture := newCombinationFixture(t, template)
		verifier, err := NewVerifier(&combinationProvider{fixture: fixture, keys: keys}, testClockOption())
		if err != nil {
			t.Fatal(err)
		}
		outcome, proof, err := verifier.VerifyRevisionProof(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
		if err != nil {
			t.Fatalf("VerifyRevisionProof(%s) error = %v", template, err)
		}
		return outcome, proof
	}
	outcome, proof := verifyProof(templateEdOrRSA, combinationKeys{rsa: keyModeOK, ed: keyModeMissing})
	if outcome != RevisionProofVerified || !proof.Valid() {
		t.Fatalf("ed|rsa with missing ed key = %q valid=%t", outcome, proof.Valid())
	}
	sets := proof.Facts().Signatures()[0].Sets()
	if len(sets) != 2 || sets[0].State() != RevisionSetAlternativeNotPassed || !sets[0].LookedUp() || sets[1].State() != RevisionSetSupportedPass {
		t.Fatalf("revision set facts = %#v", sets)
	}
	if outcome, _ := verifyProof(templateRSAAndEd, combinationKeys{rsa: keyModeOK, ed: keyModeMissing}); outcome != RevisionProofMissingKey {
		t.Fatalf("rsa,ed with missing ed key = %q, want missing_key", outcome)
	}
	if outcome, _ := verifyProof("{rsa}|{x}", combinationKeys{rsa: keyModeOK}); outcome != RevisionProofVerified {
		t.Fatalf("rsa|unknown = %q, want verified", outcome)
	}
}
