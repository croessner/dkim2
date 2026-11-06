package signing

import (
	"context"
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/verify"
)

// upwardFromDomain is the From domain that the fixture's d=example.test makes
// Authentic only through the upward match.
const upwardFromDomain = "test"

// recordingDomainPolicyProvider records every Domain Policy Record lookup and
// answers one fixed status or error.
type recordingDomainPolicyProvider struct {
	status  verify.DomainPolicyStatus
	err     error
	domains []string
}

// LookupDomainPolicy records the queried A-label domain and returns the fixed answer.
func (p *recordingDomainPolicyProvider) LookupDomainPolicy(_ context.Context, domain string) (verify.DomainPolicyStatus, error) {
	p.domains = append(p.domains, domain)
	return p.status, p.err
}

// newDomainPolicyRevisionVerifier builds a sealed revision verifier whose
// core resolves upward From candidates through policy.
func newDomainPolicyRevisionVerifier(t *testing.T, keys verify.KeyProvider, choice verify.FromAuthorization) RevisionVerifier {
	t.Helper()
	proof, err := verify.NewVerifier(keys, revisionTestClockOption(), verify.WithFromAuthorization(choice))
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	return newRevisionVerifierForProof(t, proof)
}

// TestRevisionProofResolvesUpwardFromThroughDomainPolicyRecord reproduces
// Draft-09 Sections 3.8, 7.1 item 3, 11.1, and 14.8 with the D2 algebra: a
// From domain that is a parent of d= is Authentic unless its Domain Policy
// Record is strict; record failures are TEMPERROR or PERMERROR. Only a clean
// proof yields a signing capability; TEMPERROR maps to a retryable provider
// status and PERMERROR outcomes are never forwarded (Section 13.1).
func TestRevisionProofResolvesUpwardFromThroughDomainPolicyRecord(t *testing.T) {
	fixture := newRevisionTestFixtureWithFrom(t, nil, false, nil, canonical.HashAlgorithmSHA256, "Sender <a@test>")
	tests := []struct {
		name       string
		status     verify.DomainPolicyStatus
		err        error
		outcome    verify.RevisionProofOutcome
		revision   RevisionVerificationStatus
		capability bool
	}{
		{"no record authorizes", verify.DomainPolicyAuthorized, nil, verify.RevisionProofVerified, RevisionVerificationVerified, true},
		{"strict forbids", verify.DomainPolicyStrict, nil, verify.RevisionProofFromSubdomainForbidden, RevisionVerificationProtocolRejected, false},
		{"multiple records", verify.DomainPolicyAmbiguous, nil, verify.RevisionProofDomainPolicyAmbiguous, RevisionVerificationProtocolRejected, false},
		{"invalid record", verify.DomainPolicyInvalid, nil, verify.RevisionProofDomainPolicyInvalid, RevisionVerificationProtocolRejected, false},
		{"temporary failure", "", verify.NewProviderFailure(verify.ProviderFailureTemporary), verify.RevisionProofDomainPolicyTemporary, RevisionVerificationProviderTemporary, false},
		{"permanent failure", "", verify.NewProviderFailure(verify.ProviderFailurePermanent), verify.RevisionProofDomainPolicyInvalid, RevisionVerificationProtocolRejected, false},
		{"unknown status", verify.DomainPolicyStatus("future"), nil, verify.RevisionProofDomainPolicyInvalid, RevisionVerificationProtocolRejected, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := &recordingDomainPolicyProvider{status: test.status, err: test.err}
			verifier := newDomainPolicyRevisionVerifier(t, mustRevisionStaticProvider(t, fixture), verify.SubdomainFromAuthorization(policy))
			request := verify.Request{Message: fixture.message, Envelope: fixture.envelope}
			outcome, proof, err := verifier.Core().VerifyRevisionProof(context.Background(), request)
			if err != nil || outcome != test.outcome || proof.Valid() != (outcome == verify.RevisionProofVerified) {
				t.Fatalf("VerifyRevisionProof() = %q/%t/%v, want %q", outcome, proof.Valid(), err, test.outcome)
			}
			if !slices.Equal(policy.domains, []string{upwardFromDomain}) {
				t.Fatalf("policy lookups = %q, want exactly the A-label From domain", policy.domains)
			}
			if outcome == verify.RevisionProofVerified {
				usage := proof.Facts().Usage()
				if _, ok := proof.ReplayProjection(); !ok || usage.DomainPolicyLookups() != 1 || usage.ProviderCalls() != usage.KeyLookups()+1 {
					t.Fatalf("usage = policy %d provider %d key %d", usage.DomainPolicyLookups(), usage.ProviderCalls(), usage.KeyLookups())
				}
			} else if _, ok := proof.ReplayProjection(); ok {
				t.Fatal("a failed policy outcome produced a replay projection")
			}
			result, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{Message: fixture.message, Envelope: fixture.envelope})
			if err != nil || result.Status() != test.revision || capability.Valid() != test.capability {
				t.Fatalf("VerifyForRevision() = %q/%t/%v, want %q/%t", result.Status(), capability.Valid(), err, test.revision, test.capability)
			}
		})
	}
}

// TestRevisionProofQueriesDomainPolicyOnlyForUpwardCandidates verifies that a
// downward match, an inauthentic From, a failing signature, and the
// downward-only choice never trigger a Domain Policy Record query.
func TestRevisionProofQueriesDomainPolicyOnlyForUpwardCandidates(t *testing.T) {
	tests := []struct {
		name    string
		from    string
		keys    func(revisionTestFixture) verify.KeyProvider
		choice  func(verify.DomainPolicyProvider) verify.FromAuthorization
		outcome verify.RevisionProofOutcome
	}{
		{"downward match", "a@example.test", nil, nil, verify.RevisionProofVerified},
		{"subdomain From downward", "a@sub.example.test", nil, nil, verify.RevisionProofVerified},
		{"sibling never matches", "a@other.test", nil, nil, verify.RevisionProofFromNotAuthentic},
		{"multiple addresses", "a@test, b@test", nil, nil, verify.RevisionProofFromNotAuthentic},
		{"domain literal", "a@[192.0.2.1]", nil, nil, verify.RevisionProofFromNotAuthentic},
		{"signature failure first", "a@test", func(revisionTestFixture) verify.KeyProvider {
			return revisionProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
				return verify.PublicKey{Algorithm: query.Algorithm, Metadata: verify.KeyMetadata{Status: verify.KeyStatusMissing}}, nil
			})
		}, nil, verify.RevisionProofMissingKey},
		{"downward-only choice", "a@test", nil, func(verify.DomainPolicyProvider) verify.FromAuthorization {
			return verify.DownwardOnlyFromAuthorization()
		}, verify.RevisionProofFromNotAuthentic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRevisionTestFixtureWithFrom(t, nil, false, nil, canonical.HashAlgorithmSHA256, test.from)
			policy := &recordingDomainPolicyProvider{status: verify.DomainPolicyStrict}
			var keys verify.KeyProvider = mustRevisionStaticProvider(t, fixture)
			if test.keys != nil {
				keys = test.keys(fixture)
			}
			choice := verify.SubdomainFromAuthorization(policy)
			if test.choice != nil {
				choice = test.choice(policy)
			}
			verifier := newDomainPolicyRevisionVerifier(t, keys, choice)
			outcome, proof, err := verifier.Core().VerifyRevisionProof(context.Background(), verify.Request{Message: fixture.message, Envelope: fixture.envelope})
			if err != nil || outcome != test.outcome {
				t.Fatalf("VerifyRevisionProof() = %q/%v, want %q", outcome, err, test.outcome)
			}
			if len(policy.domains) != 0 {
				t.Fatalf("policy lookups = %q, want none", policy.domains)
			}
			if outcome == verify.RevisionProofVerified && proof.Facts().Usage().DomainPolicyLookups() != 0 {
				t.Fatal("usage counted a policy lookup that did not happen")
			}
		})
	}
}

// TestRevisionProofMapsUpwardFromAcrossRewrite verifies that an aligned
// From rewrite whose reviser d= is a subdomain of the new From domain is an
// upward candidate decided by the new From domain's record.
func TestRevisionProofMapsUpwardFromAcrossRewrite(t *testing.T) {
	recipe := `{"h":{"from":[{"d":[" sender@example.test"]}],"subject":[{"d":["previous"]}]},"b":[{"d":["older body"]}]}`
	fixture := newRevisionTestFixtureWithFrom(t, &recipe, false, nil, canonical.HashAlgorithmSHA256, "list@test")
	for status, want := range map[verify.DomainPolicyStatus]verify.RevisionProofOutcome{
		verify.DomainPolicyAuthorized: verify.RevisionProofVerified,
		verify.DomainPolicyStrict:     verify.RevisionProofFromSubdomainForbidden,
	} {
		policy := &recordingDomainPolicyProvider{status: status}
		verifier := newDomainPolicyRevisionVerifier(t, mustRevisionStaticProvider(t, fixture), verify.SubdomainFromAuthorization(policy))
		outcome, _, err := verifier.Core().VerifyRevisionProof(context.Background(), verify.Request{Message: fixture.message, Envelope: fixture.envelope})
		if err != nil || outcome != want || !slices.Equal(policy.domains, []string{upwardFromDomain}) {
			t.Fatalf("%s: VerifyRevisionProof() = %q/%v lookups=%q, want %q", status, outcome, err, policy.domains, want)
		}
	}
}

// TestRevisionProofRejectsMissingFromAuthorizationChoice pins D9 at the core
// verifier: a zero or conflicting choice fails construction closed.
func TestRevisionProofRejectsMissingFromAuthorizationChoice(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	if _, err := verify.NewVerifier(mustRevisionStaticProvider(t, fixture), revisionTestClockOption()); err == nil {
		t.Fatal("verify.NewVerifier() accepted a missing Section 11.1 choice")
	}
	if _, err := verify.NewVerifier(mustRevisionStaticProvider(t, fixture), verify.WithFromAuthorization(verify.SubdomainFromAuthorization(nil))); err == nil {
		t.Fatal("verify.NewVerifier() accepted a nil Domain Policy Record provider")
	}
}
