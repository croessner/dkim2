package dsn

import (
	"fmt"
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/verify"
)

const (
	identityADomain    = "a.example.test"
	identityBDomain    = "b.example.test"
	identityMXADomain  = "mx." + identityADomain
	identitySubADomain = "sub." + identityADomain
	identityTopLevel   = "test"
)

// identityEvidence builds authenticated-shape evidence for the Section 16.2
// candidate order without running the verifier.
func identityEvidence(domains []string, linked []bool) Evidence {
	paths := make([][]byte, len(domains))
	for index, domain := range domains {
		paths[index] = []byte("<user@" + domain + ">")
	}
	return Evidence{
		form: EvidenceFormComplete, target: verify.Target{Sequence: 1, InstanceNumber: 1},
		mailFrom: []byte("<sender@origin.test>"), recipientDomains: domains,
		recipientPaths: paths, recipientLinked: linked,
	}
}

// candidateDomains projects the ordered candidate names.
func candidateDomains(candidates []SigningIdentityCandidate) []string {
	names := make([]string, len(candidates))
	for index, candidate := range candidates {
		names[index] = candidate.Domain()
	}
	return names
}

// TestSigningIdentityCandidatesFollowRelaxedMatchDirection pins Draft-08
// Section 7.2 with the rt= address as Parameter1: only the rt= domain and its
// parents are candidates, never a child or a sibling.
func TestSigningIdentityCandidatesFollowRelaxedMatchDirection(t *testing.T) {
	evidence := identityEvidence([]string{identityMXADomain}, []bool{true})
	got := candidateDomains(evidence.SigningIdentityCandidates(""))
	want := []string{identityMXADomain, identityADomain, evidenceDomain, identityTopLevel}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates=%v, want %v", got, want)
	}
}

// TestSigningIdentityCandidatesPreferLongestDomain proves the most specific
// matching domain is tried first and equal-length names tie-break by octets.
func TestSigningIdentityCandidatesPreferLongestDomain(t *testing.T) {
	evidence := identityEvidence([]string{identityBDomain, identitySubADomain, identityADomain}, []bool{true, true, true})
	got := candidateDomains(evidence.SigningIdentityCandidates(""))
	want := []string{identitySubADomain, identityADomain, identityBDomain, evidenceDomain, identityTopLevel}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates=%v, want %v", got, want)
	}
}

// TestSigningIdentityCandidatesPreferRFC3464LinkedRecipients proves a
// candidate of a linked rt= address precedes a longer candidate that matches
// only an unlinked rt= address, and that a shared parent is linked once any
// of its rt= addresses is linked.
func TestSigningIdentityCandidatesPreferRFC3464LinkedRecipients(t *testing.T) {
	evidence := identityEvidence([]string{"deep.unlinked.example.test", "linked.example.test"}, []bool{false, true})
	candidates := evidence.SigningIdentityCandidates("")
	got := candidateDomains(candidates)
	want := []string{"linked.example.test", evidenceDomain, "test", "deep.unlinked.example.test", "unlinked.example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates=%v, want %v", got, want)
	}
	if !candidates[1].Linked() || candidates[3].Linked() {
		t.Fatalf("linked flags=%v/%v", candidates[1].Linked(), candidates[3].Linked())
	}
}

// TestSigningIdentityCandidatesPreferReportingDomainOnlyWhenMatching proves
// the preferred domain moves to the front of its linkage tier when it is a
// candidate and is never added when it does not relaxed-match an rt= address.
func TestSigningIdentityCandidatesPreferReportingDomainOnlyWhenMatching(t *testing.T) {
	evidence := identityEvidence([]string{identityMXADomain, identityBDomain}, []bool{true, false})
	got := candidateDomains(evidence.SigningIdentityCandidates(evidenceDomain))
	want := []string{evidenceDomain, identityMXADomain, identityADomain, "test", identityBDomain}
	if !slices.Equal(got, want) {
		t.Fatalf("matching preferred candidates=%v, want %v", got, want)
	}
	unlinkedPreferred := candidateDomains(evidence.SigningIdentityCandidates(identityBDomain))
	if unlinkedPreferred[0] != identityMXADomain || unlinkedPreferred[4] != identityBDomain {
		t.Fatalf("unlinked preferred candidates=%v", unlinkedPreferred)
	}
	for _, foreign := range []string{"reports.other.test", "x.mx.a.example.test", "a.example"} {
		for _, candidate := range evidence.SigningIdentityCandidates(foreign) {
			if candidate.Domain() == foreign || candidate.Preferred() {
				t.Fatalf("non-matching preferred %q became a candidate", foreign)
			}
		}
	}
}

// TestSigningIdentityCandidatesAreDeterministicAndBounded proves input order
// does not change the result and that the list never exceeds its bound.
func TestSigningIdentityCandidatesAreDeterministicAndBounded(t *testing.T) {
	forward := identityEvidence([]string{"c.example.test", identityADomain, identityBDomain}, []bool{true, true, true})
	reverse := identityEvidence([]string{identityBDomain, identityADomain, "c.example.test"}, []bool{true, true, true})
	if got, want := candidateDomains(forward.SigningIdentityCandidates("")), candidateDomains(reverse.SigningIdentityCandidates("")); !slices.Equal(got, want) {
		t.Fatalf("order depends on rt= order: %v vs %v", got, want)
	}
	domains := make([]string, 0, MaxSigningIdentityCandidates+8)
	linked := make([]bool, 0, cap(domains))
	for index := range cap(domains) {
		domains = append(domains, fmt.Sprintf("r%03d.example.test", index))
		linked = append(linked, true)
	}
	if got := identityEvidence(domains, linked).SigningIdentityCandidates(""); len(got) != MaxSigningIdentityCandidates {
		t.Fatalf("candidates=%d, want bound %d", len(got), MaxSigningIdentityCandidates)
	}
	if got := (Evidence{}).SigningIdentityCandidates(evidenceDomain); got != nil {
		t.Fatalf("invalid evidence candidates=%v", got)
	}
}
