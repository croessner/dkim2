package dsn

import (
	"cmp"
	"slices"
	"strings"

	"github.com/croessner/dkim2/internal/signature"
)

// MaxSigningIdentityCandidates bounds the ordered Draft-08 Section 16.2
// candidate list, and therefore the number of local profile lookups one DSN
// can cause. Candidates beyond the bound are dropped after ordering, so the
// bound can only turn a signable report into an unsigned one, never select a
// non-matching signing domain.
const MaxSigningIdentityCandidates = 64

// SigningIdentityCandidate is one ordered candidate signing domain for a
// locally generated DSN. Its domain relaxed-matches (Draft-08 Section 7.2,
// rt= address as Parameter1, d= as Parameter2) at least one rt= address of
// the highest DKIM2-Signature of the reported message.
type SigningIdentityCandidate struct {
	domain    string
	labels    int
	linked    bool
	preferred bool
}

// Domain returns the canonical candidate signing domain.
func (c SigningIdentityCandidate) Domain() string { return c.domain }

// Linked reports whether the candidate matches an rt= address that an RFC
// 3464 Final-Recipient or Original-Recipient field of the report names.
func (c SigningIdentityCandidate) Linked() bool { return c.linked }

// Preferred reports whether the candidate is the operator-preferred domain.
func (c SigningIdentityCandidate) Preferred() bool { return c.preferred }

// SigningIdentityCandidates returns every domain that can sign this DSN under
// Draft-08 Sections 7.1 item 4 and 16.2, in a deterministic preference order:
//
//  1. candidates matching an RFC 3464-linked rt= address before candidates
//     matching only unlinked rt= addresses;
//  2. within that tier, the preferred domain (when it is itself a candidate);
//  3. then more labels (the most specific domain) first;
//  4. then ascending octet order of the canonical name as the final tie-break.
//
// Candidates are the rt= domains and their parent domains: Section 7.2 step 5
// removes labels only from the left of Parameter1, so exactly those names can
// match. Each enumerated name is admitted only through
// signature.RelaxedDomainMatch, the single owner of the rule. preferred is
// never added when it does not match; invalid evidence yields no candidates.
func (e Evidence) SigningIdentityCandidates(preferred string) []SigningIdentityCandidate {
	if !e.Valid() {
		return nil
	}
	candidates := make([]SigningIdentityCandidate, 0, len(e.recipientDomains))
	positions := make(map[string]int)
	for index, recipientDomain := range e.recipientDomains {
		linked := index < len(e.recipientLinked) && e.recipientLinked[index]
		for name := recipientDomain; name != ""; name = parentDomain(name) {
			if !signature.RelaxedDomainMatch(name, recipientDomain) {
				continue
			}
			if position, seen := positions[name]; seen {
				candidates[position].linked = candidates[position].linked || linked
				continue
			}
			positions[name] = len(candidates)
			candidates = append(candidates, SigningIdentityCandidate{
				domain: name, labels: strings.Count(name, ".") + 1,
				linked: linked, preferred: name == preferred,
			})
		}
	}
	slices.SortFunc(candidates, compareSigningIdentityCandidates)
	if len(candidates) > MaxSigningIdentityCandidates {
		candidates = candidates[:MaxSigningIdentityCandidates]
	}
	return candidates
}

// compareSigningIdentityCandidates orders two distinct candidates by RFC 3464
// linkage, operator preference, label count, and finally canonical octet
// order. Candidate names are unique, so the order is total.
func compareSigningIdentityCandidates(left, right SigningIdentityCandidate) int {
	if left.linked != right.linked {
		if left.linked {
			return -1
		}
		return 1
	}
	if left.preferred != right.preferred {
		if left.preferred {
			return -1
		}
		return 1
	}
	if left.labels != right.labels {
		return cmp.Compare(right.labels, left.labels)
	}
	return strings.Compare(left.domain, right.domain)
}

// parentDomain removes the leftmost label of a canonical DNS name (Draft-08
// Section 7.2 step 5) and returns the empty string when no dot remains.
func parentDomain(name string) string {
	dot := strings.IndexByte(name, '.')
	if dot < 0 {
		return ""
	}
	return name[dot+1:]
}
