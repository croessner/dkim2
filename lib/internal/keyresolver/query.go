package keyresolver

import (
	"strings"

	"github.com/croessner/dkim2/internal/signature"
)

// Algorithm aliases the signature owner's closed algorithm vocabulary.
type Algorithm = signature.Algorithm

const (
	// AlgorithmRSASHA256 identifies an RSA-SHA256 key query.
	AlgorithmRSASHA256 = signature.AlgorithmRSASHA256
	// AlgorithmEd25519SHA256 identifies an Ed25519-SHA256 key query.
	AlgorithmEd25519SHA256 = signature.AlgorithmEd25519SHA256
	// AlgorithmMLDSA44 identifies a pure ML-DSA-44 key query.
	AlgorithmMLDSA44 = signature.AlgorithmMLDSA44
)

// Query owns one validated canonical DNS public-key lookup tuple.
type Query struct {
	signingDomain    string
	selector         string
	algorithm        Algorithm
	presentationName string
	absoluteName     string
}

// NewQuery validates canonical components and constructs absolute DNS ownership.
func NewQuery(signingDomain, selector string, algorithm Algorithm, limits Limits) (Query, error) {
	if err := limits.Validate(); err != nil || !algorithm.Known() {
		return Query{}, newResolverError(ErrorClassContract)
	}
	domain, err := CanonicalSigningDomain(
		signingDomain,
		limits.MaxSigningDomainBytes,
		limits.MaxSigningDomainLabels,
	)
	if err != nil {
		return Query{}, newResolverError(ErrorClassContract)
	}
	canonicalSelector, err := CanonicalSelector(
		selector,
		limits.MaxSelectorBytes,
		limits.MaxSelectorLabels,
	)
	if err != nil {
		return Query{}, newResolverError(ErrorClassContract)
	}
	presentation := canonicalSelector + "._domainkey." + domain
	if len(presentation) > limits.MaxOwnerBytes || len(presentation) > hardMaxNameBytes {
		return Query{}, newResolverError(ErrorClassPermanent)
	}
	absolute := presentation + "."
	if !OwnerKindSelector.ValidAbsoluteOwner(absolute) {
		return Query{}, newResolverError(ErrorClassContract)
	}
	return Query{
		signingDomain: domain, selector: canonicalSelector, algorithm: algorithm,
		presentationName: presentation, absoluteName: absolute,
	}, nil
}

// CanonicalSigningDomain validates and canonicalizes one bounded ASCII DNS signing domain.
func CanonicalSigningDomain(value string, maxBytes, maxLabels int) (string, error) {
	return canonicalBoundedDNSName(value, maxBytes, maxLabels)
}

// CanonicalSelector validates and canonicalizes one bounded ASCII DNS selector.
func CanonicalSelector(value string, maxBytes, maxLabels int) (string, error) {
	return canonicalBoundedDNSName(value, maxBytes, maxLabels)
}

// canonicalBoundedDNSName applies shared DNS grammar and one caller-owned bound pair.
func canonicalBoundedDNSName(value string, maxBytes, maxLabels int) (string, error) {
	if maxBytes <= 0 || maxBytes > hardMaxNameBytes || maxLabels <= 0 || maxLabels > hardMaxNameLabels {
		return "", newResolverError(ErrorClassContract)
	}
	domain, labels, ok := canonicalDNSName(value)
	if !ok || len(domain) > maxBytes || labels > maxLabels {
		return "", newResolverError(ErrorClassContract)
	}
	return domain, nil
}

// OwnerKind identifies the closed set of DKIM2 TXT owner shapes. The kind is
// derived from the owner grammar once, so selector-key and Domain Policy
// Record owners can never share validation drift or a cache key space.
type OwnerKind string

const (
	// OwnerKindSelector identifies a key owner <selector>._domainkey.<domain>.
	// (Draft-09 Section 3.7).
	OwnerKindSelector OwnerKind = "selector"
	// OwnerKindDomainPolicy identifies a Domain Policy Record owner
	// _domainkey.<domain>. (Draft-09 Section 3.8).
	OwnerKindDomainPolicy OwnerKind = "domain_policy"
)

// Known reports whether the kind belongs to the closed owner vocabulary.
func (k OwnerKind) Known() bool { return k == OwnerKindSelector || k == OwnerKindDomainPolicy }

// ValidAbsoluteOwner reports whether name is a canonical absolute owner of
// exactly this kind.
func (k OwnerKind) ValidAbsoluteOwner(name string) bool {
	kind, ok := ClassifyAbsoluteOwner(name)
	return ok && kind == k
}

// ValidAbsoluteOwner validates a canonical terminal-dot DKIM2 TXT owner of
// either kind using the query grammar. Transports accept both kinds; callers
// that need one kind use OwnerKind.ValidAbsoluteOwner.
func ValidAbsoluteOwner(name string) bool {
	_, ok := ClassifyAbsoluteOwner(name)
	return ok
}

// ClassifyAbsoluteOwner validates a canonical terminal-dot DKIM2 TXT owner and
// reports its kind. A selector owner has at least one label before the single
// "_domainkey" label; a Domain Policy Record owner begins with it. Both need
// at least one domain label after it, and every other label must be a
// canonical lowercase ASCII DNS label.
func ClassifyAbsoluteOwner(name string) (OwnerKind, bool) {
	if len(name) < 3 || name[len(name)-1] != '.' || len(name)-1 > hardMaxNameBytes || strings.HasSuffix(name, "..") || name != strings.ToLower(name) {
		return "", false
	}
	labels := strings.Split(name[:len(name)-1], ".")
	domainKeyIndex := -1
	for index, label := range labels {
		if label == "_domainkey" {
			if domainKeyIndex >= 0 {
				return "", false
			}
			domainKeyIndex = index
			continue
		}
		if !validDNSLabel(label) {
			return "", false
		}
	}
	switch {
	case domainKeyIndex < 0 || domainKeyIndex >= len(labels)-1:
		return "", false
	case domainKeyIndex == 0:
		return OwnerKindDomainPolicy, true
	default:
		return OwnerKindSelector, true
	}
}

// SigningDomain returns the canonical ASCII signing domain.
func (q Query) SigningDomain() string { return q.signingDomain }

// Selector returns the canonical ASCII selector with label boundaries preserved.
func (q Query) Selector() string { return q.selector }

// Algorithm returns the requested supported algorithm.
func (q Query) Algorithm() Algorithm { return q.algorithm }

// PresentationOwner returns the canonical owner without a terminal root dot.
func (q Query) PresentationOwner() string { return q.presentationName }

// AbsoluteOwner returns the canonical transport owner with a terminal root dot.
func (q Query) AbsoluteOwner() string { return q.absoluteName }

// canonicalDNSName validates ASCII sub-domain syntax and lowercases ASCII letters.
func canonicalDNSName(value string) (string, int, bool) {
	if value == "" || len(value) > hardMaxNameBytes {
		return "", 0, false
	}
	labels := strings.Split(value, ".")
	if len(labels) == 0 || len(labels) > hardMaxNameLabels {
		return "", 0, false
	}
	for _, label := range labels {
		if !validDNSLabel(label) {
			return "", 0, false
		}
	}
	return strings.ToLower(value), len(labels), true
}

// validDNSLabel enforces ASCII letter/digit edges and letter/digit/hyphen interiors.
func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || !asciiLetterOrDigit(label[0]) || !asciiLetterOrDigit(label[len(label)-1]) {
		return false
	}
	for index := 1; index < len(label)-1; index++ {
		if !asciiLetterOrDigit(label[index]) && label[index] != '-' {
			return false
		}
	}
	return true
}

// asciiLetterOrDigit reports whether one byte is an ASCII DNS alphanumeric.
func asciiLetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
