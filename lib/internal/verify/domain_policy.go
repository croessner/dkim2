package verify

import (
	"context"

	"github.com/croessner/dkim2/internal/niliface"
)

// DomainPolicyStatus identifies one closed Draft-09 Section 3.8 Domain Policy
// Record result as the verifier consumes it. A temporary failure is reported
// by the provider as a typed temporary provider failure.
type DomainPolicyStatus string

const (
	// DomainPolicyAuthorized reports that subdomains of the domain may make
	// its From header fields Authentic (no record, or no strict flag).
	DomainPolicyAuthorized DomainPolicyStatus = "authorized"
	// DomainPolicyStrict reports a record whose f= tag carries the strict flag.
	DomainPolicyStrict DomainPolicyStatus = "strict"
	// DomainPolicyAmbiguous reports more than one record beginning with v=DKIM1.
	DomainPolicyAmbiguous DomainPolicyStatus = "ambiguous"
	// DomainPolicyInvalid reports an invalid record or a permanent lookup failure.
	DomainPolicyInvalid DomainPolicyStatus = "invalid"
)

// Known reports whether the status belongs to the closed provider vocabulary.
func (s DomainPolicyStatus) Known() bool {
	switch s {
	case DomainPolicyAuthorized, DomainPolicyStrict, DomainPolicyAmbiguous, DomainPolicyInvalid:
		return true
	default:
		return false
	}
}

// DomainPolicyProvider resolves the Domain Policy Record of one canonical
// A-label From domain (Draft-09 Sections 3.8 and 18). It returns a known
// status with a nil error, a typed temporary provider failure, or the live
// caller context error; every other pair is treated as an invalid record.
type DomainPolicyProvider interface {
	LookupDomainPolicy(ctx context.Context, domain string) (DomainPolicyStatus, error)
}

// FromAuthorization is the explicit verifier choice for the Draft-09 Section
// 11.1 upward Authentic From match. Exactly one of a Domain Policy Record
// provider or the local downward-only policy must be chosen; the zero value
// is not a choice and verifier construction fails closed on it (D9).
type FromAuthorization struct {
	provider     DomainPolicyProvider
	downwardOnly bool
}

// SubdomainFromAuthorization selects the conforming Draft-09 behavior: an
// upward match makes a From state Authentic unless the From domain's Domain
// Policy Record, resolved through provider, carries the strict flag.
func SubdomainFromAuthorization(provider DomainPolicyProvider) FromAuthorization {
	return FromAuthorization{provider: provider}
}

// DownwardOnlyFromAuthorization selects the documented local policy that
// never uses the upward match, so a From state is Authentic only when d= is
// equal to or a parent of the From domain, and no Domain Policy Record is
// ever queried.
func DownwardOnlyFromAuthorization() FromAuthorization {
	return FromAuthorization{downwardOnly: true}
}

// valid reports whether exactly one coherent choice was made.
func (a FromAuthorization) valid() bool {
	hasProvider := !niliface.IsNil(a.provider)
	return hasProvider != a.downwardOnly
}

// subdomainAuthorized reports whether the upward match may be resolved
// through a Domain Policy Record provider.
func (a FromAuthorization) subdomainAuthorized() bool {
	return a.valid() && !a.downwardOnly
}

// WithFromAuthorization records the explicit Section 11.1 choice.
func WithFromAuthorization(choice FromAuthorization) Option {
	return func(options *Options) {
		options.FromAuthorization = choice
	}
}

// resolveDomainPolicy performs one provider callback and maps every result
// into the closed revision outcome algebra input. A live caller context error
// is returned unchanged; a typed temporary failure is temporary; any other
// error or unknown status fails closed as invalid.
func (a FromAuthorization) resolveDomainPolicy(ctx context.Context, domain string) (domainPolicyResolution, error) {
	status, err := a.provider.LookupDomainPolicy(ctx, domain)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	if err != nil {
		if ProviderFailureClassOf(err) == ProviderFailureTemporary {
			return domainPolicyResolvedTemporary, nil
		}
		return domainPolicyResolvedInvalid, nil
	}
	switch status {
	case DomainPolicyAuthorized:
		return domainPolicyResolvedAuthorized, nil
	case DomainPolicyStrict:
		return domainPolicyResolvedStrict, nil
	case DomainPolicyAmbiguous:
		return domainPolicyResolvedAmbiguous, nil
	default:
		return domainPolicyResolvedInvalid, nil
	}
}

// domainPolicyResolution is the verifier-internal result of one policy lookup.
type domainPolicyResolution uint8

const (
	domainPolicyResolvedAuthorized domainPolicyResolution = iota + 1
	domainPolicyResolvedStrict
	domainPolicyResolvedTemporary
	domainPolicyResolvedAmbiguous
	domainPolicyResolvedInvalid
)

// resolveUpwardFromCandidates resolves every deduplicated upward candidate in
// field order and combines the results with the Section 14.6 sig-all
// precedence (D2): all authorized is "" (Authentic); else any strict is FAIL
// from_subdomain_forbidden; else the first ambiguous or invalid record in
// field order is PERMERROR; else TEMPERROR. Every candidate is resolved so the
// lookup count is exact, unless the caller context ends.
func (a FromAuthorization) resolveUpwardFromCandidates(ctx context.Context, domains []string) (RevisionProofOutcome, error) {
	if len(domains) == 0 {
		return "", nil
	}
	if !a.subdomainAuthorized() {
		return RevisionProofFromNotAuthentic, nil
	}
	strict, temporary := false, false
	var permanent RevisionProofOutcome
	for _, domain := range domains {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		resolution, err := a.resolveDomainPolicy(ctx, domain)
		if err != nil {
			return "", err
		}
		switch resolution {
		case domainPolicyResolvedAuthorized:
		case domainPolicyResolvedStrict:
			strict = true
		case domainPolicyResolvedTemporary:
			temporary = true
		case domainPolicyResolvedAmbiguous:
			if permanent == "" {
				permanent = RevisionProofDomainPolicyAmbiguous
			}
		default:
			if permanent == "" {
				permanent = RevisionProofDomainPolicyInvalid
			}
		}
	}
	switch {
	case strict:
		return RevisionProofFromSubdomainForbidden, nil
	case permanent != "":
		return permanent, nil
	case temporary:
		return RevisionProofDomainPolicyTemporary, nil
	default:
		return "", nil
	}
}
