package dkim2

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/verify"
)

const domainPolicyQueryRedactedText = "dkim2.DomainPolicyQuery{redacted}"

// DomainPolicyStatus identifies one closed Draft-09 Section 3.8 Domain Policy
// Record outcome. A temporary DNS failure is not a status: providers report
// it as a classified temporary provider error.
type DomainPolicyStatus string

const (
	// DomainPolicyAuthorized reports that subdomains may make From header
	// fields of the domain Authentic: no record (NXDOMAIN, NODATA, or no
	// record beginning with v=DKIM1), no f= tag, or no strict flag.
	DomainPolicyAuthorized DomainPolicyStatus = "authorized"
	// DomainPolicyStrict reports one record whose f= tag carries the
	// case-sensitive strict flag.
	DomainPolicyStrict DomainPolicyStatus = "strict"
	// DomainPolicyAmbiguous reports more than one record beginning with
	// v=DKIM1 (PERMERROR).
	DomainPolicyAmbiguous DomainPolicyStatus = "ambiguous"
	// DomainPolicyInvalid reports a record that begins with v=DKIM1 but is
	// not a valid tag-list, or a permanent lookup failure (PERMERROR).
	DomainPolicyInvalid DomainPolicyStatus = "invalid"
)

// Known reports whether the status is in the closed provider vocabulary.
func (s DomainPolicyStatus) Known() bool {
	switch s {
	case DomainPolicyAuthorized, DomainPolicyStrict, DomainPolicyAmbiguous, DomainPolicyInvalid:
		return true
	default:
		return false
	}
}

// DomainPolicyQuery identifies the canonical A-label From domain whose Domain
// Policy Record is looked up at _domainkey.<domain> (Draft-09 Sections 3.8
// and 18). The lookup uses the domain exactly, without any tree walk.
type DomainPolicyQuery struct {
	state *domainPolicyQueryState
}

type domainPolicyQueryState struct{ domain string }

// NewDomainPolicyQuery constructs one canonical explicit Domain Policy Record query.
func NewDomainPolicyQuery(domain string) (DomainPolicyQuery, error) {
	query, err := keyresolver.NewDomainPolicyQuery(domain, keyresolver.DefaultLimits())
	if err != nil || query.Domain() != domain {
		return DomainPolicyQuery{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return DomainPolicyQuery{state: &domainPolicyQueryState{domain: domain}}, nil
}

// Domain returns the canonical A-label domain that holds the record.
func (q DomainPolicyQuery) Domain() string {
	if q.state == nil {
		return ""
	}
	return q.state.domain
}

// String returns a constant representation without the queried domain.
func (DomainPolicyQuery) String() string { return domainPolicyQueryRedactedText }

// GoString returns a constant representation without the queried domain.
func (DomainPolicyQuery) GoString() string { return domainPolicyQueryRedactedText }

// Format prevents formatting from traversing the queried domain.
func (DomainPolicyQuery) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, domainPolicyQueryRedactedText)
}

// MarshalJSON rejects serialization of the queried domain.
func (DomainPolicyQuery) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of the queried domain.
func (DomainPolicyQuery) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// DomainPolicyProvider resolves Draft-09 Section 3.8 Domain Policy Records
// for the upward Authentic From match (Sections 7.1 item 3 and 11.1). It
// returns a known status with a nil error, the active caller context error,
// or a classified temporary or permanent provider error. A temporary error is
// TEMPERROR; a permanent error and every contract violation are treated as an
// invalid record (PERMERROR). Implementations must not place raw causes or
// DNS data in either return value. DNSPublicKeyProvider implements it with
// the same bounded resolver, cache, and transport as key lookups.
type DomainPolicyProvider interface {
	LookupDomainPolicy(context.Context, DomainPolicyQuery) (DomainPolicyStatus, error)
}

// LookupDomainPolicy resolves one Domain Policy Record through the provider's
// bounded DNS resolver, sharing its transport, cache, and single-flight
// coordination with key lookups.
func (p *DNSPublicKeyProvider) LookupDomainPolicy(ctx context.Context, query DomainPolicyQuery) (DomainPolicyStatus, error) {
	if p == nil || p.state == nil || ctx == nil {
		return "", newAPIError(APIErrorCodeInvalidProvider)
	}
	outcome, err := p.state.resolver.ResolveDomainPolicy(ctx, query.Domain())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return "", ctxErr
		}
		return "", newAPIError(APIErrorCodeInvalidProvider)
	}
	switch outcome.Status() {
	case keyresolver.DomainPolicyAuthorized:
		return DomainPolicyAuthorized, nil
	case keyresolver.DomainPolicyStrict:
		return DomainPolicyStrict, nil
	case keyresolver.DomainPolicyAmbiguous:
		return DomainPolicyAmbiguous, nil
	case keyresolver.DomainPolicyTemporary:
		return "", NewTemporaryProviderError()
	default:
		return DomainPolicyInvalid, nil
	}
}

// subdomainFromChoice records the explicit Draft-09 Section 11.1 choice made
// through verifier or signer options.
type subdomainFromChoice struct {
	provider     DomainPolicyProvider
	downwardOnly bool
	conflicting  bool
}

// selectProvider records an explicit Domain Policy Record provider.
func (c *subdomainFromChoice) selectProvider(provider DomainPolicyProvider) error {
	if nilDomainPolicyProvider(provider) {
		return newAPIError(APIErrorCodeInvalidOption)
	}
	c.conflicting = c.conflicting || c.downwardOnly || c.provider != nil
	c.provider = provider
	return nil
}

// selectDownwardOnly records the local downward-only policy.
func (c *subdomainFromChoice) selectDownwardOnly() {
	c.conflicting = c.conflicting || c.provider != nil
	c.downwardOnly = true
}

// resolve is the single owner of the D9 construction rule for every public
// constructor that builds a verifier: an explicit provider option, the
// explicit downward-only option, or a key provider that also implements
// DomainPolicyProvider. A missing or conflicting choice fails construction.
func (c subdomainFromChoice) resolve(keys PublicKeyProvider) (verify.FromAuthorization, error) {
	switch {
	case c.conflicting:
		return verify.FromAuthorization{}, newAPIError(APIErrorCodeInvalidOption)
	case c.downwardOnly:
		return verify.DownwardOnlyFromAuthorization(), nil
	case c.provider != nil:
		return verify.SubdomainFromAuthorization(domainPolicyBridge{provider: c.provider}), nil
	}
	if provider, ok := keys.(DomainPolicyProvider); ok && !nilDomainPolicyProvider(provider) {
		return verify.SubdomainFromAuthorization(domainPolicyBridge{provider: provider}), nil
	}
	return verify.FromAuthorization{}, newAPIError(APIErrorCodeInvalidOption)
}

// nilDomainPolicyProvider reports nil and typed-nil policy provider dependencies.
func nilDomainPolicyProvider(provider DomainPolicyProvider) bool {
	return niliface.IsNil(provider)
}

// WithDomainPolicyProvider selects the conforming Draft-09 Section 11.1
// behavior with an explicit Domain Policy Record provider: a subdomain d=
// makes a parent From Authentic unless the From domain publishes f=strict.
func WithDomainPolicyProvider(provider DomainPolicyProvider) VerifierOption {
	return func(config *verifierConfig) error {
		if config == nil {
			return newAPIError(APIErrorCodeInvalidOption)
		}
		return config.fromChoice.selectProvider(provider)
	}
}

// WithoutSubdomainFromAuthorization selects the documented local policy that
// never uses the upward Authentic From match and never queries a Domain
// Policy Record. Messages that Draft-09 defines as PASS through a subdomain
// d= then FAIL with from_not_authentic.
func WithoutSubdomainFromAuthorization() VerifierOption {
	return func(config *verifierConfig) error {
		if config == nil {
			return newAPIError(APIErrorCodeInvalidOption)
		}
		config.fromChoice.selectDownwardOnly()
		return nil
	}
}

// WithSignerDomainPolicyProvider selects the Domain Policy Record provider
// the signer's incoming-chain verification (VerifyForRevision) uses for the
// upward Authentic From match. The signer's own d= choice stays downward
// only (disposition D8).
func WithSignerDomainPolicyProvider(provider DomainPolicyProvider) SignerOption {
	return func(config *signerConfig) error {
		if config == nil {
			return newSigningError(SigningErrorInvalidOptions)
		}
		if err := config.fromChoice.selectProvider(provider); err != nil {
			return newSigningError(SigningErrorInvalidOptions)
		}
		return nil
	}
}

// WithoutSignerSubdomainFromAuthorization makes the signer's incoming-chain
// verification use the local downward-only policy.
func WithoutSignerSubdomainFromAuthorization() SignerOption {
	return func(config *signerConfig) error {
		if config == nil {
			return newSigningError(SigningErrorInvalidOptions)
		}
		config.fromChoice.selectDownwardOnly()
		return nil
	}
}

type domainPolicyBridge struct{ provider DomainPolicyProvider }

// LookupDomainPolicy adapts the closed public provider contract into the
// verifier-owned policy vocabulary without retaining raw causes.
func (b domainPolicyBridge) LookupDomainPolicy(ctx context.Context, domain string) (verify.DomainPolicyStatus, error) {
	if nilDomainPolicyProvider(b.provider) || ctx == nil {
		return "", verify.NewProviderFailure(verify.ProviderFailureContract)
	}
	query, err := NewDomainPolicyQuery(domain)
	if err != nil {
		return verify.DomainPolicyInvalid, nil
	}
	status, err := b.provider.LookupDomainPolicy(ctx, query)
	if err != nil {
		if status != "" || nilSigningCallback(err) {
			return "", verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return "", ctxErr
		}
		if ProviderErrorClassOf(err) == ProviderErrorClassTemporary {
			return "", verify.NewProviderFailure(verify.ProviderFailureTemporary)
		}
		return "", verify.NewProviderFailure(verify.ProviderFailurePermanent)
	}
	switch status {
	case DomainPolicyAuthorized:
		return verify.DomainPolicyAuthorized, nil
	case DomainPolicyStrict:
		return verify.DomainPolicyStrict, nil
	case DomainPolicyAmbiguous:
		return verify.DomainPolicyAmbiguous, nil
	default:
		return verify.DomainPolicyInvalid, nil
	}
}
