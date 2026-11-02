package app

import (
	"time"

	"github.com/croessner/dkim2"
)

// subdomainFromAuthorization is implemented by the DNS verifier, which owns
// the configured Draft-09 Section 11.1 choice
// (verification.domain_policy.allow_subdomain_from).
type subdomainFromAuthorization interface {
	AllowSubdomainFrom() bool
}

// newOperationSigner is the single daemon owner of signer construction. Every
// signer verifies its incoming chain with the same Section 11.1 choice as the
// inbound verifier: when the public-key source carries a downward-only
// choice, the signer is built downward only; otherwise the library resolves
// the choice from the public-key source as a DomainPolicyProvider and fails
// construction closed when it is none.
func newOperationSigner(
	publicKeys dkim2.PublicKeyProvider,
	routes dkim2.RouteFanoutAuthority,
	authorizer dkim2.SigningAuthorizer,
	privateKeys dkim2.PrivateKeySigner,
	at time.Time,
) (*dkim2.Signer, error) {
	options := []dkim2.SignerOption{dkim2.WithSigningClock(func() time.Time { return at })}
	if choice, ok := publicKeys.(subdomainFromAuthorization); ok && !choice.AllowSubdomainFrom() {
		options = append(options, dkim2.WithoutSignerSubdomainFromAuthorization())
	}
	return dkim2.NewSigner(publicKeys, routes, authorizer, privateKeys, options...)
}
