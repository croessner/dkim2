package signing

import "github.com/croessner/dkim2/internal/signature"

// ValidEnvelopePath reports whether exact SMTP path bytes satisfy the shared
// signing path grammar, including RFC 6531 UTF-8 local parts and U-label
// domains (Draft-07 Section 18). It is the signer-owned bridge the public
// facade exposes to adapters.
func ValidEnvelopePath(path []byte, allowNull bool) bool {
	return signature.ValidEnvelopePath(path, allowNull)
}

// EnvelopePathDomain returns the canonical lowercase A-label DNS domain of one
// non-null SMTP path, the identity a signer selects and records for a U-label
// domain (Draft-07 Section 18).
func EnvelopePathDomain(path []byte) (string, bool) {
	return signature.CanonicalEnvelopeDomain(path, false)
}
