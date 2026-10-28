package dkim2

import "github.com/croessner/dkim2/internal/signing"

// ValidEnvelopePath reports whether exact bracketed SMTP path bytes satisfy the
// DKIM2 envelope path grammar, including RFC 6531 UTF-8 local parts and
// U-label domains. allowNull admits the null reverse path "<>". Adapters use
// it so that SMTPUTF8 admission has one owner.
func ValidEnvelopePath(path []byte, allowNull bool) bool {
	return signing.ValidEnvelopePath(path, allowNull)
}

// EnvelopePathDomain returns the canonical lowercase A-label DNS domain of one
// non-null SMTP path, converting a U-label domain with the strict IDNA profile
// (Draft-08 Section 18). Null paths, address literals, and invalid paths
// report false. Adapters use it to select a signing domain from an SMTPUTF8
// envelope without their own IDNA mapping.
func EnvelopePathDomain(path []byte) (string, bool) {
	return signing.EnvelopePathDomain(path)
}
