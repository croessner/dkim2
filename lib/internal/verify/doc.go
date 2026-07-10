// Package verify coordinates DKIM2 static-key verification contracts.
//
// The package owns the library-internal verification boundary for
// draft-ietf-dkim-dkim2-spec-04. It consumes the M1 raw RFC 5322 message model,
// the M2 Message-Instance and DKIM2-Signature parsers, and the M3
// canonicalization and SHA-256 helpers. It must not reimplement raw parsing,
// DKIM2 tag parsing, base64string parsing, sequence validation, canonical body
// or header input, or Section 9.6 signature input rendering.
//
// Verification is intentionally dependency-injected. Public keys are resolved
// through KeyProvider by canonical signing domain, selector, and algorithm.
// The default algorithm policy allows exactly rsa-sha256 and ed25519-sha256.
// RSA verifier policy defaults to a 1024-bit minimum so the verifier can
// validate the active draft-required 1024 through 2048 bit range.
// RSA-SHA256 verifies SHA-256 plus PKCS#1 v1.5 over M3 Section 9.6 input
// bytes. Ed25519-SHA256 verifies Ed25519 over SHA-256 digest bytes of the same
// input.
//
// Timestamp checks use an injected Clock and explicit TimestampPolicy so tests
// and callers can evaluate future and stale signatures deterministically.
// Current SMTP envelope state is carried by immutable Envelope values.
// Matching follows draft-ietf-dkim-dkim2-spec-04 Sections 9.2 and 11.4: ASCII
// domain bytes are lowercased, local-part and non-ASCII bytes remain
// case-sensitive, and every current recipient must occur in the signed
// recipient set regardless of order or additional signed recipients. Matching
// does not perform Unicode normalization, IDNA mapping, sorting, or
// deduplication.
//
// Result and error types expose bounded facts such as allowlisted algorithms,
// status names, check kinds, sequence numbers, instance numbers, and limit
// names. Diagnostics must not contain raw messages, raw body bytes, raw header
// values, full DKIM2 fields, decoded envelope paths, recipient lists, nonces,
// raw signatures, public-key bytes, private keys, tokens, or protected
// configuration values.
package verify
