// Package verify coordinates DKIM2 static-key verification contracts.
//
// The package owns the library-internal verification boundary for
// draft-ietf-dkim-dkim2-spec-06. It consumes the raw RFC 5322 message model,
// the Message-Instance and DKIM2-Signature parsers, and the
// canonicalization helpers needed to verify every supported Message-Instance
// hash set. It must not reimplement raw parsing, DKIM2 tag parsing,
// base64string parsing, sequence validation, canonical body or header input,
// or Section 9.6 signature input rendering.
//
// Verification is intentionally dependency-injected. Public keys are resolved
// through KeyProvider by canonical signing domain, selector, and algorithm.
// The default algorithm policy allows exactly rsa-sha256 and ed25519-sha256.
// RSA verifier policy defaults to a 1024-bit minimum so the verifier can
// validate the active draft-required 1024 through 2048 bit range.
// RSA-SHA256 verifies SHA-256 plus PKCS#1 v1.5 over Section 9.6 input
// bytes. Ed25519-SHA256 verifies Ed25519 over SHA-256 digest bytes of the same
// input.
//
// Timestamp checks use an injected Clock and explicit TimestampPolicy so tests
// and callers can evaluate future and stale signatures deterministically.
// Current SMTP envelope state is carried by immutable Envelope values.
// Matching follows draft-ietf-dkim-dkim2-spec-06 Sections 9.2 and 11.4: ASCII
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
//
// Verify derives one bounded flag candidate from the already parsed selected
// DKIM2-Signature. The candidate contains only target sequence and the five
// known policy booleans; it owns no raw flag text. It remains unauthenticated
// evidence in this package. The service layer alone may upgrade it to a sealed
// policy hop after the aggregate current result is PASS. Non-PASS results may
// retain parser evidence internally but cannot create authenticated policy
// facts, feedback intent, or local actions.
//
// After aggregate current verification passes, Verify may walk authenticated
// Message-Instance history through the recipe parser, recipe applier, and
// canonical hash owner. The resulting immutable HistoryWalk records bounded
// reconstructed-content coverage only. It does not verify historical
// signatures, authenticate historical policy flags, alter current four-state
// truth, or project history through the service or public facade in this
// increment. Non-PASS results perform no recipe-history work.
package verify
