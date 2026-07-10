// Package signature parses DKIM2-Signature header fields for the DKIM2 draft
// baseline draft-ietf-dkim-dkim2-spec-04.
//
// This package owns parser-level domain types for required i=, m=, t=, d=, and
// s= tags, exactly one envelope form consisting of nd= or the mf=/rt= pair,
// plus optional n= and f= tags. Every header tag must have its draft-required
// semicolon terminator. Known flags include feedhere. The parser consumes
// immutable rawmsg.HeaderField values, preserves the M1 header occurrence
// index, and delegates shared tag-list scanning and padded base64string decoding
// to lib/internal/tagvalue.
//
// Parser scope is intentionally narrow. Collection helpers extract
// DKIM2-Signature fields from full raw messages in RFC 5322 occurrence order,
// validate contiguous i= sequences from origin value 1, and report the draft
// special case where Message-Instance numbers are above every signature m=
// reference. Current SMTP envelope matching, canonical signature input
// assembly, DNS key lookup, and cryptographic verification are deferred to
// later milestones. Diagnostics are typed and bounded, and must not expose raw
// DKIM2-Signature fields, decoded envelope paths, recipient lists, nonce
// values, selectors, signatures, or other secret-bearing message data.
package signature
