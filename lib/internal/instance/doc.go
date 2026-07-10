// Package instance parses Message-Instance header fields for the DKIM2 draft
// baseline draft-ietf-dkim-dkim2-spec-04.
//
// The parser consumes M1 raw message header fields, accepts only
// Message-Instance fields, and validates the field-local `m=`, `h=`, and
// optional `r=` tags. Every header tag must have its draft-required semicolon
// terminator. Shared DKIM2 tag-list scanning, duplicate tag detection,
// extension tag validation, and base64string parsing remain owned by
// lib/internal/tagvalue so parser behavior stays DRY across M2 packages.
//
// Collection helpers extract Message-Instance fields from a full raw message in
// RFC 5322 occurrence order and validate that m= numbers are contiguous from
// origin value 1. This package intentionally does not calculate hashes, compare
// hashes, or parse recipe JSON semantics. Those invariants are deferred to
// later canonicalization, hash, and recipe milestones.
//
// Diagnostics are structured and bounded. Errors may expose stable codes,
// small allowlisted tag names, indexes, and resource-limit metadata, but must
// not include raw header values, hash bytes, recipe bytes, or other
// message-derived secret material.
package instance
