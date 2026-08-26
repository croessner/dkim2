// Package instance parses Message-Instance header fields for the DKIM2 draft
// baseline draft-ietf-dkim-dkim2-spec-05.
//
// The parser consumes immutable raw message header fields, accepts only
// Message-Instance fields, and validates the field-local `m=`, `h=`, and
// optional `r=` tags. Every header tag must have its draft-required semicolon
// terminator. Shared DKIM2 tag-list scanning, duplicate tag detection,
// extension tag validation, and base64string parsing remain owned by
// lib/internal/tagvalue so parser behavior stays DRY across protocol packages.
//
// Collection helpers extract Message-Instance fields from a full raw message in
// RFC 5322 occurrence order and validate that m= numbers are contiguous from
// origin value 1. This package owns strict recipe base64 decoding and immutable
// decoded-byte storage but intentionally does not parse recipe JSON or apply a
// reconstruction plan; those semantics belong to lib/internal/recipe. Hash
// selection exposes supported SHA-256 and SHA-512 tuples in wire order.
// Syntactically valid unknown extension tuples remain preserved but unselected,
// and duplicate names are rejected case-insensitively across both groups.
// Canonical hash calculation and authenticated comparison remain outside this
// package.
//
// Diagnostics are structured and bounded. Errors may expose stable codes,
// small allowlisted tag names, indexes, and resource-limit metadata, but must
// not include raw header values, hash bytes, recipe bytes, or other
// message-derived secret material.
package instance
