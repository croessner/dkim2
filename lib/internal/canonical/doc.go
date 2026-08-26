// Package canonical owns DKIM2 canonical byte transformations and digest
// result containers for the draft-ietf-dkim-dkim2-spec-05 baseline.
//
// This package is the library-internal source of truth for Section 6.1 body
// hash input, Section 6.2 header hash input, and Section 9.6 signature input.
// Later builders consume immutable rawmsg, instance, and signature parser
// views instead of reparsing raw RFC 5322 messages or DKIM2 tag lists.
//
// Section 6.1 body input is MIME-agnostic and works on parser-owned body
// octets. Section 6.2 header input excludes the draft-defined header classes,
// including Delivered-To under Section 4, lowercases field names, applies
// header-hash whitespace rules, and sorts deterministically. Section 9.6
// signature input signs only DKIM2 protocol fields and uses its own all-WSP
// deletion rule. These transformations are
// intentionally distinct so later code cannot apply header hash rules to
// signature input or signature rules to header hashes.
//
// The package also owns fixed-length SHA-256 and SHA-512 Message-Instance
// digest containers while keeping signature-input SHA-256 separate. Hash
// calculation helpers build on immutable canonical byte and digest accessors,
// restrictive limits, domain-named options, and structured secret-safe
// diagnostics.
// It also provides the immutable Section 4 and Section 6.2 signed-header
// relevance classifier consumed through recipe's narrow interface, keeping the
// exclusion rules in one canonical owner without introducing a package cycle.
//
// Debug metadata is bounded by design. It may carry canonicalization kind,
// draft version, safe algorithm names, counts, lengths, and allowlisted
// excluded-header counters. It must not carry raw message bodies, raw header
// values, full DKIM2 fields, decoded envelope paths, recipients, nonces,
// signatures, private keys, tokens, or protected configuration values.
//
// Recipe parsing, application, and generation remain recipe-owned.
// Cryptographic verification, DNS lookup, policy, datasource behavior, daemon
// behavior, Milter integration, OpenAPI mapping, concrete logging, metrics,
// tracing, and public facade APIs remain outside this package.
package canonical
