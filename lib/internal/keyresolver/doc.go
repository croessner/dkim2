// Package keyresolver owns bounded DNS-04 query, TXT transport, key-record,
// decoding, cache, and coalesced-flight semantics.
//
// Queries validate ASCII selectors and signing domains, preserve dotted
// selector label boundaries, and construct lowercase absolute
// <selector>._domainkey.<domain>. owners. Input is rejected before transport
// when a component, aggregate owner, algorithm, or limit is invalid. Owners,
// selectors, domains, records, keys, cache keys, and raw provider errors never
// enter diagnostics.
//
// TXTTransport preserves resource-record count and supplies an already-
// concatenated payload only for one RR. Character-string chunks within that RR
// are concatenated by the transport without inserted whitespace. Multiple RRs
// are permanent ambiguity and retain only their count; they are never traversed
// or joined. Authoritative NXDOMAIN and NODATA carry distinct negative TTL
// provenance. DNSSECStatus is a closed diagnostic value with no verdict or TTL
// effect.
//
// ParseRecord implements draft-chuang-dkim2-dns-04 using the shared tagvalue
// scanner. Lowercase k= is recognized according to the draft prose and RFC 6376
// Erratum 5137 despite the inherited ABNF typo. DNS TXT is the sole lookup
// binding because the active signature grammar has no q=. Unknown and retired
// tags are ignored after generic validation, duplicate tags fail closed, empty
// p= is revoked, and t=y/t=s become bounded metadata. Non-empty p= permits
// omitted terminal Base64 padding as DNS-04 specifies, but canonical zero pad
// bits remain mandatory. Strict identity remains inapplicable while DKIM2 i=
// is numeric.
//
// DecodeKey accepts only PKCS#1 RSAPublicKey DER or exactly 32 raw Ed25519
// public-key bytes and keeps requested-algorithm mismatch distinct. Resolver
// outcomes form a closed found, missing, revoked, invalid, ambiguous,
// unsupported-key-type, algorithm-mismatch, temporary, permanent, and contract
// matrix. All material and result accessors return detached copies.
//
// Resolver caches only TTL-backed stable outcomes under configured caps. Cache
// keys include absolute owner and requested algorithm; deterministic LRU,
// bounded concurrency, and bounded same-key waiters prevent hidden queues.
// Non-final canceled waiters leave independently. The final canceled waiter
// cancels and owns cleanup until the context-compliant transport worker retires;
// the resolver creates no cancellation helper for a transport that ignores its
// context.
package keyresolver
