// Package keyresolver owns bounded DNS-03 query, TXT transport, key-record,
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
// ParseRecord implements draft-ietf-dkim-dkim2-dns-03 using the shared tagvalue
// scanner. Lowercase k= is recognized as the DNS-03 Section 4.2 grammar and
// RFC 6376 Erratum 5137 require. DNS TXT is the sole lookup binding because
// the active signature grammar has no q=. Unknown and deprecated tags are
// ignored after generic validation, duplicate tags fail closed, and empty p=
// is revoked. DNS-03 Section 4 deprecates h=, n=, s=, and t= and DKIM2 ignores
// them: t= is subject only to the generic tag-list rules and never yields
// testing or strict-identity semantics. Non-empty p= must carry the terminal
// Base64 padding and canonical zero pad bits that DNS-03 Section 2.3
// requires; omitted padding is a malformed record.
//
// DecodeKey accepts PKCS#1 RSAPublicKey DER and X.509 SubjectPublicKeyInfo DER
// containing RSA, or exactly 32 raw Ed25519 public-key bytes, and keeps
// requested-algorithm mismatch distinct. Resolver
// outcomes form a closed found, missing, revoked, invalid, ambiguous,
// unsupported-key-type, algorithm-mismatch, temporary, permanent, and contract
// matrix. All material and result accessors return detached copies.
//
// ResolveDomainPolicy resolves the Draft-09 Section 3.8 Domain Policy Record
// at _domainkey.<domain>. through the same transport, cache, single-flight, and
// limits. The owner kind is typed once (OwnerKind): selector and policy owners
// have disjoint grammars and therefore disjoint cache key spaces. Records not
// beginning with v=DKIM1 are ignored, more than one remaining record is
// ambiguous, an invalid record or a permanent failure is invalid, absence is
// authorized, and a temporary failure is temporary and never cached.
//
// Resolver caches only TTL-backed stable outcomes under configured caps. Cache
// keys include absolute owner and requested algorithm; deterministic LRU,
// bounded concurrency, and bounded same-key waiters prevent hidden queues.
// Non-final canceled waiters leave independently. The final canceled waiter
// cancels and owns cleanup until the context-compliant transport worker retires;
// the resolver creates no cancellation helper for a transport that ignores its
// context.
package keyresolver
