# DNS Key Resolver

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

## Status

- Increment: DNS key resolution after the public current-verification facade.
- Protocol baseline: `draft-ietf-dkim-dkim2-spec-04` and
  `draft-chuang-dkim2-dns-04`.
- Architecture owner: `lib/internal/keyresolver`, with a public provider
  adapter in the root library package.
- Status: implemented; final unchanged-diff proof and milestone commit pending.
- Commit: the milestone commit containing this document.

## Purpose

This increment adds a bounded, injectable DNS TXT key resolver and strict
DKIM2 key-record parser as another implementation of the supported public key
provider boundary. Static and fake providers remain supported and authoritative
for deterministic tests. DNS integration does not change canonicalization, cryptographic
verification, four-state result mapping, SMTP-envelope behavior, or local MTA
policy.

The resolver constructs the DNS owner name from the parser-validated selector
and signing domain, retrieves TXT resource records through a narrow transport
interface, parses exactly one record according to DNS-04, validates public key
material for the requested signature algorithm, and returns the existing
closed `PublicKeyProvider` outcome. DNS, cache, and record details never become
a second protocol model or an unbounded diagnostic channel.

## Normative Sources And Precedence

The binding sources are, in order:

1. `draft-ietf-dkim-dkim2-spec-04` for current DKIM2 signature algorithms and
   the numeric `i=` sequence model.
2. `draft-chuang-dkim2-dns-04` for selectors, textual key records, and the DNS
   TXT binding.
3. RFC 1034 and RFC 1035 for DNS names and resource-record behavior.
4. RFC 6376 where DNS-04 incorporates DKIM key semantics.
5. RFC 8017 for DER-encoded PKCS#1 `RSAPublicKey`.
6. RFC 8463 for Ed25519 public-key representation.

Repository security policy resolves undefined or ambiguous states fail
closed. Later draft text requires a durable spec and vector update before
behavior changes.

### Recorded Draft Defects And Interpretations

DNS-04 contains inherited or contradictory text that cannot be implemented
literally together with the active DKIM2 signature draft:

- Section 3.4.1 labels the key-type tag `k=` and describes `k=rsa` and
  `k=ed25519`, but its `key-k-tag` ABNF begins with `%x76`, the byte for `v`.
  This implementation follows the unambiguous prose, tag heading, and inherited
  DKIM syntax and parses lowercase `k=` (`%x6b`). RFC 6376 Erratum 5137
  verifies this exact inherited correction; DNS-04 copied the uncorrected
  production. The mismatch remains tracked as a DNS-04 editorial defect.
- DNS-04 describes the lookup type as a signature `q=` input, but the active
  DKIM2 signature grammar has no `q=` tag. This increment implements the only
  binding defined by DNS-04, DNS TXT, and exposes no invented `q` option.
- DNS-04 inherits the `t=s` rule for an AUID-like `i=@domain`, while the active
  DKIM2 signature uses numeric `i=` for sequence position. The parser preserves
  a bounded `strict_identity` flag, but this increment cannot apply it and must
  not reject or accept a signature because of it. The unresolved conflict is
  surfaced as typed metadata for later draft reconciliation.
- The `t=y` testing flag is preserved as typed metadata. It does not rewrite a
  cryptographic result or create MTA action semantics. The policy increment
  consumes it when deciding how a testing-domain result is treated.
- DNS-04 says multiple TXT records make results undefined. The reference
  implementation resolves that ambiguity fail closed as an explicit
  `ambiguous` permanent key state. It never selects, cycles, or concatenates
  across resource records.

## Scope

### In Scope

- Strict selector and signing-domain validation for DNS owner construction.
- Absolute DNS TXT lookup through an injectable, context-aware transport.
- A deterministic fake TXT transport.
- Transport conformance for DNS-04 chunk concatenation within one resource
  record while preserving record boundaries.
- Strict DNS-04 tag-list parsing with bounded resource use.
- Parsing `v=`, `k=`, `p=`, retired tags, `t=` flags, and unknown tags.
- RSA and Ed25519 public-key decoding and validation.
- Distinct missing, revoked, invalid, ambiguous, unsupported, temporary,
  permanent, and provider-contract states.
- A typed, bounded metadata seam for testing and strict-identity flags.
- Positive and negative TTL cache policy with injected time and bounded size.
- Public `PublicKeyProvider` integration with the existing verifier.
- Unit, vector, property, fuzz, abuse, cache, concurrency, and documentation
  tests.

### Out Of Scope

- DNSSEC as a protocol or policy requirement.
- DNS-over-HTTPS, DNS-over-TLS, custom recursive servers, retries, or resolver
  configuration surfaces beyond an injected transport.
- Local accept, reject, quarantine, unsigned, or testing-mode action policy.
- `Authentication-Results` formatting.
- Signing, private keys, recipes, replay storage, datasource providers,
  daemon/OpenAPI, CLI, Milter, Exim, or concrete telemetry exporters.
- CNAME/DNAME policy beyond behavior already performed by the injected DNS
  transport.
- A public lookup-type registry or `q=` option.

## Package And Dependency Boundaries

`lib/internal/keyresolver` owns:

- DNS owner construction and validation.
- TXT answer and transport contracts.
- DNS-04 textual record parsing.
- Key decoding and requested-algorithm validation.
- Typed resolver outcomes and bounded metadata.
- Cache keys, entries, expiry, eviction, and single-flight coordination.

The root `dkim2` package owns:

- A public DNS TXT lookup contract or safe constructor adapter.
- Construction of a DNS-backed `PublicKeyProvider`.
- Mapping resolver outcomes into the existing closed public provider matrix.
- Public typed metadata only where later policy must consume it.

`lib/internal/verify` continues to own public-key validation and cryptographic
verification. The DNS resolver must reuse those rules or a single shared
domain-owned validator; it must not implement a second signature verifier.
`lib/internal/service` remains the only four-state result mapper.

Internal packages never import the root package. The standalone library gains
no daemon, OpenAPI, Cobra, Viper, Fx, Prometheus, exporter, LDAP, SQL, Valkey,
or MTA dependency. Standard-library DNS and crypto packages are permitted only
behind the declared interfaces.

## DNS Query Contract

### Inputs

The resolver input is an immutable query containing:

- Canonical signing domain.
- Canonical selector.
- Requested algorithm: RSA-SHA256 or Ed25519-SHA256.

The constructor clones any caller-owned byte storage. Query accessors expose
bounded strings already validated by the signature parser; the resolver still
defends its boundary against zero, unknown, oversized, or inconsistent values.

### Selector And Domain Validation

- Selector syntax is `sub-domain *( "." sub-domain )`; dots remain DNS label
  boundaries and are never flattened or escaped into one label.
- Domain and selector labels are ASCII DNS labels for this increment. Empty
  labels, leading or trailing hyphens, labels over 63 octets, empty selector
  components, controls, whitespace, NUL, path separators, and non-ASCII input
  are rejected before lookup.
- Canonical DNS comparison lowercases ASCII letters only. No IDNA mapping,
  Unicode normalization, or locale-sensitive transformation is invented.
- The canonical presentation owner is
  `<selector>._domainkey.<signing-domain>` without a terminal dot.
- The transport receives the corresponding absolute name with a terminal
  root dot. This prevents operating-system search suffixes from redirecting a
  relative query.
- The absolute wire/presentation name must satisfy DNS label limits and the
  repository limit for at most 253 octets excluding the terminal dot.
- Zero or unknown injected query enums and internally inconsistent query state
  perform zero transport calls and return provider-contract failure. Valid
  selector/domain components whose combined owner violates DNS length rules
  perform zero calls and return a typed permanent invalid-query result with nil
  Go error. Neither outcome echoes the input.

### TXT Transport

The transport interface is context-aware and intent-level. Its result retains
the exact TXT resource-record count. When exactly one record exists, it exposes
that record as the already-concatenated payload required by DNS-04. When more
than one record exists, it exposes only the count so ambiguity can be
classified before attacker-controlled payload traversal or cloning. Chunk
concatenation is a transport responsibility because standard resolver APIs do
not necessarily expose original character-string boundaries. The result also
carries bounded TTL provenance and optional non-normative DNSSEC diagnostic
state.

Conceptually:

```text
LookupTXT(ctx, absoluteName) -> TXTLookupResult or typed transport error
TXTLookupResult.Found -> exact RecordCount, unique TXTRecordPayload when count=1, plus PositiveTTL
TXTLookupResult.Absent -> NXDOMAIN or NODATA plus NegativeTTL
```

Found and absent forms are mutually exclusive. A zero or mixed form is a
transport-contract error. `PositiveTTL` is the minimum effective TTL for the
returned RRset. `NegativeTTL` is distinct authoritative negative-caching
provenance supplied by the transport. Missing or zero negative TTL disables
negative caching; M6 never synthesizes one.

Exact Go names may differ, but raw `net.DNSError`, resolver server names,
addresses, qnames, TXT bytes, and implementation-specific models must not
cross the keyresolver boundary.

Caller cancellation or deadline matching the outer caller `ctx.Err()` is
returned as caller control flow. When the keyresolver-owned child lookup
context reaches its configured deadline while the outer caller remains live,
`context.DeadlineExceeded` from that child is recognized as a typed temporary
provider failure. A transport-originated deadline while both outer and child
contexts remain live is temporary only through the closed typed transport
classification; an unclassified raw deadline is provider-contract failure.
Other temporary DNS failure, SERVFAIL, resource exhaustion, REFUSED, or
transport unavailability is typed temporary. NXDOMAIN and authenticated or ordinary NODATA are typed
missing-key results. Permanent transport errors are reserved for locally
proven stable input or policy failures in a closed typed class. Unknown raw
errors are provider-contract failures, never classified by string matching.

The fake transport records canonical absolute queries, has deterministic
answers/errors and call counts, respects context, and never uses network or
wall-clock time.

A standard-library `net.Resolver` adapter treats each returned string as one
already-concatenated TXT resource record. It checks the returned count before
payload traversal: a unique string becomes the unique payload, while two or
more strings retain only their exact count for ambiguity classification.
Because `LookupTXT` does not expose authoritative TTL data, that adapter
returns TTL zero and therefore does not populate the cache. TTL-aware injected
transports may enable caching.

## TXT Resource-Record Semantics

- Typed `Absent(NXDOMAIN)` or `Absent(NODATA)` is missing-key state. A `Found`
  result with zero record payloads is a transport-contract violation.
- Exactly one TXT resource record is required for parsing.
- More than one TXT resource record is ambiguous permanent state, regardless
  of whether records are byte-identical or only one appears usable.
- The transport concatenates ordered character-string chunks within one record
  byte-for-byte with no inserted whitespace before returning the payload.
- Resource-record boundaries are never concatenated. A multi-record answer
  retains its count, not fabricated or partially copied payloads.
- An empty record is not a missing answer; it is malformed because required
  `p=` is absent.
- Record-payload byte limits apply before parsing. More than one payload is
  classified ambiguous from its count without traversing or cloning records.
  A transport adapter is responsible for bounding raw DNS decoding before it
  constructs the answer. Limit failures make no partial record usable.

## DNS-04 Key-Record Parser

### Lexical Rules

- The input is the concatenated bytes of one TXT resource record.
- The parser consumes `tagvalue.Scan` in an exact, case-sensitive DNS-record
  mode for DNS-04 Section 3.2 syntax, duplicate detection, and FWS handling.
  `lib/internal/tagvalue` remains the single generic scanner owner; any needed
  DNS lexical option is added there with cross-package contract tests rather
  than forking a scanner in `keyresolver`.
- Tag names are case-sensitive and the defined tags are lowercase. `V=`,
  `K=`, and `P=` are unknown tags, not aliases.
- Values are case-sensitive unless a tag explicitly defines otherwise.
- A semicolon separates tags; an optional trailing semicolon is accepted.
- A duplicate tag name invalidates the entire record, including duplicate
  retired or unknown names.
- Unknown tags are syntactically validated and ignored. Their names and values
  are not retained or exposed.
- Empty and omitted values remain distinct.
- Controls, bare CR/LF, invalid folding, invalid tag names, invalid delimiters,
  and over-limit input are rejected.
- Parsing is deterministic, linear in bounded input size, non-panicking, and
  free of unbounded recursion or error text.

### Defined Tags

`v=`:

- Optional; omission means `DKIM1`.
- When present, it must be the first tag and exactly `DKIM1`.
- Any other value or a non-first `v=` makes the record unusable/malformed.

`k=`:

- Optional; omission means `rsa`.
- `rsa` and `ed25519` are recognized case-sensitive values.
- An unrecognized key type is a typed unsupported-key record. It is not
  silently reinterpreted as RSA, and its `p=` bytes are never passed to a
  decoder.

`p=`:

- Required.
- Empty `p=` is a distinct revoked-key permanent state.
- Non-empty `p=` uses a DNS-specific optional-padding path beside the existing
  strict `tagvalue.ParseBase64String`, after scanner-owned FWS unfolding and
  permitted WSP removal. DNS-04 inherits optional trailing `=` padding;
  unpadded and padded standard-alphabet forms are accepted only with canonical
  zero pad bits. The strict Message-Instance/DKIM2-Signature parser behavior is
  unchanged.
- Decoded length is checked before key decoding and copying.
- Even for an unsupported but syntactically valid `k=`, non-empty `p=` must
  satisfy Base64 syntax, pad-bit, and decoded-size limits before the decoded
  bytes are discarded and the record becomes typed unsupported.

`h=`, `n=`, and `s=`:

- Retired in DNS-04 and ignored after generic tag-list lexical validation only.
  Their inherited tag-specific ABNF and semantics are not enforced; empty or
  otherwise unusual values are accepted when the generic `tag-value` grammar
  accepts them.
- They do not constrain hashes, service type, or policy.
- Their presence and values are not retained or exposed.

`t=`:

- Optional colon-separated flags.
- Recognized `y` becomes `testing=true` metadata.
- Recognized `s` becomes `strict_identity=true` plus an explicit
  `strict_identity_applicable=false` state under the recorded draft conflict.
- Duplicate recognized or unknown flag values are accepted idempotently; the
  draft prohibits duplicate tag names but does not prohibit repeated members
  inside the colon-separated `t=` value.
- Unknown syntactically valid flags are ignored and are never exposed.
- Empty or malformed flag elements invalidate the record.

### Parsed Record Ownership

The parsed record is immutable and contains only:

- Declared or default key type.
- Detached typed public key material after successful decode.
- Revocation or unsupported state when no key is usable.
- Bounded booleans for testing and strict-identity declarations.
- Exact draft identifier for vectors/evidence where useful.

It never retains raw TXT, unknown tags/flags, notes, selector, qname, provider
error, Base64 text, or private material.

## Public-Key Decoding And Validation

### RSA

- `k=rsa` or omitted `k` requires `p=` to decode to one DER PKCS#1
  `RSAPublicKey`, not SubjectPublicKeyInfo, a certificate, or a private key.
- DER parsing consumes the entire value and rejects trailing bytes,
  non-minimal encodings, negative integers, zero/even/invalid exponents, nil
  or even modulus, and malformed ASN.1. A narrow verify-owned structural
  predicate is reused by DNS decoding, cache/outcome validation, and
  `verify.validateRSAPublicKey`, so providers reject impossible RSA material
  without duplicating modulus/exponent rules.
- The existing RSA minimum-size and exponent policy is authoritative and must
  not be weakened by DNS lookup. Minimum-bit policy remains verifier-bound and
  is not applied by the DNS provider.
- Returned `*rsa.PublicKey` values deep-clone the modulus.

### Ed25519

- `k=ed25519` requires `p=` to decode to exactly 32 raw public-key bytes as
  specified by RFC 8463.
- DER, PEM, SubjectPublicKeyInfo, 64-byte private keys, signatures, and every
  other wrong-length or wrapped representation are rejected. A raw Ed25519
  public key and a raw private seed are both indistinguishable 32-byte strings;
  RFC 8463 supplies no provenance marker. Therefore every exact raw 32-byte
  value is structurally accepted and later treated only as public-key material;
  the resolver must not claim it can identify a seed from bytes alone.
- Returned `ed25519.PublicKey` values clone the byte slice while preserving
  the named type.

### Algorithm Coherence

- RSA-SHA256 queries accept only RSA records.
- Ed25519-SHA256 queries accept only Ed25519 records.
- A supported requested algorithm with a different supported key type is a
  distinct permanent algorithm-mismatch/key-invalid state.
- Unknown requested algorithms are rejected before DNS lookup.
- Unknown key types are typed unsupported records and never become PASS,
  missing, or temporary state.

## Resolver Outcome And Metadata Model

The internal outcome vocabulary distinguishes at least:

- `found`
- `missing`
- `revoked`
- `invalid`
- `ambiguous`
- `unsupported_key_type`
- `algorithm_mismatch`
- `temporary`
- `permanent`
- `provider_contract`

Every zero or unknown internal enum fails closed. Revoked, unsupported, and
algorithm-mismatch states remain distinct through the exact public and service
mapping declared below; none is collapsed to generic invalid state. The
one-to-one seam retains enough typed detail for policy, diagnostics, tests,
and future API evolution without exposing message- or DNS-derived values.

Metadata contains bounded values only:

- `testing_declared`
- `strict_identity_declared`
- `strict_identity_applicable` (false for the active drafts)
- optional DNSSEC diagnostic state from a closed non-normative vocabulary
- cache result from a closed vocabulary when exposed internally

M6 propagates recognized metadata through DNS record, provider/key metadata,
and verification facts without re-querying DNS. It does not create a new
top-level verification state or local action. Unknown flags and DNS details
never escape.

## Integration With Public Verification

The DNS-backed provider satisfies the existing `PublicKeyProvider` contract.
It is constructed with a TXT transport, cache policy, clock, and limits. A
safe convenience constructor may adapt `net.Resolver`, but tests and core
logic use the interface.

Mapping is closed:

- Found, validated material -> existing found RSA or Ed25519 result.
- NXDOMAIN/NODATA -> missing result.
- Revoked, malformed, unsupported key type, algorithm mismatch -> typed
  permanent non-success with bounded reason/detail.
- Multiple records -> ambiguous result.
- Temporary DNS state -> typed temporary provider error.
- Caller context -> zero result plus caller Go error.
- Unknown transport/parser/cache combination -> provider-contract failure.

M6 extends the closed public provider vocabulary with
`PublicKeyStatusRevoked`, `PublicKeyStatusUnsupportedKeyType`, and
`PublicKeyStatusAlgorithmMismatch`. `InvalidPublicKey` remains the outcome for
malformed records or malformed supported key material. Matching constructors
accept no material. The provider bridge adds matching internal key statuses;
the service/public reason vocabulary adds `revoked_key`,
`unsupported_key_type`, and `key_algorithm_mismatch`. All three are
PERMERROR-class facts, and zero/unknown combinations remain
`internal_contract`. This is the single binding mapping; DNS code does not
invent a parallel result vocabulary.

`PublicKeyResult` also carries an immutable closed `KeyPolicyMetadata` value
with `TestingDeclared`, `StrictIdentityDeclared`, and
`StrictIdentityApplicable` accessors. The provider bridge and internal
signature-set result propagate it one-to-one into the public
`SignatureSetFact`. Static providers produce zero/false metadata. Cache hit or
miss is intentionally not part of a protocol result because it would make
otherwise identical verification output depend on operational history.
DNSSEC state likewise remains resolver/observation metadata and is not copied
into `SignatureSetFact`; a future diagnostic surface may expose its bounded
class without changing protocol facts.

The existing provider bridge, static verification, and service mapper remain
authoritative. No DNS code parses DKIM2 message headers, selects targets,
canonicalizes, hashes, verifies signatures, or maps four-state results.

If the existing public provider/result vocabulary cannot carry a required
typed state or metadata, it is extended narrowly with closed enums and
one-to-one adapters. Contract-defense tests cover every legal and illegal
combination. Raw causes are never wrapped.

## Cache Policy

Caching is an optimization and must not change classification.

- The cache is optional and owned by the DNS provider/resolver, not by
  protocol packages or global state.
- Cache keys are canonical `(absolute owner, requested algorithm)` values held
  internally and never logged or returned.
- Positive found results and stable negative states may be cached only within
  the DNS TTL and configured maximum TTL.
- Missing NXDOMAIN/NODATA may use only the distinct authoritative negative TTL
  supplied by the transport and clamped to the configured cap. Missing or zero
  provenance means no negative cache entry; M6 invents no lifetime.
- Revoked, malformed, ambiguous, unsupported, and mismatch states may be
  cached no longer than the answer TTL and their configured conservative cap.
- Temporary errors, caller cancellation, provider-contract errors, and zero
  TTL answers are not cached.
- TTL values at or below zero are not cached. Overflow, absurd TTL, or missing
  expiry data also disables caching rather than synthesizing or extending
  trust.
- An injected clock controls expiry; production code does not call wall-clock
  time through hidden global state.
- Cache capacity is mandatory and bounded. Eviction is deterministic LRU:
  successful access updates recency; insertion at capacity removes the least
  recently used entry; a monotonic insertion sequence breaks equal-clock
  ties. Sequence overflow renormalizes ordering under the cache lock while
  preserving relative recency. No unbounded qname or key storage is permitted.
- Concurrent misses for the same key may be coalesced, but each waiting caller
  retains its own context cancellation. One canceled waiter must not cancel a
  lookup still required by live waiters.
- A global non-blocking semaphore bounds transport calls. The first lookup
  beyond the configured concurrency limit returns typed temporary saturation;
  no unbounded queue is created. Each coalesced key admits only the configured
  waiter count; the next waiter also receives typed temporary saturation.
- A coalesced transport context derives from an instance-owned parent and the
  configured lookup timeout, not from the first caller. A canceled non-final
  waiter leaves immediately without canceling work needed by live peers. The
  final canceled waiter removes its liveness, cancels the transport context,
  and remains the cleanup owner until the worker retires; completion cancels
  the context and wakes all remaining live waiters once.
- One coordination worker owns each active coalesced flight so non-final
  callers can leave independently without orphaning transport work. A
  compliant transport must return promptly when its context is canceled; then
  the final caller, worker, and semaphore slot are released. If an injected
  transport deliberately ignores cancellation, the final caller remains
  blocked with that one bounded flight worker and semaphore slot until the
  transport returns. M6 spawns no additional cancellation/helper goroutine to
  mask the defect, creates no unbounded workers or queue, and does not claim it
  can forcibly stop non-compliant Go code.
- Stored keys and metadata are deep-cloned on insertion and retrieval.
- Cache hits repeat algorithm and key validation or use an immutable validated
  entry; corrupted/unknown entries fail as internal/provider contract.

## DNSSEC

DNSSEC validation is not a DKIM2 conformance input under the active drafts.
An injected transport may attach `secure`, `insecure`, `bogus`, `indeterminate`,
or `unavailable` as bounded non-authoritative metadata. Per the resolved
architecture decision, these diagnostics do not change default verification
state, provider classification, key acceptance, cache TTL, or policy. A
validating transport may independently withhold an answer and return an
ordinary typed availability error, but keyresolver never infers failure from
the DNSSEC diagnostic value or creates a DNSSEC-specific error mapping. Raw
validation chains and resolver diagnostics are forbidden.

## Limits

Defaults and hard maxima are declared in one limits type and may be narrowed,
never widened:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Selector bytes, excluding separators outside the selector | 253 | 253 |
| Selector labels | 127 | 127 |
| Signing-domain bytes | 253 | 253 |
| Signing-domain labels | 127 | 127 |
| Canonical owner bytes, excluding terminal root dot | 253 | 253 |
| Usable TXT records | 1 | 1 |
| Concatenated TXT record bytes | 8 KiB | 64 KiB |
| Tags per record | 32 | 128 |
| Tag-name bytes | 63 | 63 |
| Tag-value bytes | 8 KiB | 64 KiB |
| Decoded public-key bytes | 8 KiB | 64 KiB |
| Cache entries | 1,024 | 65,536 |
| Positive TTL cap | 1 hour | 24 hours |
| Negative TTL cap | 5 minutes | 1 hour |
| Stable error-state TTL cap | 1 minute | 5 minutes |
| Concurrent transport lookups | 64 | 1,024 |
| Coalesced waiters per cache key | 64 | 1,024 |
| Per-lookup timeout | 5 seconds | 30 seconds |

DNS label length remains the protocol maximum of 63 octets independently of
these aggregate limits. A caller may disable caching by configuring zero cache entries; other
zero or negative limits are invalid. TTL caps may be narrowed to zero to make
the corresponding class immediately expire, but may not be widened.
The lookup timeout must be positive and may be narrowed, never disabled or
widened.

Exact-boundary and one-over tests are required at construction, pre-transport,
answer traversal, concatenation, parsing, Base64 decode, key decode, cache
insert, and result mapping seams. Pre-transport failures make zero calls.

## Error And Privacy Contract

All errors and outcomes use closed typed codes. Classification never inspects
error strings. Public errors/results, logs, tests, examples, fuzz diagnostics,
and completion evidence must not contain:

- DNS owner names or qnames.
- Signing domains or selectors.
- TXT records, chunks, unknown tags, notes, or flags.
- Base64 values or decoded public-key bytes.
- Resolver addresses, server names, network errors, or cache keys.
- Raw message or SMTP-envelope values.
- Tokens, credentials, private keys, or protected configuration.

Diagnostics may expose only bounded provider class, key state, requested
algorithm family, cache-result class, DNSSEC diagnostic class, duration, and
stable reason code. Metrics labels follow the existing low-cardinality policy.

## Concurrency And Cancellation

- Resolver/provider/cache instances are safe for concurrent reuse.
- Caller-owned queries, record payloads, keys, and metadata are cloned at
  ownership boundaries.
- Caller cancellation before or during lookup returns caller control flow and
  no structured result.
- Outer caller context error is caller control flow; the resolver-owned child
  lookup deadline is typed temporary while the outer caller is live; a
  transport-originated deadline while both contexts remain live is temporary
  only when explicitly typed, otherwise provider-contract.
- Cache locks are never held across transport calls or expensive parsing.
- No goroutine remains after caller cancellation, a compliant blocking
  transport observes cancellation, or a coalesced lookup completes. A
  deliberately non-compliant injected transport may retain its single bounded
  flight worker, final caller, and semaphore slot until it is explicitly
  released; tests must release it before expecting the final caller to return,
  keep an idempotent teardown release, and must not describe that state as
  cancellable.

## Required Tests

### Owner And Transport

- Exact owner construction for simple and dotted selectors.
- ASCII case canonicalization and absolute terminal dot.
- Every invalid label/name/length boundary with zero transport calls.
- Transport conformance proves one RR's chunks are concatenated without
  whitespace and record boundaries remain distinct; keyresolver consumes only
  the declared concatenated payload representation.
- Typed absent, illegal found-with-zero, one-record, and multiple-record
  outcomes.
- Caller cancel/deadline versus temporary/permanent/raw transport errors.
- Outer-caller deadline, resolver-owned child deadline, and live-context
  transport-originated deadline are tested as three disjoint classes.
- Found/absent/zero/mixed transport-result forms and distinct positive/negative
  TTL provenance; every DNSSEC diagnostic value remains verdict-neutral.
- Fake transport determinism, copying, call counts, and context behavior.

### Record Parser

- `v=DKIM1` first, omitted default, wrong case/value, and non-first `v`.
- Omitted/default RSA and explicit RSA.
- Explicit Ed25519.
- Required/empty/non-empty `p` and distinct revocation.
- Duplicate defined, retired, and unknown tags.
- Unknown tags ignored after syntax validation.
- Retired `h/n/s` ignored.
- `t=y`, `t=s`, combined/unknown/empty/malformed flags.
- Valid FWS and every bare/invalid line-ending form.
- Strict Base64 alphabet, whitespace, optional DNS padding, canonical pad bits,
  decoded-size limits, and trailing data; existing signature/header Base64
  remains strict-padded.
- The recorded `k=` ABNF interpretation.

### Key Validation

- Valid RSA PKCS#1 DER and Ed25519 raw public keys.
- RSA SPKI/certificate/private-key/trailing/weak/exponent/even-modulus
  negatives, including a shared-validator reproducer used by static and DNS
  providers.
- Ed25519 wrong lengths, DER/SPKI/64-byte-private-key negatives, plus an
  explicit proof that arbitrary raw 32-byte values are structurally accepted
  without an impossible public-key-versus-seed provenance claim.
- Requested-algorithm mismatch and unknown key type.
- Deep-copy and concurrent-mutation tests.

### Cache

- Hit/miss, exact expiry, one tick after expiry, zero/negative/overflow TTL.
- Positive, missing, revoked, malformed, ambiguous, and temporary policy.
- Capacity and deterministic eviction.
- Algorithm-separated keys.
- Concurrent reuse, miss coalescing, independent waiter cancellation, and no
  goroutine leak.
- Exact/one-over global lookup and per-key waiter saturation with immediate
  typed temporary results and no hidden queue.
- LRU hit promotion, deterministic equal-clock tie-breaking, and insertion
  sequence renormalization.
- Mutation isolation for stored and returned RSA/Ed25519 keys and metadata.

### Public Integration

- End-to-end public PASS using fake DNS for RSA and Ed25519 vectors.
- NXDOMAIN/NODATA missing, revoked, malformed, ambiguous, mismatch, temporary,
  and provider-contract mapping.
- Testing/strict metadata propagation without top-level result alteration.
- Exact result/error disjointness and M5 precedence.
- No duplicate parser, crypto, canonicalization, or four-state mapper.
- Toxic-marker checks for every forbidden input and raw error channel.

### Fuzz And Abuse

- Fuzz owner construction with bounded selector/domain bytes.
- Fuzz DNS-04 key-record parsing with valid seeds, duplicates, FWS, unknowns,
  empty p, high counts, malformed Base64, RSA DER, and Ed25519 length cases.
- Fuzz found/absent TXT result traversal and record payload bounds.
- Fuzz properties: no panic, deterministic typed class, bounded allocation,
  no input mutation, closed enums, and no raw-input leakage.
- Abuse cases for record/tag/key/cache/in-flight limits and slow or
  adversarial transports.

## Public Documentation

Package documentation and runnable synthetic examples must explain:

- How to inject a TXT transport and construct the DNS-backed provider.
- That DNS owner names are derived from signed selector/domain values and are
  sensitive diagnostics.
- TXT uniqueness, chunk concatenation, revocation, key encodings, and typed
  error classification.
- Cache TTL/capacity and cancellation behavior.
- That DNSSEC is diagnostic only.
- That testing/strict flags are metadata and do not themselves change the
  current cryptographic result in this increment.

Examples use reserved domains, frozen synthetic keys, injected fake transport
and clock, and print only bounded states/counts.

## Implementation Slices

The prompt pack should decompose implementation into sequential reviewed
slices:

1. Public/internal contracts, limits, owner construction, and fake transport.
2. Strict DNS-04 tag-list and metadata parser.
3. RSA/Ed25519 key decoding, revocation, and algorithm coherence.
4. Resolver orchestration and closed provider integration.
5. Bounded TTL cache, concurrency, and cancellation.
6. Public golden vectors and M5 verifier integration.
7. Abuse, fuzz, privacy, immutability, and race proof.
8. Documentation, examples, and final proof/evidence.

Every slice has live conformance oversight, independent review, focused tests,
and no staging or commit. One reviewed commit is created only after all slices
and final guardrails converge.

## Required Gates

Use root Make targets and focused library tests. Before the commit:

```text
go test ./lib/internal/keyresolver/...
go test ./lib/...
go test -race ./lib/...
go vet ./lib/...
make test
make vet
make lint
make race
make guardrails
git diff --check
git diff --cached --name-only
```

Enumerate and run every new fuzz target separately for a bounded smoke period.
The external vulnerability scan follows the repository's approved execution
policy and must never be reported successful when platform policy prevents it.

## Review Requirements

Independent draft/mail and security/architecture reviewers inspect the full
diff and surrounding owners. Findings require focused reproducers and root
cause fixes, followed by re-review. Review includes:

- DNS-04 and RFC fidelity, including every recorded draft conflict.
- Closed parser/key/error/cache matrices including zero and unknown enums.
- One-way package graph and single-owner rules.
- Fixed-memory bounds, cancellation, cloning, concurrency, and privacy.
- Public-provider and four-state mapping coherence.
- Test quality, generated/cmd scope, documentation, and final evidence.

Post-review gates that mutate tracked files invalidate approval. The final
unchanged diff is rehashed and re-approved before staging.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 2 to 5 hours |
| Highest-risk area | DNS-04 ambiguity, key decoding, cache concurrency, and provider-state fidelity |
| Expected prompt count | 8 sequential prompts |
| Required final gate | `make guardrails` |

The retained prompt ledger records 3h11m08s of measured wall-clock execution
across Prompts 01-08. Active engineering and blocked time were not separately
measured for Prompts 01-07 and are not reconstructed. Prompt 08 includes 40s
of separately measured reviewer-only waiting; other waiting was not separately
tracked.

## Completion Evidence

- Focused owner/parser/key/resolver/cache tests: passed, including normal and
  race runs for DNS optional padding, record parsing, unsupported-key ordering,
  structural RSA decoding, and the public provider.
- Public DNS-backed vectors: passed through the library test suite for RSA and
  Ed25519 plus exact fail-closed mappings.
- Fuzz smoke: `FuzzOwnerConstruction`, `FuzzDNSKeyRecord`,
  `FuzzTXTLookupTraversal`, `FuzzKeyDecodingCoherence`,
  `FuzzDNSPublicProvider`, and `FuzzDNSPublicVerifier` each passed an isolated
  campaign of at least ten seconds after the final production fixes.
- Full library and repository gates: `make test vet lint race` passed;
  `make guardrails` passed with formatting, vet, lint, tests, race tests, and
  `govulncheck` reporting no vulnerabilities in all four modules.
- Independent reviews: the live normative reviewer plus fresh security and
  draft/mail reviews approved the post-fix implementation with no unresolved
  content finding; unchanged-diff approval is required before staging.
- Normative source check: the official DNS-04 and active DKIM2 signature drafts
  were checked directly on 2026-07-11, together with RFC 6376 Erratum 5137 and
  the referenced RFC key/security requirements.
- Scope and generated-artifact checks: no OpenAPI or generated REST artifact
  changed; ignored `temp/` prompt artifacts remain unstaged.
- `git diff --check`: passed.
- Staging: pending.
- Commit: pending.

## Acceptance

- DNS-04 owner names, TXT boundaries, parser behavior, key encodings, and
  metadata match the active draft and recorded interpretations.
- Multiple records, malformed/revoked/unsupported/mismatch states fail closed
  with distinct internal typed outcomes.
- The resolver is injectable, context-aware, bounded, deterministic,
  concurrent-safe, immutable, and secret-safe.
- Cache policy cannot extend TTL, change classification, leak keys, or turn
  temporary/contract state into success.
- RSA and Ed25519 keys reuse the existing validation and crypto boundary.
- The DNS provider satisfies the existing public provider and result/error
  contracts without a second verifier or result mapper.
- Testing and strict-identity flags survive as bounded metadata without
  invented current-result or action semantics.
- DNSSEC remains non-normative diagnostic metadata.
- Unit, vector, negative, abuse, fuzz, race, and documentation tests pass.
- No later-scope policy, recipe, signing, datasource, replay, daemon,
  OpenAPI, adapter, CLI, or exporter behavior is added.
- Independent reviews have no unresolved finding.
- Guardrails converge, ignored prompt artifacts are unstaged, and one
  project-format commit records the increment.

## Decisions And Open Questions

- Settled: DNS TXT is the only lookup binding exposed in this increment.
- Settled: multiple TXT records are a typed ambiguous permanent state.
- Settled: `k=` follows DNS-04 prose despite the `%x76` ABNF defect.
- Settled: `q=` is not invented for the active DKIM2 signature grammar.
- Settled: `t=y` and `t=s` are bounded metadata; local action waits for policy.
- Settled: DNSSEC cannot alter conformance results.
- Settled: transport calls use absolute names.
- Open: the draft working group must reconcile `t=s` with numeric signature
  sequence `i=`.
- Open: later draft text may define DNSSEC or additional lookup bindings.
