# MVP Core Verification

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-06 authority is the migration disposition
> and current durable architecture.

Status: completed under an explicit maintainer exception for the external
vulnerability database check.

This spec defines Milestone M5, the first public library-only verification
vertical slice for the DKIM2 reference implementation. It coordinates the
completed raw-message, tag-parser, canonicalization, hash, and static-key
verification foundations into one stable request/result boundary without
introducing DNS, recipes, daemon behavior, adapters, datasource providers, or
local action policy.

M5 verifies the current message state only: the highest numbered
`DKIM2-Signature` and its associated highest current `Message-Instance`. A
successful M5 result must not imply that historical instances were
reconstructed or that the complete custody chain was cryptographically
verified.

## Source Documents

This spec is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`, especially Sections 3.1 through 3.6, 5.1 through
  5.11, 6, 10, 12, 13, 14, 15, 16, 17, and 19
- `docs/specs/spec-and-prompt-template.md`
- `docs/specs/implementation/raw-message-model.md`
- `docs/specs/implementation/dkim2-tag-parsers.md`
- `docs/specs/implementation/canonicalization-and-hashes.md`
- `docs/specs/implementation/static-key-signature-verification.md`
- `lib/internal/rawmsg`
- `lib/internal/tagvalue`
- `lib/internal/instance`
- `lib/internal/signature`
- `lib/internal/canonical`
- `lib/internal/verify`
- `lib/internal/service`
- `lib/doc.go`
- `Makefile`
- `.gitignore`
- `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05, especially Sections 3,
  4, 6, 7, 8, 9.2 through 9.6, 10, and 11
- `draft-chuang-dkim2-dns-04`, dated 2026-03-18, only for algorithm and future
  key-provider context; M5 performs no DNS parsing or lookup
- RFC 5321 for SMTP envelope evidence
- RFC 5322 and RFC 6532 for message bytes and internationalized header input
- RFC 8017 for RSA PKCS#1 v1.5 verification
- RFC 8032 for Ed25519 verification
- RFC 8601 only for the four compatible result-state names; M5 does not emit
  an `Authentication-Results` field

If this spec conflicts with a source document, implementation must stop until
the durable contract is reconciled. A later DKIM2 draft must not change M5
behavior without updating this spec and draft-versioned vectors first.

## Original Gap

M1 through M4 provide independently tested internal protocol components:

- `rawmsg` parses and owns immutable RFC 5322 bytes.
- `instance` and `signature` parse draft-04 protocol fields and validate
  contiguous numbering.
- `canonical` produces draft-04 body, header, and signature inputs from the
  authoritative raw header block.
- `verify` validates current hashes, static-key signatures, timestamps,
  current SMTP envelope evidence, `d=` alignment, and `nd=` links with typed,
  bounded facts.

The root library package is still documentation-only, and
`lib/internal/service` is still a package stub. A library consumer cannot make
one supported verification call without importing internal packages or
reimplementing result mapping. There is no public draft result type, no public
scope declaration, no stable mapping from internal facts to the four draft
states, and no end-to-end golden vector that enters through public raw-message
and envelope bytes.

Leaving coordination to consumers would duplicate protocol rules and create
several security risks:

- Internal `mixed`, `unsupported`, or `indeterminate` detail could escape as
  invented fifth top-level states.
- Unknown algorithms could be treated as failures even when a supported
  signature passes, contrary to draft-04 Section 3.4.
- A current-only PASS could be misreported as historical content/recipe or
  historical cryptographic verification.
- Missing, invalid, ambiguous, or provider-failed static keys could be mapped
  inconsistently.
- Raw messages, envelope paths, recipients, selectors, signatures, or key
  material could leak through public errors or result strings.

## Goal

Implement one cohesive public verification facade that:

- Accepts raw RFC 5322 bytes and explicit current SMTP envelope paths.
- Uses injected static key-provider behavior through a public library seam
  that does not expose internal package types.
- Coordinates only existing M1 through M4 owners; it does not duplicate raw
  parsing, tag parsing, canonicalization, cryptography, envelope matching, or
  sequence validation.
- Verifies the highest/current `DKIM2-Signature` and associated current
  `Message-Instance` by default.
- Emits exactly `PASS`, `FAIL`, `PERMERROR`, or `TEMPERROR` as the public
  draft result state.
- Preserves bounded typed reason and check facts without forcing callers to
  parse human-readable strings.
- Declares verification scope `current`, historical content/recipe and
  historical cryptography `not_evaluated`, and separately reports whether
  structural `nd=` links were evaluated.
- Remains deterministic through an injected clock and static keys.
- Fails closed on malformed, missing, ambiguous, unsupported, or
  out-of-band-only state.
- Keeps all public results, errors, fixtures, and test output free of raw
  message, envelope, recipient, selector, signature, nonce, and key material.

## Delivery Shape

The implementation is split into six focused slices and one final proof slice.

1. Public request, result, scope, and error contract:
   Add root-package request/result types, the four draft states, verification
   scope, separate historical content/recipe and historical cryptographic
   states, custody-structure coverage, bounded reason codes, immutable
   accessors, limits, and constructor options. Define the static key seam
   without exposing `lib/internal/verify` types.
2. Service coordinator and result mapping:
   Add a cohesive internal service object with internal-only request, result,
   config, and four-state DTOs. It calls the internal verifier and maps all
   internal target/check/key facts into one authoritative internal four-state
   result. It must never import the root `dkim2` package.
3. Public facade and static-key bridge:
   Implement the root verification entry point, one-to-one public/internal
   service DTO adapters, and a safe bridge from public key queries/results into
   the internal M4 provider. Enforce constructor, context, request, envelope,
   key-cloning, and limit invariants without creating an import cycle.
4. Draft-versioned public golden vectors:
   Add deterministic RSA and Ed25519 current-verification vectors through the
   public API, plus negative state-mapping vectors and explicit current-scope
   assertions.
5. Abuse, fuzz, immutability, and diagnostic tests:
   Add malformed input, limit, context, provider, unknown-algorithm,
   multi-signature, terminal-`nd=`, secret-marker, accessor immutability, and
   public-entry fuzz coverage.
6. Documentation and public examples:
   Update library package documentation and add synthetic library examples
   that demonstrate construction and structured result inspection without
   printing protected values.
7. Final proof and closeout:
   Reconcile every acceptance criterion, update measured effort, run focused
   fuzz targets and `make guardrails`, perform an independent draft/security
   review, and record final evidence.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 2 to 5 hours |
| Highest-risk area | public result mapping, current-scope truthfulness, and secret-safe API boundaries |
| Expected prompt count | 6 implementation prompts plus 1 final closeout prompt |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: no network calls, DNS parsing, recipe reconstruction, generated
  OpenAPI artifacts, command modules, datasource provider, replay store, or
  concrete telemetry exporter.
- Medium risk: the public key-provider bridge must retain provider error
  distinctions and cannot allow inconsistent algorithm or status metadata.
- Medium risk: root-package API types must be usable without leaking internal
  implementation types or exposing mutable byte storage.
- Highest risk: top-level state mapping must preserve the four draft states,
  ignore unsupported algorithms correctly, fail supported mixed signatures,
  and never overstate current-only verification as full-chain PASS.
- Highest risk: public errors and examples must remain useful without
  disclosing raw messages, SMTP paths, recipients, selectors, signatures,
  nonces, hashes, or key bytes.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-public-contract-and-errors.md` | unavailable | unavailable | unavailable | unavailable | Historical timestamps were not retained; no estimate substituted; missing fields waived under explicit maintainer exception |
| `02-service-coordinator-and-mapping.md` | unavailable | unavailable | unavailable | unavailable | Historical timestamps were not retained; no estimate substituted; missing fields waived under explicit maintainer exception |
| `03-public-facade-and-key-bridge.md` | unavailable | unavailable | unavailable | unavailable | Historical timestamps were not retained; no estimate substituted; missing fields waived under explicit maintainer exception |
| `04-public-golden-vectors.md` | approximately 2026-07-10 22:45 CEST | approximately 2026-07-10 23:17 CEST | approximately 32 minutes | unavailable | Reconstructed from the retained closeout window; exact timestamps unavailable |
| `05-abuse-fuzz-immutability-diagnostics.md` | approximately 2026-07-10 23:20 CEST | approximately 2026-07-10 23:48 CEST | approximately 28 minutes | unavailable | Reconstructed from the retained closeout window; exact timestamps unavailable |
| `06-docs-and-examples.md` | approximately 2026-07-10 23:49 CEST | approximately 2026-07-10 23:58 CEST | approximately 9 minutes | unavailable | Reconstructed from the retained closeout window; exact timestamps unavailable |
| `07-final-proof-closeout.md` | 2026-07-11 00:06 CEST | 2026-07-11 08:26 CEST | 8 hours 20 minutes | unavailable | Completed under explicit maintainer exception after platform policy denied approved egress to `vuln.go.dev` |

The required measurement is wall-clock time from prompt execution start to
that prompt's final closeout response.

## Scope

In scope:

- Root library verification facade and public domain types.
- Internal service coordination for current verification.
- Public-to-internal static key-provider bridge.
- Raw RFC 5322 and SMTP envelope request validation.
- Current highest signature and instance selection.
- Public mapping to exactly four draft states.
- Bounded reason/check facts, current verification scope, explicit historical
  content/recipe and historical cryptographic non-evaluation, and separate
  structural custody coverage.
- Draft-versioned public golden vectors, negative vectors, examples, fuzzing,
  abuse tests, immutability tests, and documentation.

Out of scope:

- DNS TXT lookup, DNS key-record parsing, caching, DNSSEC diagnostics, network
  retries, or resolver timeouts; these belong to M6.
- Local accept/reject/tempfail action policy, `donotmodify`, `donotexplode`,
  `feedback`, `feedhere`, or action plans; these belong to M7.
- Recipe JSON parsing, application, reconstruction, or generation; these
  belong to M8 and M9.
- Signing, revision signing, private-key handles, or message mutation; these
  belong to M10.
- Datasource providers, replay storage, daemon configuration, OpenAPI,
  generated clients, observability exporters, Milter, Exim, CLI behavior, or
  operator workflows.
- Full historical signature verification or a complete custody-chain PASS.
- `Authentication-Results` formatting.
- Public API stability guarantees beyond this draft-versioned implementation
  baseline.

## Public Contract

The root `dkim2` package owns the consumer-facing contract. The exact Go names
may be refined during Prompt 01, but the semantic shape is binding:

```go
type Verifier struct {
    // validated dependencies and immutable options
}

func NewVerifier(provider PublicKeyProvider, opts ...VerifierOption) (*Verifier, error)

func (v *Verifier) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
```

`VerifyRequest` contains:

- Raw RFC 5322 bytes.
- Current SMTP reverse-path bytes.
- Current SMTP forward-path byte slices.
- No parsed header, message, signature, instance, or generated REST type.

The request constructor or verification entry point must clone caller-owned
bytes before retaining them. It must enforce request and recipient limits
before expensive parsing or cryptography.

The provider is a required constructor argument so an invalid half-configured
verifier cannot be represented. The public static key seam models intent
rather than internal types:

```go
type PublicKeyProvider interface {
    LookupPublicKey(context.Context, PublicKeyQuery) (PublicKeyResult, error)
}
```

`PublicKeyQuery` contains only canonical signing domain, selector, and
algorithm fields required for lookup. Public status values form a closed set:
`found`, `missing`, `invalid`, and `ambiguous`. A found result contains the
declared algorithm and exactly `*rsa.PublicKey` or `ed25519.PublicKey` key
material; `any`, `crypto.Signer`, private keys, and other key types are
forbidden. The bridge deep-clones the RSA modulus or Ed25519 bytes before
validation or use. Returned status and algorithm must match the query before
any key is used. Provider-specific DNS, file, LDAP, SQL, or cache models are
forbidden at this boundary.

Provider errors implement a closed public classification interface with
`temporary` and `permanent` classes. Allowed return combinations are:

| Result | Error | Meaning |
| --- | --- | --- |
| zero result | error matching a non-nil `ctx.Err()` through `errors.Is` | caller control-flow Go error |
| zero result | typed temporary provider error | candidate TEMPERROR |
| zero result | typed permanent provider error | PERMERROR provider failure |
| found/missing/invalid/ambiguous result | nil | validate and map the declared status |

Every other pair is a provider-contract violation and maps to PERMERROR with a
bounded `provider_contract` reason. This includes a non-zero result plus any
error, unknown status, found-without-material, non-found-with-material,
algorithm mismatch, private key material, and unclassified raw errors. Mapping
never inspects error strings, and public results/errors never wrap or expose
the provider cause. A provider-owned timeout or deadline while the caller
context remains live is not caller control flow: it must be returned as a
typed temporary provider error to be a TEMPERROR candidate, or otherwise maps
to PERMERROR `provider_contract`.

The public result contains:

- Draft identifier exactly `draft-ietf-dkim-dkim2-spec-04`.
- One of the four public states.
- Verification scope `current`.
- Historical content/recipe state `not_evaluated`.
- Historical cryptographic-signature state `not_evaluated`.
- Custody-structure coverage with exactly `not_evaluated`, `not_present`,
  `nd_links_evaluated`, or `terminal_nd_requires_oob`. `not_evaluated` is
  required when parsing, extraction, or an earlier limit failure prevents the
  implementation from truthfully determining whether `nd=` was present; it
  can never accompany PASS. The terminal value records an inspected
  highest/current `nd=` that has no successor link to evaluate and therefore
  cannot PASS. None claims full historical custody verification.
- Current target sequence and instance number.
- Bounded reason codes and check classes.
- One bounded algorithm-family and status fact for every retained
  signature-set result, subject to the public result cap.
- No raw values or mutable internal storage.

The public API must not expose `verify.Result`, `verify.Error`,
`signature.Signature`, `instance.MessageInstance`, `rawmsg.Message`, or any
other `lib/internal` type.

Public check classes are closed to `message`, `protocol`, `body_hash`,
`header_hash`, `signature`, `key`, `timestamp`, `envelope`,
`domain_alignment`, `next_domain`, `provider`, and `internal_contract`.
Public reason codes are closed to `none`, `invalid_request`, `limit_exceeded`,
`malformed_message`, `malformed_protocol`, `missing_protocol`,
`sequence_invalid`, `unsupported_algorithm`, `hash_mismatch`,
`signature_mismatch`, `missing_key`, `invalid_key`, `ambiguous_key`,
`provider_temporary`, `provider_permanent`, `provider_contract`,
`timestamp_invalid`, `envelope_mismatch`, `domain_alignment_mismatch`,
`next_domain_mismatch`, `out_of_band_required`, and `internal_contract`.
Adding a value requires a spec and mapping-test update. Unknown internal values
map to `internal_contract`, never to PASS.

`Verify` has a disjoint result/error invariant after successful construction:

- Every message-, parser-, limit-, sequence-, key-, provider-, timestamp-,
  envelope-, custody-, hash-, or cryptography-derived outcome returns exactly
  one populated structured result and a nil Go error.
- Caller cancellation/deadline and detected API misuse return the zero result
  plus a Go error.
- A call never returns both a usable result and a non-nil Go error.
- Provider permanent, temporary, and contract failures are protocol results,
  not Go infrastructure errors; only provider errors matching the caller
  context error remain Go control flow.

## Protocol And Result Semantics

### Authoritative Input And Target

- `VerifyRequest.RawMessage` is the only authority for RFC 5322 message and
  DKIM2 header state.
- The facade must not accept independently parsed protocol objects.
- The current SMTP envelope is distinct evidence and is never inferred from
  message header fields.
- Default target is the highest numbered `DKIM2-Signature`.
- Its `m=` must reference the highest current `Message-Instance` under the
  active draft interpretation already enforced by M4.
- Explicit historical target selection is not part of the M5 public API.
- Recipe reconstruction and historical message states remain unavailable.

### Four-State Mapping

M5 exposes exactly these top-level values:

| Public state | Meaning |
| --- | --- |
| `PASS` | Current target, current hashes, required supported signatures, timestamp, and applicable custody/envelope checks passed. |
| `FAIL` | Verification was possible, but a supported body hash, header hash, or cryptographic signature did not match. |
| `PERMERROR` | Verification could not complete because of unrecoverable malformed, missing, ambiguous, unsupported, expired, custody, envelope, or key state. |
| `TEMPERROR` | Verification could not complete solely because the injected key provider reported a temporary provider failure. |

Internal `mixed`, `unsupported`, `indeterminate`, `not_applicable`, and
`not_evaluated` values are detail states only. They must never escape as a
fifth public top-level state.

The binding mapping is:

| Internal fact | Public state | Notes |
| --- | --- | --- |
| All required current checks pass and at least one supported signature set passes | `PASS` | Unknown algorithms are ignored, but may remain as bounded detail. |
| Supported body or header hash mismatch | `FAIL` | Hash algorithm detail is bounded. |
| Supported signature mismatch | `FAIL` | One supported pass plus one supported fail is still `FAIL`. |
| Only unknown signature algorithms | `PERMERROR` | Nothing checkable exists; never PASS. |
| Supported pass plus unknown algorithm | `PASS` | Draft-04 Section 3.4 requires the unknown algorithm to be ignored. |
| SHA-256 plus unknown hash algorithm | eligible for `PASS` | The unknown hash is ignored; all other required checks must pass. |
| Unknown hash algorithms without SHA-256 | `PERMERROR` | Nothing checkable covers the current message hashes. |
| Missing, invalid, ambiguous, mismatched, or policy-rejected static key | `PERMERROR` | No DNS temporary semantics exist in M5. |
| Temporary injected provider failure | `TEMPERROR` | Provider errors must be typed; arbitrary strings do not decide mapping. |
| Missing/malformed DKIM2 field, tag, sequence, current instance, or request evidence | `PERMERROR` | Includes resource-limit failure. |
| Expired or disallowed future timestamp | `PERMERROR` | Uses deterministic clock policy. |
| Current MAIL FROM, RCPT TO, `d=`, or `nd=` custody mismatch | `PERMERROR` | Raw paths/domains are not emitted. |
| Highest `nd=` requiring unmodeled out-of-band trust | `PERMERROR` | Deterministic secure default; never PASS or TEMPERROR. |
| Context canceled or deadline exceeded by the caller | Go error | Caller control flow, not a DKIM2 protocol result. |
| Invalid verifier construction or programmer misuse | Go error | No partially initialized verifier is returned. |

If several facts exist, mapping is independent of map order, signature-set
order, provider completion order, or error text. The binding precedence is:

1. Caller cancellation/deadline or API misuse: zero result plus Go error.
2. Structural or permanent protocol state: PERMERROR. This includes parser,
   limits, required fields/tags, sequence/target, timestamp, envelope,
   alignment, custody, unsupported-only algorithms, permanent/missing/
   invalid/ambiguous keys, provider-contract failure, and unknown internal
   enum values.
3. Supported integrity failures: FAIL, but only when no PERMERROR fact exists.
   This includes any supported signature failure or current hash mismatch.
4. Typed temporary provider failure: TEMPERROR, but only when no PERMERROR or
   FAIL fact exists and the temporary failure prevents a complete conclusion.
5. PASS only when every applicable required check passes, every supported
   signature set passes, SHA-256 is present, and at least one supported
   signature set is checkable.

The implementation may stop early only when this precedence cannot be changed
by unevaluated required work. Permutation tests must prove stable results for
multiple signature sets and combined failure facts. Human-readable strings
must never be the mapping source of truth.

### Verification Scope

A public PASS means only:

- The current raw message was parsed.
- Current numbering and target selection were valid.
- The highest/current instance hashes matched the current message.
- Every supported signature set that M4 could check passed.
- Unknown algorithms were ignored.
- Timestamp and applicable current envelope/domain checks passed.
- Every structural `nd=` link that M4 encountered matched its immediate
  successor. This is structural custody evidence, not historical crypto or
  recipe verification.

A public PASS does not mean:

- Previous message instances were reconstructed.
- Historical hashes or signatures were verified.
- Every historical `mf=` to prior `rt=` custody relationship was verified.
- Local delivery policy accepted the message.
- Replay detection ran.
- DNS, DNSSEC, datasource, daemon, Milter, or Exim behavior ran.

The result must therefore expose `scope=current`,
`historical_content=not_evaluated`, and
`historical_signatures=not_evaluated` on every M5 result, including PASS.
It separately exposes `custody_structure=not_evaluated` when parsing,
extraction, or an earlier limit failure prevented reliable `nd=` presence
detection; `nd_links_evaluated` when M4 inspected one or more
historical/intermediate `nd=` links; `not_present` only after successful
extraction established that no `nd=` was present; or
`terminal_nd_requires_oob` when the highest/current instance contains `nd=`
but has no successor link that M5 can evaluate. The `not_evaluated` and
terminal states cannot accompany PASS, and the terminal state must not claim
link success. No M5 value may be named or documented as full-chain success.

### Algorithms And Multiple Signatures

- SHA-256, RSA-SHA256, and Ed25519-SHA256 remain the required baseline.
- RSA uses SHA-256 with PKCS#1 v1.5.
- Ed25519 signs/verifies the native SHA-256 digest bytes of Section 9.6 input.
- Every supported signature set must be checked when possible.
- A failure in any supported set prevents PASS.
- Unknown algorithms are ignored for aggregate verification.
- Unknown hash and signature algorithm detail is exposed only as the bounded
  token `unknown`.
- Unknown algorithm names exposed in results are represented by the bounded
  token `unknown`, never by message-derived text.
- Disabled required algorithms, inconsistent provider metadata, wrong key
  types, or missing keys cannot produce PASS.

### Envelope And `nd=` State

- Current reverse-path must exactly match signed `mf=` after ASCII-only domain
  lowercasing. Local-part bytes remain case-sensitive, `<>` matches only
  `<>`, and this comparison never uses relaxed alignment.
- For a current signature using `mf=` and `rt=`, every current SMTP recipient
  must be present in signed `rt=`; signed extra recipients and order
  differences are allowed.
- Domain comparison lowercases ASCII domain parts only. Local parts remain
  case-sensitive.
- Current-envelope matching does not use relaxed domain matching.
- `d=` alignment uses the draft relaxed right-label algorithm against the
  signed MAIL FROM domain; null reverse-path is not applicable.
- A non-highest `nd=` must match the immediate successor `d=` exactly after
  canonical DNS-name parsing.
- A highest `nd=` requires out-of-band arrangements. M5 defines no OOB trust
  option, so this state maps to deterministic `PERMERROR`.

## Package Boundaries

- `lib/`:
  Owns public request/result/provider/option/error types, the public
  verification entry point, public-to-service DTO mapping, and the public
  provider to internal key-provider adapter. It imports internal service and
  verification seams but no command or adapter dependency.
- `lib/internal/service`:
  Owns orchestration, internal-only request/result/config/four-state DTOs, and
  the single mapping from internal M4 facts/errors to the internal draft state
  and coverage model. It never imports the root `dkim2` package and does not
  own parsing, canonicalization, cryptography, or local action policy.
- `lib/internal/verify`:
  Remains the owner of static-key current verification facts. M5 may add only
  narrowly justified accessors or adapter seams, not duplicate verification.
  It must preserve typed temporary-provider state distinctly from permanent or
  contract provider failure through `KeyStatus` and signature-set results so
  service mapping never reconstructs provider class from strings.
- `lib/internal/rawmsg`, `instance`, `signature`, and `canonical`:
  Remain authoritative and are not reimplemented in the facade or service.
- `cmd/dkim2d`, `cmd/dkim2ctl`, `cmd/dkim2-milter`:
  Receive no M5 implementation changes.

The library must remain free of Cobra, Viper, Fx, OpenAPI generated code,
Prometheus, OTLP exporters, Milter packages, Valkey, SQL, LDAP, and CLI
frameworks.

The dependency graph is one-way:

```text
root dkim2 public facade
  -> internal/service DTOs and coordinator
       -> internal/verify and M1-M4 owners

root public provider adapter
  -> internal/verify.KeyProvider
```

No internal package imports the root package, so the graph cannot cycle.

## Security And Privacy

- Ambiguous or missing protocol, envelope, key, target, or provider state
  fails closed.
- Request size, recipient count, signature-set count, and result-fact count
  are bounded before allocation-heavy work.
- Public options are validated atomically; unsafe zero or negative limits are
  rejected.
- Public provider results require exact algorithm and success-state
  consistency before key material reaches M4.
- Private keys are never accepted by the verification facade.
- Raw messages, bodies, header values, SMTP paths, local parts, recipient
  lists, selectors, nonces, signatures, hashes, public-key bytes, provider raw
  errors, tokens, credentials, and protected config are forbidden in public
  results, error strings, examples, fuzz failure text, or test logs.
- Returned byte slices and result collections are immutable copies.
- Caller cancellation is honored and cannot be reclassified as protocol
  success.
- No compatibility option may turn a terminal `nd=` or unsupported-only
  signature set into PASS.

Public limits are a closed typed configuration with these defaults and hard
upper bounds for M5:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Raw message bytes | 32 MiB | 32 MiB |
| Current recipients | 2,000 | 2,000 |
| Message-Instance hash sets | 16 | 16 |
| DKIM2 signature sets per field | 16 | 16 |
| Public check facts | 128 | 128 |
| Public signature-set facts | 16 | 16 |

Callers may narrow, never widen, these limits. Raw size and recipient count are
checked before parsing and before provider lookup. M5 must add a narrow
configured-parser seam to the authoritative M4 verifier so instance/signature
limits apply during extraction rather than after allocation; this seam still
extracts exclusively from `Request.Message` and must not restore caller-owned
parsed input. Result caps are checked before public result-slice allocation.
Tests assert provider call count remains zero for pre-provider limit failures
and exercise exact/over-limit boundaries.

## Observability

M5 adds no logger, metric, trace, exporter, global registry, or debug module.
Public results may expose only bounded facts that a future observer can map to
the architecture allowlist:

- Operation `verify`.
- Draft version.
- Public state.
- Verification scope.
- Reason/check class.
- Bounded algorithm family.
- Target sequence and instance numbers.
- Count values after configured limits.

Raw or hashed identities, selectors, paths, recipients, message identifiers,
request identifiers, errors, and key identifiers are not public observation
facts in M5.

## Required Tests

### Unit Tests

- Public state enum accepts exactly four values.
- Public constructor rejects nil provider, invalid limits, inconsistent
  options, and unsupported construction state.
- Request input and public result accessors are immutable.
- Service mapping covers every internal target/check/key/error status.
- Service mapping exhaustively covers every current M4 status dimension:
  target, check, signature-set, key, hash, timestamp, envelope, domain
  alignment, next-domain, and error code, including zero and unknown enum
  values. Any unrecognized value maps to PERMERROR `internal_contract`.
- Mapping precedence is deterministic and does not inspect error text.
- Unknown-only maps to PERMERROR; supported-pass plus unknown maps to PASS;
  supported-pass plus supported-fail maps to FAIL.
- Unknown-hash-only maps to PERMERROR; SHA-256 plus unknown hash remains
  eligible for PASS and exposes only bounded `unknown` detail.
- Missing/invalid/ambiguous keys map to PERMERROR; typed temporary provider
  failure maps to TEMPERROR.
- Hash and crypto mismatch map to FAIL.
- Parser, sequence, timestamp, envelope, alignment, and custody failures map to
  PERMERROR.
- Terminal `nd=` without OOB trust maps to PERMERROR.
- Every result declares `scope=current`, historical content/recipes and
  historical signatures `not_evaluated`, plus truthful custody-structure
  coverage.
- Caller context cancellation returns a Go error without a false result.
- Every legal and illegal provider `(result,error)` pair follows the closed
  provider matrix; permutations of multiple set outcomes keep one result.
- A provider error matching an active caller `ctx.Err()` returns the caller
  control-flow Go error. A provider-owned `context.DeadlineExceeded` while the
  caller context is live is TEMPERROR only when wrapped in the typed temporary
  provider class; otherwise it is PERMERROR `provider_contract`.
- Custody coverage maps pre-extraction indeterminacy to `not_evaluated`, a
  successfully extracted absence of `nd=` to `not_present`, evaluated
  intermediate links to `nd_links_evaluated`, and highest/current terminal
  `nd=` to `terminal_nd_requires_oob` with PERMERROR.

### Public Golden Vectors

Draft-versioned vectors must enter through the public API and include:

- RSA-SHA256 current PASS.
- Ed25519-SHA256 current PASS.
- Both supported algorithms PASS.
- Supported PASS plus unknown algorithm remains PASS.
- SHA-256 plus an unknown hash algorithm remains eligible for PASS.
- Unknown hashes without SHA-256 are PERMERROR.
- Supported PASS plus supported bad signature is FAIL.
- Body hash mismatch is FAIL.
- Header hash mismatch is FAIL.
- Missing, malformed, or inconsistent protocol state is PERMERROR.
- Raw-message, extraction, and pre-extraction limit failures report
  `custody_structure=not_evaluated`; they must not claim `not_present`.
- Missing and ambiguous static keys are PERMERROR.
- Typed provider failure, including a provider-owned deadline explicitly
  classified as temporary while the caller context is live, is TEMPERROR.
- An unclassified provider-owned `context.DeadlineExceeded` while the caller
  context is live is PERMERROR `provider_contract`.
- Expired timestamp is PERMERROR.
- Timestamp exactly at the 14-day maximum passes; 14 days plus one second is
  PERMERROR.
- Timestamp exactly at the five-minute future tolerance passes; one second
  beyond tolerance is PERMERROR. The five-minute tolerance is explicit local
  policy, not a draft requirement.
- Very large but parseable `t=` values fail deterministically without integer
  overflow. M5 exposes no disabled-max-age option.
- Current envelope and `d=` mismatch are PERMERROR.
- Exact and ASCII-domain-case-varied MAIL FROM pass; local-part case mismatch
  fails; signed and current null reverse-path match only each other.
- Valid intermediate `nd=` plus successor passes current checks when the
  current target itself has usable envelope evidence.
- Terminal `nd=` is PERMERROR and explicitly requires OOB trust.

Every vector records exactly `draft-ietf-dkim-dkim2-spec-04` and synthetic
input only.

### Abuse And Negative Tests

- Oversized raw message and excessive recipients fail before provider lookup.
- Oversized result facts and signature-set counts fail closed.
- Provider returns mismatched algorithm/status/key type.
- Provider returns nonzero result plus error, unclassified error, unknown
  status, non-found-with-material, found-without-material, private key, or
  signer.
- Provider-owned RSA modulus and Ed25519 bytes are mutated immediately after
  return and concurrently; verification uses the deep clone safely.
- Toxic markers in raw message, paths, selector, algorithm extension, nonce,
  signature, key bytes, and provider error never occur in results/errors.
- Returned result slices cannot mutate verifier-owned state.
- Reusing one verifier concurrently is race-safe.

### Fuzz Tests

- Fuzz the public verification entry point with bounded raw bytes and envelope
  paths plus a deterministic fake provider.
- Seed with a minimal valid current message, malformed tag list, sequence gap,
  unknown algorithm, terminal `nd=`, high numeric values, and invalid base64.
- Assert no panic, deterministic state/error class, no input mutation, bounded
  result size, and no raw-input leakage.
- Fuzzing must not perform network calls or log raw data.

### Integration Or E2E Tests

- Public root-package verification through real M1 through M4 code is the M5
  integration boundary.
- No daemon, socket, OpenAPI, Milter, Exim, DNS, Valkey, or external process is
  required.

### Documentation Checks

- Root library package docs describe the public verification facade and
  current-only scope.
- Synthetic examples inspect structured results without printing protected
  values.
- No generated OpenAPI file changes.
- All new/changed hand-written named functions and methods have concise English
  doc comments.
- Production names do not contain milestone, prompt, or task labels.

### Final Gate

Run focused root/service tests first, then:

```text
make test
make vet
make lint
make race
make guardrails
git diff --check
git status --short
```

Run every new fuzz target separately for a bounded smoke duration. If any gate
cannot run, record the exact blocker and largest equivalent passing subset.

### Review And Commit Sequence

- Every implementation prompt forbids staging and commits.
- After all prompt slices, the orchestrator runs focused tests, fuzz smoke,
  and `make guardrails`.
- An independent read-only draft/security reviewer inspects the actual diff,
  surrounding code, public mapping tables, and test evidence.
- Findings are returned to an implementer, fixed reproducer-first where
  practical, and independently re-reviewed.
- Focused tests and `make guardrails` run again after the final finding fix.
- Only M5 durable spec, library code, tests, vectors, and public documentation
  are staged. Nothing under `temp/` is staged.
- The orchestrator creates exactly one project-format M5 commit after review
  and gates succeed. The M5 spec is part of that commit; there is no separate
  preliminary docs or slice commit.

## Acceptance Criteria

- A library consumer can verify a current DKIM2 message through the public
  root package without importing internal packages.
- Public top-level results are exactly PASS, FAIL, PERMERROR, or TEMPERROR.
- Public result mapping is centralized, table-tested, and based on typed facts.
- Root-to-service dependencies are cycle-free; internal service code never
  imports public root types.
- Message/provider/protocol outcomes return a structured result with nil Go
  error; caller context and API misuse return only a Go error and zero result.
- PASS requires all applicable current checks and every supported signature
  set to pass.
- Unknown signature algorithms are ignored; unknown-only is non-success.
- Mixed supported pass/fail is FAIL.
- Temporary provider failure is the only M5 path to TEMPERROR.
- Provider status/error pairs follow the closed contract; unknown or
  inconsistent pairs are PERMERROR `provider_contract`.
- Current scope, historical content/recipe non-evaluation, historical
  cryptographic non-evaluation, and separate structural custody coverage are
  explicit on all results.
- No historical instance is checked against current raw bytes without recipe
  reconstruction.
- Terminal `nd=` cannot PASS without modeled OOB trust, and M5 models no such
  trust.
- Public request/provider/result contracts preserve immutability and do not
  leak internal types.
- Public key material is restricted to cloned RSA or Ed25519 public keys;
  private keys, signers, and `any` are rejected.
- Limits reach pre-parse, configured extraction, provider-call, and
  pre-result-allocation seams with exact/over-limit tests.
- Errors, results, examples, tests, and fuzz output are secret-safe and
  bounded.
- Library module dependencies remain free of service/adapter frameworks.
- Public golden, negative, abuse, fuzz, race, and immutability tests pass.
- `make guardrails` and `git diff --check` pass.
- An independent draft/security review has no unresolved finding.
- Prompt timings and completion evidence are recorded.
- Exactly one project-format commit records the completed M5 milestone; ignored
  `temp/` artifacts are not staged.

## Completion Evidence

- Focused tests: `go test . ./internal/service/... ./internal/verify/...` passed
  after the final mapping and lint fixes.
- Public golden vectors: passed through the public root-package test suite.
- Fuzz smoke: all nine public, verifier, parser, signature, and
  canonicalization fuzz targets passed separately for 10 seconds after the
  final code and Makefile changes.
- Full local checks: `go test ./...`, `go vet ./...`, and
  `go test -race ./...` passed in `lib`; `make test`, `make vet`, `make lint`,
  and `make race` passed for all four workspace modules.
- Generated checks: the OpenAPI existence checks passed as part of the local
  guardrail sequence; no OpenAPI or generated artifacts changed.
- Guardrails: all local phases passed. The final
  `GOCACHE=/tmp/dkim2-m5-go-cache make guardrails` attempt passed formatting,
  vet, lint, unit, race, and OpenAPI checks, then failed at the first live
  `govulncheck` database request. Explicit maintainer approval for network
  access was granted, but platform policy denied the egress to `vuln.go.dev`.
  No vulnerability module was reported as successfully scanned. The external
  vulnerability check is waived for this closeout under that explicit
  maintainer exception; it must not be represented as a successful scan.
- Independent review: two independent read-only reviewers approved the final
  implementation tree before the final local gates; all draft/security,
  bounded-mapping, provider-deadline, and status-matrix findings were fixed
  and re-reviewed. The external vulnerability-check exception was explicitly
  authorized by the maintainer after the platform-policy denial.
- `git diff --check`: passed after the final evidence update.
- `git status --short`: inspected; M5 files and the required multi-module
  Makefile lint fix remain unstaged, and no command/OpenAPI file changed.
- Skipped checks: the external `govulncheck` database scan is waived under the
  explicit maintainer exception. It was attempted, but platform policy denied
  approved egress before any module scan succeeded. No other check was
  skipped.
- Timing exception: the unavailable historical Prompt 01 through Prompt 03
  timing fields are separately waived under the explicit maintainer exception.
  No times were invented; best-available evidence for later prompts is
  retained above.
- Commit: ready under the explicit maintainer exception after final review;
  staging and committing remain orchestrator responsibilities.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Public library-only current verification | Implemented in `lib`; the root Makefile lint target was corrected to analyze each workspace module | done | No DNS, recipes, policy actions, commands, adapters, providers, replay, or exporters |
| Public API | Root request/provider/result types hide internal packages | Immutable bounded public facade and typed provider seam implemented | done | No internal type escapes |
| Result states | Exactly PASS, FAIL, PERMERROR, TEMPERROR | Closed enums and centralized typed mapping tested | done | Unknown or contradictory facts fail as `internal_contract` |
| Current verification | Highest/current signature and instance verified | Current-only scope and both historical non-evaluation dimensions are explicit | done | Structural custody is separate |
| Algorithms | Supported sets checked; unknown ignored; supported mixed fails | Golden and permutation coverage passes | done | Draft-04 Sections 3.4 and 11.6 |
| Custody | Current envelope, `d=`, and `nd=` states fail closed | Exact closed envelope/alignment matrices and terminal OOB handling pass | done | Contradictory typed states fail closed |
| Provider | Static provider bridge validates algorithm/status/material | Closed matrix, deep cloning, and caller/provider deadline distinction tested | done | Only explicitly typed temporary failures produce TEMPERROR |
| Tests | Unit, golden, negative, abuse, fuzz, race, immutability | All local suites and nine separate fuzz smokes pass | done | External vulnerability database check waived separately |
| Security | No protected or high-cardinality values escape | Marker, diagnostic, bounded-output, and independent review evidence passes | done | `govulncheck` attempted but platform-policy egress denial waived by explicit maintainer exception; no successful scan claimed |
| Boundaries | Library remains adapter-framework free | Dependency direction and unchanged command/OpenAPI surfaces reviewed | done | No generated REST types |
| Documentation | Public scope/examples and draft version are accurate | Package docs, examples, vectors, and this evidence updated | done | English-only technical docs |
| Effort | Prompt timings recorded | Best-available timestamps recorded; missing Prompt 01 through Prompt 03 fields explicitly waived under maintainer exception | done | Completed with exception; no unsupported times invented |
| Commit | One reviewed M5 commit, no `temp/` staging | Ready for orchestrator staging and commit after final review | done | External vulnerability scan covered by explicit maintainer exception |

## Decisions And Open Questions

- Settled: M5 is bound to `draft-ietf-dkim-dkim2-spec-04`.
- Settled: Public verification operates only on the highest/current signature
  and associated current instance.
- Settled: Root public DTOs adapt one-to-one to internal service DTOs;
  `internal/service` never imports the root package.
- Settled: `NewVerifier` requires the public provider as an explicit first
  argument.
- Settled: Public top-level states are exactly the four states in draft-04
  Section 11.1.
- Settled: `mixed`, `unsupported`, and `indeterminate` remain internal detail
  and map to FAIL or PERMERROR according to typed causes.
- Settled: Unknown algorithms are ignored when a supported path passes;
  unknown-only is PERMERROR.
- Settled: One failing supported signature set prevents PASS.
- Settled: Structural/permanent PERMERROR facts outrank FAIL, FAIL outranks
  TEMPERROR, and TEMPERROR outranks PASS after caller-control Go errors.
- Settled: Provider result/error combinations use the closed matrix; unknown
  combinations fail as PERMERROR `provider_contract`.
- Settled: Current-scope PASS reports historical content/recipes and
  historical signatures as not evaluated, while separately reporting absent
  or evaluated structural `nd=` links. Pre-extraction failures report custody
  as `not_evaluated` and cannot PASS.
- Settled: Terminal `nd=` without modeled OOB trust is PERMERROR with
  `custody_structure=terminal_nd_requires_oob`.
- Settled: M5 uses injected static keys only. DNS begins in M6.
- Settled: Context cancellation and construction misuse return Go errors rather
  than invented DKIM2 protocol results.
- Settled: M5 adds no local acceptance/action policy and no
  `Authentication-Results` formatter.
- Open: The eventual long-term public API compatibility window remains
  deferred until DNS, policy, recipes, signing, and daemon integration provide
  enough implementation evidence. M5 names may be refined within this
  milestone, but its semantic contract and tests are binding.
