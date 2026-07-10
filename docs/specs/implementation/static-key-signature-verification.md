# Static-Key Signature Verification

Status: completed.

This spec defines Milestone M4, static-key DKIM2 signature verification for
the reference library. It covers RSA-SHA256 and Ed25519-SHA256 verification
with injected public keys, multi-signature behavior, timestamp checks, current
SMTP envelope checks, body and header hash validation, negative crypto
vectors, fail-closed error taxonomy, and library-only tests. This work builds
on the completed M1 raw message model, M2 DKIM2 tag parsers, and M3
canonicalization and hash foundation.

M4 is intentionally not the full MVP verification vertical slice. It should
prove the cryptographic and protocol-checking core with deterministic static
keys so M5 can add public-facing result coordination, golden MVP fixtures, and
the first end-to-end library verifier without introducing DNS, daemon, Milter,
OpenAPI, datasource, policy-engine, replay-store, or observability-exporter
complexity.

## Source Documents

This spec is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`, especially Sections 3.1, 3.2, 3.3, 3.4, 3.5,
  3.6, 5.1, 5.2, 5.3, 5.4, 5.6, 5.7, 6.2, 6.3, 9, 11.1, 11.2, 11.4,
  11.5, 12.1, 12.2, 12.3, 12.5, 13, 14, 15, 16, and 18
- `docs/specs/spec-and-prompt-template.md`
- `docs/specs/implementation/raw-message-model.md`
- `docs/specs/implementation/dkim2-tag-parsers.md`
- `docs/specs/implementation/canonicalization-and-hashes.md`
- `lib/internal/rawmsg`
- `lib/internal/tagvalue`
- `lib/internal/instance`
- `lib/internal/signature`
- `lib/internal/canonical`
- `Makefile`
- `.gitignore`
- `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05, especially
  Sections 3.1, 3.4, 6.1, 6.2, 8.2, 8.4, 8.7, 8.8, 9.2, 9.3, 9.4, 9.6, 10,
  11.2, 11.3, 11.4, 11.6, and 11.7
- `draft-chuang-dkim2-dns-04`, dated 2026-03-18, only for DKIM2 key-record
  and algorithm context needed by static public-key modeling
- RFC 5321 SMTP envelope concepts for reverse-path and forward-path evidence
- RFC 5322 Internet Message Format semantics already modeled by M1
- RFC 4648 base64 behavior already constrained by M2

If this spec conflicts with a source document, stop and reconcile the durable
artifact before implementation continues.

`draft-ietf-dkim-dkim2-spec-04` and `draft-chuang-dkim2-dns-04` remain the
binding implementation baselines for M4. If a later draft exists or changes
verification semantics, record it as a caveat or follow-up, but do not switch
the repository behavior baseline without updating durable documentation and
draft-versioned vectors first.

Post-closeout verification corrections implement current-draft envelope
matching, unknown-algorithm aggregation, signing-domain alignment, the
14-day default timestamp maximum, and the highest-current-signature to
highest-current-instance interpretation. After the M2 draft-04 parser
migration, M4 also validates `nd=` chain links and represents terminal
out-of-band acceptance as typed non-success.

## Original Gap

The repository currently has completed foundations for M1 through M3:

- `lib/internal/rawmsg` owns byte-preserving RFC 5322 parsing, immutable
  header/body views, strict CRLF policy, and bounded parser metadata.
- `lib/internal/tagvalue` owns shared DKIM2 tag-list scanning and strict
  padded base64string parsing.
- `lib/internal/instance` parses `Message-Instance` fields, hash sets,
  optional recipe base64 containers, and contiguous `m=` sequences.
- `lib/internal/signature` parses `DKIM2-Signature` fields, envelope-path
  containers, signature sets, flags, nonces, contiguous `i=` sequences, and
  the unreferenced-instance special case.
- `lib/internal/canonical` owns Section 6.1 body hash input, Section 6.2
  header hash input, Section 9.6 signature input, SHA-256 digest containers,
  and bounded debug metadata.

There is no package that coordinates these pieces into cryptographic
verification. There is no static public-key provider abstraction, no
algorithm-specific RSA or Ed25519 verifier, no timestamp policy, no current
SMTP envelope matcher, no hash comparison result taxonomy, no multi-signature
selection semantics, and no negative crypto vector suite.

M5 needs this foundation before it can expose a complete library-only
verification vertical slice. If M4 duplicates raw parsing, tag parsing,
canonicalization, or sequence validation, later code will drift from M1-M3. If
M4 reaches directly for DNS, daemon config, Milter callback state, OpenAPI
DTOs, or a concrete datasource, it will violate the library boundary before
the key resolver and service layers exist.

## Goal

Implement a library-internal static-key verification coordinator that:

- Consumes one parser-owned `rawmsg.Message` as the sole protocol authority and
  derives all M2/M3 state from its immutable accessors.
- Uses `lib/internal/canonical` for all body hash, header hash, and signature
  input bytes.
- Verifies `rsa-sha256` signatures with SHA-256 plus PKCS#1 v1.5 RSA public
  key verification.
- Verifies `ed25519-sha256` signatures by calculating SHA-256 over the same
  Section 9.6 canonical signature input bytes and checking the Ed25519
  signature over that native digest bytes value.
- Accepts public keys only through injected static key material or an
  injected key-provider interface.
- Enforces an exact default algorithm allowlist of `rsa-sha256` and
  `ed25519-sha256`.
- Checks current body and header hashes for the target `Message-Instance`
  referenced by the target `DKIM2-Signature`.
- Checks the highest/current `DKIM2-Signature` against the supplied SMTP
  envelope when current-envelope verification is requested.
- Applies deterministic timestamp policy through an injected clock and
  explicit tolerance/age settings.
- Checks every known, allowed, key-backed signature set that the verifier can
  evaluate for a selected DKIM2-Signature, and reports mixed pass/fail state
  without accepting unknown, unsupported, missing-key, malformed, or failed
  signature sets as success.
- Returns structured, bounded, secret-safe facts and typed errors suitable for
  M5 result mapping.

M4 must not implement DNS lookup, DNS key TXT parsing, recipe JSON semantics,
previous-instance reconstruction, public facade APIs, daemon behavior, Milter
behavior, OpenAPI behavior, datasource providers, replay detection, local
policy action plans, concrete logging, tracing, metrics, Prometheus labels, or
OpenTelemetry exporters.

## Delivery Shape

The implementation should be split into focused, reviewable slices executed in
order. Expected prompt count is five implementation prompts plus one final
closeout prompt.

1. Verification package contract and error taxonomy:
   Add `lib/internal/verify` as the M4 coordinator. Define request, result,
   check status, static key, key provider, algorithm policy, clock/timestamp
   policy, envelope, limits, typed errors, and package documentation. The
   package must consume M1-M3 types and must not own parsing or
   canonicalization rules.
2. Static key provider and algorithm validation:
   Implement an in-memory static public-key provider for tests and examples,
   normalize `(domain, selector, algorithm)` lookup keys, validate public key
   types for `rsa-sha256` and `ed25519-sha256`, enforce RSA verifier
   key-size policy, require nil-error provider results to return the requested
   algorithm with `found` metadata, and reject unknown, disabled, or
   invariant-violating results as non-success states.
3. Hash and signature verification flow:
   Coordinate parsing/extraction inputs, validate instance and signature
   references, calculate body/header SHA-256 through `canonical`, compare
   digest bytes to the selected `Message-Instance`, build Section 9.6 input
   for the selected `DKIM2-Signature`, calculate the SHA-256 signature-input
   digest, and verify RSA/Ed25519 signature bytes using standard-library
   crypto.
4. Multi-signature, timestamp, and envelope checks:
   Implement target/highest signature selection, all-checkable-signatures
   semantics, current-envelope matching for the highest/current
   `DKIM2-Signature`, injected clock handling, future timestamp tolerance,
   maximum age policy, and typed partial/mixed result states.
5. Negative vectors, fuzz smoke, and secret-safe diagnostics:
   Add deterministic static-key vectors for RSA and Ed25519 pass cases plus
   negative vectors for bad body hash, bad header hash, wrong key, wrong
   algorithm, malformed signature bytes, missing key, stale timestamp, future
   timestamp, envelope mismatch, unknown algorithm, and multi-signature mixed
   state. Add fuzz/abuse tests for bounded request shapes and diagnostic
   redaction.
6. Final proof and closeout:
   Reconcile the full spec against implementation evidence, update measured
   effort, run final gates, and verify no production code names reference
   prompt labels or transient planning milestones.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 4 to 8 agent-days |
| Highest-risk area | cryptographic verification semantics, signature-input selection, and fail-closed result taxonomy |
| Expected prompt count | 5 implementation prompts plus 1 final closeout prompt |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: no network calls, no OpenAPI generation, no daemon wiring, no
  concrete datasource provider, no Milter adapter behavior, and no concrete
  observability exporter.
- Medium risk: public-key abstraction must prepare for M6 DNS resolver work
  without leaking DNS TXT record models into M4 verification code.
- Medium risk: timestamp policy is local architecture policy layered over
  parsed `t=` values. It must be explicit, injectable, deterministic, and easy
  to revise if later drafts add sharper timestamp requirements.
- Medium risk: current SMTP envelope matching must fold ASCII domain bytes to
  lowercase while preserving case-sensitive local-part and non-ASCII bytes,
  require every current recipient to occur in signed `rt=`, allow additional
  signed recipients, and avoid Unicode or IDNA normalization.
- Highest risk: multi-signature handling must check every signature set the
  verifier can evaluate and must not turn unknown algorithms, missing keys, or
  one passing signature into blanket success for failed checkable signatures.
- Highest risk: Section 9.6 target rendering currently nulls every `s=`
  signature value in the target field. M4 must either use that M3 contract or
  update M3/M4 documentation and golden vectors before implementing
  per-algorithm nulling.

Measured effort was filled during implementation closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| M4 spec agent | 2026-07-03 12:25:32 CEST | 2026-07-03 12:31:30 CEST | 5m58s | Not separately tracked | Spec corrected by orchestrator after completion: RSA verifier minimum is 1024 bits; Ed25519-SHA256 verifies over SHA-256 digest bytes. |
| M4 prompt-pack agent | 2026-07-03 12:33:52 CEST | 2026-07-03 12:40:19 CEST | 6m27s | Not separately tracked | Prompt pack created for six M4 slices. |
| `01-verification-contract-and-errors.md` | 2026-07-03T12:41:23+02:00 | 2026-07-03T12:48:44+02:00 | 7m21s | Not separately tracked | Passed; verification contract, typed errors, defaults, immutable result and envelope accessors. |
| `02-static-key-provider-and-algorithms.md` | 2026-07-03T12:49:51+02:00 | 2026-07-03T12:59:18+02:00 | 9m27s | Not separately tracked | Passed; static key provider, canonical lookup tuple, algorithm policy, RSA/Ed25519 key validation. |
| `03-hash-and-signature-verification-flow.md` | 2026-07-03T13:00:24+02:00 | 2026-07-03T13:08:33+02:00 | 8m09s | Not separately tracked | Passed; M3 hash comparison, M3 Section 9.6 signature input digest, RSA and Ed25519 crypto checks. |
| `04-multisignature-timestamp-envelope.md` | 2026-07-03T13:09:38+02:00 | 2026-07-03T13:20:55+02:00 | 11m17s | Not separately tracked | Passed; highest/current target selection, mixed signature facts, timestamp policy, and the original envelope matcher. A later draft-04 conformance follow-up corrected recipient-set and domain-case semantics. |
| `05-negative-vectors-fuzz-diagnostics.md` | 2026-07-03T13:22:03+02:00 | 2026-07-03T13:32:13+02:00 | 10m10s | Not separately tracked | Passed; deterministic vectors, negative/abuse/immutability/diagnostic tests, verify fuzz target. |
| `06-final-proof-closeout.md` | 2026-07-03T13:34:07+02:00 | 2026-07-03T13:38:03+02:00 | 3m56s | Not separately tracked | Passed; final proof gates, boundary checks, durable completion evidence, prompt timing ledger. |

Total measured productive wall-clock for implementation prompts 01 through 06
is 50m20s. Prompts 01 through 05 account for 46m24s, and the final proof
closeout accounts for 3m56s. Total measured M4 wall-clock including the
spec-agent and prompt-pack-agent preparation is 1h02m45s. This is far below
the planning estimate of 4 to 8 agent-days because the implementation stayed
inside the library-internal `verify` package, consumed M1-M3 package
boundaries directly, used standard-library cryptography, and did not add DNS,
daemon, Milter, OpenAPI, datasource, recipe, replay, policy, CLI, or concrete
observability work.

A post-closeout conformance follow-up corrected the original envelope matcher
against `draft-ietf-dkim-dkim2-spec-04` Sections 9.2 and 11.4. It is not added
to the prompt timing ledger because execution timing was not recorded from the
start of that follow-up; its focused test evidence is recorded under Completion
Evidence.

The required measurement is wall-clock time from the start of prompt execution
to the final closeout response for that prompt. Active engineering time may be
recorded as an additional estimate, but it does not replace wall-clock time.

## Scope

In scope:

- `lib/internal/verify` as the library-internal coordinator for static-key
  signature verification.
- Static public-key provider abstractions and deterministic in-memory key
  provider fixtures.
- RSA-SHA256 and Ed25519-SHA256 verification using Go standard-library crypto.
- Algorithm allowlist and public key type validation.
- RSA public key size policy.
- Current body and header hash comparison for selected `Message-Instance`
  values using M3 canonical digests.
- Section 9.6 signature input verification for selected
  `DKIM2-Signature` values using M3 canonical input.
- Multi-signature behavior for checkable signature sets within a
  `DKIM2-Signature` field.
- Target signature and highest/current signature selection semantics.
- Timestamp checks using injected clock and explicit tolerance/age policy.
- Current SMTP envelope matching for the highest/current DKIM2 signature.
- Structured verification result facts and typed secret-safe errors suitable
  for M5 result mapping.
- Unit tests, negative crypto vectors, golden-style synthetic vectors where
  useful, fuzz smoke, and final Makefile-driven validation evidence.

Out of scope:

- Public `lib` facade APIs, unless a later implementation prompt updates this
  spec with a concrete facade need.
- Raw RFC 5322 parsing changes in `lib/internal/rawmsg`.
- DKIM2 tag parser changes in `lib/internal/tagvalue`,
  `lib/internal/instance`, or `lib/internal/signature`, unless an M4 test
  exposes a root-cause defect in those packages and this spec is updated first.
- Canonicalization changes in `lib/internal/canonical`, unless M4 proves the
  M3 signature-input target rendering contract is wrong and M3/M4 golden
  vectors are updated before behavior changes.
- DNS key TXT record parsing, network DNS lookup, cache policy, DNSSEC
  diagnostics, revoked-key handling, or resolver temp/permanent error split.
- Recipe JSON parsing, recipe application, recipe generation, previous
  instance reconstruction, or previous-instance hash validation.
- Local policy evaluation, `donotmodify`, `donotexplode`, feedback action
  planning, replay detection, or trust-boundary reporting.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl` changes.
- OpenAPI contracts or generated artifacts.
- Concrete logging, tracing, metrics, Prometheus labels, OpenTelemetry
  exporters, debug modules, or REST/CLI output.
- Commits or staging.

## Protocol, Runtime Or Domain Semantics

M4 is bound to `draft-ietf-dkim-dkim2-spec-04`. It uses
`draft-chuang-dkim2-dns-04` only as key-record and algorithm context for the
shape of static public keys. The static provider is not DNS and must not
pretend to validate DNS publication, TXT record cardinality, DNS TTLs,
revocation, DNSSEC, NXDOMAIN, or temporary resolver failures.

### Normative Draft Mapping

| Behavior | Source | M4 interpretation |
| --- | --- | --- |
| SHA-256 body/header hash algorithm | DKIM2 Section 3.1 and M3 | M4 accepts `sha256` current hash sets only for success and uses M3 digest containers. Unknown message hash algorithms remain non-success data. |
| Body hash input | DKIM2 Section 6.1 and M3 | M4 calls `canonical.BodyHashFromMessage` or equivalent M3 helpers and compares digest bytes to the target `Message-Instance` body hash. |
| Header hash input | DKIM2 Section 6.2 and M3 | M4 calls `canonical.HeaderHashFromMessage` or equivalent M3 helpers and compares digest bytes to the target `Message-Instance` header hash. |
| Signature input bytes | DKIM2 Section 9.6 and M3 | M4 calls `canonical.SignatureInput` for the selected target signature and does not reimplement ordering, WSP deletion, or null-signature rendering. |
| Message-Instance parsing and sequence rules | DKIM2 Sections 7, 11.2, and 11.4 and M2 | M4 consumes `instance.Extract` results and treats missing origin, duplicate numbers, gaps, and unreferenced higher instances as fail-closed verification errors. |
| DKIM2-Signature parsing and sequence rules | DKIM2 Sections 8, 11.2, and 11.4 and M2 | M4 consumes `signature.Extract` results and treats missing origin, duplicate sequences, gaps, and malformed fields as fail-closed verification errors. |
| Cryptographic signature verification | DKIM2 Sections 3.4 and 11.6 and architecture Section 11.2 | M4 verifies all implemented algorithms, ignores unimplemented algorithms for aggregate success, and reports each signature-set outcome. |
| Hash validation | DKIM2 Section 11.7 and M3 | M4 validates current body and header hashes for the target instance before treating a signature as protocol success. |
| Current envelope check | Current DKIM2 draft-04 Sections 9.2 and 11.4, tied to parsed `mf=` and `rt=` tags | M4 compares the highest/current signature `mf=` to the supplied reverse-path and requires every current forward-path to occur in signed `rt=`. ASCII domain bytes are lowercased for comparison; local-part and non-ASCII bytes remain case-sensitive. Additional signed recipients are allowed and recipient order is irrelevant. No Milter implementation is included. |
| Signing-domain alignment | DKIM2 Sections 8.8, 9.4, and 11.4 | M4 checks exact or DNS-label-boundary suffix alignment between canonical `d=` and the signed `mf=` domain, skips the check for `mf=<>`, and emits only bounded alignment facts. |
| Timestamp check | DKIM2 Sections 8.4 and 11.3 plus architecture Sections 9, 11.4, and 12.1 | M4 applies an injected clock, a five-minute future tolerance, and the draft-recommended 14-day default maximum age. |
| Key record and algorithm context | DKIM2 DNS draft Section 3.2, only as context | M4 models static public keys by `(domain, selector, algorithm)` and rejects mismatched key type or disabled algorithm. DNS lookup and TXT parsing remain M6. |

### Verification Inputs

M4 supports one internal trust shape: `Request.Message` is the sole protocol
authority. The verifier extracts M2 instances and signatures from that message,
validates sequence/reference rules, and passes the freshly derived state only
through an unexported verification path. There is no exported or test-only API
that combines one message with caller-supplied parsed slices from another
message. Public facade APIs remain deferred.

The request must include current SMTP envelope data when envelope checking is
enabled. Envelope values are byte strings representing RFC 5321 paths:

- Reverse-path is `<>` or `<local@domain>` including angle brackets.
- Forward-path entries are `<local@domain>` including angle brackets.
- SMTP parameters are out of scope for M4 and must not be silently mixed into
  path comparisons.
- EAI/SMTPUTF8-capable bytes are preserved. M4 lowercases only ASCII domain
  bytes for envelope comparison; it must not apply Unicode normalization,
  IDNA mapping, local-part normalization, Unicode case folding, recipient
  sorting, or recipient deduplication.

### Target And Current Signature Selection

M4 must distinguish target verification from current-envelope verification:

- The highest/current DKIM2 signature is the parsed signature with the largest
  contiguous `i=` sequence after M2 sequence validation.
- Current inbound verification checks the highest/current signature by
  default.
- An explicit target sequence may be accepted for unit tests, diagnostics, and
  M5 partial verification support.
- If a target sequence is requested, M4 verifies the selected signature input
  for that target sequence and validates the `Message-Instance` referenced by
  that signature's `m=` value.
- If an explicit non-current target references an older `m=` than the current
  message instance, M4 returns typed `unsupported_target` state before hashing
  current message bytes. Historical reconstruction remains unavailable.
- Envelope matching is mandatory for the highest/current signature in default
  inbound mode. For non-current target diagnostics, envelope matching may be
  disabled only by an explicit option and must produce a result fact stating
  that the current-envelope check was not applicable.
- A missing `Message-Instance` target, missing `DKIM2-Signature` target,
  duplicate target, sequence gap, or unreferenced current instance is a
  fail-closed verification error.

### Body And Header Hash Validation

M4 must validate message hashes before reporting cryptographic protocol
success for a target signature:

- Select the `Message-Instance` whose `m=` equals the target signature's
  `m=` reference.
- Find the known `sha256` hash set in that instance.
- Compute current body and header SHA-256 values through M3 canonical helpers.
- Compare digest bytes in constant time where practical for fixed-length
  values.
- Report body hash mismatch and header hash mismatch separately.
- Treat missing known `sha256` hash set, malformed parser-owned hash state,
  unsupported hash algorithm, or digest length mismatch as fail-closed.
- Preserve unknown hash algorithms as non-success data; do not accept a
  message because an unknown hash is present.

Recipe-based previous-instance reconstruction is out of scope. If a target
signature references a previous instance whose content cannot be validated
without recipe application, M4 must report that as unsupported or deferred
rather than inventing success. The default M4 acceptance path is the current
message state and target instance whose body/header hashes can be computed
from the available M1 raw message.

### Signature Input Verification

M4 must build cryptographic input through `lib/internal/canonical`:

- Use `canonical.SignatureInput` with the authoritative M1 `HeaderBlock` and
  target `i=` sequence. M3 reparses and validates all protocol fields from that
  block; M4 supplies no independently trusted parsed slices.
- Do not parse or render DKIM2 tag lists again except through M3 APIs that
  already own Section 9.6 rendering.
- Do not include regular message headers or body bytes in cryptographic
  signature input. Message content is covered indirectly through
  `Message-Instance` hashes.
- Treat canonicalization errors as fail-closed verification errors.
- Preserve the M3 contract that the incomplete target `DKIM2-Signature` field
  nulls every signature value inside `s=`. If draft review or vectors prove
  per-algorithm nulling is required, update the M3 and M4 specs plus
  draft-versioned golden vectors before changing behavior.

### Algorithm And Public-Key Semantics

The default M4 algorithm allowlist is exact:

- `rsa-sha256`
- `ed25519-sha256`

Unknown algorithms, disabled algorithms, or known algorithms without a usable
matching public key cannot produce success.

RSA-SHA256 semantics:

- The provider must supply an RSA public key for `rsa-sha256`.
- The verifier calculates SHA-256 over the Section 9.6 canonical signature
  input bytes and verifies the decoded `s=` signature with PKCS#1 v1.5
  SHA-256 verification from Go's `crypto/rsa`.
- RSA public keys must pass an explicit size policy before use. The initial
  verifier minimum is 1024 bits so the reference implementation can validate
  the DKIM2 draft-required 1024 through 2048 bit range. Larger keys may also
  be accepted.
- RSA verification failure is a typed cryptographic failure, not a parser
  failure, and must not leak signature bytes or key material.

Ed25519-SHA256 semantics:

- The provider must supply an Ed25519 public key for `ed25519-sha256`.
- The parser already enforces 64-byte Ed25519 signature values. M4 must also
  validate the public key length and type before use.
- The verifier calculates SHA-256 over the Section 9.6 canonical signature
  input bytes and checks the decoded `s=` signature over the native 32-byte
  digest using Go's `crypto/ed25519`. This follows the active draft text that
  defines Ed25519-SHA256 as PureEdDSA over the SHA-256 hash value, not over
  the raw canonical signature input bytes.

Provider and key matching:

- Static keys are matched by canonical signing domain `d=`, selector, and
  algorithm.
- Domain and selector comparisons use the canonical parser views produced by
  M2. M4 must not add wildcard matching, parent-domain fallback, IDNA mapping,
  or case-insensitive local-part behavior.
- A key for the wrong domain, wrong selector, wrong algorithm, wrong Go key
  type, too-small RSA modulus, or invalid Ed25519 length is a typed
  non-success state.
- A nil-error provider result is successful only when `PublicKey.Algorithm`
  exactly equals the requested algorithm and `Metadata.Status` is `found`.
  Any mismatch is an invalid-key non-success state before material use.
- Provider lookup errors must distinguish missing key, ambiguous key,
  invalid key, unsupported algorithm, and internal provider error. With the
  static provider, no temporary network state exists.
- Provider APIs may be context-aware to prepare for M6, but M4 static provider
  tests must remain deterministic and must not perform network or filesystem
  I/O.

### Multi-Signature Behavior

`DKIM2-Signature` `s=` can contain multiple signature sets. M4 must implement
all-checkable-signatures semantics:

- For the selected target signature field, enumerate every signature set in
  field order.
- Ignore unknown algorithms for success, but record that they were present and
  unsupported using the fixed bounded algorithm token `unknown`; do not retain
  attacker-controlled algorithm strings in result facts.
- For known allowed algorithms, attempt static key lookup by domain, selector,
  and algorithm.
- A known allowed signature set with a matching key is checkable and must be
  cryptographically verified.
- A known allowed signature set with a missing key is a non-success result
  fact. It must not be counted as pass.
- If at least one checkable signature passes and another checkable signature
  fails, the target signature result is mixed and must not be collapsed to a
  simple pass.
- If no signature set is checkable, the target signature result is
  indeterminate or fail-closed depending on the result taxonomy chosen by
  implementation; it must not be pass.
- If all checkable known signature sets pass, and hash, timestamp, envelope,
  sequence, and key-policy checks also pass, the target may be reported as
  cryptographically verified for M4.
- M4 result facts must preserve per-algorithm and per-selector statuses
  without exposing raw selector names in future default telemetry. Unit test
  assertions may use synthetic selector strings.

This multi-signature behavior prepares M5 result mapping. It does not yet
define local policy such as accepting a message with one passing algorithm and
one missing optional key.

### Timestamp Policy

M2 parses `t=` as unsigned Unix seconds. M4 must add deterministic verification
policy:

- The verifier must receive a clock through constructor injection or an option.
  The default can be `time.Now` for production use, but tests must inject a
  fixed clock.
- Timestamp conversion must reject values that cannot be represented safely as
  a Go `time.Time` or would overflow internal arithmetic.
- Future timestamps fail if `t=` is later than `now + future_tolerance`.
- Stale timestamps fail if a maximum age is configured and
  `now - t > max_age`.
- The M4 default maximum age is 14 days per DKIM2 Section 11.3 and the
  default future tolerance is 5 minutes. Both values are explicit in package
  options and deterministic tests.
- Timestamp checks return typed statuses: pass, future, expired, malformed
  parsed state, disabled/not configured, or not applicable for non-current
  diagnostic targets.
- Timestamp errors must not include raw header fields, nonces, recipients, or
  unbounded time strings.

The 14-day default implements the draft's Section 11.3 SHOULD. Operators may
configure a different positive maximum or explicitly disable it, but such a
change is local policy and does not alter the draft-versioned default.

### Envelope Checks

The current SMTP envelope is mandatory for default inbound verification of the
highest/current DKIM2 signature. M4 must:

- Compare the current reverse-path with decoded `mf=` from the highest/current
  `DKIM2-Signature`, lowercasing ASCII domain bytes before comparison while
  preserving local-part case and every non-ASCII byte.
- Require every forward-path actually used in the current SMTP delivery to be
  present in decoded `rt=`. Signed `rt=` may contain additional recipients,
  and recipient order does not affect the result.
- Treat missing current envelope, missing reverse-path, missing recipients,
  a current recipient absent from signed `rt=`, reverse-path mismatch, empty
  path outside the null reverse-path syntax, or parser-owned invalid path state
  as fail-closed.
- Do not perform Unicode case folding, Unicode normalization, IDNA mapping,
  local-part normalization, recipient sorting, or
  recipient deduplication.
- Separately apply the draft's relaxed DNS-label-boundary match between `d=`
  and the domain recorded in `mf=`. Lowercase ASCII domain bytes, accept only
  exact or dot-boundary suffix alignment, and skip this check for `mf=<>`.
- For every non-highest signature using `nd=`, require its canonical value to
  equal the immediate successor signature's canonical `d=` exactly. Missing
  successors and mismatches fail closed without exposing either domain.
- Do not apply SMTP envelope or `d=`/`mf=` alignment checks to an `nd=`
  signature. A highest/current signature using `nd=` requires out-of-band
  acceptance under Sections 9.3 and 11.4; because M4 has no OOB option, return
  a typed unsupported non-success fact rather than PASS.
- Avoid logging or exposing raw sender paths, recipient paths, local parts, or
  recipient lists in errors or default result strings.
- Keep Milter callback fidelity out of M4. M4 receives an already supplied
  current-envelope value; `cmd/dkim2-milter` later owns how that evidence is
  collected and diagnosed.

For explicit non-current target diagnostics, M4 may allow envelope checks to
be skipped only with a typed option and visible result fact. This must not be
the default inbound behavior.

### Result And Error Taxonomy

M4 should define typed, bounded verification facts that M5 can map into the
public result model. Recommended result dimensions:

- Overall target status:
  `pass`, `fail`, `mixed`, `indeterminate`, or `error`.
- Parser/sequence status:
  raw message, instances, signatures, references.
- Hash status:
  body hash, header hash, selected hash algorithm.
- Signature status:
  per signature set, algorithm, selector class, key status, crypto status.
- Timestamp status:
  pass, future, expired, disabled, malformed, not applicable.
- Envelope status:
  pass, missing input, reverse-path mismatch, recipient value mismatch, not
  applicable.
- Key status:
  found, missing, ambiguous, invalid, wrong type, policy rejected, provider
  error.
- Error class:
  malformed, missing, duplicate, unsupported, mismatch, crypto, key,
  timestamp, envelope, limit, internal.

Typed errors and result strings must not include:

- Raw RFC 5322 messages.
- Raw body content.
- Raw header values.
- Full canonical byte inputs.
- Full `Message-Instance` fields.
- Full `DKIM2-Signature` fields.
- Decoded `mf=` or `rt=` paths.
- Raw sender or recipient local parts.
- Full recipient lists.
- Raw nonces.
- Raw signature bytes.
- Public-key material when it may identify tenants.
- Private keys, tokens, passwords, protected config values, or unbounded
  error strings.

M4 may include small allowlisted tokens such as algorithm names, check status
names, bounded sequence numbers, bucketed sizes, and synthetic test fixture
names where needed.

## Package Boundaries

Intended ownership:

- `lib/internal/verify`:
  Owns the M4 verification coordinator, request/result types, static key
  provider interface, in-memory static provider fixture, algorithm allowlist,
  key validation, RSA/Ed25519 cryptographic checks, timestamp policy,
  envelope comparison, hash comparison, per-signature-set statuses, typed
  verification errors, and package documentation.
- `lib/internal/rawmsg`:
  Remains the source of truth for byte-preserving RFC 5322 message
  representation. M4 consumes `Message`, `HeaderBlock`, and `Body` accessors
  and must not alter raw parsing or CRLF policy.
- `lib/internal/tagvalue`:
  Remains the owner of generic DKIM2 tag-list scanning and base64string
  parsing. M4 consumes immutable decoded signature, hash, and envelope
  containers through M2 types and must not implement parallel base64 parsing.
- `lib/internal/instance`:
  Remains the owner of `Message-Instance` parsing, hash-set parsing,
  optional recipe base64 containers, and `m=` sequence validation. M4 invokes
  extraction from `Request.Message`, consumes only those freshly parsed
  instances, and may add no parallel `h=` parser.
- `lib/internal/signature`:
  Remains the owner of `DKIM2-Signature` parsing, signature-set parsing,
  envelope containers, flags, nonces, and `i=` sequence validation. M4 invokes
  extraction from `Request.Message`, consumes only those freshly parsed
  signatures, and may add no parallel `s=`, `mf=`, or `rt=` parser.
- `lib/internal/canonical`:
  Remains the single source of truth for Section 6.1, Section 6.2, and
  Section 9.6 byte transformations plus SHA-256 digest containers. M4 consumes
  these helpers and must not duplicate canonicalization.
- `lib/internal/keyresolver`:
  Does not change in M4 unless implementation evidence strongly favors placing
  only an interface there. DNS lookup, DNS key record parsing, resolver cache
  policy, and network failure taxonomy remain M6.
- `lib/internal/policy`, `lib/internal/service`, `lib/internal/datasource`,
  `lib/internal/recipe`, and `lib/internal/observability`:
  Do not change in M4.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl`:
  No M4 code changes.

Generated REST DTOs must stay at HTTP boundaries. Core DKIM2 packages must not
import generated OpenAPI types, Cobra, Viper, Fx, Prometheus, OTLP exporters,
Milter packages, SQL drivers, LDAP drivers, Valkey clients, or CLI frameworks.

### API Ownership Sketch

The concrete names are implementation details, but the durable ownership
shape is:

- `Verifier` or equivalent cohesive type owns validated verification options
  and dependencies.
- `KeyProvider` is a narrow interface for lookup by canonical domain,
  selector, and algorithm. It returns public key material plus safe metadata
  or typed key errors.
- `StaticKeyProvider` or equivalent in-memory implementation is deterministic
  and used by unit/vector tests.
- `Clock` or `Now func() time.Time` is injected for timestamp tests.
- `Envelope` stores current reverse-path and forward-path byte slices with
  immutable accessors.
- `Result` stores per-check facts and does not require string parsing by
  callers.

`lib/internal/verify` may import standard-library packages such as
`context`, `crypto`, `crypto/rsa`, `crypto/ed25519`, `crypto/sha256`,
`crypto/subtle`, `errors`, and `time`, plus M1-M3 internal packages. It must
not import command/service/runtime packages.

## Security And Privacy

Default behavior is restrictive:

- Missing DKIM2 protocol fields fail closed through M2 extraction.
- Message-Instance and DKIM2-Signature sequence gaps fail closed.
- Missing target instances, missing target signatures, duplicate targets, and
  unreferenced current instances fail closed.
- Missing known `sha256` hash sets fail closed for M4 success.
- Body hash mismatch and header hash mismatch fail closed.
- Unsupported algorithms cannot create success.
- Disabled algorithms cannot create success.
- Missing keys cannot create success.
- Ambiguous or invalid keys fail closed.
- Nil-error provider responses with a mismatched algorithm or status other
  than `found` fail closed before public-key material is used.
- RSA keys below the configured verifier minimum bit length fail closed.
- Ed25519 public keys with the wrong type or length fail closed.
- Signature verification failures fail closed.
- Current-envelope mismatch fails closed in default inbound mode.
- Future or expired timestamps fail according to explicit timestamp policy.
- Static key providers must copy or encapsulate key material so callers cannot
  mutate verifier-owned state after construction.
- Parser, canonicalization, provider, and crypto errors are wrapped or mapped
  into typed bounded verification errors without raw message-derived values.
- Synthetic tests must not contain live messages, production recipients,
  production domains, real tenant selectors, private keys, tokens, passwords,
  or protected config values.
- Private keys are not needed in production M4 code. Test vectors may generate
  private keys inside tests or use synthetic fixture keys, but private key
  material must not be logged, returned, stored in docs, or emitted in errors.

Recommended initial resource and policy defaults:

| Setting | Initial default |
| --- | ---: |
| Maximum checked signature sets per target | 16, matching M2 parser default |
| Minimum RSA public key size | 1024 bits |
| Allowed algorithms | `rsa-sha256`, `ed25519-sha256` |
| Future timestamp tolerance | 5 minutes |
| Maximum timestamp age | 14 days |
| Current-envelope check | required for highest/current inbound target |

If implementation evidence shows these defaults are not practical, update this
spec before changing behavior.

## Observability

M4 should not add concrete logging, metrics, tracing, Prometheus labels,
OpenTelemetry exporters, or debug modules. `verify` may expose structured
errors, result facts, and bounded metadata that future observers can safely
classify.

Allowed future observation facts from M4 state are low-cardinality or bucketed:

- Verification result class.
- Draft baseline.
- Target sequence bucket or exact small sequence number when safe.
- Target instance bucket or exact small instance number when safe.
- Algorithm name from the allowlist.
- Check kind: body hash, header hash, signature, timestamp, envelope, key.
- Check status.
- Key status class.
- Error code.
- Error class.
- Signature set count bucket.
- Checked signature set count bucket.
- Current-envelope check enabled/disabled/not applicable.
- Timestamp policy enabled/disabled.
- Input and canonical byte size buckets.

Forbidden observation values include:

- Raw RFC 5322 messages.
- Raw body content.
- Raw header values.
- Full canonical header input.
- Full canonical body input.
- Full canonical signature input.
- Raw `Message-Instance` fields.
- Raw `DKIM2-Signature` fields.
- Raw `mf=` or `rt=` decoded paths.
- Raw sender or recipient local parts.
- Full recipient lists.
- Raw nonce values.
- Raw hash values.
- Raw signature values.
- Raw public-key bytes.
- Private keys, tokens, passwords, protected config values, and datasource
  secrets.
- Raw or unbounded error strings.

Prometheus labels, when added by later milestones, must remain on a strict
low-cardinality allowlist and must not include identity values, raw hashes,
raw errors, or message-derived strings.

## Required Tests

Unit tests:

- Verifier construction rejects nil key providers, nil clocks when a clock is
  required, RSA minimum sizes below 1024 bits, unknown enabled algorithms,
  and unsafe timestamp options.
- Static key provider stores and looks up keys by canonical domain, selector,
  and algorithm.
- Static key provider rejects duplicate keys for the same lookup tuple.
- Static key provider rejects RSA keys below the configured verifier minimum
  size.
- Static key provider rejects Ed25519 keys with wrong length or wrong type.
- Algorithm allowlist accepts only `rsa-sha256` and `ed25519-sha256` by
  default.
- Unknown `s=` algorithms are represented as unsupported and cannot produce
  success; result facts expose only the fixed `unknown` token.
- Nil-error provider results with a mismatched `PublicKey.Algorithm` or
  missing `found` metadata are invalid-key non-success states.
- Missing keys for known algorithms produce typed non-success key results.
- Wrong key type for an algorithm fails closed.
- RSA-SHA256 positive vector verifies with a static RSA public key.
- RSA-SHA256 negative vectors fail for wrong key, modified signature input,
  modified signature bytes, unsupported algorithm, too-small RSA key, and
  missing key.
- Ed25519-SHA256 positive vector verifies with a static Ed25519 public key.
- Ed25519-SHA256 negative vectors fail for wrong key, modified signature
  input, modified signature bytes, wrong public key length, unsupported
  algorithm, and missing key.
- Current body hash comparison passes when M3 body digest matches the selected
  `Message-Instance`.
- Current body hash comparison fails when the message body changes after
  signing.
- Current header hash comparison passes when M3 header digest matches the
  selected `Message-Instance`.
- Current header hash comparison fails when a signed header changes after
  signing.
- Missing `sha256` hash set, unknown-only hash sets, and digest length
  mismatch cannot produce success.
- Signature input verification uses M3 Section 9.6 bytes and does not include
  regular message headers or body bytes directly.
- Highest/current signature is selected by largest contiguous `i=` sequence.
- Explicit target sequence verifies the selected signature without treating
  later signatures as part of that target input only when current message
  bytes suffice; an older referenced `m=` returns typed `unsupported_target`
  before current-byte hashing.
- Missing target signature, missing target instance, duplicate target, and
  sequence gap fail closed.
- Multi-signature target with all checkable known signatures passing reports
  pass for the signature-set dimension.
- Multi-signature target with a passing implemented algorithm and an unknown
  algorithm reports aggregate pass while preserving the ignored unknown fact.
- Multi-signature target with one checkable pass and one checkable fail reports
  mixed and not simple pass.
- Multi-signature target with only unknown algorithms reports unsupported or
  indeterminate, not pass.
- Multi-signature target with known algorithm but missing key reports missing
  key and not pass.
- Timestamp check passes for `t=` within allowed window.
- Timestamp check fails for future `t=` beyond tolerance.
- Timestamp check fails for stale `t=` when max age is configured.
- Timestamp check passes at exactly 14 days and fails one second beyond the
  default maximum.
- Timestamp arithmetic handles large parsed values without overflow.
- Current envelope check passes when `mf=` matches after ASCII domain
  lowercasing and every current recipient occurs in signed `rt=`.
- Current envelope check permits additional signed recipients and ignores
  recipient order.
- Current envelope check fails on missing envelope, reverse-path mismatch, or
  a current recipient absent from signed `rt=`.
- Signing-domain alignment accepts exact and label-boundary suffix matches,
  rejects lookalike suffixes, and is not applicable for `mf=<>`.
- The highest current `i=` references the highest current `m=`; a decreasing
  reference fails closed as the draft-versioned Section 8.2 interpretation.
- Envelope comparison preserves case-sensitive local-part and EAI-capable
  bytes and does not apply Unicode/IDNA normalization, sort, deduplicate, or
  parse local parts.
- Error strings and result summaries do not include raw body content, full raw
  header values, DKIM2 field values, decoded envelope paths, recipient local
  parts, recipient lists, nonces, signatures, public-key bytes, private keys,
  or secret marker strings.
- Accessor immutability: mutating returned result, envelope, key metadata, or
  digest byte slices cannot mutate verifier-owned state.
- Protocol-source coherence: same-number parsed objects originating from a
  different message cannot be injected into verification or canonical input.

Golden or vector tests:

- Draft-versioned static RSA vector with synthetic message, envelope,
  `Message-Instance`, `DKIM2-Signature`, public key, and expected per-check
  result.
- Draft-versioned static Ed25519 vector with synthetic message, envelope,
  `Message-Instance`, `DKIM2-Signature`, public key, and expected per-check
  result.
- Negative crypto vector table for body hash mismatch, header hash mismatch,
  wrong RSA key, wrong Ed25519 key, missing key, unsupported algorithm, stale
  timestamp, future timestamp, envelope mismatch, and mixed multi-signature
  outcome.
- Vector metadata must name `draft-ietf-dkim-dkim2-spec-04`.
- Test fixtures must be synthetic and must not contain private-key material in
  durable docs. If test private keys are needed, generate them inside tests or
  keep them in package-local test fixtures with clear synthetic labels and no
  reuse outside tests.

Fuzz and abuse tests:

- Fuzz the static-key verifier request path with synthetic messages and
  bounded parser/canonical/verification limits where practical.
- Fuzz or table-test key-provider lookup tuples with malformed but
  parser-shaped domains, selectors, algorithms, duplicate tuples, and wrong
  key types.
- Fuzz or table-test timestamp arithmetic near Unix epoch, current time,
  future tolerance boundary, configured maximum age boundary, and large
  uint64 parsed values.
- Abuse tests for many signature sets up to M2 limits, no checkable
  signatures, repeated missing-key lookups, and secret-marker diagnostics.
- Assert no panics, no unbounded memory growth, deterministic error classes,
  no caller input mutation, and no raw input leakage in error strings.

Integration or E2E tests:

- None required for daemon, Milter, OpenAPI, DNS, datasource, replay, or CLI.
- The M4 proof is library-only unit, vector, negative, and fuzz-smoke
  coverage.
- M5 will add the first MVP core verification vertical slice and public result
  coordination.

Generated and documentation checks:

- No OpenAPI generated artifacts are touched.
- Package documentation for `lib/internal/verify` must describe the static-key
  verification ownership contract, draft baseline, M1-M3 dependency chain,
  algorithm allowlist, key-provider abstraction, timestamp policy, envelope
  matching, multi-signature semantics, and secret-safe diagnostics.
- All changed or added hand-written named functions and receiver methods must
  have concise English doc comments.

Final gate:

- `make guardrails`
- `git diff --check`
- `git status --short`

If `make guardrails` cannot run because a tool such as `golangci-lint` is not
installed, run the largest equivalent subset through Makefile targets and
document the exact blocker.

## Acceptance Criteria

- `lib/internal/verify` owns static-key DKIM2 signature verification
  coordination without duplicating M1 raw parsing, M2 tag parsing, or M3
  canonicalization.
- Static public-key lookup is injectable, deterministic, and keyed by
  canonical domain, selector, and algorithm.
- Default algorithm allowlist is exactly `rsa-sha256` and
  `ed25519-sha256`.
- RSA-SHA256 verification uses SHA-256 over M3 Section 9.6 bytes and Go
  standard-library RSA PKCS#1 v1.5 verification.
- Ed25519-SHA256 verification uses SHA-256 over M3 Section 9.6 bytes and Go
  standard-library Ed25519 verification over the native digest bytes.
- RSA and Ed25519 public keys are type-checked and policy-checked before
  cryptographic use.
- Current body and header hashes are computed through M3 and compared against
  the selected M2 `Message-Instance` `sha256` hash set.
- The highest/current `DKIM2-Signature` is selected by contiguous `i=`
  sequence for default inbound verification.
- Explicit target sequence support exists for diagnostics and M5 coordination
  without weakening default current-envelope verification.
- The highest/current DKIM2 signature envelope matches current draft-04
  Sections 9.2 and 11.4 in default inbound mode: `mf=` matches with ASCII
  domain case folding, and every current recipient is present in signed `rt=`
  regardless of order or additional signed recipients.
- Timestamp checks use an injected clock and explicit tolerance/age policy.
- Multi-signature behavior checks every known, allowed, key-backed signature
  set and reports mixed/unsupported/missing-key states without collapsing them
  to pass.
- Verification errors and result facts are typed, bounded, and secret-safe.
- No daemon, Milter, OpenAPI, CLI, datasource, DNS, concrete observability
  exporter, Valkey, SQL, LDAP, or service-only dependency leaks into `lib`.
- Unit, negative crypto vector, golden/vector, abuse, and fuzz-smoke tests
  cover the M4 behavior named in `docs/ARCHITECTURE.md`.
- `make guardrails` passes, or skipped portions are explicitly justified with
  narrower passing commands.
- Prompt timings are recorded in the measured effort table during closeout.

## Completion Evidence

- Independent-review coherence/security follow-up: focused
  `go test ./internal/canonical ./internal/verify -count=1` passed after
  eliminating caller-supplied parsed protocol slices, adding foreign-message
  regression coverage, rejecting unreconstructable historical targets before
  hashing, validating provider success invariants, and sanitizing unknown
  result algorithms to `unknown`.

- Post-closeout draft-04 verifier regression: `GOCACHE=/tmp/dkim2-gocache go
  test ./lib/internal/verify -run
  'TestVerifier(IgnoresUnknownSignatureSetBesideSupportedPass|ReportsUnknownOnlySignatureSets|AggregatesMultipleSignatureSets|ChecksSigningDomainAgainstMailFrom|AppliesTimestampPolicy|RejectsCurrentSignatureReferencingOlderInstance)$'`
  passed, followed by passing `make test` and `make vet`. The regression covers
  ignored future algorithms beside a supported pass, unknown-only and known
  mixed non-success, bounded `d=`/`mf=` alignment, the null reverse-path
  exception, the exact 14-day timestamp boundary, and the highest `i=` to
  highest `m=` interpretation. Test-only clocks are injected at the synthetic
  fixture time so the production `time.Now` default remains unchanged.
- Post-closeout draft-04 envelope regression: `cd lib && go test
  ./internal/verify/... -run
  'TestVerifier(MatchesEnvelopeAccordingToDraft|RequiresUsedRecipientsWithoutOrder|LowercasesOnlyEnvelopeDomains)$'`
  passed; `TestVerifierNegativeVectors/unsigned_recipient_mismatch` also
  passed, followed by a passing full `go test ./internal/verify/...` run. The
  regression covers signed-recipient supersets, order-independent
  current-recipient membership, missing used recipients, ASCII-only domain case
  folding, case-sensitive local parts, and no Unicode normalization.
- Draft-04 `nd=` regression: focused tests cover exact canonical `nd=` to next
  `d=` success for an intermediate target, typed mismatch and missing-successor
  failures with domain-free diagnostics, terminal OOB-required unsupported
  state, and not-applicable envelope/domain-alignment facts. Focused normal and
  race runs with `-run
  'NextDomain|SigningDomainAgainstMailFrom|CanSkipEnvelope'` pass, as does the
  focused `go vet ./internal/verify` check.
- Focused tests: `cd lib && GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache go test ./internal/verify/...` passed.
- Focused dependency tests: `cd lib && GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache go test ./internal/rawmsg/... ./internal/tagvalue/... ./internal/instance/... ./internal/signature/... ./internal/canonical/... ./internal/verify/...` passed.
- Golden/vector tests: covered by `lib/internal/verify/vector_test.go`, `crypto_test.go`, and `negative_test.go`; `go test ./internal/verify/...` passed.
- Fuzz-smoke: `cd lib && GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache go test ./internal/verify/... -run '^$' -fuzz=FuzzVerifyStaticKeyRequest -fuzztime=10s` passed.
- Generated checks: OpenAPI/command surfaces were not changed; `git diff -- docs/specs/openapi cmd` and `git status --short docs/specs/openapi cmd` were empty, and `make guardrails` passed `check-openapi`.
- Library dependency check: `cd lib && go list -f '{{join .Imports "\n"}}' ./internal/verify` showed only standard-library imports plus M1-M3 internal packages (`canonical`, `instance`, `rawmsg`, `signature`); no service-only dependencies were present.
- Final gates: `make test`, `make vet`, `make lint`, `make race`, and `make guardrails` passed with `/private/tmp/dkim2-gocache` and `/private/tmp/dkim2-golangci-cache`.
- `git diff --check`: passed.
- `git status --short`: run during closeout; dirty state remains expected because M1-M4 files are not staged or committed.
- Skipped checks: none.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Work stays inside `lib/internal/verify`, package-local tests, package-local testdata, and this spec unless a documented M1-M3 defect requires a spec update first | M4 implementation is contained in `lib/internal/verify`; closeout also updated this durable spec, prompt ledger, and corrected stale package documentation. | done | No command modules, OpenAPI contracts, generated artifacts, DNS resolver, datasource, Milter, recipe, replay, policy, or concrete observability code changed. |
| Behavior | Static-key RSA-SHA256 and Ed25519-SHA256 verification, hash validation, timestamp checks, envelope checks, and multi-signature semantics follow the bound draft sections plus architecture decisions | RSA uses SHA-256 plus PKCS#1 v1.5 over M3 Section 9.6 bytes; Ed25519 verifies over SHA-256 digest bytes; RSA minimum is 1024 bits; envelope matching follows current draft-04 Sections 9.2 and 11.4 recipient membership and ASCII domain-case rules; M2 state is freshly extracted from `Request.Message` and M3 canonical helpers reparse the same authoritative header block. | done | Covered by focused verify tests, crypto tests, vector tests, negative tests, timestamp/envelope/multisignature tests, and final gates. |
| Tests | Unit, negative crypto vector, golden/vector, abuse, immutability, and fuzz-smoke coverage exist | `lib/internal/verify` includes vector, negative, abuse, immutability, diagnostic, hash, crypto, key, timestamp, envelope, multisignature, and fuzz tests. | done | Focused tests, dependency tests, fuzz smoke, `make test`, `make vet`, `make lint`, `make race`, and `make guardrails` passed. |
| Security | Fail-closed and secret-safe behavior is preserved | Missing keys, unsupported/disabled algorithms, provider invariant failures, mismatches, unreconstructable historical targets, timestamp failures, envelope failures, and crypto failures are non-success states; diagnostic tests cover synthetic secret markers. | done | Message bytes are the sole protocol authority; result facts use fixed `unknown` for attacker-controlled algorithms and do not expose raw messages, headers, paths, recipients, signatures, public-key bytes, or private keys. |
| Boundaries | Module and generated-code boundaries hold | `lib/internal/verify` imports only standard library plus `canonical`, `instance`, `rawmsg`, and `signature`; OpenAPI and command module diffs are empty. | done | No service-only, generated REST DTO, Milter, DNS, datasource, recipe, replay, policy, Valkey, SQL, LDAP, CLI, Prometheus, or OTLP dependency entered `lib`. |
| Observability | Only bounded result facts and errors exist; no concrete exporters or high-cardinality labels | M4 added structured result/error facts only; no logging, metrics, tracing, exporters, debug modules, or labels were added. | done | Future observability remains a mapping layer over bounded M4 facts. |
| Effort | Prompt timings are measured and compared to the 4 to 8 agent-day estimate | Productive implementation prompts took 50m20s; total including spec and prompt-pack preparation took 1h02m45s. | done | Actual measured wall-clock is far below estimate due to tight scope, standard-library crypto, and no adapter/service expansion. |

## Decisions And Open Questions

- Settled: M4 adds `lib/internal/verify` as the coordinator for static-key
  verification rather than moving cryptographic verification into
  `signature` or `canonical`.
- Settled: `signature` remains the owner of `DKIM2-Signature` parsing,
  envelope containers, signature sets, flags, nonces, and `i=` sequence
  validation.
- Settled: `canonical` remains the owner of body hash input, header hash
  input, signature input, and SHA-256 digest containers.
- Settled: M4 consumes M1-M3 immutable accessors and does not implement a
  second raw parser, tag parser, base64 parser, hash canonicalizer, or
  signature-input renderer.
- Settled: `Request.Message` is the sole verification protocol authority.
  Exported caller-parsed input is forbidden, and M3 reparses canonical input
  fields from the same message header block.
- Settled: Static keys are matched by canonical `d=`, selector, and
  algorithm.
- Settled: The default M4 algorithm allowlist is `rsa-sha256` and
  `ed25519-sha256`.
- Settled: RSA-SHA256 verification uses SHA-256 plus PKCS#1 v1.5 over M3
  Section 9.6 signature input bytes.
- Settled: Ed25519-SHA256 verification uses Ed25519 over SHA-256 digest bytes
  of M3 Section 9.6 signature input, not over raw signature input bytes.
- Settled: RSA verifier keys must be at least 1024 bits by default so M4 can
  validate the active draft-required 1024 through 2048 bit range.
- Settled: Current-envelope matching follows current draft-04 Sections 9.2 and
  11.4: ASCII domain bytes are lowercased, local-part and non-ASCII bytes remain
  case-sensitive, every current recipient must occur in signed `rt=`, signed
  extras are allowed, and recipient order is irrelevant.
- Settled: Timestamp policy is explicit local verification policy over parsed
  `t=`, using an injected clock, a five-minute future tolerance, and a 14-day
  default maximum age per Section 11.3.
- Settled: Unknown signature algorithms are ignored for aggregate success per
  Section 3.4 while their bounded per-set facts remain visible under the fixed
  `unknown` token. Unknown-only targets remain non-success and known failures
  still prevent pass.
- Settled: Signing-domain alignment follows Sections 8.8, 9.4, and 11.4,
  using ASCII lowercase and exact or dot-boundary suffix comparison; `mf=<>`
  and every `nd=` signature are not applicable.
- Settled: Sections 8.7, 9.3, and 11.4 require exact canonical `nd=` to the
  immediate successor `d=` for non-highest signatures. Terminal `nd=` requires
  OOB acceptance; M4 has no OOB policy option and therefore reports typed
  unsupported non-success rather than PASS.
- Settled: The highest current `i=` must reference the highest current `m=`.
  M4 treats this as the versioned Section 8.2 interpretation and fails closed
  on a decreasing current reference.
- Settled: DNS lookup, DNS TXT key parsing, resolver caching, DNSSEC
  diagnostics, revoked-key handling, and temporary DNS failure taxonomy are
  deferred to M6.
- Settled: Recipe application and previous-instance reconstruction are
  deferred. M4 reports unsupported/deferred state rather than verifying
  previous instances without recipe support.
- Settled: Public facade result mapping is deferred to M5. M4 result facts
  must still be structured enough for M5 to consume without parsing strings.
- Settled: Draft-04 Section 9.6 requires the active M3 signature-input contract
  to null every `s=` signature value in the target field; M4 consumes that
  all-signature rendering without a per-algorithm variant.
- Open: The final public facade shape for static-key verification remains
  deferred until M5 service coordination needs it.
- Open: The exact policy distinction between mixed multi-signature state and
  final acceptance remains deferred to M5/M7. M4 must preserve the facts
  without collapsing them into a local-policy decision.
