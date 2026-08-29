# Replay Store And Valkey Provider

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-06 authority is the migration disposition,
> the current replay runbook, and current durable architecture.

Status: implementation and closeout evidence prepared; external exact-artifact review and commit pending.

Milestone: M12.

Implementation base: commit
`682f44851b075e4c5a3d4837ae46bb3c64bbd64c`.

Language: English.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`, especially Sections 3.4, 5.8, 7.3, 7.4, 7.5,
  12, 13, 15, and 16;
- `docs/specs/implementation/datasource-providers.md`;
- `docs/specs/spec-and-prompt-template.md`;
- `Makefile`;
- `draft-ietf-dkim-dkim2-spec-04`, especially the distinction between
  authenticated message facts and local policy, the relevant
  `Message-Instance` header hash as message identity, and the authenticated
  `exploded` indication;
- RFC 2104 for HMAC;
- RFC 6234 for SHA-256;
- the official Valkey `SET` command contract, including `NX` and `PX`;
- the official Valkey RESP error-prefix contract;
- the official Valkey 9.1 ACL database-permission contract, including
  `ACL SETUSER db=...`, `ACL GETUSER databases`, and database-zero connection
  establishment;
- the official tagged Valkey server `9.1.0` source and wire shape; the reviewed
  source archive SHA-256 is
  `7789fe1df257774457bafb4c1d56c9f7020c3879a7f5b4234af9030b2bd82dfd`;
- `github.com/valkey-io/valkey-go` release `v1.0.77` and its official context
  cancellation and retry documentation.

The implemented and tested DNS behavior remains pinned to the repository's
reviewed historical DNS identifier. Replay storage does not interpret DNS key
records and does not alter that baseline.

Internet-Draft and external dependency identifiers are behavior inputs under
review. A future draft, Valkey server, or client release must not silently
change replay identity, retention, result, error, retry, or privacy semantics.

## Original Gap

M11 supplies exact datasource selection and opaque signing-handle binding, but
the repository has no durable replay-store contract or implementation.

The architecture requires replay detection as an explicit local-policy feature
for the first daemon release. It names Valkey as the default production
backend, while requiring the protocol library to remain independent of Valkey,
Redis-shaped APIs, daemon configuration, and transport credentials.

Without M12 there is no single owner for:

- a storage-neutral `CheckAndRemember` operation;
- first-seen, replayed, disabled, indeterminate, unavailable, and closed
  outcomes;
- privacy-preserving, deployment-bound, versioned replay keys;
- exact retention and non-extension behavior;
- deterministic in-memory and explicit disabled providers;
- one-command Valkey `SET ... NX PX ...` behavior;
- the ambiguity created when a client returns after a command may already have
  reached Valkey;
- bounded lifecycle, concurrency, cancellation, redaction, and abuse behavior;
- provider parity and dependency-direction evidence.

This gap must be closed before daemon, OpenAPI, observability, Milter, or Exim
integration can apply replay policy safely.

## Goal

Implement a small storage-neutral replay domain that records whether one
already-derived local-policy replay identity is observed for the first time
within an exact retention window.

The result must:

- distinguish first-seen from already remembered;
- expose explicit disabled behavior rather than pretending success;
- never claim first-seen or replayed after an indeterminate backend write;
- preserve exact caller cancellation only before a mutation may have been
  dispatched;
- keep raw messages, addresses, protocol headers, signature bytes, selectors,
  nonces, datasource identities, credentials, and protected configuration out
  of keys, values, errors, formatting, and diagnostics;
- use one deterministic privacy-preserving key algorithm with an explicit
  version;
- provide bounded memory and no-op implementations for deterministic use;
- provide a production Valkey implementation without leaking Valkey types into
  the library replay contract;
- remain local policy rather than new DKIM2 protocol conformance.

M12 does not decide whether a replay is accepted, rejected, tempfailed,
quarantined, or observed. Later service and adapter milestones apply local
policy to the sealed replay result.

## Delivery Shape

Implementation is divided into sequential, independently reviewed slices:

1. Public replay contracts, closed errors, limits, retention, and lifecycle.
2. Versioned framed replay identity and HMAC-SHA256 key derivation.
3. Bounded memory and explicit disabled providers.
4. Root-facade exposure and cross-module dependency guards.
5. Valkey command boundary and exact `SET NX PX` result mapping.
6. Valkey lifecycle, indeterminate-write handling, and provider parity.
7. Abuse, fuzz, race, privacy, integration, and durable documentation.
8. Complete guardrails, two exact-snapshot approvals, and one commit.

The ignored prompt pack belongs under `temp/replay-store-valkey-prompts/`.
`temp/` must never be staged or committed.

## Implementation Effort

The architecture calibrates M12 at three to eight agent-hours with high review
and stabilization risk.

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 3-8 agent-hours |
| Highest-risk area | sealed replay identity and uncertain Valkey mutation |
| Expected prompt count | 8 |
| Required final gate | `make guardrails` plus `make test-valkey` |

Risk notes:

- Low risk: closed enum and retention wrappers.
- Medium risk: memory heap, lifecycle, root facade, and dependency guards.
- Highest risk: authenticated recipient-scoped identity, privacy boundary,
  production security evidence, backend authority confinement, and
  indeterminate write handling.

That estimate includes the durable specification, prompt pack, implementation,
focused tests, one real-Valkey integration path, fuzz smoke, race tests,
privacy review, dependency evidence, full guardrails, two exact-snapshot
reviews, and one project-formatted commit.

Prompt start and completion timestamps are recorded in the ignored ledger.
Active engineering time is not inferred from wall-clock spans.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-contracts.md` | 2026-07-24T11:25:59+02:00 | 2026-07-24T11:50:57+02:00 | 24m58s | 24m58s | Exact wall-clock and active time retained. |
| `02-identity.md` | 2026-07-24T11:53:56+02:00 | 2026-07-24T12:46:55+02:00 | 52m59s | 52m59s | Exact wall-clock and active time retained. |
| `03-memory-disabled.md` | 2026-07-24T12:50:03+02:00 | 2026-07-24T13:18:09+02:00 | 28m06s | 28m06s | Exact wall-clock and active time retained. |
| `04-facade-boundaries.md` | 2026-07-24T13:20:38+02:00 | 2026-07-24T14:05:12+02:00 | 44m34s | 44m34s | Exact wall-clock and active time retained. |
| `05-valkey-command.md` | 2026-07-24T14:08:33+02:00 | 2026-07-24T15:30:27+02:00 | 1h21m54s | not separately tracked | Replacement time was not separately retained and is not inferred. |
| `06-valkey-security-lifecycle.md` | 2026-07-24T15:37:03+02:00 | 2026-07-24T19:50:10+02:00 | 4h13m07s | not separately tracked | Work resumed at 2026-07-24T16:38:57+02:00; active time is not inferred. |
| `07-abuse-integration-docs.md` | 2026-07-24T20:50:15+02:00 | 2026-07-24T21:32:04+02:00 | 41m49s | not separately tracked | Exact wall-clock retained; active time is not inferred. |
| `08-closeout.md` | external only | external only | external only | external only | Terminal timing follows candidate freeze and is retained only in the ignored ledger. |

Prompts 01 through 07 total 8h47m27s of measured wall-clock time. This exceeds
the planning estimate's eight-hour upper bound by 47m27s. Prompt 08 remains
external-only so its terminal review, staging, commit, and proof time is not
invented inside the candidate it attests.

## Scope

### In Scope

- A library-internal replay core with a public root-facade contract for
  command-module consumption.
- A narrow storage-neutral store interface.
- Closed result, state, error, retention, and limit types.
- A protected deployment secret and HMAC-SHA256 key deriver.
- Versioned and length-framed synthetic replay identity facts.
- An immutable protected replay key with constant redacted formatting.
- A bounded in-memory provider with injected time.
- An explicit disabled provider.
- A `cmd/dkim2d` Valkey provider using `valkey-go v1.0.77`.
- A production compatibility floor of the ACL database-permission capability
  introduced by official Valkey `9.1.0`.
- Exactly one non-retryable `SET` command with `NX` and `PX`.
- Deterministic handling of OK, null, unexpected, cancelled, timed-out,
  transport-failed, panicking, nil, and contradictory client outcomes.
- Provider lifecycle, concurrent use, close, capacity, retention, and state.
- Provider parity, dependency guards, fuzz, race, abuse, privacy, and mandatory
  real-Valkey integration evidence through an explicit target.
- Durable replay-store documentation and architecture reconciliation.

### Out Of Scope

- Wiring replay identity selection into daemon, Milter, or Exim request
  lifecycles. M12 nevertheless freezes and implements the only permitted
  extraction from an authoritative aggregate current-verification PASS.
- Changing DKIM2 verification, signing, revision, recipe, DNS, datasource, or
  policy semantics.
- Treating replay storage as cryptographic proof or protocol conformance.
- Deciding an SMTP, HTTP, Milter, or Exim disposition.
- Cobra, Viper, Fx, OpenAPI, generated server/client code, daemon routes,
  configuration files, environment expansion, TLS file loading, authentication
  secret loading, readiness aggregation, or service lifecycle wiring. M12
  still defines and enforces the production security attestation that such
  wiring must supply.
- Logs, traces, metrics exporters, Prometheus labels, or debug modules.
- Milter or Exim integration.
- LDAP, SQL, or general datasource changes.
- Active-active consensus, distributed locking, Redlock, multi-key
  transactions, scripts, background scans, or administrative mutation APIs.
- Automatic retries of replay writes.
- Sliding retention or extending TTL when a replay is observed.
- Storing diagnostic records, raw facts, or user-provided values in Valkey.

## Protocol, Runtime, And Domain Semantics

### Local-Policy Boundary

Replay detection is local policy outside DKIM2 cryptographic correctness.

The draft's authenticated `exploded` indication reports legitimate creation of
multiple address-specific copies. When that indication is absent, the draft
allows an MTA to make a local assumption; it does not require one universal
replay disposition.

M12 therefore:

- does not turn the draft's `MAY` into a conformance `MUST`;
- does not use a sender, `Message-ID`, selector, nonce, or creator-private
  `n=` value as replay identity;
- does not classify an authenticated exploded copy as acceptable or abusive;
- derives replay evidence only from the verifier's sealed aggregate current
  PASS and the exact current recipient paths that already passed the
  authenticated envelope check;
- derives one replay key per unique current recipient, so one recipient cannot
  hide another recipient in an aggregate grouping key;
- preserves the authenticated `exploded` bit as a bounded policy fact but does
  not omit, weaken, or change the storage check because of it;
- records the store fact without changing the authoritative verification
  result.

No replay derivation or store mutation is permitted for FAIL, PERMERROR,
TEMPERROR, historical-only, testing-only, incomplete, unknown, or
internal-contract verification state. The sealed evidence is constructed in
the same internal verifier-to-service projection that establishes aggregate
current PASS; callers cannot construct it from public enum values or arbitrary
digests.

### Public Contract

The minimal public root-package contract is intent-shaped:

```go
type ReplayStore interface {
    CheckAndRemember(
        context.Context,
        ReplayKey,
        ReplayRetention,
    ) (ReplayCheck, error)
}

type ManagedReplayStore interface {
    ReplayStore
    State() ReplayStoreState
    Close(context.Context) error
}
```

The names above and the closed behavior in this specification are frozen.
`State` is a bounded lock-free snapshot and never performs network I/O, a
Valkey scan, a map scan, or a blocking wait. There is no portable `Usage`
method in the store interface. Exact memory usage is test-only state owned by
the memory provider; backend capacity and health belong to deployment
readiness.

The operation must not be Valkey-shaped. The domain interface must not expose
`SET`, `NX`, `PX`, pipelines, slots, clients, URLs, passwords, or driver reply
types.

The provider-neutral validation precedence is exact:

1. a nil context is `invalid_request`;
2. a terminal context before admission is `cancelled` or
   `deadline_exceeded`;
3. `closing` or `closed` rejects a new check as `closed`;
4. the disabled provider returns `disabled` without inspecting key or
   retention;
5. enabled providers validate present key and retention, then their
   provider-specific security prerequisites, admission caps, and backend
   readiness in that order. Memory has no production attestation prerequisite.

Every method has a closed result pair:

- success returns one valid result and nil error;
- failure returns a zero result and one valid typed replay error;
- a nonzero result plus error, zero result plus nil, unknown enum, panic, or
  contradictory in-process pair is an internal invariant;
- raw provider errors are never returned or wrapped.

A nil or typed-nil constructor dependency and incomplete constructor
configuration are `misconfigured`; they are not runtime invariant failures.

### Package And Import Graph

The domain ownership is:

```text
lib/internal/replay
  -> standard library only
  -> contracts, errors, limits, identity, key derivation, memory, disabled

lib/internal/verify
  -> constructs verify.ReplayProjection with unexported fields only with
     aggregate current PASS

lib/internal/service
  -> maps verify.ReplayProjection into service.ReplayProjection, whose fields
     and constructor remain unexported outside internal/service

lib package root
  -> maps service.ReplayProjection into unexported fields on VerifyResult
  -> constructs internal/replay identities only through
     ReplayIdentities(VerifyResult)
  -> defines public ReplayStore, ReplayKey, ReplayCheck, error, state,
     retention, deriver, memory, and disabled wrappers

cmd/dkim2d/internal/replay/valkey
  -> github.com/croessner/dkim2 public root facade
  -> github.com/valkey-io/valkey-go v1.0.77
  -> no lib/internal imports
```

No public `lib/replay` package is introduced. This exact graph avoids a
constructor/capability cycle and ensures external callers cannot construct
sealed verifier evidence or a nonzero ReplayIdentity from caller-supplied
digests. Root types are not imported back into any internal package. No
parent/internal import cycle or duplicated replay taxonomy is permitted.

`valkey-go` belongs only to `cmd/dkim2d/go.mod` and workspace vendor output.
It must not appear in `lib/go.mod`.

The dependency review is fixed to `v1.0.77`: Apache-2.0 license, module
`go 1.25.0`, compatible with the repository's Go 1.26 toolchain, and
`golang.org/x/sys v0.43.0` in its module graph. M12 records the direct
dependency rationale, runs license and vulnerability checks against the
vendored graph, and rejects a version or checksum drift without a new review.

`valkey-go v1.0.77` exposes an authoritative server failure as
`*valkey.ValkeyError`, but does not expose a general error-kind accessor.
`ValkeyMessage.Error()` strips an exact leading `ERR ` before producing that
error, and the named helpers cover only a subset of kinds and use prefix
matching. The error string is therefore not authoritative kind evidence.
The same release's `ValkeyResult.ToString()` returns the original untrimmed
message payload as its value alongside that direct typed error, while
`NonValkeyError()` separately reports transport/client failure. `ToString()`
collapses RESP simple and blob strings, so it cannot by itself prove that
`OK` was the required simple-string reply. For that public constant only, the
provider uses the pinned `ValkeyMessage.CacheSize`/`CacheMarshal` layout as a
bounded response-type discriminator. No server-error payload is cache-marshaled.
The provider otherwise uses only the lossless same-result string/error pair
through one narrow bounded error-kind extractor. These dependency limitations
permit inspection only of the exact leading RESP error-prefix token under the
rules below; they do not permit arbitrary error-string classification or
message-body matching.

### Closed Result States

`ReplayCheck` is a closed sum with exactly these successful states:

- `first_seen`: the store atomically created the identity with its retention;
- `replayed`: the identity already existed and its retention was not changed;
- `disabled`: an explicitly selected disabled provider performed no storage
  operation.

`disabled` is not equivalent to `first_seen`. It remains visible to later local
policy.

Unavailable, capacity, invalid, cancelled, deadline, indeterminate,
inconsistent, closed, and internal outcomes are typed failures, not successful
checks. `degraded` is a store state, not a second error for the same operation.

The check contains no key, timestamp, expiry, count, raw cause, provider
identity, address, or message fact.

### Closed Error Taxonomy

The replay domain has exactly these error codes:

- `invalid_request`;
- `misconfigured`;
- `limit_exceeded`;
- `unavailable`;
- `indeterminate`;
- `inconsistent`;
- `cancelled`;
- `deadline_exceeded`;
- `closed`;
- `internal_invariant`.

No `degraded`, raw-provider, catch-all, or dynamically constructed error code
is permitted. `ReplayStoreState` has exactly `ready`, `degraded`, `disabled`,
`closing`, and `closed`.

The distribution is exact:

- invalid zero values, missing key presence, invalid retention, nil context,
  or impossible enabled-provider request pairs are `invalid_request`;
- constructor or production-attestation failures are `misconfigured`;
- a hard entry, waiter, or configured resource cap is `limit_exceeded`;
- a non-context backend or transport availability failure proved to occur
  before command dispatch is `unavailable`;
- any non-authoritative error or panic after dispatch may have begun is
  `indeterminate`;
- an authoritative successful non-error Valkey reply with an unexpected shape,
  an authoritative application-SET `ERR`/unknown server-error kind, a malformed
  or oversized typed Valkey error payload or prefix, a malformed/unknown auditor
  error token, a malformed/impossible/contradictory bounded auditor reply shape,
  or a contradictory backend success pair is `inconsistent`;
- a terminal caller context observed before dispatch is `cancelled` or
  `deadline_exceeded`;
- a store that rejects a new operation after close begins is `closed`;
- an impossible in-process invariant, including a backwards injected clock
  before mutation, is `internal_invariant`.

Typed cancellation and deadline failures preserve `errors.Is` identity only
when the operation is known not to have crossed a mutation boundary.

Once a Valkey command may have been dispatched, a timeout, cancellation,
connection loss, client close, panic, or other non-authoritative failure is
`indeterminate`. It must not unwrap to caller cancellation because that would
hide the unknown store mutation state.

Errors format only as their stable code. They do not wrap raw client, server,
network, address, credential, key, or context text.

### Replay Retention

Retention is an explicit validated value.

- It is positive.
- It is an exact whole number of milliseconds.
- Its exact minimum is one second.
- Its exact default is fourteen days.
- Its exact hard maximum is thirty days.
- Conversion to signed Valkey PX milliseconds is checked before mutation.
- Duration addition for in-memory expiry is checked for overflow.
- Zero, negative, sub-millisecond, non-integral millisecond, over-limit, and
  overflowing values fail before store access.
- A replay does not extend or replace the original expiry.
- At the exact expiry boundary the old observation is expired and the next
  atomic operation may become first-seen.

These limits remain below both `time.Duration` and Valkey integer limits.
Unsafe widening is a protocol-adjacent security change requiring a durable
specification and new vectors, not an ordinary M13 configuration change.

### Replay Identity Facts

M12 adds exact projection types at the existing trust boundaries:

```go
// internal/verify; fields and constructor are unexported.
type ReplayProjection struct { /* fixed digests, recipients, exploded */ }
func (r Result) ReplayProjection() (ReplayProjection, bool)

// internal/service; fields and constructor are unexported.
type ReplayProjection struct { /* fixed digests, recipients, exploded */ }
func (r Result) ReplayProjection() (ReplayProjection, bool)

// root package; replayProjection remains unexported inside VerifyResult.
func ReplayIdentities(VerifyResult) (ReplayIdentitySet, error)
```

The two internal projection types expose only cloning, fixed-array, bounded
enum, boolean, and validity methods required by the next trusted mapping
package. Go's `internal` import rule prevents command modules and external
consumers from importing either constructor path. `ReplayIdentitySet` is an
immutable root wrapper over internal/replay fixed-size identity values; it has
the exact public surface:

```go
func (s ReplayIdentitySet) Valid() bool
func (s ReplayIdentitySet) Len() int
func (s ReplayIdentitySet) Identity(index int) (ReplayIdentity, error)
func (s ReplayIdentitySet) Exploded() bool
```

`Identity` returns `invalid_request` for an out-of-range index. The set has no
public constructor or raw accessor. Its zero value is invalid. Fixed arrays
remove caller-owned mutable buffers, so the set does not claim a Close or
memory-erasure guarantee.

The verifier projection exists only when all of these conditions are true:

1. the selected target is the highest current DKIM2-Signature and references
   the highest current Message-Instance;
2. aggregate verification is PASS with coherent current scope and custody;
3. the selected Message-Instance SHA-256 header-hash set was uniquely selected
   and matched the authoritative canonical current header hash;
4. at least one supported signature set passed over the authoritative
   canonical signature input;
5. current SMTP envelope comparison passed; and
6. all current forward paths were parsed by the existing authoritative
   envelope parser.

The sealed projection owns:

- the exact ASCII draft identifier
  `draft-ietf-dkim-dkim2-spec-04`;
- the 32 decoded bytes of the selected Message-Instance SHA-256 header hash;
- the 32-byte SHA-256 digest of the exact canonical signature input used for
  the highest current signature verification;
- the authenticated `exploded` flag as a bounded policy bit; and
- one 32-byte SHA-256 recipient-scope digest per unique actual SMTP forward
  path.

Recipient canonicalization reuses the verifier's already-validated bracketed
SMTP path. It removes only the surrounding `<` and `>`, preserves the local
part byte-for-byte and case-sensitively, lowercases only ASCII letters in the
domain, preserves the existing route/address grammar decision, rejects an
empty recipient, and performs exact byte deduplication after that
normalization. It neither performs Unicode normalization nor invents EAI,
IDNA, plus-address, alias, list, Bcc, or case-folding semantics. For each
canonical recipient it computes
`SHA-256("dkim2-replay-recipient-v1\x00" || uint32be(length) || bytes)` and
retains only that 32-byte scope digest. The projection sorts those digests
lexicographically; request order is not security-significant.

The `exploded` bit is the logical OR over every relevant authenticated
DKIM2-Signature in the complete current verification set, not merely the
highest selected header. A signature is relevant only when its sequence is in
the selected current chain and the exact complete signature header field was
included in the canonical signature input authenticated by the passing highest
current signature set. Unverified historical, malformed, skipped,
unsupported-only, or unrelated fields do not contribute. If complete
relevant-signature coverage cannot be established, the replay projection is
absent and no replay mutation occurs. This implements the draft-04 Section 8.10
"at least one relevant signature" rule as OR, without turning the resulting
fact into a disposition.

One `ReplayIdentity` contains the exact draft, the two 32-byte authenticated
digests, and exactly one 32-byte recipient-scope digest. No caller-facing
constructor accepts these facts independently. The only production constructor
consumes the sealed aggregate PASS projection. It returns the complete sorted
set of recipient-scoped identities or a typed failure and never a partial set.
Store integration must process every returned identity before making one
message disposition; it must not stop on the first replayed or failed
recipient. Partial backend mutation is therefore reported by the later batch
coordinator as indeterminate and must never be collapsed to first-seen.

Digest presence is represented separately from the 32 bytes. An all-zero
32-byte message or signature-input digest is valid when the authoritative
projection says the digest is present. Nil, wrong length, absent presence,
unknown draft, invalid recipient, duplicate internal state, or non-PASS
projection fails before key derivation and before any store side effect.

Identity values have no raw formatter, text marshaler, JSON marshaler, or
exported byte-slice accessor. Test-only constructors live in `_test.go` files
inside internal/replay and cannot enter production APIs.

### Versioned Privacy-Preserving Keys

The key algorithm is named `dkim2-replay-hmac-sha256-v1` and is frozen byte for
byte.

The deriver:

- uses HMAC-SHA256;
- uses one exactly 32-byte deployment-local secret and one nonzero unsigned
  32-bit key epoch;
- rejects an absent or all-zero secret;
- clones the secret and best-effort clears owned secret memory at close;
- uses the exact domain-separation label and framing below;
- emits a fixed ASCII namespace and unpadded base64url HMAC digest;
- never places input digests directly in the storage key;
- produces the same key for the same secret and facts;
- produces unrelated keys for changed secrets, versions, or any fact.

The storage representation is exposed only through the narrow provider
boundary necessary for third-party backend implementations. That access is a
protected value, not safe diagnostic data.

The exact HMAC input is the concatenation below. Integers are unsigned
big-endian. No newline, whitespace, NUL terminator, textual integer, or
alternate encoding is present:

```text
15 bytes  "dkim2-replay-v1"
1 byte    0x00
1 byte    0x01
4 bytes   uint32(len(draft))
N bytes   ASCII "draft-ietf-dkim-dkim2-spec-04"
1 byte    0x02
4 bytes   uint32(32)
32 bytes  selected Message-Instance SHA-256 header hash
1 byte    0x03
4 bytes   uint32(32)
32 bytes  SHA-256 of highest canonical signature input
1 byte    0x04
4 bytes   uint32(32)
32 bytes  recipient-scope SHA-256 digest
```

The storage key is exactly:

```text
dkim2:replay:v1:<epoch>:<digest>
```

`<epoch>` is exactly eight lowercase hexadecimal digits for the configured
nonzero uint32 epoch. `<digest>` is the 43-character unpadded RFC 4648
base64url encoding of the 32-byte HMAC output. The fixed prefix is therefore
25 ASCII bytes and every storage key is exactly 68 ASCII bytes. The stored
value is exactly the two ASCII bytes `v1`.

The protected key is an immutable root value wrapping an internal 68-byte
array. It has no exported bytes or string method. The only backend seam is:

```go
func UseReplayStorageKey(
    key ReplayKey,
    use func(storageKey string) error,
) error
```

The function rejects nil callback or invalid key, recovers callback panic as
`internal_invariant`, invokes the callback synchronously exactly once, and
returns only a typed replay error. A callback is strictly a pre-dispatch command
builder: it may retain the string only inside the completed one-command value
that it returns to its provider; it must not perform I/O. The provider
dispatches that completed command after `UseReplayStorageKey` returns, drops
the command value immediately after result mapping, and owns a separate
post-dispatch panic boundary that maps uncertainty to `indeterminate`.
The callback returns nil on one complete non-retryable command; a typed replay
error is passed through, any raw/unknown error is `internal_invariant`, and no
command is dispatched after callback error or panic.

The root helper creates the immutable string immediately before the callback
and retains no additional reference after return. Go cannot prevent an
authorized callback from retaining that string or an external consumer from
calling an exported function. This is therefore an explicitly trusted,
privacy-sensitive backend authorization seam, not a language-enforced
non-disclosure guarantee. Repository import guards and review restrict
production callers; focused tests prove the in-repository implementations do
not capture beyond command dispatch. Reflection, unsafe extraction, formatting,
or duplicate serialization is forbidden.

All active instances sharing a Valkey namespace must use the same draft,
algorithm version, epoch, and HMAC secret. Rotation requires a new epoch and
secret. M12 supports only a fully drained change: replay-checked traffic stops,
the old epoch remains authoritative until the thirty-day hard maximum
retention has elapsed, and all instances then restart on the new epoch before
traffic resumes. Dual-epoch read/write, online secret rotation, and migration
coordination are out of scope and require a future durable specification.
M12 implements no unsafe instant rotation, fallback to an unknown secret, or
silent namespace reuse. M13 must reject a production configuration that
declares rotation without the complete drain state.

Production-derived replay keys and all HMAC secrets are forbidden in logs,
traces, metrics, errors, snapshots, REST, CLI, configuration display, and test
failure output. The only permitted literal replay keys are deterministic
golden constants produced from published synthetic fixture facts and a
published non-production synthetic key in dedicated derivation and command
tests.

### In-Memory Provider

The memory provider is deterministic and bounded.

- It owns a map indexed only by protected replay key.
- It owns an expiry min-heap so cleanup never requires an unbounded full-map
  scan.
- It accepts an injected clock through a test seam.
- Its exact default entry cap is 65,536 and exact hard configurable cap is
  1,048,576.
- Its exact default concurrent-waiter cap is 1,024 and exact hard configurable
  cap is 65,536; cap+1 fails before joining the provider-owned wait queue.
- Its exact default expired-entry prune budget is 4,096 and exact hard
  configurable budget is 65,536 heap removals per operation.
- A zero config value selects the corresponding default. After defaulting,
  every cap must be in `[1, hard maximum]`; negative or over-hard values are
  `misconfigured`.
- It serializes only the short map/heap mutation critical section; key
  derivation, validation, state reads, and unrelated caller work remain
  concurrent.
- Waiting for the serialization token is context-aware and the provider owns
  no background goroutine.
- It rechecks context after acquiring the token and before mutation.
- The injected clock must be nondecreasing. A backwards reading returns
  `internal_invariant` before pruning, insertion, or expiry change and
  publishes degraded state.
- A nil clock is `misconfigured`. A zero reading or clock panic is
  `internal_invariant` before mutation and publishes degraded state. The clock
  is called exactly once per admitted operation.
- It removes all entries with expiry less than or equal to the captured
  operation time before capacity evaluation, up to the exact prune budget.
- If the prune budget is exhausted and insertion still lacks capacity, the
  operation returns `limit_exceeded` without evicting an unexpired entry;
  later calls continue bounded pruning.
- It inserts one key and expiry atomically.
- Existing unexpired keys return replayed without changing expiry.
- Capacity is hard bounded; cap+1 returns `limit_exceeded` without eviction,
  mutation, or expiry extension.
- Heap and map entries remain one-to-one; stale heap nodes are not accumulated.
- Close is idempotent, clears all entries, and makes later checks unavailable
  with the closed error.

Concurrent same-key calls have exactly one first-seen winner and only replayed
successes afterward. Race detection supplements deterministic barrier
assertions.

Close publishes `closing`, rejects new checks with `closed`, and waits for
already-admitted critical sections to finish. An in-flight operation that
linearized before close returns its authoritative result even when its caller
context becomes terminal after mutation. If a close context expires while
draining, Close returns the exact bounded context error, leaves the provider in
`closing`, and a later Close may finish the same drain; no goroutine is
abandoned. The transition to `closed` clears map and heap exactly once.

### Disabled Provider

The disabled provider is explicit.

- While open, every valid request returns `disabled`.
- It performs no key derivation, allocation proportional to caller data,
  clock access, network call, or mutation.
- It requires no HMAC secret, epoch, or present ReplayKey. A nil or terminal
  context still fails before disabled success; key and retention validation are
  intentionally bypassed because storage is disabled.
- Close is idempotent and changes the provider to closed.
- It never returns first-seen.

### Valkey Provider

The Valkey provider lives only in `cmd/dkim2d`.

Production construction is owned and cannot accept an arbitrary prebuilt
client:

```go
func NewProductionStore(
    context.Context,
    ClientConfig,
    OperatorAttestation,
    AuditorConfig,
) (*Store, error)

func (s *Store) Revalidate(context.Context, AuditorConfig) error
```

The provider package's single application-client factory validates
`ClientConfig`, creates a standalone `valkey-go v1.0.77` client with
`ForceSingleClient: true`, and retains ownership.
There is no borrowed production constructor. Package-private `_test.go` helpers
may inject a narrow fake command client; nil or typed-nil fake clients are
`misconfigured`. The owned production store closes its client exactly once
after admitted calls drain.

M13 owns loading endpoint, database, username, password, TLS trust files, dial
settings, and Fx lifecycle wiring. M12 owns the normalized value contract and
the invariants the loaded configuration and client must prove before the
provider can publish ready:

- TLS is enabled with peer-name verification, `InsecureSkipVerify` is false,
  and the trust source is explicit;
- authentication is enabled and the dedicated principal is least-privileged;
- ACL key access is restricted to `~dkim2:replay:v1:*`;
- ACL database access is restricted to database zero through the exact
  root-selector rule `db=0`;
- the principal's exact command allowlist is the standalone set below;
  no category, wildcard, selector, or additional command right is permitted;
- the write target is exactly one audited standalone primary; read replicas are
  never replay authorities;
- the deployment uses a dedicated Valkey database with
  `maxmemory-policy noeviction`;
- every authoritative node has a positive finite `maxmemory` between exactly
  16 MiB and 1 TiB, and startup/revalidation proves at least the larger of
  16 MiB or `ceil(maxmemory/10)` bytes remains available. The ceiling is
  computed by checked quotient/remainder arithmetic and available bytes are
  checked `maxmemory-used_memory`;
- every simultaneously active daemon instance uses the same key algorithm,
  draft, epoch, HMAC secret, namespace, and retention limits;
- persistence and replication are explicitly configured and documented for
  the accepted replay-loss window; asynchronous failover is never advertised
  as globally exactly-once; and
- secret rotation declares the complete drain-only contract defined above.

`ClientConfig` is a redacted value whose validator proves locally:

- TLS is enabled, server name and owned trust-root DER are nonempty, peer
  verification is enabled, and insecure verification cannot be selected;
- application authentication metadata is present without formatting its
  secret;
- topology is exactly standalone-primary; cluster production is rejected;
- database is exactly zero;
- client name is empty and client-side cache, tracking, replica reads, and
  arbitrary init commands are disabled;
- standalone-primary has exactly one initial endpoint and sets
  `ForceSingleClient: true`, so `valkey-go` never probes `CLUSTER SHARDS` or
  `CLUSTER SLOTS`;
- `DisableRetry` is true, `ConnLifetime` is exactly zero, and
  `ShardsRefreshInterval` is exactly zero, preventing ordinary retries and the
  client's unconditional expired-connection retry; reactive cluster refresh
  is inapplicable because cluster mode is forbidden;
- `DisableCache` is true; replica routing, standalone redirect, Sentinel,
  custom initialization, credential callbacks, invalidation callbacks,
  shuffling, client naming, tracking, and client eviction/touch options are
  absent;
- the validated dial timeout, TCP keepalive, and connection write timeout are
  positive bounded values copied exactly into `Dialer` and
  `ConnWriteTimeout`; background PING therefore remains enabled and is the
  reason for the `+ping` application grant;
- `ClientSetInfo` is a newly allocated non-nil zero-length slice, the
  documented `valkey.DisableClientSetInfo` shape, so optional
  `CLIENT SETINFO` initialization is absent and needs no ACL grant; construction
  does not depend on the mutable exported slice variable;
- all `valkey.ClientOption` fields not explicitly constructed by this
  specification remain their nil, zero, or false value; tests compare the
  complete option value at the factory seam rather than a selected subset;
- the returned client `Mode()` is exactly `standalone`; every other mode is
  rejected and its client is closed;
- a non-nil client returned together with an error is closed exactly once
  before the bounded constructor failure is returned; a factory panic is
  contained, closes any already-published partial client exactly once, and is
  `internal_invariant`; and
- ordinary network retry policy leaves completed SET commands non-retryable;
- draft, namespace, epoch, retention, in-flight, and waiter limits match the
  replay contract.

Configuration bounds and normalization are exact:

- the sole endpoint input is 1 through 47 bytes and parses as canonical
  `IP-literal:port`; port is canonical unsigned decimal in `[1,65535]` with no
  leading zero, an IPv6 literal is bracketed, and the IP text must equal
  canonical `netip.Addr.String()`;
- DNS names, host aliases, load balancers, Unix sockets, zone identifiers,
  percent escapes, paths, schemes, credentials, whitespace, and more than one
  endpoint are rejected. This binds the audit and application client to the
  same direct network authority;
- the TLS server name is 1 through 253 bytes and is either canonical IP text or
  a lowercase ASCII DNS name with 1-through-63-byte labels matching
  the whole-label Go-valid grammar
  `[a-z0-9]([a-z0-9-]*[a-z0-9])?`; one-byte labels are valid, while a leading
  or trailing hyphen is not. Trailing root dots and IDNA conversion
  are rejected. `InsecureSkipVerify` is false, minimum TLS is 1.3,
  maximum TLS is also 1.3, renegotiation is disabled, session tickets are
  disabled, `NextProtos` is empty, every TLS callback is nil, and explicit root
  trust is nonempty;
- root trust input is one through 128 owned DER-encoded CA certificates. Each
  DER value is 1 through 64 KiB, aggregate root DER is at most 256 KiB, every
  value parses as exactly one `x509.Certificate`, every certificate has
  `BasicConstraintsValid=true` and `IsCA=true`, and a nonzero `KeyUsage`
  includes `KeyUsageCertSign`. Duplicate DER values are rejected. The
  validator copies the bounded DER, parses it, constructs a fresh private
  `x509.CertPool`, and retains neither a caller-supplied pool nor an opaque
  verifier. Client
  certificates are exactly absent; M12 does not accept a `tls.Certificate`,
  `crypto.Signer`, private-key interface, callback, or mTLS client-auth input;
- application and auditor usernames are 1 through 128 bytes matching
  `[A-Za-z0-9._-]+`; their protected passwords are 1 through 1,024 bytes and
  are never converted for diagnostics;
- `Dialer.Timeout` is in `[100ms,30s]`, `Dialer.KeepAlive` is in `[1s,5m]`,
  and `ConnWriteTimeout` is in `[100ms,30s]`; no zero-value substitution is
  allowed at the client seam; and
- retained endpoints, credentials, bounded root DER byte slices, dial settings,
  and option slices are copied into provider-owned values before factory or
  auditor use. A fresh `tls.Config` and fresh private root pool are constructed
  only from those values. Inputs are borrowed for the synchronous duration of
  the constructor or revalidation call and callers must not mutate them
  concurrently; mutation after the call returns cannot change peer
  verification, trust, credentials, routing, or options.
  The store never retains `AuditorConfig` or auditor credentials; every audit
  owns and clears its protected clones.

Construction order is exact: check context; copy and locally validate
`ClientConfig`, `OperatorAttestation`, and `AuditorConfig`; complete the
ephemeral auditor and its cleanup; create the least-privileged application
client; recheck context; require exact standalone mode; then publish immutable
evidence and the store. An application client is never created before authority
proof succeeds, and every acquired auditor connection or application client is
closed exactly once on every later failure or panic path.

The factory checks a nil or terminal context before either network acquisition
and creates no connection or client. `valkey.NewClient` has no context
parameter, so once invoked it is bounded by the validated dial and
connection-write timeouts rather than by a false mid-call cancellation claim.
The context is checked again immediately after return; if it became terminal,
every returned non-nil client is closed exactly once and the exact context
error is returned. Complete option-value tests use synthetic credentials and
field-by-field secret-safe assertions; they never format passwords, certificate
DER, roots, or endpoints through a generic structural diff.

`OperatorAttestation` is an immutable value with unexported retained fields. Its
constructor accepts only the following closed, credential-free input schema;
every zero or unknown enum and every false required assertion is
`misconfigured`:

- `PersistenceMode` is exactly `rdb`, `aof`, or `rdb_aof`; disabled
  persistence is forbidden;
- `AppendFsyncPolicy` is exactly `inactive`, `always`, or `everysec`.
  `inactive` is legal only for `rdb`; `always` or `everysec` is required for
  `aof` and `rdb_aof`; `appendfsync no` is never an accepted active-AOF
  policy;
- `SaveSchedule` uses the strict attestation subset of the canonical bounded
  CONFIG grammar below: every seconds and change-count value is positive. It is
  nonempty for `rdb` and `rdb_aof` and empty for `aof`;
- `MinReplicasToWrite` is an unsigned integer in `[0,3]` and
  `MinReplicasMaxLagSeconds` is an unsigned integer in `[1,3600]`; both must
  equal the corresponding live CONFIG values;
- `LossWindowAcceptance` is exactly `asynchronous_acknowledged`, asserting
  that an acknowledged write may be lost after failover and an uncertain write
  may have committed, and `NoGlobalExactlyOnceClaim` is true;
- `RotationState` is exactly `unchanged` or `drain_completed`.
  `unchanged` asserts the current epoch/secret set has not changed while replay
  traffic is active. `drain_completed` asserts replay traffic stopped, the old
  epoch remained authoritative for the complete thirty-day hard maximum,
  every active instance restarted on the new epoch/secret set, and traffic did
  not resume earlier; an in-progress, partial, instant, dual-epoch, or unknown
  rotation state is forbidden; and
- `DedicatedDeployment`, `DedicatedDatabaseZero`, `DirectIPAuthority`,
  `NoEndpointSubstitution`, `StandaloneAuthority`, `SharedDraft`,
  `SharedAlgorithm`, `SharedNamespace`, `SharedEpoch`, `SharedSecretSet`, and
  `SharedRetention` are all true. The shared assertions refer to every
  simultaneously active daemon instance and the exact values validated by the
  replay contract; they do not disclose those values.

The live auditor compares persistence mode, active `appendfsync`, exact
`SaveSchedule`, `MinReplicasToWrite`, and `MinReplicasMaxLagSeconds`.
For `rdb`, CONFIG `appendfsync` still must be one of its three canonical server
tokens but is inactive and is not compared. All remaining fields are explicit
trusted operator assertions, never inferred from a live probe. The attestation
value has content-free `String`, `GoString`, text/JSON, and error behavior and
contains no endpoint, certificate, username, password, epoch, secret,
namespace, or retention value.

Production cluster mode is deferred. In `valkey-go v1.0.77`,
`ShardsRefreshInterval: 0` disables only periodic refresh: MOVED/ASK and other
events can still trigger reactive topology refresh and dispatch to a newly
discovered or promoted node whose authority was not part of the current audit,
while returning only the final SET result. That cannot satisfy the fail-closed
audited-authority contract. M12 therefore rejects cluster configuration as
`misconfigured`, exposes no cluster-ready state, and grants no cluster command.
A future owned router or transport must confine each dispatch to an immutable
current audited authority set and surface redirects before execution before
cluster production can be specified.

`AuditorConfig` is a protected, redacted value containing only the separate
ephemeral auditor username and password; it cannot select an endpoint, TLS
server name, root, dial policy, database, or topology. Both construction and
revalidation derive their auditor transport from the exact immutable validated
`ClientConfig` authority and transport values owned by the store. Revalidation
can replace credentials and evidence but cannot change the write authority.
The provider's single internal `securityAuditor` implementation constructs a
narrow owned TLS/authenticated RESP2 wire client, executes only the exact
bounded probes below, maps replies immediately to closed evidence, and closes
it before returning. The privileged auditor does not use `valkey.Client`,
`ValkeyResult`, or a generic command/reply API: those abstractions cannot prove
the raw pre-decode reply cap or preserve duplicate alternating fields.

- `maxmemory-policy` is exactly `noeviction`;
- `maxmemory` is within the exact finite range and current used memory leaves
  the required startup/revalidation headroom;
- standalone target ROLE is exact wire token `master`, and `INFO cluster`
  proves `cluster_enabled:0`;
- persistence and replication settings match the operator attestation;
- current persistence health matches the selected mode: configured RDB requires
  `rdb_last_bgsave_status=ok`; configured AOF requires
  `aof_last_write_status=ok` and `aof_last_bgrewrite_status=ok`; a disabled
  mechanism is not treated as healthy evidence for a mode that requires it;
- current replication health has at least `min-replicas-to-write` connected
  replicas whose observed lag is no greater than `min-replicas-max-lag`; the
  auditor validates bounded integer fields from `ROLE` and `INFO replication`
  against the attested settings;
- `ACL GETUSER` proves the exact effective application-principal contract
  below, and targeted `ACL DRYRUN` proves every allowed command plus
  in-namespace SET succeeds while out-of-namespace SET fails.

The exact ACL database-permission schema introduced by official Valkey `9.1.0`
is the production compatibility floor. The security capability is
proved directly rather than inferred from an `INFO server` version string:
the auditor requires the exact `ACL GETUSER databases` field and rule described
below. No separate version-banner probe or parser is permitted, and the
capability proof does not claim brand or version attestation. The hermetic
integration target remains pinned to exactly `9.1.0`. A later compatible
server is accepted only while the complete bounded reply shape remains
unchanged; a newly added field or semantic shape requires an explicit
specification, parser, and compatibility review rather than being ignored.

The ephemeral auditor negotiates no RESP3 mode and speaks only RESP2. Its
application-principal `ACL GETUSER` reply must therefore be one RESP2 array
with exactly fourteen elements, parsed as seven ordered key/value pairs so
duplicate keys remain observable. The parser must not call `ToMap`, `AsMap`,
`ToAny`, or another conversion that can collapse duplicate fields. Pair order
is not semantically significant, but the seven field names must each occur
exactly once:

```text
flags
passwords
commands
keys
channels
databases
selectors
```

Each field retains its official `9.1.0` value shape. `flags` is an array of two
or three scalar bulk strings under the exact order-insensitive grammar below,
`passwords` and `selectors` are arrays, and `commands`, `keys`, `channels`, and
`databases` are scalar bulk strings. The accepted application policy later
narrows password count to one and selectors to empty; other structurally valid
counts are policy mismatches, not malformed wire shapes. No other container or
scalar type is accepted, and the complete encoded RESP reply is capped at 4,096
bytes while reading. An absent, duplicate, unknown, wrongly typed, truncated,
oversized, or otherwise malformed field is `inconsistent`; future metadata is
not silently skipped.

Under RESP2, every element of a nonempty `selectors` array is exactly one
eight-element alternating-name/value array in the tagged emission order
`commands`, `keys`, `channels`, `databases`. All four names and values are bulk
strings. Each value is validated under the same command-envelope, key,
channel, and database grammar as its root-selector counterpart before the
nonempty selector is classified as a policy mismatch. A duplicate, missing,
unknown, reordered, wrongly typed, malformed, or oversized nested field is
`inconsistent`; nested values are parsed duplicate-preservingly and never
converted through a map.

The auditor transport uses the application store's immutable endpoint, TLS
server name, owned trust-root DER, certificate policy, and bounded dialer plus
only the dedicated protected credentials from `AuditorConfig`. It performs
exactly one `AUTH <username> <password>` and
requires exact simple-string `OK` before any probe. It never sends `SELECT`,
never changes database zero, never pipelines, retries, follows redirects,
accepts pushes, or starts background work. Each probe writes one closed
command shape and reads exactly one response under its two-second child
deadline.

The auditor's private RESP2 decoder enforces limits while reading framing,
before allocating or decoding declared content. Every reply permits at most
4,096 encoded bytes, 256 aggregate RESP values, six container levels including
the root, and at most 512 bytes before CRLF for a RESP
control/simple/error line or one line
inside an INFO bulk payload.

The decoder accepts only the exact simple-string, error, integer, bulk-string,
null-bulk, and array types required by the frozen probes; negative non-null
lengths, overflow, cap+1 declarations, unsupported types, premature EOF,
invalid CRLF, and excess elements, depth, or line length are
`inconsistent`. Protected reply bytes are retained only in one bounded
auditor-owned buffer,
never formatted or returned, and are cleared before release. Authentication,
transport, and TLS failures use the existing bounded
construction/revalidation mapping; a decoder or cleanup panic is
`internal_invariant`.

An auditor RESP2 error line uses the same bounded 1-through-32-byte
`[A-Z][A-Z0-9_]*` leading-token grammar as application error classification;
the suffix is discarded without inspection. Exact `NOAUTH`, `WRONGPASS`,
`NOPERM`, `ERR`, `READONLY`, `MASTERDOWN`, `CLUSTERDOWN`, `LOADING`,
`MISCONF`, `NOREPLICAS`, `MOVED`, `ASK`, `TRYAGAIN`, or `OOM` on any audit
command is a well-formed authority, capability, privilege, topology, or health
mismatch. `BUSY` is additionally well-formed on probes two through eleven,
whose command definitions do not allow execution during a yielding long
command; AUTH itself is tagged `allow_busy`, so BUSY on command one is
`inconsistent`. A well-formed mapped error returns construction
`misconfigured`, while runtime returns
`unavailable` with revalidation-clearable degradation. Authentication failure
stops before command two. A malformed token or well-formed unknown token is
`inconsistent`; no error suffix is used to refine that result.

Caller context has precedence over internal timeout mapping: if the parent is
terminal, its exact cancellation or deadline result is returned. Expiry of an
auditor-owned two-second command deadline or thirty-second global deadline
while the parent remains live is bounded `unavailable`, not a synthetic caller
deadline. Cleanup panic dominates every prior result as `internal_invariant`.
An ordinary `net.Conn.Close` error replaces only success with `unavailable`;
an existing caller-context, unavailable, mismatch, or inconsistent result is
retained. Matrix tests cover success plus close error, caller cancellation plus
close error, malformed reply plus close error, and every primary result plus
close panic.

The wire command inventory is closed. Every command counts toward an exact
eleven-command per-audit cap:

```text
AUTH <auditor-username> <auditor-password>
ROLE
CONFIG GET appendfsync appendonly maxmemory maxmemory-policy min-replicas-max-lag min-replicas-to-write save
INFO memory
INFO persistence
INFO replication
INFO cluster
ACL GETUSER <application-username>
ACL DRYRUN <application-username> PING
ACL DRYRUN <application-username> SET dkim2:replay:v1:a v1 NX PX 1000
ACL DRYRUN <application-username> SET outside:dkim2-replay-a v1 NX PX 1000
```

No INFO server, CLUSTER SLOTS, SELECT, CLIENT SETINFO, AUTH DRYRUN, HELLO
DRYRUN, CLUSTER SHARDS, ASKING, globbed CONFIG, or unspecified probe is sent.
A command is counted before writing, so command twelve is never sent.

`CONFIG GET` must return one RESP2 array containing exactly fourteen scalar
bulk strings as seven distinct alternating name/value pairs in the requested
alphabetical order. Missing, duplicate, unknown, reordered, wrongly typed, or
malformed fields are `inconsistent`. Canonical well-formed values are parsed
as follows:

- `maxmemory` is unsigned canonical decimal fitting `uint64`, with no sign or
  leading zero except the single value `0`;
- `min-replicas-max-lag` and `min-replicas-to-write` are unsigned canonical
  decimal in `[0,2147483647]`, the tagged-source `int32` range. Values outside
  the narrower attested ranges are well-formed policy mismatches;
- `appendonly` is exactly `yes` or `no`, and `appendfsync` is exactly `always`,
  `everysec`, or `no`;
- `maxmemory-policy` is 1 through 32 lowercase ASCII bytes matching
  `[a-z0-9-]+`. Every syntactically valid token except exact `noeviction` is a
  policy mismatch. This deliberately bounded forward-compatible grammar does
  not freeze the tagged enum registry;
- live `save` is either empty or at most 512 ASCII bytes containing one or more
  canonical decimal seconds/change pairs separated by one ASCII space. On the
  supported 64-bit target, seconds are unsigned in `[1,MaxInt64]`, matching the
  tagged-source signed `long`/`time_t` parse and `%jd` output. Change counts are
  signed in `[MinInt32,MaxInt32]`, matching the tagged-source unchecked
  nonnegative-`long`-to-`int` conversion and `%d` output. A minus sign is
  permitted only for a negative change count; plus signs, leading zeros except
  the single value `0`, empty tokens, overflow, or trailing space are malformed.
  The attested `SaveSchedule` uses the stricter same grammar with every change
  count in `[1,MaxInt32]`, so a structurally valid live zero or negative change
  count is a policy mismatch rather than `inconsistent`.

A well-formed value that differs from the attested policy is a construction
`misconfigured` result or runtime revalidation `unavailable`; malformed,
missing, duplicate, or overflow data is `inconsistent`.

Each INFO command must return one bulk string whose payload consists only of
CRLF-terminated lines. A section line is exact `# ` followed by 1 through 64
ASCII bytes matching `[A-Za-z0-9_-]+`. A field line has a 1-through-128-byte
ASCII name matching `[A-Za-z0-9_.-]+`, the first colon delimiter, and a
possibly empty value bounded by the 512-byte line cap. Empty lines and unknown
section or field lines inside this deliberate bounded forward-compatible
envelope are ignored. A field line must follow a section line. Each requested
INFO reply contains exactly one corresponding section header: `# Memory`,
`# Persistence`, `# Replication`, or `# Cluster`; every required field below
must occur exactly once within that section. A duplicate or missing required
field or section, bare LF/CR, nonempty line outside the two grammars, field
before a section, malformed canonical decimal, or overflow is `inconsistent`:

- `INFO memory`: `used_memory`, canonical unsigned decimal, and it must not
  exceed CONFIG `maxmemory`; remaining headroom and
  `max(16 MiB, ceil(maxmemory/10))` are computed in bytes with checked
  arithmetic;
- `INFO persistence`: `rdb_last_bgsave_status`,
  `aof_enabled`, `aof_last_write_status`, and
  `aof_last_bgrewrite_status`; `aof_enabled` is exactly `0` or `1` and must
  agree with CONFIG `appendonly`; RDB status counts only when CONFIG `save` is
  nonempty, and AOF status counts only when appendonly is `yes`;
- `INFO replication`: `role` is exact `master`, `connected_slaves` is
  canonical unsigned decimal fitting `uint64`, matching tagged-source
  `listLength`/`unsigned long` output on the supported 64-bit target, and the
  exact contiguous
  `slave0` through `slaveN-1` lines contain exactly the ordered
  `ip,port,state,offset,lag,type` subfields with no duplicate, missing,
  reordered, or unknown subfield. The structural tagged-`9.1.0` state set is
  exactly `wait_bgsave`, `bg_transfer`, `send_bulk`, `online`, or
  `rdb_transmitted`; type is exactly `rdb-channel`, `main-channel`, or
  `replica`. Displayed `ip` is 0 through 255 bytes with no comma, CR, or LF;
  it may be a configured noncanonical REPLCONF value. Displayed port is
  canonical signed decimal fitting `int32`; offset and lag are canonical signed
  decimal fitting `int64`. A negative lag is structurally possible after wall
  clock rollback but is unhealthy. Structurally valid noncanonical host, port,
  offset, or lag metadata is a policy mismatch, not `inconsistent`. Only a
  canonical IP literal, port in `[1,65535]`, nonnegative offset and lag, exact
  `state=online`, exact `type=replica`, and lag no greater than CONFIG
  `min-replicas-max-lag` counts toward `min-replicas-to-write`.
  `connected_slaves` is never converted to an allocation or iteration bound.
  The parser first collects the bounded `slaveN` lines present in the payload,
  rejects duplicate indices, compares their count to `connected_slaves`, and
  sorts and checks those observed indices against their zero-based positions.
  This is linearithmic only in the bounded payload and never scans a range
  derived from the claimed count. A missing, extra, or noncontiguous line is
  `inconsistent`; therefore a claim such as 65,536 in a reply bounded to 4 KiB
  necessarily fails shape validation without a 65,536-step loop. Only after
  complete shape validation is a count greater than three, such as four exact
  lines, a well-formed unsupported policy mismatch;
- `INFO cluster`: `cluster_enabled` occurs exactly once and is exactly `0`.
  Exact `1` is a well-formed unsupported topology mismatch.

The accepted `ROLE` reply is one exact three-element RESP2 array: bulk string
`master`, one nonnegative integer replication offset, and one array of zero
or more online-replica triples within the universal reply caps. Each triple is
exactly three bulk strings: a 0-through-255-byte configured host, canonical
signed-decimal port fitting `int32`, and canonical signed-decimal acknowledged
offset fitting `int64`. Accepted health further requires canonical IP text,
port in `[1,65535]`, and nonnegative offset. A well-formed triple that fails
that strict health subset is a policy mismatch, not malformed. After complete
shape validation, more than three triples is a well-formed unsupported policy
mismatch. ROLE replica count must equal `connected_slaves`; disagreement
between two individually well-formed sequential probes is a policy mismatch,
while a well-formed healthy-replica shortfall is also a policy mismatch. Tests
freeze canonical/noncanonical host, port `0`, negative/out-of-range port,
offset `-1`, the three/four boundaries for INFO and ROLE, and a claimed
`connected_slaves=65536` with bounded observed lines that fails as
`inconsistent` without a claimed-count loop.

Official non-master ROLE shapes are parsed only far enough to classify
authority drift without retaining their values. `slave` is exactly a
five-element array containing that token, an arbitrary bulk master host bounded
only by the universal encoded-reply cap, an integer port in `[0,65535]`, one of
the exact bulk state tokens `handshake`, `none`, `connect`, `connecting`,
`sync`, `connected`, or `unknown`, and an integer offset in `[-1,MaxInt64]`.
`sentinel` is exactly a two-element array containing that token and an
array of bulk master names within the universal aggregate-value and
encoded-byte caps. Names are arbitrary bulk strings, including empty values;
the auditor never interprets or retains them. Tests include 16 and 17 valid
names;
either well-formed non-master shape is a construction `misconfigured` result
or runtime `unavailable` with revalidation-clearable degradation. An unknown
role token, wrong official arity/type, out-of-bound value, or malformed shape
is `inconsistent`.

Audits are sequential snapshots, not transactions. A disagreement between
individually well-formed ROLE, CONFIG, INFO, or ACL probes can
result from concurrent failover or reconfiguration and is never promoted to an
impossible wire shape. Construction maps that churn to `misconfigured`;
runtime maps it to `unavailable` with revalidation-clearable degradation.
`inconsistent` and restart-only degradation are reserved for malformed,
duplicate, impossible, or self-contradictory shape inside one authoritative
reply. Deterministic tests change role, replica, AOF, memory, and topology
evidence between sequential replies and prove this recovery class.

ACL DRYRUN success is exact simple-string `OK`. A nonempty bounded bulk-string
denial of required PING or the in-namespace SET is a well-formed policy
mismatch. The out-of-namespace SET must return one nonempty bounded bulk-string
denial; denial text is always discarded without matching or formatting. An
out-of-namespace OK is a policy mismatch. For each of the three probes, an
empty denial, null, wrong scalar/container type, malformed frame, or oversized
reply is `inconsistent`; a well-formed RESP2 error line follows the global
auditor error-token mapping above. AUTH and HELLO are deliberately not
DRYRUN-tested because their `NO_AUTH` status would make those probes vacuous.

The exact common application command set for `valkey-go v1.0.77` is:

```text
PING
SET
```

The database is exactly zero, so `SELECT` is not
allowed. Client-side caching is disabled, so `CLIENT CACHING` and tracking
commands are not allowed. READONLY is not allowed because replay writes never
route to replicas. `ForceSingleClient: true` prevents standalone discovery from
depending on a CLUSTER/NOPERM error-string fallback. `AUTH` and `HELLO` are
pre-authentication commands that Valkey marks `NO_AUTH` and cannot be removed;
they are transport/authentication behavior, not application-principal grants.
Optional `CLIENT SETINFO` is disabled.

The canonical `ACL GETUSER` proof requires:

- flags exactly the two-element set `on`, `sanitize-payload`, with
  `nopass` absent;
- exactly one 64-byte lowercase hexadecimal SHA-256 password-hash bulk string,
  consumed only as protected proof and immediately cleared without formatting;
- no selectors;
- no channel patterns;
- exactly one key pattern `~dkim2:replay:v1:*`;
- database permissions exactly the canonical root-selector bulk string
  `db=0`;
- an ordered command rule beginning with `-@all`, followed only by exact
  positive command grants `+ping` and `+set`.

An official null-bulk `ACL GETUSER` reply means the application user is absent
and is a well-formed policy mismatch. In an otherwise exact fourteen-element
reply, every structurally valid but noncanonical user policy is also a mismatch:
The exact official flags grammar is order-insensitive and contains exactly one
of `on|off`, optional `nopass`, and exactly one of
`sanitize-payload|skip-sanitize-payload`; a duplicate, missing group, or unknown
flag is malformed. `off`, present `nopass`, or `skip-sanitize-payload` is a
well-formed policy mismatch.

The official command descriptor is one bulk string bounded by the universal
4 KiB reply cap. Tagged ACL rules preserve source-supplied legacy
first-argument bytes, lowercase them, and join them into a descriptor that is
not safely reducible to a whitespace-token grammar: source-reachable
noncanonical descriptors can contain SP, HT, CR, LF, VT, FF, quotes,
backslashes, `@`, `=`, or `,`. The structural envelope therefore requires an
exact closed prefix `-@all` or `+@all`, meaning the prefix is either the complete
descriptor or is followed by one ASCII space and at least one further byte.
The complete descriptor contains neither NUL nor ASCII uppercase. Every
non-exact descriptor inside that envelope is a well-formed policy mismatch;
wrong type, cap breach, NUL, ASCII uppercase, or absent closed prefix is
`inconsistent`. The accepted policy remains the exact byte string
`-@all +ping +set`. This intentionally avoids both a frozen built-in/module
registry and a falsely restrictive parser for source-reachable legacy rules.

Other structurally valid but noncanonical policy includes zero or multiple
well-formed password hashes, any non-exact command descriptor inside the safe
envelope, any well-formed selector, extra or different key pattern, channel
pattern, and canonical database alternatives `alldbs`, empty no-database value,
`db=1`, or `db=0,1`. Construction maps every policy mismatch to
`misconfigured`; runtime revalidation maps it to `unavailable` with
revalidation-clearable sticky degradation.

The official root-selector key grammar is empty or a space-separated sequence
of bounded glob tokens beginning with exactly `~`, `%R~`, or `%W~`. The suffix
may be empty and may contain any byte except NUL or the C-locale whitespace
bytes HT, LF, VT, FF, CR, and ASCII space. Suffixes are unique across the whole
sequence regardless of prefix. Tagged read-plus-write patterns are merged and
emitted once with the plain `~` prefix; this merge can emit `~*` alongside
other key tokens without setting the all-keys flag. The channel grammar is
empty or the same unique-suffix grammar with the exact `&` prefix, including a
structurally valid bare `&`; exact `&*` is the sole token when present.
Duplicate suffixes or `&*` beside another channel token are source-impossible
and `inconsistent`. The accepted application policy still requires the sole
exact read/write token `~dkim2:replay:v1:*` and no channel token; every other
structurally valid key or channel token or sequence is a policy mismatch.

The official database grammar is `alldbs`, empty, or `db=` followed by a
strictly increasing comma-separated list of distinct canonical unsigned IDs in
`[0,2147483647]`. The accepted application policy remains exactly `db=0`.

An absent, duplicate, or unknown top-level field; wrong container/scalar type or
arity; malformed password hash, flag, command, key, channel, selector, or frame;
and, outside the command descriptor and INFO grammar's explicitly deliberate
bounded forward-compatible envelopes, a value the official server cannot emit
is `inconsistent`. Impossible database values include `resetdbs`, `db=`, IDs
above `2147483647`, signed or non-decimal identifiers, leading-zero
identifiers, duplicate or unsorted
identifiers, case drift, whitespace drift, or a non-bulk-string value. These
create restart-only sticky
degradation at runtime.
This exact structural proof, rather than a finite deny sample, establishes the
least-privilege allowlist. DRYRUN remains a positive functional cross-check and
an out-of-namespace key-pattern check. The auditor connection starts in
database zero, as all new Valkey connections do, so each DRYRUN command checks
the required database-zero application behavior. `SELECT` remains absent from
the application allowlist and the loaded client configuration remains pinned
to database zero.

The auditor permits exactly one standalone primary and performs every role,
memory, persistence, replication, topology, and ACL allow/deny proof against
that direct authority. Each command has a two-second child deadline; the whole
audit has a thirty-second deadline; the exact per-audit cap is eleven commands.
Each command has exactly one reply under its command-specific encoded-byte,
aggregate-value, depth, and line caps above. The counter advances before
writing and rejects command twelve. A well-formed authoritative
policy value that does not match the required role, memory, persistence,
replication, or ACL policy is `misconfigured` at construction and
`unavailable` with revalidation-clearable sticky degradation at runtime.
Malformed, impossible, duplicate, truncated, oversized, or contradictory reply
shape is `inconsistent` at construction and runtime and creates restart-only
sticky degradation at runtime. No generic command, iterator, raw reply, server
string, or privileged client crosses the provider package boundary.

The auditor connection is closed immediately after validation and is never
stored on `Store`; the least-privileged application client therefore cannot
issue privileged proof commands. A non-context `net.Conn.Close` error prevents
evidence publication and maps to `unavailable`; a close panic is
`internal_invariant`. Cleanup is invoked exactly once on every success, error,
cancellation, deadline, and panic path, and raw cleanup text is discarded.
M13 owns supplying `AuditorConfig` and its protected credentials without
logging them.

The validator returns an unexported-field `validatedSecurityEvidence` that only
the provider package can construct. A local config, operator assertion,
well-formed authoritative policy-value mismatch, incomplete auditor config, or
client-factory mismatch makes `NewProductionStore` return nil plus
`misconfigured`. A non-context auditor transport failure returns nil plus
`unavailable`; terminal caller
cancellation or deadline returns exact `cancelled` or `deadline_exceeded`; an
impossible or contradictory bounded probe shape returns nil plus
`inconsistent`. No unattested Store object exists. A well-formed runtime policy
mismatch or non-context transport failure publishes revalidation-clearable
sticky degradation and returns `unavailable` before any replay SET. Runtime
malformed/impossible/contradictory reply shape returns `inconsistent` with
restart-only sticky degradation; an impossible local invariant remains
`internal_invariant`.

M13 must call the M12 `Revalidate(context.Context, AuditorConfig)` managed
method at least every sixty seconds. Evidence is valid for exactly five
minutes from the last complete successful probe. `CheckAndRemember` reads the
atomic evidence deadline before admission and, when stale, returns
`unavailable` without dispatch and publishes degraded. A successful
revalidation refreshes evidence and restores ready only when no restart-only
invariant or contract degradation remains and the store is still open. Clock
zero, backwards movement, or panic in this security timer is
`internal_invariant`. There is no provider-owned background goroutine.

Credentials and URLs are never accepted by the replay domain contract.

For each valid operation the provider issues exactly one command semantically
equivalent to:

```text
SET <protected-key> <constant-marker> NX PX <retention-ms>
```

Rules:

- the marker is a fixed non-secret bounded version string;
- the command contains exactly one key and is cluster-slot safe;
- no `GET`, script, transaction, pipeline batch, read-before-write, or
  follow-up TTL mutation is used;
- the command is built by the ordinary
  `client.B().Set().Key(...).Value("v1").Nx().PxMilliseconds(...).Build()`
  path and `IsRetryable()` must be false immediately before dispatch;
- neither the provider nor client factory calls `ToRetryable` or wraps this
  write in retry middleware;
- the provider performs no automatic retry;
- client-side caching is not used;
- an authoritative `OK` reply means first-seen;
- an authoritative null reply means replayed;
- replayed does not alter the existing TTL;
- an authoritative successful non-error reply other than exact `OK` or exact
  null is `inconsistent`;
- a nil or impossible in-process fake/adapter reply object that cannot
  represent any client result is `internal_invariant`; production uses the
  non-pointer `valkey.ValkeyResult` value and has no nil-reply state;
- any non-authoritative result after dispatch is indeterminate;
- no raw Valkey error string is propagated.

Authoritative Valkey error replies are matched only by their exact stable
server error kind and are never returned verbatim. Exact classification is:

1. A non-nil `ValkeyResult.NonValkeyError()` is non-authoritative and maps
   through the post-dispatch uncertainty rule without inspecting or formatting
   it. No string conversion or message serialization follows.
2. With no non-Valkey error, the provider calls `ValkeyResult.ToString()` once.
   It rejects a returned string longer than 4 KiB before any parsing or
   serialization.
3. Nil error plus a string other than exact `OK` is an authoritative
   unexpected success and is `inconsistent`; error-looking text is never
   reclassified. For exact `OK` only, `ToMessage()` must also return nil error.
   The returned message must report `IsString()==true`; false, including a
   float, verbatim string, big number, or any other non-string reply whose
   scalar text is `OK`, is an authoritative unexpected shape and is
   `inconsistent` before marshaling. Only then may `CacheSize()` run: it must
   be exactly 18, and `CacheMarshal()` into one exact
   zero-length, capacity-18 buffer must return exactly 18 bytes containing
   seven zero TTL bytes, type byte `+`, unsigned big-endian length two, and the
   two bytes `OK`. A valid `$` bulk-string
   `OK` is `inconsistent`. Any other framing, length, TTL, type, or
   value contradiction is `internal_invariant`. This version-pinned type proof
   is not client caching or persistence, and it never serializes a raw server
   error.
4. The authoritative null singleton is recognized separately with
   `valkey.IsValkeyNil`, requires an empty returned string, and maps to
   replayed. A null error paired with any other string is
   `internal_invariant`.
5. Only the original string value returned by the one `ToString()` call
   together with a
   direct, non-nil `*valkey.ValkeyError` error is an authoritative server-error
   pair. Wrapped errors, errors merely containing the same text, and every
   other error type do not supply server-error-kind authority; step 6
   classifies them without reading their text, and `errors.As` must not promote
   them. `ValkeyError.Error()` is never used for kind extraction because
   `valkey-go v1.0.77` has already removed an exact leading `ERR ` there.
6. An empty typed-error payload is `inconsistent`.
   `valkey.IsParseErr` without a typed server error represents an authoritative
   unexpected reply shape and is `inconsistent`; any other non-nil error after
   `NonValkeyError()` returned nil is an impossible adapter/fake pair and is
   `internal_invariant`.
7. The extractor accepts exactly one leading token of 1 through 32 ASCII bytes
   from the already bounded original string
   with grammar `[A-Z][A-Z0-9_]*`, terminated only by one ASCII space or by the
   end of the payload. It performs exact token comparison, never
   `HasPrefix`. A missing delimiter, malformed byte, or overlong token is
   `inconsistent`.
8. Only the extracted token is switched against the frozen table below. The
   suffix after the first ASCII space is never inspected, classified, retained,
   formatted, logged, stored, returned, or included in diagnostics. A
   well-formed unknown token is `inconsistent`.

The 4 KiB payload cap bounds provider-owned classification and retention after
`valkey-go` has decoded the application reply; it does not claim a pre-decode
allocation bound inside the dependency. Empty or oversized typed payloads are
`inconsistent`. The 32-byte token cap is sufficient for every frozen kind while
keeping the classification input small. `valkey-go` redirection handling may
continue to use its own helpers internally, but provider result mapping has
exactly this one authoritative error-kind source. The pinned 18-byte `OK`
layout has dedicated regression tests; any client-version or layout drift
requires a dependency review and cannot silently broaden success.

| Server error kind | Replay error | Mutation meaning |
| --- | --- | --- |
| `OOM` | `limit_exceeded` | rejected before mutation |
| `NOAUTH`, `WRONGPASS` | `unavailable` and restart-only sticky degraded | application-client credential binding cannot be repaired by the separate auditor |
| `NOPERM` | `unavailable` and revalidation-clearable sticky degraded | runtime ACL drift; constructor probe would be misconfigured |
| `READONLY`, `MASTERDOWN`, `CLUSTERDOWN`, `LOADING` | `unavailable` and revalidation-clearable sticky degraded | authority, topology, or audited server-state drift |
| `MISCONF`, `NOREPLICAS` | `unavailable` and revalidation-clearable sticky degraded | persistence or replication policy refused the write |
| `MOVED`, `ASK` | `unavailable` and revalidation-clearable sticky degraded | unsupported topology drift without application retry |
| `TRYAGAIN`, `BUSY` | `unavailable` and transient degraded | bounded authoritative pre-execution refusal without application retry |
| `ERR` or any other well-formed authoritative error kind | `inconsistent` and degraded | client/server contract mismatch; the message suffix is never inspected |

An OOM result never evicts an old replay key and never becomes first-seen.
NOAUTH/WRONGPASS application credential binding requires closing and
constructing a new provider; ordinary Revalidate cannot clear it. NOPERM/ACL,
role, cluster, memory headroom, persistence, and replication drift require one
complete successful Revalidate before ready can be restored. Unknown
network/client errors without an authoritative server reply remain
`indeterminate`.

`ForceSingleClient: true` keeps `valkey-go` on the one audited direct
standalone authority and prevents cluster redirect following or topology
refresh. Any authoritative `MOVED` or `ASK` reply is therefore unsupported
topology drift and maps to revalidation-clearable `unavailable` without a
provider retry. A reconnect, timeout, cancellation, or transport failure
without an authoritative reply is `indeterminate`; provider code never
constructs or dispatches a second SET itself. Tests assert one dispatch for
every redirect and non-redirection failure path.

The official client notes that context cancellation may return before a command
whose bytes were likely already sent. Therefore preflight and post-dispatch
context semantics are intentionally different:

1. A terminal valid context before dispatch returns exact typed cancellation or
   deadline and no command.
2. After the one call begins, cancellation, deadline, transport error, client
   close, panic, or absence of an authoritative reply cannot prove whether
   Valkey committed the key and returns `indeterminate`.
3. A syntactically authoritative server reply with an unexpected type or value
   is `inconsistent`; the server definitely replied, so it is not classified as
   an uncertain transport failure.
4. The provider never retries to "discover" the answer, because a second
   `NX` result could misclassify a successful first attempt as a pre-existing
   replay.

### Valkey State And Lifecycle

The Valkey provider has closed bounded states:

- `ready`;
- `degraded`;
- `closing`;
- `closed`.

An indeterminate, unavailable, panicking, backend-OOM, or contradictory client
operation publishes degraded state after the operation linearizes. Expected
local admission refusal before dispatch does not indicate backend-health drift:
a check rejected because waiter capacity is exhausted while the in-flight cap
is full and a revalidation rejected by the exclusive token return
`limit_exceeded` without changing `ready` or `degraded`. Degradation is either
transient or sticky:

- non-authoritative transport indeterminate, `TRYAGAIN`, and `BUSY` are
  transient; a later authoritative OK or null may restore ready;
- OOM/headroom, NOPERM/ACL, READONLY, MASTERDOWN, CLUSTERDOWN, LOADING,
  MOVED/ASK topology drift, persistence health, replication health, and stale,
  failed, or mismatched security-audit evidence is sticky;
  only one complete successful `Revalidate` that proves current health clears
  it;
- NOAUTH/WRONGPASS application credential failure is restart-only sticky
  because the auditor does not reconstruct the already-owned application
  client;
- callback/client panic, internal invariant, and inconsistent contract failure
  are sticky until the store is closed and the process constructs a new
  provider; Revalidate cannot certify code-contract recovery.

OOM always publishes sticky degradation because the finite-memory headroom
invariant no longer holds. A successful ordinary SET never clears sticky
security, configuration, resource, or contract degradation. There is no stale
cache or provider-owned background recovery goroutine.

Calls execute concurrently; the provider does not serialize all Valkey
operations. An admission gate rejects new calls after `closing` and counts
in-flight calls. The exact default in-flight cap is 1,024, the hard cap is
65,536, the exact default waiting-admission cap is 1,024, and its hard cap is
65,536. Zero selects the default, values outside `[1, hard maximum]` are
`misconfigured`, and waiter cap+1 is `limit_exceeded` before dispatch. Admission
waiting is context-aware and creates no provider goroutine. Close:

- is context-aware and idempotent;
- publishes closing before rejecting new work;
- waits for admitted operations without cancelling or reclassifying their
  authoritative results;
- publishes closed before releasing an owned client;
- closes an owned client exactly once;
- returns only bounded typed failures.

Revalidation uses the same lifecycle admission gate and increments the same
in-flight count that Close drains. Exactly one revalidation may be admitted at
a time through an atomic exclusive token; a concurrent second call returns
`limit_exceeded` before constructing an auditor client. It does not consume a
replay-command slot and does not block already-admitted checks; checks continue
using the prior evidence until its exact deadline. Nil/terminal context and
closing/closed precedence matches the public contract. A revalidation admitted
before closing may finish; Close waits for it and its auditor client. A
revalidation after closing begins returns `closed` and creates no client.

Auditor probes are non-mutating, so their context cancellation and deadline
remain exact caller errors; they are never classified as an indeterminate
replay write. The revalidation method closes its ephemeral auditor on every
success, error, cancellation, deadline, and panic path. Successful
revalidation atomically replaces the evidence deadline and clears only
revalidation-clearable sticky state; restart-only invariant/contract
degradation remains degraded. There is no provider-owned revalidation
goroutine or queue.

Lifecycle state dominates all recovery publication. `closing` and `closed`
have higher precedence than ready or degraded. An admitted check or
revalidation may return its authoritative result after Close publishes
closing, but every ready/degraded transition uses compare-and-swap only from
ready/degraded and must never overwrite closing or closed. Revalidation may
finish cleanup and discard refreshed evidence during closing; it cannot reopen
the provider. Closed is terminal.

If the close context expires, the provider remains closing and a later Close
continues the same drain. After drain, production invokes the owned
`valkey.Client.Close()` exactly once; that API returns no error, so no
authoritative production close-failure state exists. A recovered application
client close panic is `internal_invariant`. State remains closed and ownership
is relinquished. M12 claims exact client ownership and invocation count, not
synchronous release timing for dependency-owned network resources.

The key deriver has the same admission/close model. It clones and owns only the
supplied 32-byte secret buffer, clears that owned buffer after admitted derives
finish, and makes no claim about transient HMAC implementation copies or
runtime memory. Later derives return closed.

### Replication And Failover

`SET NX PX` is atomic on the authoritative Valkey node that executes it.

M12 does not claim global exactly-once behavior across asynchronous replication,
failover, network partition, backup restore, active-active products, or
operator key deletion. A successful primary response may be lost after
failover, and an uncertain response may still have committed.

Production readiness therefore requires the noeviction, primary-routing,
replication, persistence, shared-secret, and rotation contract above. These are
bounded operational risks, not DKIM2 protocol semantics, and do not justify
hidden retries.

### Provider Parity

Memory and Valkey providers must agree on the storage-neutral observable
contract:

- first valid observation is first-seen;
- a later observation before expiry is replayed;
- replay does not extend expiry;
- an observation at or after expiry may become first-seen;
- invalid retention and key fail before mutation;
- closed providers do not serve;
- one same-key concurrency winner exists.

Disabled is intentionally not parity-equivalent to an enabled provider.

Backend-specific degraded and indeterminate conditions retain their closed
error classes and do not become first-seen or replayed.

## Package Boundaries

`lib/internal/replay` owns:

- replay identity and protected key types;
- key derivation;
- store interface;
- checks, states, errors, limits, and retention;
- memory and disabled implementations;
- backend-neutral tests and fixtures.

The root `lib` package owns:

- stable aliases or wrappers needed by command modules;
- the only public `ReplayIdentities(VerifyResult)` adaptation, which succeeds
  only when the immutable result contains the verifier-owned sealed PASS
  projection;
- constructor and result adaptation without duplicated rules;
- public dependency and API tests.

`cmd/dkim2d/internal/replay/valkey` owns:

- the `valkey-go` adapter;
- exact command construction;
- reply and failure mapping;
- Valkey state and client ownership;
- fake-client and mandatory explicit real-server integration tests.

M12's Valkey provider package owns the sole concrete `valkey-go` client factory
and its retry/redirection/security options. M13 owns config and secret loading,
TLS/auth material loading, passing validated inputs into that factory, startup
and periodic execution of the M12 security validator, health aggregation, and
Fx lifecycle composition. It may not construct a parallel client, weaken, or
bypass the M12 production attestation.

M15 owns replay observations, metrics, traces, logs, and redaction enforcement
at telemetry exporters.

M16 and M17 own adapter-facing policy and operational behavior.

No replay package imports:

- raw message, recipe, signature, signing, verification, policy, or datasource
  implementations;
- Cobra, Viper, Fx, OpenAPI generated types, Milter, Exim, slog handlers,
  OpenTelemetry exporters, or Prometheus;
- Valkey outside the one command provider package.

## Security And Privacy

Replay inputs and storage artifacts are protected metadata. Canonical current
recipient bytes exist only transiently during authoritative envelope
projection and recipient-scope hashing; no replay identity retains them. The
ordinary request and parser may retain their own immutable input according to
their existing lifecycle, so M12 makes no false Go memory-erasure claim.

Mandatory rules:

- no raw RFC 5322 message, body, or header in replay storage or diagnostics;
- no raw sender, recipient, local part, domain, or `Message-ID` in replay
  storage or diagnostics;
- no raw `Message-Instance` or `DKIM2-Signature` in replay storage or
  diagnostics;
- no raw signature value, selector, nonce, key handle, datasource identifier,
  Valkey key, address, URL, username, password, token, certificate, or private
  key;
- no unbounded raw error or server reply;
- no secret-dependent branching that changes public formatting;
- no secret or protected key in `%s`, `%q`, `%v`, `%+v`, `%#v`, `%x`, `%X`,
  `%p`, `String`, `GoString`, text, JSON, container, panic, or failed-test
  output.

All public and concrete protected types require explicit formatting and
serialization tests. Default JSON for protected types must be absent, rejected,
or a constant empty/redacted form.

HMAC provides keyed pseudonymization, deployment separation, and domain
separation while the deployment secret remains protected. Per-recipient
identity construction prevents one recipient from being hidden in an aggregate
recipient-set key. HMAC alone does not provide anonymity, unlinkability, or
grouping resistance, and it does not make an exposed replay key safe to log.

Memory capacity, heap growth, key length, retention, client calls, waiters,
goroutines, and close behavior are hard bounded.

Ambiguous state fails closed. No policy weakening, stale fallback, fail-open
default, retry, or test expectation change may hide an uncertain write.

## Observability

M12 constructs no logger, metric, tracer, exporter, or global telemetry state.

The replay domain may expose only bounded facts later consumable by M15:

- provider kind;
- provider state;
- replay check class;
- replay error class;
- key algorithm version;
- retention bucket;
- duration measured outside the domain operation.

Raw or hashed replay keys, identity digests, secrets, endpoints, database
numbers, client addresses, session/request/trace IDs, raw errors, and
credentials are forbidden.

Prometheus label design remains M15 ownership.

## Required Tests

### Domain And Error Tests

- Every known and unknown enum.
- Every valid and invalid result pair.
- Nil context, typed-nil constructor dependency, panic, raw error, wrapped
  error, and contradictory outcomes.
- Exact preflight cancellation and deadline identity.
- No context identity for post-dispatch indeterminate writes.
- Stable constant formatting and serialization privacy.

### Identity And Key Tests

- Exact deterministic HMAC-SHA256 golden vectors.
- Domain separator, algorithm version, draft, and field framing.
- Exact recipient-scope SHA-256 label, uint32 framing, canonicalization,
  deduplication, lexicographic order, and per-recipient identity count.
- `exploded` is ORed over every relevant signature header authenticated by the
  passing highest canonical signature input; unrelated or unauthenticated
  headers cannot set it.
- PASS provenance is mandatory; forged, zero, copied incomplete, non-PASS, and
  cross-boundary projections cannot construct identities.
- Same secret and facts produce one exact key.
- Any changed fact, order, version, or secret changes the key.
- Exact golden vectors assert the full production storage key only from
  synthetic fixed facts and a published non-production synthetic secret.
- Nil, short, long, all-zero, mutated, and closed secret handling.
- All-zero present message and signature digests are accepted and have golden
  vectors; absent digest presence is rejected.
- Caller mutation cannot change identity or key.
- Key and secret formatting/marshaling privacy matrices.
- Close and best-effort secret clearing behavior.

### Retention And Limit Tests

- Exact minimum and maximum.
- Exact one-second minimum, fourteen-day default, and thirty-day hard maximum.
- Zero, negative, sub-millisecond, non-integral millisecond, cap+1, conversion,
  addition, and platform-width overflow.
- Exact expiry boundary.
- No TTL extension on replay.
- Exact key length and constant marker bounds.
- Zero/default/minimum/hard-maximum entry, waiter, prune, in-flight, and
  admission-waiter limits.

### Memory Provider Tests

- First-seen, replayed, expired, and first-seen again.
- Injected-clock determinism.
- Nil, zero, backwards, and panicking injected clocks fail before mutation.
- Min-heap/map one-to-one invariants.
- Expired pruning before capacity.
- Exact prune-budget exhaustion and progressive bounded cleanup.
- Capacity exact and cap+1 without eviction.
- Same-key deterministic concurrency with one winner.
- Distinct-key concurrency.
- Context cancellation while waiting and after acquisition before mutation.
- Close racing with check, exact linearization, idempotence, and zero retained
  entries.
- Race tests with barrier assertions.

### Disabled Provider Tests

- Valid requests return only disabled.
- Nil and terminal contexts remain failures; key, secret, epoch, and retention
  are not required while disabled.
- No first-seen result.
- No mutation or dependency calls.
- Idempotent close and closed behavior.

### Valkey Unit Tests

- Exact one-command tokens: `SET`, one protected key, constant marker, `NX`,
  `PX`, exact integer retention.
- Command is not retryable.
- `IsRetryable()` is false immediately before dispatch and no production code
  calls `ToRetryable`.
- Production factory uses exactly one canonical IP-literal endpoint with
  `ForceSingleClient=true`; complete option and init-command capture tests prove
  it dispatches no CLUSTER command, follows no MOVED/ASK reply, and performs no
  ordinary network retry.
- Construction rejects cluster, DNS, load-balancer, failover, Unix-socket, and
  multi-endpoint configuration before creating either client.
- OK maps to first-seen.
- Null maps to replayed.
- Replay does not issue a second command.
- Exhaustive v1.0.77 reply-category tests cover non-OK simple strings, bulk
  strings, integers, floats, booleans, verbatim strings, big numbers, arrays,
  sets, maps, pushes, null contradictions, simple errors, blob errors, and
  malformed replies.
  Reachable scalar text `OK` variants for `+`, `$`, `=`, `(`, and `,` prove
  exact simple-string success, coherent unexpected-shape inconsistency, and
  that only `+`/`$` reach the bounded cache discriminator after `IsString`.
- Direct typed authoritative `OOM`, auth/ACL, read-only/cluster/loading,
  MISCONF/NOREPLICAS, redirection/TRYAGAIN/BUSY, `ERR`, and unknown
  server-error kinds map exactly to the table by the bounded leading token.
- Error-kind tests cover the exact 4 KiB payload cap, 1-byte and 32-byte token
  bounds, cap+1, exact-token versus prefix collisions, grammar bytes, ASCII
  space/end delimiters, empty/malformed payloads, wrapped typed errors,
  arbitrary errors with known-token text, and suffix non-inspection.
- A lossless-result reproducer proves `ERR OOM detail` remains kind `ERR` even
  though `ValkeyError.Error()` alone exposes `OOM detail`; the provider parses
  only the original `ToString()` value paired with the direct typed error.
- Pair tests require `NonValkeyError()==nil`, one `ToString()` call, direct
  type identity, and matching authoritative value/error provenance; no
  `Error()` string or named `HasPrefix` helper participates in classification.
- Exact simple-string `OK` succeeds while blob/bulk-string `OK` is
  inconsistent; float, verbatim-string, big-number, and every other
  non-string `OK` fail as authoritative unexpected shapes before marshaling.
  The pinned 18-byte cache-layout test proves `IsString`, the seven zero TTL
  bytes, `+` type, big-endian length, and public constant without
  cache-marshaling error payloads.
- Nil-error/error-looking raw text, null/nonempty raw, typed-error/empty or
  malformed raw, parse errors, arbitrary fake errors after nil
  `NonValkeyError`, and cache-layout drift cover every contradictory pair.
- Pre-dispatch cancellation/deadline performs zero client calls.
- During-call cancellation/deadline, transport failure, panic, and client close
  map exactly to indeterminate; impossible fake reply objects are internal and
  authoritative unexpected replies are inconsistent.
- No raw client/server marker appears in any error or formatting surface.
- Transient success recovery, sticky revalidation-only recovery, and
  restart-only contract/invariant recovery transitions.
- Close ownership, admission draining, exactly-once client close, and
  post-close failure.
- No read, retry, pipeline, script, transaction, or TTL-refresh fallback.
- Every authoritative MOVED/ASK reply is unavailable topology drift, while a
  redirect transport failure without authoritative reply is indeterminate; all
  cases issue no provider retry.
- Production construction rejects every missing TLS, peer verification, auth,
  ACL, primary, noeviction, finite maxmemory/headroom, shared epoch/secret,
  persistence/replication, and rotation-attestation field.
- Attestation tables cover every zero/unknown enum, persistence-mode and
  appendfsync/save combination, replica and lag boundary, accepted loss-window
  value, required assertion, and unchanged/drain-completed rotation state.
  Formatting and serialization remain content-free.
- Acquisition-order tests prove local validation precedes the auditor, the
  auditor and cleanup precede application-client construction, final
  context/mode checks precede publication, and every acquired resource closes
  exactly once under every error and panic combination.
- Startup and five-minute-expiry revalidation distinguish local config proof,
  operator assertions, privileged auditor probes, and the least-privileged
  application client; stale or failed evidence dispatches no SET.
- Auditor tests cover one standalone primary, command 11/12,
  per-command/global deadlines, exact raw frame/value/depth/line caps,
  `INFO cluster` zero/one, exact requested/unknown INFO section and field
  grammars with every length/byte boundary, and the complete
  ACL/config/topology proof.
- CONFIG tests separate tagged live grammar from accepted policy: save zero and
  negative changes are structural mismatches, save seconds freeze
  `MaxInt64`/cap+1, save changes freeze `MinInt32`/`MaxInt32` and both overflow
  boundaries, min-replica integers freeze the `INT32_MAX`/cap+1 boundary, and
  bounded forward-compatible `maxmemory-policy` tokens remain mismatches unless
  exact `noeviction`.
- INFO replication tests require exact ordered
  `ip,port,state,offset,lag,type`, every tagged state/type token, signed
  port/offset/lag boundaries, negative lag, empty/noncanonical announced host,
  delimiter corruption, steady-state health, and policy-mismatch recovery.
- ROLE tests cover master announced host 0/255 bytes, signed-int32 port,
  negative offset, strict healthy metadata, arbitrary bounded slave/sentinel
  hosts and names, slave port zero, all official slave states, disconnected
  offset `-1`, and policy-mismatch rather than malformed classification.
- ACL tests prove the exact standalone allowlist, ordered `-@all` rule, single
  namespace pattern, empty channels/selectors, order-insensitive official flags,
  exact password-hash count, exact database-zero permission, every allowed
  DRYRUN, and out-of-namespace SET denial. Command-envelope cases include empty,
  dotted, punctuation-bearing, category, subcommand, legacy first-argument,
  whitespace, quote, and backslash variants as policy mismatches, plus closed
  prefix, NUL, ASCII-uppercase, and cap failures as `inconsistent`. Pattern
  cases include bare `~`, `%R~`, `%W~`, and `&`, suffix deduplication,
  read/write collapse, coexisting merged `~*`, sole `&*`, and every excluded
  pattern byte.
- TLS ownership tests mutate every caller-owned endpoint, credential, root DER,
  dial, and option input after construction and prove the provider-owned values
  remain unchanged. Race tests exercise independently owned concurrent
  construction inputs. Tests reject root count, per-DER,
  aggregate-DER, parse, CA, and duplicate boundaries and every client
  certificate, private-key, verifier, or TLS callback input.
- ACL database tests prove the private auditor emits no HELLO or RESP3
  negotiation, directly parses exactly fourteen RESP2 top-level elements as
  seven distinct required ACL pairs, accepts every ACL pair permutation while
  retaining CONFIG's separate exact requested-order rule, preserves duplicates
  without map conversion, requires exact `databases` bulk string `db=0`,
  covers the complete
  policy-mismatch table, `~`/`%R~`/`%W~` patterns, database
  `INT32_MAX`/cap+1, insignificant top-level pair order, and
  malformed/impossible encodings, and rejects absent, duplicate, unknown, or
  wrongly typed fields.
- ACL selector tests cover zero selectors and nonempty arrays whose elements
  are exact ordered eight-element RESP2 arrays for `commands`, `keys`,
  `channels`, and `databases`; every nested value grammar is reused before a
  valid nonempty selector becomes a policy mismatch, while nested
  duplicate/missing/unknown/reordered/type/cap failures are `inconsistent`.
- Compatibility tests prove no server-version string grants readiness:
  database-permission capability is required, a pre-9.1 reply without
  `databases` fails closed, and future metadata remains a review-blocking
  inconsistent shape.
- Table/fuzz tests inject every representative category, wildcard, selector,
  key/channel, bare parent command, extra subcommand, rule reordering, unknown
  field, and arbitrary added positive grant and require rejection without
  revealing password hashes or raw ACL replies.
- Auditor result tests distinguish well-formed policy mismatch, malformed or
  contradictory shape, exact caller cancellation/deadline, and non-context
  transport failure at construction and revalidation.
- Persistence and replication audit tests require current RDB/AOF status and
  current healthy replica count/lag, not merely matching configured settings.
- Revalidation tests cover exclusive admission, concurrent cap+1, prior-evidence
  check behavior, every cleanup path, close draining, closing/closed rejection,
  exact context identity, and sticky-state recovery classes.
- Admission-state tests begin separately from `ready` and from a preexisting
  `degraded` state, exhaust check in-flight plus waiter capacity and the
  revalidation exclusive token, and prove each pre-dispatch `limit_exceeded`
  leaves the exact prior state unchanged and dispatches no SET or auditor.
- Check-vs-Close and Revalidate-vs-Close barriers prove ready/degraded recovery
  cannot overwrite closing or closed.
- `UseReplayStorageKey` rejects invalid input, runs exactly once, recovers
  panic, retains no provider-owned copy, and is absent from unapproved
  production imports.

### Provider Parity And Integration Tests

- The complete observable first-seen/replayed/expiry/non-extension contract
  runs against memory and Valkey server `9.1.0`.
- Same-key concurrent Valkey calls have exactly one first-seen result.
- A real TTL expires and permits a later first-seen result without refresh.
- The integration path uses only synthetic protected keys and constant values.
- The explicit `make test-valkey` target starts only a hermetic local Valkey
  `9.1.0` process on a private temporary Unix socket with TCP disabled,
  an exact synthetic RDB schedule, AOF disabled, finite `maxmemory`,
  `maxmemory-policy noeviction`, synthetic keys, and a temporary working
  directory. It creates a synthetic application user with exact
  `-@all +ping +set`, namespace, `db=0`, password, and flags plus a separate
  synthetic auditor user with only the exact ROLE, CONFIG GET, INFO, ACL
  GETUSER, and ACL DRYRUN privileges; the default user is disabled before
  evidence collection.
- Through a package-private Unix-socket test transport, the real-server target
  executes the exact eleven-command RESP2 auditor plan and proves the actual
  Valkey `9.1.0` ACL `databases` field, DRYRUN success/denial scalar types,
  CONFIG ordering and values, ROLE, and all four INFO shapes. It uses the same
  production framing and parser while bypassing only production TCP/TLS
  construction; TLS authority and ownership remain covered by deterministic
  factory tests. It then runs the provider parity operations through the
  synthetic application user.
- The harness terminates the process and deletes its directory on success,
  failure, signal, or test timeout.
- `make test-valkey` fails clearly when the exact server version or binary is
  unavailable; it never skips. The final M12 evidence must record a successful
  run. Default unit tests remain independent of an external server.
- TLS construction is exercised with deterministic certificate/configuration
  tests in M12; M13 adds concrete secure loading and Fx wiring without changing
  the store or auditor contract.

### Fuzz And Abuse Tests

Non-vacuous bounded fuzz targets cover:

- replay identity construction and key derivation;
- result and error pair validation;
- memory state transitions under bounded operation sequences;
- Valkey authoritative/null/unexpected/error mapping;
- retention conversion and overflow.

Fuzz inputs are bounded before allocation. Corpus and diagnostics contain only
synthetic fixed-size facts, never secrets or production identities.

Abuse tests cover:

- capacity exhaustion;
- repeated expired entries;
- high same-key contention;
- cancellation storms;
- close races;
- panicking or blocking fake clients;
- malformed and oversized replies;
- raw marker privacy;
- client failure after possible dispatch.

### Dependency And Guardrail Tests

- `lib/internal/replay` has no command/service/Valkey dependencies.
- `lib/go.mod` has no Valkey client.
- `cmd/dkim2d` Valkey package imports only the public root facade plus its
  intentional client dependency.
- No command module imports `lib/internal`.
- Exactly one replay taxonomy and key algorithm exist.
- Every changed handwritten named function and method has an English doc
  comment.
- Production names contain no milestone or prompt labels.
- `make test`, `make vet`, `make lint`, `make race`, and `make guardrails`
  pass.
- `govulncheck` is clean.
- All replay fuzz targets run for at least ten seconds on the final snapshot.
- The mandatory explicit real-Valkey integration target is run and recorded.

## Acceptance Criteria

- Replay remains explicit local policy and does not alter DKIM2 conformance.
- The public contract is storage-neutral and implementable from `cmd/dkim2d`
  without importing `lib/internal`.
- The library module remains independent of `valkey-go`.
- Replay keys are deterministic, versioned, deployment-bound, framed, fixed
  length, and privacy-preserving.
- Raw message, envelope, protocol, credential, provider, and protected key
  facts are absent from storage values and diagnostics.
- Memory storage is bounded, expiry-aware, race-safe, and scan-free.
- Disabled behavior is explicit and never presented as first-seen.
- Valkey uses one non-retryable atomic `SET NX PX` command.
- Authoritative OK and null replies are the only first-seen and replayed
  successes.
- Only a direct typed non-nil `*valkey.ValkeyError` supplies a server error
  kind, and only when paired with the original bounded `ValkeyResult.ToString()`
  value after `NonValkeyError()` is nil; its exact leading token maps once
  through the frozen table and its raw payload and suffix never propagate.
- Exact simple-string `OK` is proven with the bounded pinned-v1.0.77 cache
  layout after `IsString`; bulk, float, verbatim, big-number, and every other
  non-simple-string `OK` plus every layout contradiction fail closed, and no
  error payload is cache-marshaled.
- A non-authoritative failure after possible dispatch is indeterminate and
  never retried; authoritative refusals use their exact closed error mapping.
- Replay does not extend retention.
- Provider close and ownership are exact and idempotent.
- Valkey replication/failover limitations are documented as operational risk.
- Provider parity, real integration, fuzz, abuse, privacy, race, dependency,
  and full guardrail evidence pass.
- Two independent reviewers approve one exact unchanged implementation
  snapshot.
- `temp/` is absent from the index and commit.
- Exactly one project-formatted M12 commit is created.

## Closeout Integrity

Closeout has two phases. Before candidate freeze, this durable file may change
only in these exact mutable regions:

1. the single top-level `Status:` line;
2. the measured-effort table after
   `Measured effort is filled during closeout:` and before `## Scope`, with
   actual Prompt 01 through Prompt 07 timings only;
3. the Completion Evidence body after `## Completion Evidence` and before
   `## Review Matrix`; and
4. the Review Matrix body after `## Review Matrix` and before
   `## Decisions And Open Questions`.

The Prompt 08 row remains external-only because its true terminal completion
occurs after candidate freeze, final review, staging, commit, and post-commit
proof. Prompt 08 start, candidate-freeze time, terminal completion, and exact
duration are retained only in the ignored ledger. The durable Status at freeze
must remain an honest in-progress/candidate-frozen state; it must not claim
terminal completion before the commit exists.

The durable Final review matrix row at freeze records only that the external
gate is defined and still pending. Actual reviewer identities, approval
results, candidate formula hash, path-list hash, manifest hash, Git tree OID,
commit identity, and terminal completion are recorded only in the ignored
ledger and external review records. They must not be embedded in this file
because that would change the candidate they attest.

Before and after the permitted durable closeout edits, a normative projection
must remove exactly the four mutable regions above and remain byte-identical.
This immutable section, Goal, Scope, semantics, package boundaries, security,
tests, Acceptance Criteria, Decisions, and Definition Of Done are never removed
from that projection and cannot change during closeout.

## Completion Evidence

Self-reference-free implementation and validation evidence:

- Focused tests: replay facade, replay core, verification projection, service
  projection, and Valkey provider package tests pass in normal and race modes.
- Real Valkey `9.1.0`: the exact official local server version is required and
  `make test-valkey` passes the private-Unix-socket eleven-command audit plus
  memory/Valkey parity; missing or wrong binaries fail instead of skipping.
- Fuzz smoke: `FuzzReplayIdentityAndKey`, `FuzzReplayResultPair`,
  `FuzzMemoryStateSequence`, `FuzzValkeyResultMapping`, and
  `FuzzReplayRetention` each run non-vacuously for at least ten seconds and
  pass.
- Generated/dependency checks: OpenAPI presence, deterministic workspace
  vendor output, module-readonly resolution, exact Valkey dependency ownership,
  checksums, Apache-2.0 license, NOTICE, and production import-direction guards
  pass.
- Vulnerability checks: all four modules report no vulnerabilities against an
  official complete Go vulnerability-database snapshot fetched as one fixed
  bulk artifact and consumed locally without disclosing module paths.
- Guardrails: formatting, vet, lint with zero findings, unit tests, race tests,
  OpenAPI checks, deterministic vendor checks, and vulnerability checks pass
  through the complete root guardrail target.
- `git status --short`: only replay-increment durable paths are dirty, the real
  index is empty before final approval, and the ignored prompt pack is outside
  the durable snapshot.
- Skipped checks: none. The fixed bulk vulnerability database replaces remote
  per-module requests for privacy; it does not omit any module scan.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | M12 replay storage only | Storage-neutral replay identities/providers, daemon-owned Valkey provider, tests, and operator evidence implemented | done | No daemon wiring, local disposition, telemetry, OpenAPI behavior, or adapter integration |
| Draft behavior | draft-04 identity and exploded semantics preserved | Sealed aggregate-current PASS supplies exact current identity facts; replay remains explicit local policy | done | No protocol result or DKIM2 conformance rule is changed |
| Store behavior | Exact first-seen, replayed, disabled and errors | Memory, disabled, and Valkey providers preserve exact retention, non-extension, lifecycle, uncertainty, and closed result pairs | done | Shared parity and concurrency evidence passes |
| Privacy | No production key, recipient, secret, or raw error disclosure | Protected values remain absent from formatting, marshaling, errors, callbacks, failed-test output, and provider diagnostics | done | Marker matrices cover value, pointer, fake-client, config, result, and lifecycle surfaces |
| Valkey security | TLS, ACL, primary, noeviction, retry and drift contract | Immutable direct-primary authority, TLS 1.3, exact application/auditor ACLs, noeviction/headroom, persistence/replication evidence, and no-retry writes are enforced | done | Exact Valkey 9.1.0 audit and operator guide define the asynchronous loss window |
| Boundaries | Internal core, root facade, cmd-only Valkey dependency | Library replay ownership stays standard-library-only; exact valkey-go v1.0.77 ownership remains confined to the daemon provider | done | Machine guards reject import, module/workspace replacement, vendor, license, and NOTICE drift |
| Tests | Unit, race, fuzz, abuse, real Valkey 9.1.0 | Focused/race suites, five bounded fuzz targets, deterministic cancellation/close storms, privacy abuse, and real-server parity pass | done | Missing or wrong server binary is a hard integration failure |
| Effort | Prompt 01-07 timings recorded; Prompt 08 terminal timing external | Prompt 01-07 exact spans total 8h47m27s; Prompt 08 terminal timing remains externally recorded by contract | done | Measured pre-closeout total exceeds the eight-hour estimate ceiling by 47m27s |
| Guardrails | Complete local gate clean | Formatting, tests, vet, lint, race, OpenAPI, deterministic vendor, dependency/license, and vulnerability checks pass | done | Official bulk vulnerability database preserves complete scans without module-path disclosure |
| Final review | Two approvals of one exact unchanged snapshot | External exact formula/spec/projection/path/manifest/tree gate is defined and pending | pending | Reviewer identities, artifact hashes, commit identity, and terminal timing remain outside this candidate |

## Decisions And Open Questions

### Decisions

1. Replay storage is local policy, not DKIM2 protocol correctness.
2. The operation is `CheckAndRemember`, not a Valkey command abstraction.
3. The library owns an internal replay core and exposes only the exact root
   facade required by command providers.
4. Valkey code and `valkey-go v1.0.77` remain in `cmd/dkim2d`.
5. M12 freezes the production TLS, ACL, noeviction, primary-routing,
   persistence/replication, shared-secret, epoch, rotation, and attestation
   invariants. M13 owns loading and wiring them without weakening them.
6. Keys use versioned framed HMAC-SHA256 with a deployment-local 32-byte
   secret.
7. M12 derives identity only from a sealed aggregate current PASS: the selected
   Message-Instance SHA-256 header hash, SHA-256 of the exact canonical highest
   signature input, and one SHA-256 scope digest per canonical actual current
   recipient.
8. Memory expiry uses a bounded heap and never a full-map background scan.
9. Disabled returns an explicit disabled check.
10. Enabled providers never extend retention on replay.
11. Valkey uses exactly one non-retryable `SET NX PX` command.
12. A non-authoritative failure after possible dispatch is indeterminate and
    is not unwrapped as ordinary context cancellation; authoritative refusals
    use the exact closed server-error mapping.
13. Async replication and failover are operational limitations, not protocol
    semantics.
14. `ReplayStore` has only `CheckAndRemember`; lifecycle and lock-free state are
    an optional managed interface and no portable usage scan exists.
15. M15 owns telemetry and M16/M17 own adapter policy.
16. `valkey-go v1.0.77` has no general error-kind accessor and strips `ERR `
    from `ValkeyError.Error()`. The provider therefore extracts only a bounded
    exact RESP leading token from the original `ValkeyResult.ToString()` value
    paired with a direct typed `*valkey.ValkeyError` after
    `NonValkeyError()` is nil; it never classifies arbitrary error strings or
    the server message suffix. Because `ToString()` collapses simple and blob
    strings, only the public constant `OK` uses the bounded pinned-v1.0.77
    cache serialization as a response-type proof; error payloads never do.

### Open Questions Deferred By Ownership

- Replay disposition modes and defaults belong to service policy and adapter
  milestones.
- Concrete standalone endpoint, database, TLS trust, authentication, secret
  loading, and readiness configuration belong to M13, subject to M12's frozen
  security attestation and rotation contract. Cluster routing remains
  unsupported until a later durable owned-router design is approved.
- Telemetry buckets and labels belong to M15.
- Multi-region consensus products remain operator policy and are not claimed
  by M12.

None of these deferrals permits M12 implementations to invent a fallback.

## Definition Of Done

- The durable specification has independent normative and architecture
  approval before the prompt pack is frozen.
- The ignored prompt pack is sequential, reviewed, hashed, and never staged.
- Public contracts, errors, limits, identity, key derivation, memory, disabled,
  and Valkey providers are implemented once within the documented import graph.
- Reproducer-first tests retain every defect found during implementation.
- No protocol result or local disposition is silently changed.
- Retention, capacity, concurrency, lifecycle, cancellation, and
  indeterminate-write invariants are deterministic and bounded.
- Privacy tests cover every formatter, marshaler, error, result, provider, key,
  identity, fake-client marker, and failed-test surface.
- Provider parity and explicit real-Valkey integration pass.
- Every fuzz target is non-vacuous, bounded, enumerated, and run for at least
  ten seconds on the final snapshot.
- Formatting, tests, vet, lint, race, vulnerability, dependency, and generated
  artifact guardrails pass.
- Two independent reviewers approve the identical exact implementation hash
  with no open findings.
- The staged manifest is byte-identical to the approved manifest.
- `temp/` is absent from staging.
- Exactly one structured M12 commit records the milestone.
