# DKIM2 Datasource Providers

Status: completed; implementation and completion evidence recorded.

This specification defines the storage-neutral datasource boundary used to
resolve DKIM2 signing profiles and opaque private-key handles. It is the
durable contract for the original in-memory and flat-file provider milestone.
LDAP and SQL were follow-on seams in this document and are now implemented
under [`ldap-sql-datasource-legacy-migration.md`](ldap-sql-datasource-legacy-migration.md),
[`native-datasource-key-custody.md`](native-datasource-key-custody.md), and
[`mysql-mariadb-datasource.md`](mysql-mariadb-datasource.md). Current operator
truth lives in [`../../operator/datasource-backends.md`](../../operator/datasource-backends.md).

## Source Documents

This specification is governed by:

- `AGENTS.md`.
- `POLICY.md`.
- `docs/ARCHITECTURE.md`.
- `docs/specs/spec-and-prompt-template.md`.
- `docs/specs/implementation/signing-and-revision.md`.
- [draft-ietf-dkim-dkim2-spec-04](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-04), especially Sections 4, 7, 8, and 9.
- [draft-chuang-dkim2-dns-04](https://datatracker.ietf.org/doc/html/draft-chuang-dkim2-dns-04), especially the signing-key and algorithm constraints.
- RFC 5321 and RFC 5322 where SMTP envelope and message-domain facts enter
  profile selection.
- RFC 8259 for the flat-file JSON representation.
- `Makefile`.

The implementation baseline is exactly the two `-04` drafts. A later draft is
not an implicit behavior update. Provider behavior must not reinterpret,
weaken, or duplicate protocol validation owned by signing, verification, DNS,
canonicalization, recipe, or policy packages.

## Goal

Add a cohesive datasource domain that:

- resolves one exact immutable signing profile from bounded lookup facts;
- returns opaque private-key handles rather than private-key material;
- resolves one exact administrative domain/tenant policy for an explicit
  profile-use purpose;
- distinguishes every closed success, absence, ambiguity, authorization,
  malformed-data, unavailable, cancellation, and invariant state;
- provides behaviorally equivalent in-memory and flat-file implementations;
- integrates with the M10 signing callback boundary without teaching
  datasource providers how to construct or sign DKIM2 fields;
- publishes immutable snapshots atomically and remains race-safe;
- keeps secrets and high-cardinality identity data out of diagnostics;
- leaves LDAP, SQL, replay storage, configuration, daemon wiring, and
  observability exporters to their later milestones.

Correctness means exact profile identity and an authorized opaque handle are
resolved before signing begins. A missing or ambiguous selector, fallback
record, partial profile, stale snapshot, unauthorized handle, or provider
failure must never silently select another identity.

## Scope

In scope:

- domain-owned provider interfaces under `lib/internal/datasource`;
- immutable validated lookup facts, profile IDs, profiles, key-handle IDs,
  domain/tenant policy, provider states, typed errors, limits, and usage;
- exact profile lookup and opaque handle lookup;
- deterministic in-memory provider construction and reads;
- strict JSON flat-file loading into an immutable in-memory snapshot;
- safe bounded reload with atomic publication and fail-closed degraded state;
- signing-boundary adapters that pass only approved public profile facts and
  opaque signing handles to M10;
- LDAP and SQL design contracts and mapping documentation without drivers,
  network clients, queries, schemas, or production implementations;
- unit, integration, negative, abuse, fuzz, race, privacy, and dependency
  evidence;
- architecture and package documentation required by this work.

Out of scope:

- replay detection, replay keys, TTLs, Valkey, Redis, or `CheckAndRemember`;
- DNS key publication or lookup;
- parsing or canonicalizing messages, DKIM2 fields, recipes, or key records;
- deciding whether a revision is required;
- signing bytes inside a provider or returning raw private-key bytes;
- daemon, OpenAPI, Cobra, Viper, Fx, CLI, Milter, Exim, metrics, traces, or
  exporter wiring;
- LDAP or SQL dependencies and executable implementations;
- filesystem watching, background polling, or process-global mutable state;
- tenant fallback, wildcard domains, suffix matching, "first row wins",
  provider chaining, or compatibility aliases.

Replay storage is exclusively M12. This milestone must not introduce a replay
interface merely as a placeholder.

## Architectural Ownership

`lib/internal/datasource` is a lower leaf and owns storage-facing domain
contracts, identifiers, records, limits, errors, and immutable resolved
snapshots. `lib/internal/datasource/memory` owns the in-memory implementation.
`lib/internal/datasource/flatfile` owns strict JSON and confined file loading.
`lib/internal/datasource/signingprofile` is the only higher integration
adapter: it imports datasource contracts and `lib/internal/signing`, constructs
the existing M10 profile, owns one immutable `KeyHandleID` to M10
`PrivateKeyHandle` registry, and validates the projection. Datasource core,
memory, and flatfile do not import signing; signing does not import any
datasource package. The integration adapter is the sole reviewed package that
imports both domains. Other protocol packages never import a concrete provider.

M10 signing owns protocol validation, hash gates, field construction,
cryptographic input, route authorization, and final result publication.
Datasource code supplies an immutable profile projection and an opaque handle
that an authorized signing callback can use. It must not accept raw message
bytes, construct signing input, render fields, apply recipes, or own custody
state.

The library remains independent of service-layer dependencies. JSON, hashing,
and immutable snapshots use the Go standard library. The flat-file package may
add only `golang.org/x/sys/unix`, pinned in `lib/go.mod`, for the Unix
descriptor-relative no-follow open and metadata checks specified below. No
LDAP, SQL, daemon, configuration-framework, or telemetry dependency is allowed.

## Domain Model

### Lookup Facts

A lookup request is an immutable closed value created through validation. It
is exactly one of:

- `profile`: an exact validated `ProfileID` plus one `ProfileUse`;
- `policy`: an exact validated `TenantID`, exact validated domain, and one
  `ProfileUse` value: `originator`, `ordinary_transit`, or
  `next_domain_transit`.

The two lookup forms are distinct constructors or closed variants. A zero
value, mixed form, empty identifier, invalid domain, oversized value,
non-ASCII control, or unknown role is invalid. Map keys, raw recipients,
local-parts, message bodies, headers, IP addresses, sessions, or arbitrary
caller metadata are forbidden.

Domain comparison follows the existing DKIM2 domain normalization contract:
ASCII case-insensitive comparison after strict validation, no trailing-dot
repair, no Unicode normalization, no implicit IDNA conversion, and no suffix
or organizational-domain fallback. The provider receives an already
authorized exact lookup; it is not a policy engine.

The `ProfileUse` value is administrative selection only under draft-04
Section 9.5. It never asserts or replaces the M10 hash-derived Originator,
Forwarder, Reviser, or next-domain role; route or custody authorization;
`d=`, `mf=`, `rt=`, or `nd=` validation; envelope evidence; or the mandatory
fresh DNS publication check.

`ProfileID`, `KeyHandleID`, `TenantID`, and `FeedbackRouteID` share one exact
syntax: 1 through 128 ASCII bytes, first byte `[a-z0-9]`, remaining bytes
`[a-z0-9._-]`. Uppercase, whitespace, slash, backslash, colon, control,
non-ASCII, and non-canonical input are rejected rather than normalized.

### Profile Identity

`ProfileID` is a validated opaque identifier with one canonical byte form.
It is not a filename, path, LDAP DN, SQL key, selector, domain, tenant name, or
logging label. Equality is exact. Empty, malformed, non-canonical, oversized,
or control-bearing identifiers are rejected before provider access.

Every profile record declares exactly one `ProfileID`. Duplicate IDs are a
snapshot-wide ambiguity and reject the whole snapshot. Lookups never pick the
first or last duplicate.

### Signing Profile

A resolved signing profile is immutable and complete. It contains only facts
needed by the signing boundary, including:

- exact profile identity;
- validated signing domain;
- exactly one or two credentials, in canonical RSA-SHA256 then
  Ed25519-SHA256 order;
- for every credential, one validated selector, its baseline algorithm, its
  validated detached public key, and one `KeyHandleID`;
- explicit profile status;
- optional not-before and not-after validity instants, both present or both
  absent, with not-before strictly before not-after.

Credentials reject duplicate algorithms and duplicate selectors. Public
verification material is stored as one canonical SPKI DER value encoded as
strict padded standard base64 in JSON, decoded under a 2,048-byte per-key bound,
and validated through the existing `cryptodkim2` and M10 constructors. It is
public material, not a secret. The integration adapter must still perform the
fresh M10 DNS publication lookup and exact `(selector, d=, algorithm, public
key)` comparison immediately before private signing. Datasource success never
substitutes for DNS publication.

The final projection reuses M10 domain types and validators instead of
maintaining parallel algorithm, domain, selector, route, or policy rules.
Provider records do not contain private keys, passwords, tokens, certificates,
raw signer callbacks, arbitrary metadata, or provider connection data.

Profiles have exactly two status values: `active` and `disabled`. Only `active`
is signable. When a validity window exists, the caller supplies one captured
UTC evaluation instant and the interval is half-open
`not_before <= now < not_after`. Providers do not call the wall clock.
Well-formed disabled, expired, and not-yet-valid profiles return `inactive`.
An unknown status rejects the snapshot as `malformed_data`; an impossible
post-construction inconsistency is `internal_invariant`. None falls back.

### Opaque Private-Key Handles

`KeyHandleID` is a validated provider reference. Its textual form is not a
filesystem path and is never resolved through string concatenation. Datasource
snapshots retain only this provider-neutral ID. The higher integration adapter
maps it through an immutable registry. Each registry entry contains exactly one
`KeyHandleID`, one existing inert M10 `PrivateKeyHandle`, exact `ProfileID`,
signing domain, selector, and algorithm, the SHA-256 digest of the exact
canonical public SPKI DER, and one nonempty canonical set of allowed
`ProfileUse` values. One ID has exactly one entry. Reusing one physical private
key for multiple credentials requires distinct IDs whose entries may contain
the same M10 handle but bind different exact facts.

Before constructing an M10 credential, the adapter compares every entry fact
including a constant-time public-key digest comparison, and the request use
with the resolved snapshot. Any mismatch is `inactive` before any private
signing callback; a duplicate or inconsistent registry is rejected at adapter
construction. The registry is fixed for the adapter lifetime; changing it
requires construction and atomic publication of a new adapter. Neither
providers nor the registry contain or return a `PrivateKeySigner`, callback,
key loader, or signing method.

The handle must not expose raw private-key bytes through fields, accessors,
formatters, JSON, text marshaling, errors, debug output, comparison helpers, or
generic serialization. The separately injected M10 `PrivateKeySigner` remains
the only owner of the signing operation and interprets the opaque handle
outside datasource. Production registries accept existing M10 opaque handles,
not private-key bytes or signer capabilities. Test-only keys remain in
explicit test fixtures.

Profile-to-handle resolution is exact and total within one snapshot. A profile
whose handle is absent, duplicated, malformed, algorithm-incompatible,
or unauthorized makes the snapshot invalid or the lookup a typed closed
failure; it never falls back to another handle.

### Administrative Domain And Tenant Policy

One policy record binds the exact tuple `(TenantID, domain, ProfileUse)` to:

- one exact `ProfileID`;
- `status`: `active` or `disabled`;
- `rollout`: `enforce`, `observe`, or `off`;
- `compatibility`: exactly `strict`;
- optional `FeedbackRouteID`.

Duplicate tuples reject the complete snapshot. `enforce` is the only rollout
state eligible for signing; `observe` and `off` return a valid administrative
policy but the signing-profile adapter fails closed with `inactive`. Feedback
route IDs are opaque references for a later service and do not authorize
feedback, release, transport, or signing. No policy field weakens M10 or M7
validation. This is the complete M11 ownership of domain/tenant selection,
optional feedback routing reference, compatibility, and rollout facts.

## Provider Contract

The domain interface is narrow, context-aware, and intent-level. It exposes
exactly two read operations:

- `ResolveProfile(ctx, ProfileRequest) (ResolvedProfile, error)` performs one
  atomic snapshot read and returns the complete immutable datasource profile
  with its one or two bound `KeyHandleID` values;
- `ResolvePolicy(ctx, PolicyRequest) (ResolvedPolicy, error)` performs one
  atomic snapshot read and returns the exact administrative binding together
  with its complete immutable resolved profile and bound handles from that
  same snapshot.

`ResolvedProfile` is self-contained and has no later provider dereference.
`ResolvedPolicy` is likewise self-contained; callers must not resolve its
profile ID again. There is no public generation token and no two-step
policy/profile/handle lookup, so a reload cannot mix generations. Each result
carries only a monotonically increasing nonzero generation number for equality
and deterministic tests; callers cannot use it to retrieve records. Zero
result plus nil error, nonzero result plus error, partial credentials, and
generation disagreement inside one result are invariant failures.

In one higher-adapter call, the adapter resolves one of these self-contained
results, maps every handle ID through the immutable registry, and constructs
the M10 profile. A missing registry binding fails closed before signing.
Because the registry never mutates and policy resolution already contains its
profile, there is no cross-generation profile/handle mix.

Every operation:

- checks nil and already-cancelled context before work;
- observes cancellation at bounded provider boundaries;
- returns no partial success after cancellation;
- performs bounded work and allocation;
- is safe for concurrent callers;
- returns immutable values without borrowed mutable maps or slices;
- has no hidden retry, fallback, network, or clock behavior;
- returns typed, secret-safe failures.

Nil interfaces, typed-nil implementations, zero values, panics from injected
capabilities, and internally inconsistent results are caught at the owning
boundary and become opaque invariant failures. Provider panics never escape
the public library API.

### Closed Result And Error Taxonomy

The stable error codes are exactly:

| Code | Meaning |
| --- | --- |
| `invalid_request` | invalid request, identifier, time, or zero value |
| `not_found` | no exact profile, policy, handle, or registry binding |
| `ambiguous` | duplicate identity or exact policy tuple |
| `inactive` | disabled, outside validity, non-enforce rollout, or unauthorized |
| `malformed_data` | syntactically or semantically invalid provider input |
| `limit_exceeded` | one named hard or configured bound was exceeded |
| `unavailable` | provider cannot safely serve the current generation |
| `unsupported_platform` | required confined file semantics are unavailable |
| `cancelled` | context cancellation |
| `deadline_exceeded` | context deadline |
| `internal_invariant` | impossible provider/result/callback state |

Callers can branch by stable code or predicate, not error strings. Provider,
path, profile, handle, selector, domain, record, row, DN, query, key, and
secret values do not appear in error strings. Wrapped operating-system or JSON
errors are classified at the provider boundary and are not returned verbatim.

Absence is not success with a zero profile. Ambiguity is never downgraded to
absence. Malformed data is never downgraded to unavailability. Cancellation
preserves `errors.Is` compatibility for `context.Canceled` and
`context.DeadlineExceeded` without adding protected facts.

For both resolve methods the only success pair is one fully valid nonzero
result plus nil error. Every non-success is a zero result plus exactly one
typed error. Any other pair is `internal_invariant`. `ResolvePolicy` returning
an `observe` or `off` policy with its complete profile is intentional provider
success; the higher signing adapter returns zero M10 profile plus `inactive`.

Flat-file classification is exact: missing file is `not_found`; permission
denial, unsafe owner/mode/root/link/type, I/O failure, and degraded provider are
`unavailable`; unsupported build target is `unsupported_platform`; JSON,
schema, timestamp, public-key, cross-reference, and duplicate input are
`malformed_data` or `ambiguous` as applicable; configured bounds are
`limit_exceeded`. Reload cancellation is `cancelled` or
`deadline_exceeded`. Memory and flat-file lookup of the same valid snapshot
must return the same domain result codes.

## Limits And Accounting

Limits are immutable, validated, and nonzero. Defaults are also hard maxima:

| Limit | Value |
| --- | ---: |
| identifier bytes | 128 |
| signing-domain bytes / labels | 253 / 127 |
| selector bytes / labels | 253 / 127 |
| profiles | 1,024 |
| credentials per profile | 2 |
| registered handles | 2,048 |
| policy bindings | 4,096 |
| JSON file bytes | 1,048,576 |
| JSON nesting depth | 16 |
| one JSON string bytes | 16,384 |
| aggregate decoded string bytes | 1,048,576 |
| decoded public key bytes | 2,048 |
| records examined per load | 9,216 |

Domain, selector, algorithm, RSA, signature-input, and signing-output limits are
additionally narrowed by the existing M10 and keyresolver limits. A datasource
configuration may lower but never raise a hard maximum.

The JSON scanner has a structural depth safety cap of 16; the closed valid
schema reaches at most depth 5. File, depth, string, aggregate-string, and
decoded-key bounds are parser/accounting caps and need not describe a
semantically valid document exactly at the cap. Tests prove that the scanner
accepts or accounts through exactly the cap before later schema/key validation,
and rejects cap+1 before unbounded work. Profile, credential, handle, policy,
identifier, domain, and selector limits are semantic: valid exact-limit
datasets succeed and one-over datasets fail.

One examined record/work unit is each profile, nested credential, declared
handle, and policy, so the maximum is
`1024 + (1024 * 2) + 2048 + 4096 = 9216`. Limit arithmetic uses checked
addition. Usage reports only bounded counts and byte totals, never raw values.
A caller cannot disable a limit with zero, negative, overflowed, or
maximum-integer sentinel values.

## In-Memory Provider

The in-memory provider is both a production-capable static provider and the
reference behavior for tests. Its constructor:

- consumes validated records or strictly validates all input records;
- deep-copies input collections and byte-bearing values;
- rejects duplicate IDs, duplicate exact mappings, dangling handles,
  incompatible algorithms, incomplete profiles, and unknown fields/states;
- constructs all indexes before publication;
- returns no provider on any error.

The static memory provider publishes one immutable snapshot at construction
and its reads are lock-free without returning aliases. Caller mutation after
construction cannot change results. Repeated identical lookups are
deterministic. Concurrent lookup through independent handle IDs must pass the
race detector.

## Flat-File Provider

### File Format

The flat-file provider uses one versioned UTF-8 JSON document. Its root has
exactly four required members:

- `"version": "dkim2-datasource-v1"`;
- `"handles"`: an array of objects containing only `"id"`;
- `"profiles"`: an array of profile objects;
- `"policies"`: an array of administrative policy objects, which may be empty.

A profile object contains exactly `id`, `domain`, `status`, `credentials`, and
optionally the pair `not_before` and `not_after`. Each credential contains
exactly `algorithm`, `selector`, `public_key_spki`, and `handle_id`.
`algorithm` is `rsa-sha256` or `ed25519-sha256`. Timestamps are canonical UTC
RFC3339Nano with `Z`. A policy object contains exactly `tenant_id`, `domain`,
`use`, `profile_id`, `status`, `rollout`, `compatibility`, and optionally
`feedback_route_id`.

This complete valid single-credential shape is normative; durable golden files
must replace the example values only with equally valid bounded values:

```json
{
  "version": "dkim2-datasource-v1",
  "handles": [{"id": "key.example.ed25519"}],
  "profiles": [{
    "id": "profile.example",
    "domain": "example.test",
    "status": "active",
    "credentials": [{
      "algorithm": "ed25519-sha256",
      "selector": "s1",
      "public_key_spki": "MCowBQYDK2VwAyEAIClZTFkgcVVuQpqSIcMJ98ohgPBzN3SrWTX3gbhSofw=",
      "handle_id": "key.example.ed25519"
    }]
  }],
  "policies": [{
    "tenant_id": "tenant.example",
    "domain": "example.test",
    "use": "originator",
    "profile_id": "profile.example",
    "status": "active",
    "rollout": "enforce",
    "compatibility": "strict"
  }]
}
```

Unknown, duplicate, missing, null, wrong-type, trailing-token, non-UTF-8,
non-canonical identifier, and out-of-range fields reject the complete load.
JSON numbers are not used for identifiers. Duplicate object names must be
detected rather than silently overwritten by generic unmarshaling. Loading
performs structural limits before or while decoding so a JSON bomb cannot
bypass byte, depth, entry, or aggregate-string limits.

The durable schema and examples must never embed private keys. A handle record
declares only a `KeyHandleID`; the higher adapter requires the corresponding
inert M10 handle in its immutable registry. There is no provider-owned signing
capability or key loader. The JSON document cannot contain private-key
PEM/DER/base64, passwords, tokens, callbacks, key paths, or command lines.

### Filesystem Confinement

The production loader supports Linux and macOS through build-tagged files using
`golang.org/x/sys/unix`. Other platforms return `unsupported_platform`; tests
may use an injected narrow opener only to exercise parsing and state logic.
Record values never become paths.

Construction borrows an already-open root directory descriptor and duplicates
it atomically with close-on-exec by calling `fcntl(F_DUPFD_CLOEXEC)` through
`golang.org/x/sys/unix`. `Dup` followed by `F_SETFD` is forbidden because its
fork/exec race can leak the capability. Both Linux and macOS implementations
must provide the atomic primitive or construction returns
`unsupported_platform`. The provider thereafter uses only its owned duplicate.
It captures
`unix.Geteuid()` as the exact expected owner and validates the duplicate with
`Fstat`. The root must be a directory owned by that UID, with owner read and
execute bits and no group/world write bits (`mode & 0022 == 0`). Constructor
failure closes the duplicate. After successful construction the caller may
close or reuse its original descriptor without affecting confinement.

The filename is exactly one nonempty component and rejects `/`, `\`, NUL, `.`,
`..`, absolute, volume, device, and platform escape forms.

Each load performs one `openat` relative to that descriptor with
`O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`, then one `fstat` on the returned
descriptor.
The same descriptor is read and never reopened by name. It must be a regular
file owned by the expected UID, have link count exactly one, have owner-read
set, and have no permission bits outside `0600`; therefore only `0400` and
`0600` are accepted. Symlinks, directories, devices, sockets, FIFOs,
hard-links, writable-by-other files, and ownership mismatches fail closed.
There is no compatibility switch for broader permissions. Holding the root and
file descriptors closes parent replacement and check/reopen races.

`Close(ctx context.Context) error` is idempotent. It acquires the same
context-aware single-slot serialization boundary as reload, atomically marks
the provider closed, invalidates its stored descriptor number, and invokes
`close(2)` on the local descriptor exactly once. Even if that syscall reports
an error or `EINTR`, it is never retried because retry could close an unrelated
reused descriptor. The first Close returns a typed secret-safe `unavailable`
error for a close failure while closed state remains published; subsequent
Close calls return nil. A resolve or reload that
linearizes after closed publication returns zero result plus `unavailable`; an
operation already linearized before close may complete from its captured
snapshot or file descriptor. Cancellation before slot acquisition returns the
typed context error without changing state; Close after closed publication
returns nil. Tests force caller-close and descriptor-number
reuse, constructor failure, repeated Close, and concurrent Close/reload/resolve
orderings. A focused build-tagged test or source guard proves use of
`F_DUPFD_CLOEXEC`, absence of a `Dup` plus `F_SETFD` fallback, and the
CLOEXEC flag on the owned descriptor.

### Load And Reload

Loading is transactional:

1. capture one file identity through the confined open handle;
2. read at most `MaxFileBytes + 1`;
3. validate encoding, schema, records, cross-references, and all limits;
4. build a complete immutable in-memory provider;
5. publish the new snapshot with one atomic generation change.

No lookup observes a partial load. A failed initial load produces no provider.
A failed explicit reload retains the last-known-good snapshot only for
recovery and diagnosis, marks the provider degraded, and makes every later
resolve return `unavailable` until a successful reload atomically publishes a
new generation and clears degraded state. It never signs silently from the
retained snapshot.

Reloads are serialized by one provider-owned buffered-channel semaphore of
capacity one. Acquisition selects between that channel and `ctx.Done()`; there
is no FIFO promise among simultaneous callers. A reload linearizes when it
acquires the slot, and successful or degraded publication occurs before it
releases the slot. A resolve linearized before a reload failure remains
authoritative for that already-started operation and is not retroactively
revoked. A resolve starting after degraded publication fails. Deterministic
barriers test these rules; generations never publish out of order.

Background reload, filesystem notification, and retry loops are out of scope.
Reload is an explicit bounded method invoked by a later service layer.

## Signing Integration

The datasource-to-signing adapter validates the resolved profile and handle
again at the trust boundary and maps only allowed fields into M10 types. It
must prove:

- requested profile identity equals resolved identity;
- profile, handle, algorithm, selector, and signing domain are mutually
  consistent;
- the pair comes from one immutable snapshot;
- the handle is authorized for that exact profile and operation;
- inactive, degraded, or malformed state cannot enter signing;
- a handle failure maps to the existing closed signing error model;
- no result or failure reveals provider facts or key material.

Datasource lookup is completed before irreversible signing publication. A
cancelled, unavailable, ambiguous, or invalid datasource result causes no
partial DKIM2 field, recipe, custody transition, route release, or replay-side
effect.

## LDAP And SQL Follow-On Contract

Durable design notes defined how the now-implemented LDAP and SQL providers
satisfy the same domain contract. They include:

- exact attribute/column-to-domain mapping;
- one-record uniqueness and ambiguity behavior;
- pagination and result-count limits;
- snapshot/transaction consistency requirements;
- context deadlines and cancellation;
- connection and degraded-state classification;
- secret and query redaction;
- migration and schema-version policy;
- integration-test expectations.

The notes must not add build dependencies, executable stubs that return unsafe
defaults, provider-specific public types, or placeholder success behavior.
LDAP DNs and SQL text are protected data and never enter domain errors or
telemetry.

## Security And Privacy Requirements

- Private keys, raw messages, recipients, local-parts, credentials, tokens,
  provider records, file contents, DNs, SQL, paths, and protected identifiers
  never enter errors, logs, traces, metrics, REST/CLI output, formatters, or
  test failure output.
- `String`, `GoString`, `MarshalText`, `MarshalJSON`, and `%v/%+v/%#v` behavior
  for public or crossing-boundary values is either absent or explicitly
  redacted and tested.
- Stable error codes and bounded counters are the only diagnostic contract.
- No raw profile, domain, selector, handle, provider, backend, or error value
  is suitable as a Prometheus label or trace attribute.
- Equality and map keys use canonical validated identifiers. Secret-dependent
  comparisons use appropriate constant-time behavior where content is secret;
  identifiers themselves are not treated as authentication secrets.
- Provider failures fail closed. There is no permissive mode, anonymous
  profile, default key, emergency selector, or last-record fallback.

## Required Test Evidence

Unit tests cover:

- every constructor, zero value, exact limit, and one-over limit;
- exact ID/domain lookup, case behavior, and forbidden fallback;
- every provider result and error state;
- duplicate, dangling, incompatible, inactive, and ambiguous records;
- immutability against caller mutation;
- atomic profile/handle snapshot binding;
- context cancellation before and during each injected boundary;
- nil, typed-nil, panic, partial result, and invariant failures;
- secret-safe formatting, marshaling, wrapping, and errors.

Flat-file tests cover:

- strict valid versioned examples;
- duplicate JSON names, unknown fields, nulls, trailing data, invalid UTF-8,
  depth/size/count/string bombs, and malformed cross-references;
- absolute/traversal/separator/device paths, symlinks, non-regular files,
  replacement races, unsafe ownership/permissions, and writable roots;
- initial-load failure, successful reload, failed reload retaining but not
  serving the prior generation, degraded resolve failure, recovery reload, and
  concurrent reload/resolve ordering;
- no private-key material in schema, fixtures, errors, or generated docs.

Integration tests prove that memory and flat-file providers return equivalent
domain results for the same logical dataset and that their output drives the
M10 signing seam without bypassing its validation.

Fuzz targets cover strict JSON loading, identifiers, mapping ambiguity,
cross-reference validation, lookup facts, and provider-to-signing projection.
Seeds and generated arguments contain only synthetic non-secret values and
markers because the Go fuzz harness may print and persist reproducing input.
Inputs are bounded before allocation, real provider records are forbidden from
the corpus, and application diagnostics remain secret-safe.

Race tests cover concurrent memory lookups, flat-file lookups during reload,
concurrent failed and successful reload attempts, and safe use of independent
opaque handles. Tests must not rely only on `-race`; deterministic barriers
assert the intended snapshot and publication order.

Dependency tests prove:

- protocol packages depend only on datasource contracts;
- datasource core, memory, and flatfile do not import signing;
- `datasource/signingprofile` is the sole package allowed to import both
  datasource contracts and signing, while signing never imports it;
- `lib/` gains no daemon, LDAP, SQL, Cobra, Viper, Fx, Prometheus, OpenTelemetry
  exporter, Milter, or CLI dependency;
- replay-store APIs are absent.

## Delivery Shape

The ignored prompt pack should divide implementation into these sequential
review slices:

1. Domain contracts, identifiers, limits, usage, and closed errors.
2. Immutable profiles, opaque handle binding, and M10 projection.
3. In-memory provider and exhaustive state tests.
4. Strict versioned flat-file schema and bounded decoder.
5. Confined file loading, permissions, atomic reload, and concurrency.
6. Signing integration and memory/flat-file parity.
7. LDAP/SQL design notes and dependency-boundary evidence.
8. Abuse, fuzz, race, privacy, and cancellation hardening.
9. Documentation, complete guardrails, two exact-snapshot approvals, and the
   milestone's one commit.

The prompt pack lives under ignored `temp/datasource-providers-prompts/` and
must never be staged or committed.

## Completion Evidence

- The storage-neutral contracts, exact immutable profile and policy model,
  closed error taxonomy, hard/narrowable limits, memory provider, confined
  flat-file provider, signing-profile bridge, and LDAP/SQL design contracts are
  implemented within the documented ownership boundaries.
- The flat-file provider uses an owned atomically duplicated directory
  descriptor, one no-follow relative file open per load, strict bounded
  `dkim2-datasource-v1` decoding, atomic generation publication, fail-closed
  degraded state, explicit recovery, and idempotent close behavior on Linux and
  macOS. Unsupported platforms return the closed platform error.
- Provider parity and root signing integration prove that datasource selection
  completes before M10 publication and does not replace fresh DNS publication,
  route authorization, signing validation, or the private signer callback.
- Focused normal and race tests, the six required datasource fuzz targets for
  at least ten seconds each, `make test`, `make vet`, `make lint`, `make race`,
  and `make guardrails` pass on the final unchanged snapshot. Govulncheck
  reports no known vulnerabilities.
- Dependency evidence keeps datasource core, memory, and flat-file independent
  of signing and service dependencies; `datasource/signingprofile` is the sole
  datasource/signing bridge. LDAP, SQL, replay, daemon, OpenAPI, Milter, CLI,
  and telemetry implementation remain absent.
- The frozen normative projection is byte-identical before and after closeout.
  `temp/datasource-providers-prompts/` remains ignored and absent from staging.
- Prompt 01 through Prompt 08 measured 5h18m48s wall-clock. Prompt 09 and the
  exact nine-prompt total are finalized in the ignored timing ledger at
  closeout; active engineering time was not separately tracked. A
  measured-versus-planned comparison is unavailable because this durable
  specification contained no planning estimate.
- The 2026-07-24 Datatracker check found that
  `draft-ietf-dkim-dkim2-dns-00` replaced
  `draft-chuang-dkim2-dns-04` on 2026-07-20 with a normatively identical body.
  M11 behavior and tests remain explicitly pinned to the reviewed historical
  `-04` identifier; identifier and vector migration is a separate reviewed
  baseline update.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Spec reconciliation | Frozen datasource behavior is implemented without normative closeout drift | Normative projection is byte-identical; closeout edits are limited to status and evidence | approved | Final spec and projection hashes are recorded in the ignored review record |
| Scope | Storage-neutral providers and signing bridge only | Memory, flat-file, exact bridge, and design-only LDAP/SQL work are present | approved | Replay and service/runtime integrations remain deferred |
| Behavior | Exact immutable results, closed states, no fallback, atomic reload | Memory and flat-file parity plus degraded/recovery and lifecycle matrices pass | approved | No stale snapshot is served while degraded |
| Tests | Focused normal and race suites cover the complete provider and bridge behavior | Datasource, provider, bridge, and root integration suites pass | approved | No required test is skipped |
| Security and privacy | Opaque handles, confined loading, secret-safe failures, restrictive defaults | Descriptor confinement, exact authorization, redacted surfaces, abuse and privacy tests pass | approved | Private keys and provider-specific backend identities/facts never cross the provider boundary |
| Boundaries | One datasource/signing bridge and no service dependencies | Import guards prove the sole bridge and standalone library boundary | approved | LDAP/SQL drivers and replay APIs are absent |
| Full guardrails | Every root quality gate passes on one unchanged snapshot | Formatting, vet, lint, tests, race, OpenAPI checks, and govulncheck pass | approved | `make guardrails` is the final repository gate |
| Fuzz enumeration | Every datasource fuzz target is enumerated and runs for at least ten seconds | Exactly six required non-vacuous targets pass for at least ten seconds each | approved | Constructor, mapping, JSON, cross-reference, parity, and signing projection invariants are covered |
| Documentation | README, architecture, package docs, design contracts, and baseline status agree | Durable documents describe implemented ownership and the reviewed DNS rename policy | approved | DNS identifier migration is deliberately separate |
| Normative/mail/security review | Independent live review approves the exact candidate artifacts | Slice reviews are complete; final formula/spec/projection/path/manifest/tree approval follows content freeze | pending | Final approval is recorded in the ignored ledger without mutating the approved snapshot |
| Architecture/DRY/API/security/test review | Separate independent review approves the identical candidate artifacts | Slice reviews are complete; final ownership, API, test, docs, and artifact approval follows content freeze | pending | Any candidate edit invalidates both final approvals |
| Manifest/staging identity | Approved and staged raw Git manifests are byte-identical | Explicit candidate manifest is built before review; real staging is permitted only after both approvals | pending | Final byte-identity proof is recorded externally; `temp/` and unrelated paths remain absent |
| Staging | Only the explicit approved durable path list is staged | Real index remains empty until both exact candidate approvals | pending | Repository-wide add is forbidden |
| Commit count | Exactly one project-formatted datasource commit follows the fixed base | No datasource commit exists before both exact candidate approvals | pending | Final commit ID and count are recorded in the ignored closeout ledger |
| Time | Exact retained timings are recorded without inference | Prompt ledger records exact wall-clock spans; active time was not tracked | approved | Durable measured-versus-planned comparison is unavailable |

## Definition Of Done

- The durable spec and prompt pack have independent normative and architecture
  approval before implementation begins.
- All provider contracts, types, errors, limits, and ownership boundaries are
  documented and implemented once.
- Memory and flat-file providers have equivalent closed behavior.
- Profile/handle binding is atomic, exact, authorized, immutable, and
  compatible with M10 without exposing private keys.
- Flat-file loading is strict, bounded, confined, permission-checked,
  transactional, and race-safe.
- LDAP and SQL remain design-only and add no runtime dependencies.
- Replay storage remains entirely deferred to M12.
- Tests, fuzz smoke, race, privacy, dependency, formatting, vet, lint, and
  vulnerability checks pass on one unchanged snapshot.
- Two independent reviewers approve that exact snapshot with no open finding.
- `make guardrails` passes.
- `temp/` is ignored and absent from the index and commit.
- Exactly one project-formatted commit records the complete datasource-provider
  milestone.
