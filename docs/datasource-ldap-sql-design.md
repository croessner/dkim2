# LDAP And SQL Datasource Provider Design

Status: implemented contract for daemon-owned LDAP and PostgreSQL providers.

This document defines how LDAP and PostgreSQL readers map persisted
administrative data into the existing storage-neutral contracts in
`lib/internal/datasource`. Deployable schema and DDL live in `contrib/schema`;
installation, daemon configuration, and migration procedures live in
`docs/operator/datasource-ldap-postgresql.md` and
`docs/operator/opendkim-migration.md`.

The provider boundary remains:

- `ResolveProfile(context.Context, datasource.ProfileRequest)`;
- `ResolvePolicy(context.Context, datasource.PolicyRequest)`.

Both implementations must construct the existing datasource values through
their validators. They must not add provider-specific fields to those values,
return raw provider records, expose private-key material, or change signing,
DNS publication, policy, or protocol behavior.

## Ownership And Non-Goals

Datasource contracts and validation remain owned by
`lib/internal/datasource`. A concrete provider belongs in an explicit provider
package and is wired by a service module. LDAP libraries, SQL drivers,
connection pools, migration tools, and configuration frameworks must not
become dependencies of the standalone library or protocol packages.

`lib/internal/datasource/signingprofile` remains the only bridge from a
datasource result to the signing profile. A provider returns only an opaque
`KeyHandleID`; for LDAP and PostgreSQL v2, the same immutable generation maps
that identifier to canonical PKCS#8 DER and an inert in-memory signing handle.
Flat-file retains its separately protected local registry. A datasource success does not authorize a route, replace
the fresh DNS publication lookup, perform a signature, or make a cryptographic
or protocol verdict.

Replay detection is a separate storage concern. These designs contain no
replay key, retention, expiry, first-seen operation, or replay result. An LDAP
or SQL product may eventually implement both provider classes in separate
packages, but it must not merge their interfaces, records, transactions, or
failure semantics.

## Common Dataset Model

LDAP and SQL expose one committed, immutable logical dataset at a time. A
dataset has:

- the exact network schema version `dkim2-datasource-v2`;
- one nonzero, monotonically increasing unsigned generation;
- a closed publication state whose only readable value is `committed`;
- zero or more handle declarations;
- zero or more complete profiles and their credentials;
- zero or more complete policy bindings.

All records in a dataset carry the same generation. Records are never updated
in place after that generation is committed. A writer builds and validates a
new generation before publishing it. Restoring older content is done by
publishing that content as a new, higher generation; moving the published
generation backwards is invalid.

A provider load reads one complete committed generation, converts every
record through the existing constructors, validates all cross-references and
limits, builds the same immutable indexes as the memory provider, and only
then publishes the snapshot locally. Lookups use that local immutable snapshot
and perform no provider round trip. This model provides:

- one generation for a policy and its embedded profile;
- no policy/profile/handle time-of-check/time-of-use split;
- bounded and deterministic lookup work;
- no hidden network retry or fallback during signing;
- independence of an already published local snapshot from later source
  changes.

An initial load failure produces no provider. Refresh preflight validates the
context, deadline, limits, and provider state before the operation acquires
its serialization boundary. A preflight rejection or cancellation while
waiting for that boundary does not change provider state. Once a refresh
linearizes and begins backend work, any failure retains the last snapshot only
for diagnosis, publishes the provider state as degraded, and makes every
subsequent resolve return `unavailable`. A complete refresh of the unchanged
current generation while ready is a successful health no-op only when every
immutable dataset fact and native key binding is exactly equal after
both sides have been revalidated. Changed facts under the current generation
degrade the runtime; an exact no-op does not republish or replace the current
snapshot. A later successful higher-generation refresh
atomically publishes the new generation and clears degraded state. Serving the
retained snapshot while degraded is forbidden.

The source generation becomes the `Generation()` of every
`ResolvedProfile` and `ResolvedPolicy`. A provider accepts a first nonzero
generation and thereafter requires each published refresh to have a strictly
higher generation. Revalidation of the exact current generation while ready is
not a published refresh. A first generation equal to the maximum unsigned 64-bit
value is valid and terminal. A provider already at that generation rejects a
later refresh during preflight with `limit_exceeded`, before serialization,
backend access, or provider-state mutation, and remains ready and available.
For every other generation, attempted source generation republication, rollback, mixed
generations, a zero or out-of-range generation, or a non-committed dataset
discovered after the refresh linearizes is `malformed_data`; the provider
becomes degraded and the externally visible resolve state is `unavailable`.

## Exact Domain Mapping

The names below are logical schema field names. LDAP uses the attribute name in
the LDAP column; SQL uses the column name in the SQL column. They do not imply
an object-class definition, DDL, storage type, query, index name, DN shape, or
database namespace.

### Dataset Metadata

| LDAP attribute | SQL column | Required representation | Datasource use |
| --- | --- | --- | --- |
| `dkim2SchemaVersion` | `schema_version` | Exact ASCII text `dkim2-datasource-v2` | Selects native network key custody |
| `dkim2Generation` | `generation` | Nonzero unsigned 64-bit integer | Passed to `NewResolvedProfile` and `NewResolvedPolicy` |
| `dkim2DatasetState` | `dataset_state` | Exact ASCII text `committed` | Makes the generation eligible for loading |

The v2 native key record adds generation, tenant, signing domain, profile use,
handle, algorithm, canonical public SPKI DER, and canonical unencrypted private
PKCS#8 DER. Concrete providers validate it against the public credential before
constructing an in-memory signer. Private bytes never enter the library model.

There is exactly one metadata record for a published generation. Absence is
`not_found`; more than one current metadata record is `ambiguous`; an unknown
version, invalid state, invalid generation, or cross-record generation
mismatch is `malformed_data`.

### Handle Declarations

| LDAP attribute | SQL column | Cardinality | Datasource mapping |
| --- | --- | ---: | --- |
| `dkim2Generation` | `generation` | one | Must equal dataset generation |
| `dkim2HandleID` | `handle_id` | one | `NewKeyHandleID` |

A handle declaration contains no DN, path, key bytes, key URI, certificate,
credential, callback, command, or provider connection fact. The validated
`KeyHandleID` is the only value that crosses the provider boundary.

### Profiles

| LDAP attribute | SQL column | Cardinality | Datasource mapping |
| --- | --- | ---: | --- |
| `dkim2Generation` | `generation` | one | Must equal dataset generation |
| `dkim2ProfileID` | `profile_id` | one | `NewProfileID` |
| `dkim2SigningDomain` | `signing_domain` | one | `NewProfile` signing-domain argument |
| `dkim2RecordStatus` | `record_status` | one | `ParseRecordStatus`, then `NewProfile` |
| `dkim2NotBefore` | `not_before_utc` | zero or one | Canonical UTC RFC3339Nano text parsed to `time.Time` |
| `dkim2NotAfter` | `not_after_utc` | zero or one | Canonical UTC RFC3339Nano text parsed to `time.Time` |

The two validity values are both absent or both present. Present values end in
`Z`, round-trip to the identical canonical RFC3339Nano text, and satisfy
`not_before < not_after`. `NewProfile` remains authoritative for the half-open
validity interval and status validation.

### Profile Credentials

| LDAP attribute | SQL column | Cardinality | Datasource mapping |
| --- | --- | ---: | --- |
| `dkim2Generation` | `generation` | one | Must equal dataset generation |
| `dkim2ProfileID` | `profile_id` | one | Exact parent `ProfileID` |
| `dkim2Algorithm` | `algorithm` | one | Exact `rsa-sha256` or `ed25519-sha256` closed value |
| `dkim2Selector` | `selector` | one | `NewCredential` selector argument |
| `dkim2PublicKeySPKI` | `public_key_spki` | one binary value | Exact canonical public SPKI DER passed to `NewCredential` |
| `dkim2HandleID` | `handle_id` | one | `NewKeyHandleID`, then `NewCredential` |

The public-key field is binary public material, not Base64 text and not a
private key. The provider copies it before validation. `NewCredential` owns
SPKI parsing, canonical-DER equality, algorithm/key compatibility, selector
validation, the per-key byte limit, and detached storage. `NewProfile` owns
credential count, duplicate-algorithm, duplicate-selector, duplicate-handle,
and canonical RSA-before-Ed25519 ordering.

### Administrative Policies

| LDAP attribute | SQL column | Cardinality | Datasource mapping |
| --- | --- | ---: | --- |
| `dkim2Generation` | `generation` | one | Must equal dataset generation |
| `dkim2TenantID` | `tenant_id` | one | `NewTenantID` |
| `dkim2SigningDomain` | `signing_domain` | one | `NewPolicy` signing-domain argument |
| `dkim2ProfileUse` | `profile_use` | one | `ParseProfileUse` |
| `dkim2ProfileID` | `profile_id` | one | `NewProfileID`, then `NewPolicy` |
| `dkim2RecordStatus` | `record_status` | one | `ParseRecordStatus` |
| `dkim2Rollout` | `rollout` | one | `ParseRollout` |
| `dkim2Compatibility` | `compatibility` | one | `ParseCompatibility`; only `strict` is accepted |
| `dkim2FeedbackRouteID` | `feedback_route_id` | zero or one | `NewFeedbackRouteID` |

The exact policy identity is `(TenantID, canonical signing domain,
ProfileUse)`. The referenced profile must exist in the same generation and
have the same canonical signing domain. A resolved policy embeds that complete
same-generation profile through `NewResolvedPolicy`; callers never perform a
second profile lookup.

`ProfileUse` remains an administrative selection purpose. It does not assert
an Originator, Forwarder, Reviser, or next-domain protocol role. A feedback
route is an opaque future-service reference and grants no signing, transport,
release, or feedback authority.

## Local Lookup Semantics

LDAP and SQL lookups over a published local snapshot match the memory-provider
control flow exactly.

`ResolveProfile` validates the request and configured limits, then selects
only the exact requested `ProfileID`. The request `ProfileUse` is validated
administrative authorization input for the later handle-registry projection;
it is not part of profile identity and cannot select an alternate profile.
The provider calls `Profile.ActiveAt` with the request's caller-captured
`EvaluationTime`. It does not read a provider clock.

`ResolvePolicy` selects only the exact tuple `(TenantID, canonical signing
domain, ProfileUse)`. It requires an active policy record, resolves the exact
referenced same-generation profile, requires the policy and profile signing
domains to agree, and calls `Profile.ActiveAt` with the same request
`EvaluationTime`. A disabled policy or inactive profile is `inactive`.

An active `observe` or `off` policy is a complete provider success containing
its complete profile. The signing-profile adapter subsequently applies
`Policy.Eligible` and returns `inactive`; the provider does not collapse
rollout state into absence or redefine adapter authorization. Compatibility
remains exactly `strict`.

Neither resolve method retries, consults another generation or provider,
falls back by tenant or domain, re-resolves an embedded profile, or returns a
partial result. Context termination observed before final return produces the
exact context error and a zero result.

## Uniqueness, Absence, And Ambiguity

Storage constraints should prevent duplicates where the backend supports
them, but storage enforcement is not trusted as the only check. Each provider
independently validates the complete loaded generation before publication.

The following values are unique within one generation:

- the metadata record;
- every `KeyHandleID`;
- every `ProfileID`;
- every exact policy tuple `(TenantID, signing domain, ProfileUse)`;
- every credential algorithm within one profile;
- every credential selector within one profile;
- every credential `KeyHandleID`, including across profiles.

Every credential handle has exactly one handle declaration. Every policy
references exactly one profile. A profile has one or two complete credentials.
Dangling references, cross-generation references, partial records, duplicate
fields, and inconsistent domain bindings reject the complete generation.

An exact requested identity with no record is `not_found`. Multiple records
for an exact identity or duplicate snapshot identities are `ambiguous`, never
first-row, last-row, nearest-DN, or lowest-key success. Invalid field syntax,
unknown closed values, invalid public keys, incomplete cross-references, and
mixed generations are `malformed_data`. Limit violations remain
`limit_exceeded`.

There is no tenant default, wildcard, suffix match, organizational-domain
search, LDAP-tree inheritance, SQL ordering fallback, alias, or provider
chain. DNs, primary keys, row locators, and database-generated identifiers are
storage mechanics and never become domain identity.

## Bounded Loading And Paging

A provider configuration may narrow, but never widen,
`datasource.HardLimits()`. The complete load enforces:

| Work class | Maximum |
| --- | ---: |
| profiles | 1,024 |
| credentials per profile | 2 |
| credentials in a maximal dataset | 2,048 |
| handle declarations | 2,048 |
| policy bindings | 4,096 |
| total examined records | 9,216 |
| identifier bytes | 128 |
| signing-domain bytes / labels | 253 / 127 |
| selector bytes / labels | 253 / 127 |
| one decoded public key | 2,048 bytes |
| aggregate decoded string bytes | 1,048,576 |

One examined-record unit is charged for every profile, credential, handle, and
policy returned by the backend, including a record later rejected as a
duplicate or malformed. Metadata records, transport pages, SQL batches, LDAP
continuation controls, and validation steps have separate bounded loop
counters and cannot reset the domain work counters.

The requested transport page size is positive, fixed for one load, and no
greater than 256 records or the configured maximum for that record class,
whichever is smaller. It does not shrink with the remaining record budget.
Each response is checked against that remaining budget before any returned
record is accepted or copied.
The total transport-response count for one record class is independently
capped at that class's configured record maximum plus one. This admits the
worst case of one accepted record per response and one final response proving
completion, while bounding servers that return undersized or empty responses.
Reaching the local response cap before completion, a non-advancing SQL cursor,
or the first record at configured maximum plus one is `limit_exceeded`.

Values are length-checked before conversion or copying where the backend API
permits. Multi-valued fields that are specified as single-valued reject
zero/multiple values before selecting one. Counts use checked addition.
Backends may return smaller pages but cannot cause unbounded empty-page or
continuation loops.

LDAP loading uses the RFC 2696 Simple Paged Results control and requests only
the mapped attributes. The paging control is critical. The LDAP search
sizeLimit is the checked configured record-class maximum plus one, so an
ignored or broken paging control still cannot return unbounded entries; the
requested page size remains below that server-side one-over cap and local
record and response counters remain authoritative. The continuation cookie is
fully opaque, length-bounded, never persisted, and never exposed. The client
makes no assumptions from its bytes: it sends the exact cookie from the last
response, including a repeated nonempty value, and treats only an empty cookie
as normal paging completion.
An empty result page with a nonempty cookie is valid and consumes one bounded
transport response. Cookie equality and page emptiness are never interpreted
as no-progress failures. If the original operation context is already
cancelled or its deadline has elapsed, the client immediately closes or
discards the connection and returns the exact context failure; it does not
attempt abandonment with a terminated context.

If a local limit or backend failure stops paging before an empty-cookie
response while the original operation context remains active, the client
makes one bounded RFC 2696 abandonment request with page size zero and the
last successfully accepted, length-bounded cookie using that same active
context. It creates no replacement cleanup context. If the stop was caused by
an oversized cookie, a malformed or missing paging control, or any condition
that leaves no accepted cookie, the client does not echo untrusted control
data and immediately closes or discards the connection. If cleanup fails or
the original context terminates during cleanup, the client likewise closes or
discards the connection rather than returning cursor state to a pool.

SQL loading uses deterministic keyset progress inside one transaction; offset
pagination is not a consistency boundary. Ordering and cursor columns are
storage mechanics and do not enter datasource values.

## LDAP Consistency And Security Contract

LDAP stores each generation under a generation-specific, implementation-owned
subtree. The configured search base is a protected service setting and is
never derived from a request, profile, tenant, domain, selector, or handle.
Record DNs are not identity and their layout is not part of the public
contract.

A publication operation creates all entries for a new generation, validates
them independently, marks that generation committed, and only then changes
the single current-generation metadata reference. Entries in a committed
generation are immutable. A reader captures the current committed generation
once and restricts every paged search to that exact generation-specific
subtree and generation attribute. It builds the entire local snapshot before
returning from load. After all pages and validation, it reads the current
metadata record again and requires the schema version, generation, and
committed state to equal the first read. A changed or absent final fence is
`unavailable`; the provider does not retry. A missing subtree, mutable record,
mismatched generation, or partially published generation is not safe to
serve. Writers retain a published generation for at least the documented
maximum load duration plus an operational grace interval; deletion must never
race an eligible reader.

An implementation must use strict authenticated transport, server identity
verification, and a least-privilege read-only authorization. Anonymous access,
plaintext credential transport, referral following, filter construction by
string concatenation, and request-derived search bases are forbidden.
Validated lookup facts are still passed through the LDAP library's filter
value encoder. Referrals do not create an implicit provider chain.

LDAP connection acquisition, bind, transport, page retrieval, and unbind/close
are cancellation-aware boundaries. The provider performs no automatic retry,
endpoint failover, referral chase, or stale-snapshot fallback.

## SQL Consistency And Security Contract

SQL stores metadata, handles, profiles, credentials, and policies as distinct
logical record sets keyed by the same generation. Table names, namespaces,
indexes, and physical types are implementation details outside this contract.

A load uses one read-only transaction that provides a stable snapshot across
all mapped record sets. The database and driver must provide repeatable-read
or stronger semantics sufficient to prevent a committed generation from
changing beneath that transaction. The transaction reads the one committed
metadata record, pages all record sets for that exact generation, validates
the complete dataset, and re-reads the metadata in the same snapshot before
successful transaction completion and local publication. Both metadata reads
must agree exactly.
A provider that cannot establish or prove this consistency level is
`unavailable`; it must not emulate consistency with independent autocommit
reads.

All statements are fixed, reviewed provider code with explicit projected
columns and bound parameters. Request or record values never become SQL
syntax, identifiers, ordering expressions, connection settings, or table
names. Dynamic SQL text, value interpolation, stored procedure side effects,
and read-time migration are forbidden. The runtime principal has read-only,
least-privilege access to the mapped record sets.

Connection acquisition, transaction start, each page, transaction completion,
and connection release are cancellation-aware boundaries. There is no
automatic retry for disconnects, serialization conflicts, deadlocks,
transaction aborts, or endpoint changes. A service may explicitly start a
later refresh after observing a typed failure.

## Context, Deadlines, And Failure Classification

Every load, refresh, and resolve checks a nil or already-terminated context
before touching provider state. A nil context is `invalid_request`. A canceled
context is `cancelled` and preserves `errors.Is(err, context.Canceled)`. An
elapsed deadline is `deadline_exceeded` and preserves
`errors.Is(err, context.DeadlineExceeded)`.

Local `ResolveProfile` and `ResolvePolicy` calls use an already published
immutable snapshot. They accept any active non-nil context and do not require
a deadline, preserving parity with the memory and flat-file providers.

Backend-facing LDAP and SQL load and refresh operations require a
caller-supplied deadline bounded by one nonzero immutable provider maximum.
A missing deadline or one wider than that maximum is `invalid_request` before
network or pool work. The provider never extends a caller deadline. Every
blocking backend call receives that context. Helper goroutines must not mask a
backend that ignores cancellation.

If the context terminates during backend work, the context code takes
precedence only when the backend result is consistent with the actual terminal
context state. A backend cancellation code with an active or differently
terminated context is an internal provider-contract failure. Cancellation
returns zero result and never publishes a partial snapshot.

The closed datasource error taxonomy is used without provider error strings:

| Condition | Datasource code |
| --- | --- |
| Nil, incomplete, over-wide-deadline, or otherwise invalid request | `invalid_request` |
| No exact committed dataset or requested domain identity | `not_found` |
| Duplicate metadata, identity, policy tuple, or exact result | `ambiguous` |
| Disabled policy, or disabled/outside-validity profile, at provider lookup | `inactive` |
| Active `observe`/`off` policy at later signing-profile projection | `inactive` |
| Invalid schema/version/field/key/cross-reference/generation | `malformed_data` |
| Count, byte, page, cursor, or work bound exceeded | `limit_exceeded` |
| Context canceled | `cancelled` |
| Context deadline elapsed | `deadline_exceeded` |
| Connection/pool acquisition, name resolution, TLS, authentication, authorization, referral, server-busy, I/O, transaction, serialization, or commit failure | `unavailable` |
| Impossible driver/library/result pair, panic, or cancellation mismatch | `internal_invariant` |

`unsupported_platform` remains part of the shared datasource taxonomy but is
not produced by networked LDAP or SQL providers; it is reserved for providers,
such as the confined flat-file implementation, whose required platform
primitive may be unavailable.

An LDAP result indicating partial results, unavailable critical paging,
administrative size limit, or an unverified referral is `unavailable` unless a
local configured hard limit was already exceeded, in which case it is
`limit_exceeded`. SQL truncation, uncertain commit/rollback state, inconsistent
transaction snapshot, or driver result truncation is `unavailable`.

A refresh failure after backend work has linearized marks an already
constructed provider degraded. Preflight rejection or cancellation before
linearization leaves state unchanged. While degraded, both resolve methods
return zero result plus `unavailable`. Provider recovery requires one complete
successful explicit refresh; a connectivity probe alone cannot clear degraded
state.

## Redaction And Diagnostics

The following data is protected and must not appear in errors, wrapping,
formatters, logs, traces, metrics, REST or CLI output, test failure text, or
panic recovery:

- LDAP DNs, search bases, filters, attribute values, continuation values,
  bind identities, endpoints, referrals, and raw LDAP errors;
- SQL text, query parameters, DSNs, database/schema/table/column names, row
  values, cursor values, transaction identifiers, server identifiers, and raw
  driver errors;
- provider records, connection credentials, TLS key material, tokens, paths,
  private keys, opaque handle values, profile/tenant/feedback identifiers,
  domains, selectors, public-key bytes, and validity instants.

Errors expose only a stable datasource code and context identity where
applicable. Diagnostics may expose bounded counters and closed classes such as
provider kind, operation class, result class, provider state, duration bucket,
page count, and examined-record count. Those values must remain
low-cardinality and must not encode a protected value.

Provider structs, configuration, requests, results, records, and lifecycle
errors either have no generic serializer or implement explicitly redacted
`String`, `GoString`, `Format`, and marshaling behavior. Backend errors are
classified at the provider boundary and are never wrapped verbatim. Panic
recovery returns `internal_invariant` without panic text.

Tests use synthetic toxic markers and assert their absence. Test failures
identify only a case name, bounded position or count, and stable error code;
they do not print DNs, queries, records, connection settings, or request
values.

The logical SQL column labels in the mapping tables above are public contract
documentation. Concrete database, schema, table, index, and physical column
names selected by an implementation are protected operational identifiers.

## Versioning And Migration Policy

Network readers accept exactly `dkim2-datasource-v2`. An absent version is
`malformed_data`; an unsupported older or newer version is
`malformed_data`. Readers do not infer a version from record shape and do not
apply compatibility aliases.

A schema change requires:

1. a new durable mapping contract and version identifier;
2. updated closed validators and resource bounds before a reader accepts it;
3. an out-of-process, separately reviewed migration;
4. conformance fixtures for the old rejection and new acceptance behavior;
5. atomic publication as a new, higher immutable generation;
6. an explicit deployment and rollback procedure.

The read-only provider never creates, alters, backfills, or deletes storage
schema and never migrates records on lookup or refresh. The current reader
accepts only the exact version above. Mixed-version records reject the
generation. Rollback publishes restored content under a new higher generation
rather than moving the metadata pointer backwards.

## Integration Evidence

The shared conformance harness runs the same logical dataset and requests
against memory, flat-file, LDAP, and PostgreSQL projections and proves
identical logically shared resolve behavior:

- complete profile and policy facts;
- generation agreement within each result;
- exact lookup and domain case behavior;
- success, `invalid_request`, `not_found`, `inactive`, `limit_exceeded`,
  `cancelled`, and `deadline_exceeded` classifications;
- immutable returned values and race-safe concurrent resolves;
- zero result on every failure.

The same harness tests `ambiguous` and `malformed_data` while constructing or
loading logically equivalent invalid datasets, not as ordinary reads from a
valid immutable snapshot. LDAP and SQL lifecycle suites additionally test
`unavailable` and degraded recovery. The static memory provider is not
expected to manufacture a network or lifecycle `unavailable` state.

Disposable LDAP integration tests must cover page boundaries, smaller pages,
the exact echo of repeated opaque cookies, empty pages with nonempty cookies,
empty-cookie completion, local response-budget exhaustion, bounded RFC 2696
abandonment and connection discard on incomplete cleanup, server size limits,
duplicate entries, partial generations, manifest publication, failed
refresh/degraded state/recovery, strict transport and authorization failures,
cancellation at each network boundary, and concurrent publication attempts.

Disposable SQL integration tests must cover keyset page boundaries,
transaction snapshot stability during a concurrent writer commit, duplicate
and dangling records despite storage constraints, isolation-level rejection,
pool exhaustion, disconnects, transaction aborts, serialization conflicts,
commit uncertainty, failed refresh/degraded state/recovery, cancellation at
each transaction boundary, and concurrent refresh attempts.

Both suites must cover exact and one-over domain limits, generation rollback
and overflow, schema-version migration and rejection, toxic backend errors,
formatting and marshaling privacy, panic containment, no hidden retry, and no
last-known-good serving while degraded. Tests must use synthetic values and
must not print credentials, connection details, DNs, queries, or provider
records.

Signing integration tests must prove datasource resolution completes before
route or private-signing work, the fresh DNS publication check still precedes
the private signing callback, and every datasource denial produces no partial
field, recipe, custody transition, release, callback, or route side effect.

Dependency tests must prove:

- datasource core and concrete providers do not import signing;
- `datasource/signingprofile` is the sole datasource/signing bridge;
- signing and other protocol packages do not import datasource providers;
- LDAP and PostgreSQL drivers remain outside the standalone library and are
  owned by the daemon service module;
- no replay interface, operation, or provider is introduced by this design.
