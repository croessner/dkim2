# LDAP And SQL Datasource Providers And Legacy Migration

Status: implemented.

Custody note: the public-provider and legacy-inventory work remains historical
implementation evidence, but its local-registry policy is superseded by
`docs/specs/implementation/native-datasource-key-custody.md`. LDAP and
PostgreSQL runtime generations now require `dkim2-datasource-v2` native key
material and have no local-manifest or legacy fallback.

This specification turns the storage mappings and migration contract in
`docs/datasource-ldap-sql-design.md` into executable daemon-owned LDAP and
PostgreSQL providers, deployable schema artifacts, and a separate
OpenDKIM-to-DKIM2 bootstrap workflow. It preserves the storage-neutral
datasource model, immutable generation publication, opaque signing handles,
fresh DNS publication proof, and restrictive Draft-04 signing boundary.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`, especially Sections 3.2 through 3.8, 5.8, 7.2
  through 7.5, 11, 12, 13, 14, 15, 16, and 18.1;
- `docs/datasource-ldap-sql-design.md`;
- `docs/specs/implementation/datasource-providers.md`;
- `docs/specs/implementation/signing-and-revision.md`;
- `docs/specs/implementation/openapi-daemon-foundation.md`;
- `docs/specs/implementation/observability-foundation.md`;
- `docs/specs/implementation/security-hardening.md`;
- `docs/specs/implementation/packaging-container-delivery-operator-guide.md`;
- `docs/specs/implementation/interoperability-reference-release-candidate.md`;
- `docs/specs/spec-and-prompt-template.md`;
- `docs/specs/openapi/dkim2d.yaml`;
- `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05;
- `draft-chuang-dkim2-dns-04`, dated 2026-03-18, as the historical behavior
  and vector identifier retained by this repository;
- RFC 4511, RFC 4512, RFC 4513, RFC 4515, RFC 4517, and RFC 4519 for LDAP
  protocol, schema, authentication, filters, syntaxes, and standard schema;
- RFC 2696 for LDAP simple paged results;
- RFC 4528 for the LDAP assertion control used by publication fencing;
- PostgreSQL documentation for read-only repeatable-read transactions,
  constraints, row locking, and transactional DDL/DML;
- the existing public DKIM2 provider and signing-store boundaries under
  `lib/provider` and `cmd/dkim2d/internal/signingstore`;
- `Makefile`, CI workflows, module metadata, vendor metadata, and image
  delivery owners.

The repo-local `dkim2-spec-conformance` skill still mentions Draft-02. That
sentence is stale. `AGENTS.md`, the architecture, current vectors, and this
specification have higher authority and require Draft-04 plus the historical
DNS-04 behavior identifier.

If this specification conflicts with a governing source, implementation stops
and the durable artifacts are reconciled before behavior changes.

## Original Gap

The library already owns validated storage-neutral datasource identifiers,
profiles, credentials, policies, limits, immutable memory and flat-file
providers, and the sole datasource-to-signing projection. The daemon already
owns a protected flat-file datasource and private-key store. The repository
also contains a detailed LDAP/SQL mapping and an architecture-level OpenDKIM
bootstrap contract.

The following production work is absent:

- no installable RNS DKIM2 LDAP schema exists;
- no daemon-owned LDAP client, paged loader, lifecycle, or configuration
  exists;
- no SQL DDL, transactionally consistent loader, pool lifecycle, or
  configuration exists;
- no public service-neutral bridge lets `cmd/dkim2d` construct the existing
  `lib/internal/datasource` values without violating Go's `internal` import
  rule;
- no provider-neutral daemon lifecycle can atomically publish a complete
  datasource snapshot and matching protected signing registry generation;
- no shared parity runner exercises memory, flat-file, LDAP, and SQL;
- no bounded, secret-safe legacy inventory, protected key import, DNS proof,
  publication, dry-run, or rollback tool exists;
- public reference material still reports executable LDAP/SQL and legacy
  migration as deferred.

The Go import boundary is a concrete architecture implementation gap, not
permission to duplicate datasource validation in `cmd/dkim2d`. A command
module cannot import `lib/internal/datasource`. The smallest reconciliation is
a narrow service-neutral public bridge in the library module that delegates to
the existing internal constructors and signing projection. LDAP and SQL
drivers, connection types, records, transactions, configuration, and
publication code remain outside `lib`.

## Goal

Deliver production-capable LDAP and PostgreSQL datasource paths that:

- read one exact complete committed generation into an immutable local
  snapshot;
- resolve profiles and policies with the same behavior as memory and
  flat-file providers;
- never perform backend I/O during a signing lookup;
- reject aliases, wildcards, suffixes, defaults, first-row selection,
  provider chains, stale snapshots, mixed generations, partial data, and
  ambiguous identities;
- carry only provider-neutral opaque `KeyHandleID` values across the
  datasource boundary;
- never store private keys in LDAP or SQL;
- bind a loaded datasource generation to one exact protected signing registry
  generation before readiness or signing;
- use authenticated, verified, least-privilege backend connections with
  caller deadlines, finite resource limits, no hidden retry, and typed
  secret-safe failures;
- provide exact LDAP schema and PostgreSQL DDL plus reproducible validation;
- bootstrap validated active OpenDKIM RSA/Ed25519 pairs only through a
  separate protected administrative command;
- reject `DKIMDomain != associatedDomain`, never map `DKIMIdentity` to DKIM2
  numeric `i=`, and never infer validity from LDAP timestamps;
- require a fresh unique DNS key result matching the protected handle's
  canonical public SPKI before publication;
- publish or roll back only by adding a higher immutable generation;
- keep all operator, report, log, trace, metric, CLI, REST, and test output
  free of private material and protected backend or identity facts.

LDAP and SQL are administrative storage providers. They do not define DKIM2
protocol semantics, authorize a custody role, replace policy evaluation,
replace replay detection, or replace the mandatory signing-time DNS
publication check.

## Delivery Shape

Implementation proceeds in this order:

1. Reconcile the service/library import seam with a narrow provider-neutral
   dataset bridge and shared lifecycle contracts.
2. Deliver the exact RNS LDAP schema, structural layout, mapper, and schema
   validation fixtures.
3. Implement bounded authenticated LDAP loading, RFC 2696 paging,
   cancellation, fencing, degraded recovery, and immutable local publication.
4. Deliver PostgreSQL DDL, fixed mapping, constraints, and migration fixtures.
5. Implement read-only repeatable-read SQL loading, keyset paging,
   cancellation, degraded recovery, and immutable local publication.
6. Add typed daemon configuration, protected credential loading, Fx
   composition, readiness, reload ownership, and secret-safe observations.
7. Add one shared provider parity corpus and disposable OpenLDAP/PostgreSQL
   lifecycle, failure, race, and recovery evidence.
8. Add bounded legacy OpenDKIM inventory, explicit mapping-plan validation,
   and a nonpublishing redacted dry-run.
9. Add protected signer-registry import and fresh DNS/SPKI proof.
10. Add atomic LDAP/PostgreSQL publication, concurrent-writer fencing,
    higher-generation rollback, cleanup, and crash-boundary tests.
11. Complete operator documentation, packaging/CI/generator/dependency
    evidence, reference-claim updates, security campaigns, and full gates.
12. Perform a fresh independent finding-first review and root-cause fixes on
    the unchanged implementation candidate.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | very large |
| Estimated wall-clock effort | 2 to 6 agent-days |
| Highest-risk area | cross-system immutable publication with protected key import and no partial activation |
| Expected prompt count | 11 cumulative implementation prompts plus one independent review prompt |
| Required final gates | disposable LDAP/SQL/migration integration gates and `make guardrails` |

Risk notes:

- Medium risk: adding a narrow public provider bridge without widening the
  protocol API or leaking backend models.
- High risk: hostile or malfunctioning LDAP paging, BER sizes, SQL cursors,
  transaction cancellation, and pool lifecycle.
- High risk: preserving a ready/degraded state that never serves a stale
  snapshot after a linearized refresh failure.
- Highest risk: importing legacy private keys and activating a datasource
  generation without exposing bytes, accepting domain disagreement, skipping
  fresh DNS proof, or publishing only one side of the datasource/registry
  pair.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-provider-neutral-bridge-and-lifecycle.md` |  |  |  |  |  |
| `02-ldap-schema-and-mapping.md` |  |  |  |  |  |
| `03-ldap-loader-security-and-recovery.md` |  |  |  |  |  |
| `04-postgresql-ddl-and-mapping.md` |  |  |  |  |  |
| `05-postgresql-loader-transactions-and-recovery.md` |  |  |  |  |  |
| `06-daemon-config-composition-and-observability.md` |  |  |  |  |  |
| `07-provider-parity-and-disposable-integration.md` |  |  |  |  |  |
| `08-opendkim-inventory-plan-and-dry-run.md` |  |  |  |  |  |
| `09-protected-key-import-and-dns-proof.md` |  |  |  |  |  |
| `10-publication-rollback-and-concurrency.md` |  |  |  |  |  |
| `11-security-docs-release-gates-closeout.md` |  |  |  |  |  |
| independent review |  |  |  |  |  |

The required measurement is wall-clock time from prompt start through prompt
closeout. Active engineering time may be recorded additionally but never
replaces wall-clock time.

## Scope

In scope:

- a narrow public library bridge over the existing internal datasource
  contracts and signing projection;
- daemon-owned concrete LDAP and PostgreSQL providers;
- the exact 17 LDAP attributes and five object classes under
  `1.3.6.1.4.1.31612.1.7`;
- OpenLDAP schema, index, ACL, and `slaptest` fixtures;
- PostgreSQL schema, constraints, indexes, roles, and publication DDL;
- immutable snapshot construction, initial load, serialized refresh,
  degraded state, recovery, readiness, and shutdown;
- typed stable daemon config paths for selecting flat-file, LDAP, or
  PostgreSQL;
- protected LDAP bind secret, PostgreSQL password, CA, and signing-registry
  material loading;
- synthetic parity fixtures and disposable OpenLDAP/PostgreSQL integration;
- an offline `dkim2d datasource bootstrap-opendkim` administrative command
  tree that never starts the HTTP daemon;
- legacy inventory, explicit plan, dry-run, protected key import, fresh DNS
  proof, publication, rollback, and secret-safe reports;
- Make/CI/image/operator/reference updates needed to make these paths
  reproducible and accurately supported.

Out of scope:

- changing Draft-04 or historical DNS-04 semantics or identifiers;
- changing raw RFC 5322, canonicalization, recipe, signature, policy, replay,
  Milter, or Exim behavior except to fix a proven root-cause regression;
- LDAP or SQL drivers in `lib`;
- private keys, signer callbacks, commands, paths, DNs, or database locators
  in datasource values;
- runtime reads of historical OpenDKIM objects;
- read-time schema inference, conversion, backfill, or migration;
- LDAP write support in the runtime provider or SQL writes from the runtime
  provider;
- alias, wildcard, suffix, parent-domain, tenant-default, ordering, provider,
  endpoint, or stale-generation fallback;
- automatic migration of legacy records whose lookup and signing domains
  differ;
- automatic activation based only on `DKIMActive=TRUE`;
- importing inactive history by default;
- mapping DKIM AUIDs or LDAP create/modify timestamps into DKIM2 fields;
- a REST migration API, privileged `dkim2ctl` mutation API, or OpenAPI
  contract change;
- database-backed replay storage;
- a real release tag, registry publication, or production credential use;
- the deferred Exim adapter work.

## Package And Dependency Boundaries

### Library bridge

`lib/internal/datasource` remains the only owner of datasource identifiers,
record validation, exact matching, limits, errors, and immutable results.
Implementation adds only the minimum public bridge under `lib/provider`
needed for an external command module to:

- construct provider-neutral records through the internal validators;
- build one immutable snapshot from a complete dataset;
- resolve exact profile and policy results through a narrow public interface;
- project an approved snapshot plus immutable opaque-handle registry into the
  existing `dkim2.SigningProfile`;
- classify failures without raw backend detail.

The bridge must wrap or alias behavior rather than copy validators. Its values
must be immutable and explicitly redacted under formatting and marshaling.
Existing public flat-file behavior remains compatible. Exported API additions
are documented and included in the reference API manifest. The bridge imports
no LDAP, SQL, Cobra, Viper, Fx, Prometheus, OTLP, Milter, or CLI dependency.

### Concrete providers

Concrete implementations live under service ownership, for example:

- `cmd/dkim2d/internal/datasource/ldap`;
- `cmd/dkim2d/internal/datasource/postgresql`;
- `cmd/dkim2d/internal/datasource/runtime`;
- `cmd/dkim2d/internal/migration/opendkim`.

LDAP records, controls, DNs, cookies, connections, and client errors never
leave the LDAP package. SQL rows, queries, transactions, pools, cursors, and
driver errors never leave the PostgreSQL package. Both build the same
provider-neutral snapshot through the library bridge.

The first SQL implementation is PostgreSQL. It uses a pinned, maintained Go
driver in `cmd/dkim2d` only and the standard context-aware transaction
boundary. Dependency selection is reviewed for cancellation behavior, TLS
control, maintained Go 1.26 support, and vulnerability status. No ORM, dynamic
query builder, schema auto-migrator, or driver abstraction enters `lib`.

### Signing registry and daemon

`cmd/dkim2d/internal/signingstore` is refactored so datasource loading and
protected key-registry loading are separate cohesive objects joined by one
generation-checked runtime. Flat-file behavior remains supported. LDAP and
PostgreSQL snapshots bind to a generation-specific protected registry
manifest before readiness.

The existing `dkim2-private-keys-v1` manifest remains accepted only for the
existing flat-file path and retains its current implicit generation behavior.
Network providers and migration require a new exact
`dkim2-private-keys-v2` generation manifest with one explicit nonzero
generation and otherwise equivalent closed entry facts. There is no implicit
v1-to-v2 conversion, cross-version fallback, or read-time rewrite.

`cmd/dkim2d/internal/config` owns typed selection and secret-file paths.
`cmd/dkim2d/internal/app` and Fx own startup, readiness, explicit refresh, and
shutdown. Protocol packages do not know which provider is selected.

## Common Dataset And Lifecycle Contract

Both providers accept exactly `dkim2-datasource-v1`. One readable dataset has
one nonzero unsigned 64-bit generation and exact state `committed`. Every
handle, profile, credential, and policy record has that generation. A complete
load:

1. validates a non-nil active context with a caller deadline no wider than the
   configured immutable maximum;
2. captures one exact current metadata fence;
3. reads every record class under finite page, response, record, byte, and
   time bounds;
4. converts every value through the existing provider-neutral constructors;
5. rejects duplicate, incomplete, mixed-generation, dangling, or inconsistent
   records;
6. builds the same immutable indexes as memory/flat-file;
7. rereads the metadata fence inside the backend consistency boundary;
8. validates the matching protected registry generation;
9. publishes the complete joined generation locally in one atomic operation.

Initial load failure returns no runtime provider and prevents daemon
readiness. Refresh preflight rejection before serialization changes no state.
Once refresh linearizes and backend work starts, any failure marks the runtime
degraded. The previous snapshot may remain allocated only for diagnosis or
outstanding leases; new resolves and lease acquisition return
`unavailable`. While ready, a complete revalidation of the unchanged current
generation is a successful health no-op only when every immutable dataset
fact and protected registry binding is exactly equal: the newly loaded
candidate is destroyed and no generation is republished. Changed facts under
the current generation degrade the runtime. A later complete successful
refresh atomically publishes a strictly higher generation and clears degraded
state. There is no stale
serving, hidden retry, endpoint failover, provider fallback, or background
recovery other than the single configured serialized refresh owner.

The first nonzero generation is accepted only through the explicit
`expected_current: "0"` administrative bootstrap fence. Zero means that the
publisher must prove both the current pointer and every generation record
absent; it is never a runtime generation or a fallback for an unreadable
backend. Thereafter only a strictly greater generation is publishable.
Revalidating the exact current generation while ready is not a publication and
is permitted only after both datasource and registry have been loaded and
validated again. `math.MaxUint64` is valid and terminal. Attempted publication
reuse, backward movement, a noncanonical zero, mixed generations, or an
unreadable state after linearization fails closed. Rollback republishes prior
logical content under a new higher generation and therefore never accepts the
zero bootstrap fence.

The initial registry may remain in the selected immutable protected-generation
directory. Its owner-only mode-`0700` parent is the registry publication root.
Later migration generations are sealed numeric sibling directories under that
root. The daemon retains a descriptor-confined parent capability, uses the
configured manifest name only, and opens the exact numeric child selected by
the backend fence without path fallback.

The limits and accounting in `docs/datasource-ldap-sql-design.md` are exact:
1,024 profiles, two credentials per profile, 2,048 credentials and handles,
4,096 policies, 9,216 examined domain records, 128 identifier bytes,
253/127 domain and selector bytes/labels, 2,048 decoded public-key bytes,
1 MiB aggregate decoded strings, page size at most 256, and class response
count at most the configured class maximum plus one. Configuration may narrow
but never widen these limits.

Service-owned transport and migration limits are also non-widenable:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| one backend load or refresh deadline | 5 seconds | 30 seconds |
| one LDAP BER response | 4 MiB | 4 MiB |
| aggregate LDAP response bytes per load | 16 MiB | 32 MiB |
| one LDAP entry DN | 1,024 bytes | 4,096 bytes |
| one accepted paging cookie | 1,024 bytes | 4,096 bytes |
| attributes returned for one entry | 18 | 24 |
| values examined for one attribute | 2 | 4 |
| aggregate SQL row bytes per load | 16 MiB | 32 MiB |
| PostgreSQL open connections | 2 | 4 |
| PostgreSQL idle connections | 1 | 2 |
| one legacy private-key value | 64 KiB | 64 KiB |
| one migration plan or machine report | 256 KiB | 256 KiB |
| concurrent load/publication operation | 1 | 1 |

The LDAP client may receive a small amount of protocol framing beyond decoded
domain bytes, but it must reject a declared BER message larger than the exact
response cap before allocating that body. SQL row accounting charges encoded
driver values before conversion. Narrower configuration must remain positive.
Deadlines are caller supplied and may be shorter; providers never extend them.

The existing closed datasource taxonomy remains authoritative:
`invalid_request`, `not_found`, `ambiguous`, `inactive`, `malformed_data`,
`limit_exceeded`, `unavailable`, `unsupported_platform`, `cancelled`,
`deadline_exceeded`, and `internal_invariant`. Network providers do not
produce `unsupported_platform`. A failure always returns a zero result.

## LDAP Schema And Storage Contract

### OID allocation

The committed schema file is named `rnsdkim2.schema` and declares:

```text
objectidentifier RNSRoot      1.3.6.1.4.1.31612
objectidentifier RNSLDAP      RNSRoot:1
objectidentifier RNSDKIM2     RNSLDAP:7
objectidentifier RNSDKIM2at   RNSDKIM2:1
objectidentifier RNSDKIM2oc   RNSDKIM2:2
```

The exact attribute allocation is immutable:

| Suffix | Descriptor | Syntax and matching | Cardinality |
| ---: | --- | --- | --- |
| 1 | `dkim2SchemaVersion` | IA5 String, `caseExactIA5Match` | single |
| 2 | `dkim2Generation` | Integer, `integerMatch`, `integerOrderingMatch` | single |
| 3 | `dkim2DatasetState` | IA5 String, `caseExactIA5Match` | single |
| 4 | `dkim2HandleID` | IA5 String, `caseExactIA5Match` | single |
| 5 | `dkim2ProfileID` | IA5 String, `caseExactIA5Match` | single |
| 6 | `dkim2SigningDomain` | IA5 String, `caseExactIA5Match` | single |
| 7 | `dkim2RecordStatus` | IA5 String, `caseExactIA5Match` | single |
| 8 | `dkim2NotBefore` | IA5 String, `caseExactIA5Match` | single |
| 9 | `dkim2NotAfter` | IA5 String, `caseExactIA5Match` | single |
| 10 | `dkim2Algorithm` | IA5 String, `caseExactIA5Match` | single |
| 11 | `dkim2Selector` | IA5 String, `caseExactIA5Match` | single |
| 12 | `dkim2PublicKeySPKI` | Octet String, `octetStringMatch` | single |
| 13 | `dkim2TenantID` | IA5 String, `caseExactIA5Match` | single |
| 14 | `dkim2ProfileUse` | IA5 String, `caseExactIA5Match` | single |
| 15 | `dkim2Rollout` | IA5 String, `caseExactIA5Match` | single |
| 16 | `dkim2Compatibility` | IA5 String, `caseExactIA5Match` | single |
| 17 | `dkim2FeedbackRouteID` | IA5 String, `caseExactIA5Match` | single |

IA5 String uses `1.3.6.1.4.1.1466.115.121.1.26`, Integer uses
`1.3.6.1.4.1.1466.115.121.1.27`, and Octet String uses
`1.3.6.1.4.1.1466.115.121.1.40`. RFC3339Nano validity text deliberately uses
IA5 String rather than LDAP Generalized Time so the persisted representation
round-trips exactly through the existing datasource constructor. Domains and
selectors must already be canonical lowercase ASCII; the provider still
validates them rather than trusting the matching rule.

The exact object classes are:

| Suffix | Descriptor | Required DKIM2 attributes | Optional DKIM2 attributes |
| ---: | --- | --- | --- |
| 1 | `dkim2Dataset` | schema version, generation, dataset state | none |
| 2 | `dkim2Handle` | generation, handle ID | none |
| 3 | `dkim2Profile` | generation, profile ID, signing domain, record status | not-before and not-after as an all-or-none pair |
| 4 | `dkim2Credential` | generation, profile ID, algorithm, selector, public SPKI, handle ID | none |
| 5 | `dkim2Policy` | generation, tenant ID, signing domain, profile use, profile ID, record status, rollout, compatibility | feedback route ID |

All five are `STRUCTURAL`, derive from `top`, and additionally require standard
`cn` only as the bounded storage RDN. `cn`, entry DN, and subtree position are
never datasource identity and are not requested by the mapper except where the
LDAP client unavoidably supplies the entry DN. The provider bounds but never
logs or returns those mechanics.

### Structural layout and publication fence

One configured base DN has:

```text
cn=current,<base>
ou=generations,<base>
  dkim2Generation=<G>,ou=generations,<base>
    ou=handles,...
    ou=profiles,...
    ou=credentials,...
    ou=policies,...
```

`cn=current` is a `dkim2Dataset` publication reference. Each generation root
is also a `dkim2Dataset`; its child records carry the identical generation.
The runtime reads `cn=current`, derives the generation subtree only from the
validated unsigned decimal generation and configured generations base, loads
that exact subtree, requires the generation-root metadata to agree, and
rereads `cn=current` after loading. It never follows LDAP aliases or referrals.

A publisher creates a new generation root in `staging`, adds and validates all
children, changes only that generation root to `committed`, then performs one
assertion-controlled modify of `cn=current` from the expected prior generation
to the new committed generation. A reader accepts only exact committed values.
Unreferenced staging or committed generations are inert. Existing committed
records are never edited or deleted by normal publication.

Schema validation includes exact descriptor/OID uniqueness, `MUST`/`MAY`
sets, standard `cn`, single-value flags, syntaxes, matching rules, and clean
installation through `slaptest`. Suggested indexes are equality indexes for
`objectClass`, generation, schema version, dataset state, handle ID, profile
ID, signing domain, tenant ID, profile use, algorithm, and selector. Indexes
are deployment performance settings, never correctness.

ACL examples define separate principals:

- anonymous receives no access;
- the runtime principal can authenticate and read only current metadata and
  mapped attributes beneath the generation tree;
- the publisher principal can create a new generation and update only the
  current fence through the reviewed publisher;
- the legacy inventory principal cannot read `DKIMKey`;
- the protected import principal may read `DKIMKey` only during an approved
  import;
- schema administration is separate from runtime and migration.

The runtime principal has no add, modify, delete, modrdn, schema, or legacy-key
privilege.

### LDAP transport and paging

The runtime supports verified TLS only: `ldaps` or StartTLS is selected
explicitly, server identity and CA roots are verified, insecure verification
is impossible, and simple bind credentials are sent only after TLS. Anonymous
bind, plaintext credential transport, referral following, automatic endpoint
failover, and request-derived search bases are forbidden. One configured
endpoint is authoritative for a load.

The LDAP client requests only mapped attributes and uses a critical RFC 2696
control. Page size is fixed for one load and at most 256. Search size limit is
the checked record-class maximum plus one. The cookie is opaque,
length-bounded, never persisted or emitted, echoed exactly after acceptance,
and only an empty cookie proves completion. Empty pages and repeated nonempty
cookies are valid but consume the independent response budget.

If active-context local failure stops paging, the client makes at most one
bounded page-size-zero abandonment with the last accepted cookie. It never
echoes an oversized or otherwise unaccepted cookie. Cancellation closes or
discards the connection immediately rather than creating a cleanup context.
Failed cleanup also discards the connection. LDAP protocol framing,
attributes, values, DNs, controls, pages, and aggregate response bytes are
bounded before copying or allocation wherever the client API permits. A
selected LDAP dependency must provide a demonstrable bounded-message boundary;
otherwise the implementation adds and tests one at the owned connection seam.

## PostgreSQL Schema And Transaction Contract

The shipped DDL owns one versioned PostgreSQL schema with these logical tables:

- dataset generations;
- one singleton current-generation reference;
- handles;
- profiles;
- credentials;
- policies.

The exact committed DDL uses stable names, explicit projected columns, and no
ORM metadata. Generation is `numeric(20,0)` with a check from 1 through
18446744073709551615 so the full datasource `uint64` contract is preserved.
Identifiers, domains, selectors, enums, and canonical RFC3339Nano validity
instants are `text COLLATE "C"` with finite octet-length checks. Public SPKI is
`bytea`. Application constructors remain authoritative for grammar,
cryptographic validity, closed values, exact timestamp round-trip, and
cross-record invariants.

Required relational constraints include:

- one row per generation and one singleton current pointer;
- primary keys for `(generation, handle_id)`, `(generation, profile_id)`, and
  `(generation, tenant_id, signing_domain, profile_use)`;
- one credential per `(generation, profile_id, algorithm)`;
- unique credential selector within a profile;
- unique credential handle across a generation;
- foreign keys from credentials to profiles and handles;
- a same-generation, same-domain foreign-key path from policy to profile;
- all-or-none validity timestamps;
- exact schema version and closed staging/committed state checks.

Committed-generation content is immutable. DDL permissions and triggers deny
update/delete of committed generation rows. The runtime role has only
`CONNECT`, namespace usage, and `SELECT` on the mapped tables. The publisher
role is distinct and has only the reviewed insert, staging-to-committed, and
singleton-pointer update privileges.

One runtime load uses a single read-only repeatable-read or serializable
transaction. It proves the effective isolation level, reads current metadata,
loads each exact generation record set with fixed parameterized SQL and
deterministic keyset pagination, rereads metadata in the same snapshot, and
completes the transaction before local publication. Offset pagination,
autocommit multi-query loads, dynamic identifiers, interpolated SQL,
caller-selected ordering, stored procedure side effects, read-time migration,
and automatic transaction retry are forbidden.

The provider uses one explicitly configured verified-TLS PostgreSQL endpoint.
It constructs driver configuration from typed fields rather than accepting an
arbitrary DSN. Server name, CA, database, user, password file, address,
timeouts, and pool bounds are protected config. TLS disable/prefer/allow,
multi-host fallback, environment-driven libpq defaults, service files, and
password-command behavior are rejected.

Connection acquisition, transaction start, isolation proof, every page,
metadata reread, transaction completion, connection release, and shutdown are
context-aware. Pool exhaustion, disconnect, serialization conflict,
transaction abort, uncertain completion, TLS/auth failure, and inconsistent
driver outcomes are typed `unavailable` with no retry and no raw error.

## Daemon Configuration, Composition, And Readiness

Existing stable flat-file paths retain their meanings. `signing.backend` gains
the exact values `ldap` and `postgresql` in addition to existing values.
Backend-specific stable subtrees are `signing.ldap.*` and
`signing.postgresql.*`. They contain typed endpoint, verified-TLS, protected
credential-file, base/database, page, pool, load-deadline, refresh, and
narrowed-limit settings. Irrelevant backend fields are rejected rather than
ignored. Inline passwords and arbitrary LDAP URLs or SQL DSNs are forbidden.

Scalar environment placeholders expand once before typed validation, missing
variables fail closed, map keys never expand, and protected file metadata is
retained. Password files, CA files, and registry manifests use the existing
descriptor-confined protected loader or an equally restrictive owner. Config,
snapshots, provider values, and errors remain explicitly redacted under
formatting and marshaling.

Fx constructs exactly one selected provider, one generation-matched protected
registry, one serialized refresh lifecycle, and one signing runtime. Startup
requires a complete initial generation. Readiness is false while initial load
is incomplete, provider/registry generations disagree, a linearized refresh
has failed, or shutdown has begun. Health remains process liveness. Existing
in-flight leases retain their pinned generation; no new lease is granted while
degraded. Shutdown stops refresh, joins workers within context, closes backend
resources, retires generations after leases, and reports only bounded failure
classes.

No OpenAPI change is required. Provider selection and migration are local
operator surfaces, not HTTP semantics. If implementation evidence proves an
OpenAPI change necessary, this specification and authoritative OpenAPI
document must be revised before generated code changes.

## Legacy OpenDKIM Bootstrap Contract

### Command and configuration

The administrative surface is an offline Cobra command under `dkim2d`, shaped
as:

```text
dkim2d datasource bootstrap-opendkim --config <absolute-protected-path> --dry-run
dkim2d datasource bootstrap-opendkim --config <absolute-protected-path> --apply
dkim2d datasource rollback --config <absolute-protected-path> --generation <new-generation>
```

It never constructs or starts the HTTP server, Milter, replay store, normal
daemon provider, metrics endpoint, or tracing exporter. Migration config has a
separate exact version and separate runtime, legacy-read, protected-import,
DNS-proof, and publication principals. `--dry-run` is the default-safe
nonpublishing mode; mutation requires the explicit `--apply` flag and an exact
expected current generation. Canonical `"0"` is permitted only for first
publication into a provably empty backend. It is not inferred from a failed
read and is forbidden for rollback. Conflicting flags and interactive prompts
are forbidden.

### Inventory and mapping plan

Inventory performs a bounded authenticated verified-TLS read and does not
request `DKIMKey`. It refreshes the dated architecture snapshot rather than
assuming its counts. It validates:

- supported external `DKIM` object shape;
- complete required fields;
- unique canonical lowercase ASCII selector identities while retaining each
  exact LDAP spelling solely for protected legacy lookup;
- no duplicate active `(domain, algorithm)`;
- exact closed RSA/Ed25519 key types;
- canonical `associatedDomain`;
- exact canonical equality of `DKIMDomain` and `associatedDomain`;
- active/inactive counts and bounded rotation groups;
- all source record, page, response, byte, and deadline limits.

`DKIMDomain != associatedDomain` is `malformed_data` for automatic migration.
No alias policy is synthesized. `DKIMIdentity` is recorded only as a counted
ignored legacy field and never becomes DKIM2 `i=` or another identity.
`createTimestamp` and `modifyTimestamp` are counted only as ignored audit
presence and never become validity instants.

An active wildcard `DKIMDomain` is ambiguous and fails closed. A bounded
inactive wildcard-domain row may contribute only to count-only historical
inventory; it never becomes a profile, credential, key lookup, DNS name, or
fallback.
Other inactive rotation history remains counted and skipped unless a later
separately reviewed plan defines a disabled-profile import.

An exact protected mapping plan supplies facts absent from OpenDKIM:
generation, expected current generation, tenant, profile ID, profile use,
opaque handle IDs, rollout, strict compatibility, optional feedback route,
optional explicit validity, a canonical legacy source-selector identity, a
distinct canonical DKIM2 target selector, and target backend. The inventory
retains exact LDAP spelling internally for lookup; it is never accepted as a
plan alias. Backward-compatible same-selector plans remain explicit; the
implementation never infers selector aliases. IDs are explicit canonical
inputs and are never derived from DNs, selectors, paths, primary keys, key
hashes, or private material.

By default only complete active records form active profile candidates.
Inactive rotation history is counted and skipped. Importing history requires a
separately reviewed explicit plan that creates distinct disabled profiles; it
is not inferred by this implementation.

### Protected key import and DNS proof

The protected import phase reads `DKIMKey` only through the import principal
and only after inventory and plan validation. Each value is bounded before
decode, retained for the shortest possible scope, parsed through existing
private-key validation, checked against the declared algorithm and strength,
and cleared on every path where Go ownership permits. It derives canonical
public SPKI DER and creates one generation-specific protected registry entry
for the explicit opaque handle. Raw key bytes never enter a datasource record,
report, log, trace, metric, error, CLI output, test failure, temporary
world-readable file, process argument, or environment variable.

Legacy RSA input may be one bounded, unencrypted PKCS#1 PEM block. The importer
parses and validates that exact form, proves the declared RSA algorithm and
minimum strength, and serializes canonical PKCS#8 for the protected registry.
Encrypted PEM, additional blocks, trailing material, malformed RSA, algorithm
mismatch, and legacy Ed25519 conversion fail closed; no generic key-format
fallback is permitted.

The importer stages private material and manifests under the existing
descriptor-confined root using no-follow relative opens, restrictive
ownership/mode checks, atomic rename, file and directory synchronization, and
no overwrite. A generation-specific registry manifest identifies exactly one
datasource generation. Existing exact immutable bytes may be recognized
idempotently; any mismatch fails closed.

Every candidate credential then performs a fresh DNS lookup through the same
key-record parser and public-key validation owner used by signing, with cache
bypass and a bounded caller deadline. The lookup uses only the explicit
canonical DKIM2 target selector, never the exact-case legacy source selector.
Exactly one usable `selector._domainkey.signing-domain` record must match
algorithm and canonical SPKI. Missing, ambiguous, invalid, revoked, mismatched,
unavailable, or stale evidence prevents publication. Migration proof
supplements but never removes the normal signing-time fresh DNS publication
check.

### Dry-run report

The deterministic report schema is
`dkim2.opendkim-bootstrap-report.v1`. It contains only:

- schema and tool version;
- target provider kind;
- dry-run/apply/result closed classes;
- bounded counts and count buckets;
- closed failure classes;
- whether inventory, plan, key validation, DNS proof, registry staging,
  datasource staging, and publication were attempted and completed;
- candidate/report identities derived only from repository candidate bytes
  and the redacted normalized report itself. Protected input and plan digests
  remain internal verification state and are not emitted.

It contains no DN, domain, selector, tenant, profile, handle, AUID, endpoint,
database object, LDAP filter, SQL, path, key, key digest, SPKI, DNS text,
credential, source row, raw error, or validity instant. Human output is
equally bounded. Tests use toxic synthetic markers and inspect stdout, stderr,
errors, logs, traces, metrics, JSON, cleanup state, and test failure helpers.

## Publication, Crash Safety, And Rollback

Publication authority is separate from inventory and runtime authority. The
common preconditions are:

- exact expected current generation;
- strictly higher new generation;
- complete plan and source inventory;
- complete protected registry generation;
- complete provider-neutral dataset validation;
- successful fresh DNS proof for every active credential;
- no unresolved warning or partial result.

For a nonzero expected generation, LDAP publication stages the complete
generation subtree, validates readback, marks its metadata committed, then
uses RFC 4528 assertion control to update the current fence from the expected
generation. For `expected_current: "0"`, it first proves that `cn=current` and
all generation children are absent, atomically adds a unique `cn=current`
entry in `staging` state as the first-writer claim, stages and validates the
generation, and finally uses a critical RFC 4528 assertion over exact schema,
generation, and `staging` state to activate that pointer as `committed`.
Concurrent first publishers cannot both claim the current DN. A crash after
the claim leaves a noncurrent staging pointer that blocks runtime and later
bootstrap until explicitly inspected and repaired; it never becomes an
implicit retry or success.

For a nonzero expected generation, PostgreSQL publication holds the singleton
current row lock. For `expected_current: "0"`, one serializable transaction
predicate-checks that the current table and all five generation-backed tables
are empty. The same transaction inserts, validates, commits, and uniquely
inserts the singleton current pointer. Serializable predicate conflict or the
singleton constraint prevents two first publishers from committing.
Concurrent publishers cannot both succeed. A timeout, process termination,
uncertain backend result, failed registry synchronization, failed DNS proof,
or pointer conflict publishes no claim of success.

The protected registry generation is installed before the datasource current
pointer changes and is inert until selected by that generation. Orphaned
staging registry or datasource generations are safe and reported only as
bounded cleanup counts. Cleanup never deletes a committed current or retained
rollback generation. Exact crash-boundary tests terminate after every durable
step and prove restart selects either the old complete pair or the new complete
pair, never a mixed or partial pair.

Rollback never moves a pointer backward. It selects previously validated
logical content, revalidates keys and fresh DNS, writes a new protected
registry manifest and datasource generation with a strictly higher number,
then performs the same publication protocol. Rollback has the same dry-run,
apply, expected-current, authorization, audit, redaction, concurrency, and
failure requirements as forward publication.

## Security And Privacy

The protected data set includes LDAP DNs, bases, filters, attributes, cookies,
bind identities, endpoints, referrals, backend errors; PostgreSQL addresses,
database/schema/table/column names outside committed DDL, SQL, parameters,
cursors, transactions, server identities, driver errors; provider records,
domains, selectors, tenants, profiles, handles, feedback routes, validity
times, registry locations, public-key bytes and digests; all credentials,
private keys, tokens, CAs, config values, and raw DNS text.

None may appear in runtime errors, wrapped errors, formatting, marshaling,
logs, traces, metrics, REST, CLI, reports, panic recovery, or test failure
text. Public committed schema and DDL documentation is not permission to emit
live object names or values. Backend errors are classified at their owning
boundary and never wrapped verbatim. Panic recovery produces only
`internal_invariant`.

Transport and query behavior is restrictive:

- verified TLS and explicit server identity are mandatory;
- credentials come only from protected files or descriptors;
- no anonymous LDAP, referral chase, dynamic filter concatenation, dynamic
  SQL, arbitrary DSN, environment fallback, multi-endpoint failover, hidden
  retry, or stale serving;
- every backend call uses the original bounded context;
- sizes, pages, responses, records, loops, cursors, cookies, strings, SPKI,
  private keys, reports, and concurrency are hard-bounded;
- all arithmetic is checked;
- ambiguous or indeterminate state fails closed.

## Observability

Observation uses the central daemon runtime only. Library wrappers construct no
exporter or global state. Allowed low-cardinality facts are:

- provider kind: `flat_file`, `ldap`, or `postgresql`;
- operation class: initial load, refresh, resolve, inventory, key validation,
  DNS proof, staging, publication, rollback, shutdown;
- provider state: initializing, ready, degraded, or closed;
- closed datasource/result/error class;
- duration, record, page, response, and byte buckets;
- dry-run/apply boolean;
- TLS/auth/isolation/publication phase as a closed class.

Raw or hashed identities are not Prometheus labels. Generation numbers,
endpoints, DNs, domains, selectors, handles, tenants, database objects,
queries, cookies, cursors, DNS data, key material, report IDs, and raw errors
are forbidden from default logs, traces, and metrics. No new debug module is
required. If one is proposed, this spec must first define its bounded,
deployment-local, secret-safe contract.

## Required Tests

### Unit and contract tests

- public bridge delegates every validation and error rule to the internal
  datasource owner and introduces no backend-specific type or dependency;
- exact identity, no fallback, immutable values, zero-result failure matrix,
  generation ordering/overflow, narrowed limits, typed-nil and panic handling;
- LDAP attribute/OID/class exactness, duplicate/unknown/multivalue fields,
  canonical values, SPKI bytes, metadata fence, filters, DN construction, and
  response accounting;
- RFC 2696 boundaries including small/empty pages, repeated opaque cookies,
  completion, response exhaustion, abandonment, discarded connections, and
  cancellation at every boundary;
- PostgreSQL fixed statements, parameter binding, keyset progress, full
  uint64 conversion, isolation proof, snapshot fence, cursor progress,
  transaction completion, and cancellation at every boundary;
- lifecycle initial failure, refresh preflight, serialized refresh,
  linearized degradation, no stale serving, recovery, terminal generation,
  leases, shutdown, and panic containment;
- config source precedence, conditional fields, env expansion, missing
  variables, protected-file checks, redaction, and stable flat-file behavior;
- migration inventory, domain disagreement, duplicates, inactive history,
  AUID/timestamp nonmapping, explicit-plan closure, dry-run nonmutation,
  private-key validation, DNS states, registry matching, publication fencing,
  idempotence, rollback, crash steps, and concurrent attempts.

### Shared provider parity

One shared synthetic corpus and normalized harness runs against memory,
flat-file, LDAP, and PostgreSQL. It proves identical complete results and
codes for successes, exact case behavior, invalid request, not found,
inactive, limit, cancellation, and deadline. Construction/load cases prove
ambiguous and malformed data. Network lifecycle cases additionally prove
unavailable/degraded/recovery. Results are immutable and race-safe, and every
failure is zero-valued.

### Disposable integration

Pinned digest-addressed OpenLDAP and PostgreSQL fixtures prove:

- schema/DDL installation and clean validation;
- least-privilege runtime and separate publisher/import roles;
- exact-limit and one-over datasets;
- paging/keyset boundaries and hostile progress;
- stable snapshot under concurrent writer;
- duplicate/dangling/partial/mixed/unsupported-version data;
- strict TLS, wrong CA/name, auth denial, pool exhaustion, disconnect,
  server limit, transaction abort, serialization conflict, and cancellation;
- current fence changes, generation rollback/overflow, refresh degradation and
  recovery, concurrent publishers, crash boundaries, and no stale serving;
- complete provider and registry generation agreement.

Synthetic legacy fixtures include one and two active algorithms, rotation
history, domain disagreement, missing key, duplicate selector, duplicate
active algorithm, unsupported key type, invalid key, toxic values, and
oversized inputs. No live directory, key, domain, or credential enters tests.

### Signing integration

- provider resolution and registry binding finish before routing or private
  signing;
- fresh DNS publication proof occurs before the private signing callback;
- migration DNS proof does not bypass signing-time proof;
- every provider, registry, plan, migration, and DNS denial has no partial
  header, recipe, custody, signature, release, route, datasource publication,
  or registry activation side effect.

### Fuzz, race, privacy, and dependencies

Add closed first-party fuzz owners for LDAP record/control mapping, SQL row and
generation mapping, public dataset bridge input, migration plan/report, and
legacy record mapping. Run affected fuzz targets for at least 10 seconds after
the last edit and add them to the M19 inventory. Run focused and full race
tests, hostile provider stress, toxic-marker privacy, module boundary,
generated/vendor, license, and vulnerability checks.

Dependency checks prove:

- no LDAP/SQL driver or service dependency enters `lib`;
- datasource core does not import signing;
- the sole signing projection remains the only datasource/signing bridge;
- protocol, Milter, Exim, OpenAPI, and replay packages do not import concrete
  datasource providers;
- no replay operation or SQL-backed replay store was introduced.

### Documentation and final gates

Required durable artifacts include schema, DDL, config examples, provider
guide, migration/rollback runbook, security/ACL/role guidance, package docs,
architecture completion history, reference capability/limitation updates, and
Make/CI help. Generated OpenAPI code remains byte-identical unless the durable
OpenAPI authority is revised first.

Required final commands include repository-owned equivalents of:

```text
make check-datasource-schema
make test-datasource-ldap
make test-datasource-postgresql
make test-datasource-parity
make test-opendkim-bootstrap
make check-conformance
make check-security
make check-reference
make test
make vet
make lint
make race
make guardrails
```

Every skipped platform or container check needs an exact reason and cannot
support a production-ready claim. Final approval requires the disposable
OpenLDAP/PostgreSQL and migration gates on the unchanged candidate.

## Acceptance Criteria

- The library contains no LDAP or SQL driver and the daemon imports no
  `lib/internal` package.
- The public bridge reuses, rather than duplicates, the storage-neutral
  datasource validators and signing projection.
- `rnsdkim2.schema` contains exactly the 17 reserved attribute OIDs and five
  reserved object-class OIDs with the specified contracts and passes
  reproducible `slaptest`.
- The PostgreSQL DDL preserves the full nonzero uint64 generation range,
  exact uniqueness/cross-reference rules, read-only runtime role, committed
  immutability, and transactionally atomic current publication.
- LDAP and PostgreSQL loaders are deadline-bound, finite, authenticated,
  verified, cancellation-aware, no-retry, exact-generation, and fail closed.
- A post-linearization refresh failure makes resolves/readiness unavailable;
  no retained stale snapshot is served.
- Memory, flat-file, LDAP, and PostgreSQL pass the same logical parity corpus.
- Runtime datasource generation and protected registry generation must match
  before readiness and signing.
- Inventory never requests private keys; protected import never emits them.
- `DKIMDomain != associatedDomain` is rejected; `DKIMIdentity` and LDAP
  timestamps are not mapped.
- Every active credential has a fresh unique DNS/SPKI proof before
  publication and again at signing time.
- Dry-run mutates nothing and emits only bounded counts and closed classes.
- Forward publication and rollback activate either one complete pair or none;
  rollback always uses a higher generation.
- Observability and all operator surfaces are low-cardinality and secret-safe.
- OpenAPI wire behavior remains unchanged.
- All reference documents stop claiming LDAP/SQL/migration is deferred only
  after the exact implementation and evidence are complete.
- Independent review finds no unresolved issue, all required gates pass on one
  unchanged snapshot, `temp/` remains ignored/unstaged, and the milestone is
  delivered by one project-formatted commit.

## Completion Evidence

Fill after implementation:

- candidate identity: recorded in the ignored execution ledger after the final
  unchanged-snapshot gate, avoiding a self-referential durable digest.
- schema and DDL identities: LDAP
  `5ac1f3fbce3e1cec8983a50dd22b5a1263cb7680a49e189ccafce8510428add8`;
  PostgreSQL
  `e07c674206a8482fd90ed7207384a8b77feafba16ed72dcf8fcf2f9a84017741`.
- focused unit/fuzz/race results: exact commands and outcomes are recorded in
  the ignored execution ledger.
- OpenLDAP integration: the exact pinned image, two disposable runs, negative
  transport/authentication/name/cancellation cases, and normalized report
  identity are recorded in the ignored execution ledger.
- PostgreSQL integration: the exact pinned image, two disposable runs,
  runtime-role denial, committed immutability, transport/authentication/name
  denials, and normalized report identity are recorded in the ignored
  execution ledger.
- provider parity: memory, flat-file, LDAP, and PostgreSQL use the shared
  normalized parity corpus.
- migration dry-run/import/DNS/publication/rollback: unit, race, fault,
  concurrency, exact-readback, and disposable-service evidence is recorded in
  the ignored execution ledger.
- config/Fx/readiness: typed config, protected inputs, initial load, no-op
  revalidation, degraded state, higher-generation recovery, lease retirement,
  and shutdown are covered by unit and race gates.
- privacy/dependency/generated/reference checks: secret-safe reports,
  dependency boundaries, unchanged OpenAPI bytes, reproducible vendoring, and
  reference evidence are required by the final gate and recorded in the
  ignored execution ledger.
- `make guardrails`: exact unchanged-snapshot result is recorded in the
  ignored execution ledger.
- independent reviewer approval: finding-first review and approval are
  recorded in the ignored execution ledger.
- orchestrator approval: the separate second approval is recorded in the
  ignored execution ledger before commit.
- `git status --short`: exact durable scope, empty index, ignored evidence, and
  deferred Exim stash proof are recorded in the ignored execution ledger.
- skipped checks and reason: none.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Bridge | Service-owned providers reuse one storage-neutral library owner | Public provider bridge over authoritative datasource constructors | complete | No concrete driver or backend DTO enters `lib` |
| LDAP schema | Exact 17 attributes, five classes, layout, indexes, ACL, `slaptest` | Exact allocation and deployable schema bundle | complete | Host and disposable OpenLDAP validation |
| LDAP runtime | Bounded verified paged snapshot and degraded recovery | Verified TLS, fixed projection, exact paging/fence, finite snapshot lifecycle | complete | Referrals, hostile BER lengths, stale and malformed generations fail closed |
| PostgreSQL DDL | Full-generation constraints, roles, immutability, publication | Transactional DDL, split roles, immutable committed generations, forward-only current | complete | Real role and transition denials included |
| PostgreSQL runtime | Repeatable-read keyset snapshot and degraded recovery | Typed connection, read-only transaction, fixed keyset queries, final fence | complete | Environment/service/password fallback rejected |
| Daemon | Typed config, protected credentials, Fx, readiness, lifecycle | Stable conditional config and generation-joined signer/provider lifecycle | complete | Same-generation revalidation and higher-generation recovery covered |
| Parity | Memory, flat-file, LDAP, PostgreSQL shared behavior | One normalized shared corpus | complete | Unit/race plus real network providers |
| Inventory | Bounded read-only secret-safe legacy observation | Fixed public-only projections and closed report classes | complete | Private-key attribute is never requested |
| Migration | Explicit mapping, protected import, fresh DNS proof, no partial activation | Offline safe-default command with exact staging/readback and DNS/SPKI proof | complete | Dry-run and failure steps preserve nonmutation |
| Rollback | Higher immutable generation and crash/concurrency proof | Shared strictly-forward publication protocol | complete | At most one exact-current publisher wins |
| Privacy | No protected identity, backend, query, key, or raw error emission | Closed reports, logs, traces, labels, and diagnostics | complete | Toxic fixtures and report schemas covered |
| Boundaries | No drivers in lib, no replay/OpenAPI/adapter leakage | Concrete providers and compatibility fork remain daemon-owned | complete | OpenAPI wire bytes unchanged |
| Documentation | Schema/DDL/config/operator/reference claims are current | Design, operator, migration, reference, and supply-chain docs updated | complete | No deferred-only LDAP/SQL claim remains |
| Gates | Full disposable integration, security, reference, and guardrails pass | Exact outcomes and evidence identities recorded in ignored ledger | complete | Required on one unchanged final snapshot |
| Effort | Prompt timings and exact evidence identities recorded | Per-prompt timings, findings, fixes, hashes, and approvals in ignored ledger | complete | Durable spec avoids self-referential candidate hash |

## Decisions And Open Questions

- Settled: the active behavior baseline is Draft-04 plus historical DNS-04.
- Settled: the first SQL backend is PostgreSQL; no generic ORM or dynamic SQL
  surface is added.
- Settled: LDAP and PostgreSQL are daemon-owned concrete providers and use a
  narrow public library bridge because Go's `internal` rule prevents direct
  command-module access.
- Settled: the LDAP schema uses exactly 17 new attributes and five new object
  classes; standard `cn` is storage-only and no sixth class or eighteenth
  attribute is allocated.
- Settled: validity is canonical RFC3339Nano IA5 text, not LDAP Generalized
  Time.
- Settled: runtime providers are read-only; mutation exists only in the
  separate administrative bootstrap/publication path.
- Settled: migration is a local offline `dkim2d` command and does not change
  OpenAPI or `dkim2ctl`.
- Settled: inactive legacy history is skipped by default; no identity or
  validity fact is inferred.
- Settled: the datasource current pointer is the activation boundary because
  generation-specific protected registry material is installed inertly first.
- Settled: rollback republishes under a higher generation.
- Open: none. Implementation findings that require a semantic change must
  amend this specification before the change.
