# Native Datasource Private-Key Custody

Status: complete.

This specification moves DKIM2 signing-key custody for the LDAP and
PostgreSQL datasource backends into the selected datasource generation. It
keeps flat-file custody available only for the flat-file backend, removes the
network-backend dependency on a local private-key manifest, and preserves the
existing signing, Milter, and REST contracts.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`;
- `docs/datasource-ldap-sql-design.md`;
- `docs/specs/implementation/ldap-sql-datasource-legacy-migration.md`;
- `docs/specs/implementation/signing-and-revision.md`;
- `docs/specs/implementation/observability-foundation.md`;
- `docs/specs/spec-and-prompt-template.md`;
- `docs/specs/openapi/dkim2d.yaml` as an explicitly unchanged boundary;
- `draft-ietf-dkim-dkim2-spec-04`;
- `draft-chuang-dkim2-dns-04` for the implemented DNS behavior baseline;
- RFC 4511, RFC 4512, RFC 4513, RFC 4515, RFC 4517, RFC 4519, RFC 2696,
  and RFC 4528 for LDAP behavior;
- PostgreSQL transactional, privilege, constraint, and trigger semantics;
- `Makefile` and the repository guardrails.

This specification deliberately supersedes the earlier local policy that
LDAP and PostgreSQL store only public material. The DKIM2 protocol does not
dictate private-key storage. Native datasource custody is an operator security
and rotation policy implemented exclusively in the daemon provider layer.

## Original Gap

The LDAP and PostgreSQL loaders currently fence and load public dataset rows,
then join them to a matching private-key registry under
`signing.private_manifest_file`. This makes a network generation incomplete
without a separately staged local filesystem generation. The offline
OpenDKIM bootstrap tool must therefore coordinate DNS, a protected local key
tree, and the administrative datasource.

That split prevents the datasource publisher from owning an atomic rotation
unit. It also conflicts with deployments where LDAP or SQL is the intended
security-zone boundary for exportable signing keys and the DKIM service should
receive only the generation it is currently authorized to use.

The normal REST API has no key-management endpoint and must not acquire one.

## Goal

For LDAP and PostgreSQL, one committed immutable generation contains both the
public datasource projection and the exact private key material needed by its
opaque handles. A loader obtains both through one authenticated backend
session and one fenced generation snapshot, validates all relationships and
public/private key equivalence, builds an in-memory signer registry, and only
then makes the generation ready.

Private keys are canonical unencrypted PKCS#8 DER values. Encryption at rest,
backup protection, transport protection, principal lifecycle, and audit are
owned by the LDAP or PostgreSQL operator. The daemon never exposes key bytes
through REST, CLI output, logs, traces, metrics, errors, reports, or tests.

## Delivery Shape

1. Define the native key-material model and an in-memory registry constructor.
2. Add versioned LDAP schema, mapping, paging, loader, and publisher support.
3. Add versioned PostgreSQL DDL, mapping, paging, loader, and publisher support.
4. Make protected config and application composition backend-specific.
5. Extend bootstrap, publication, and higher-generation rollback so key
   material is committed in the datasource after fresh DNS/SPKI proof.
6. Update operator documentation, Mailstack schema and ACLs, migrate the live
   deployment, and prove signing, replication, queues, and rollback readiness.
7. Run an independent finding-first audit and close every in-scope defect.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 8-16 hours including production rollout |
| Highest-risk area | secret-safe immutable publication and live LDAP migration |
| Expected prompt count | 8 |
| Required final gate | `make guardrails` plus live Mailstack proofs |

Risk notes:

- Low risk: the REST, Milter, and DKIM2 protocol contracts remain unchanged.
- Medium risk: backend-specific configuration and removal of the local
  manifest requirement for network backends.
- High risk: hostile key payloads, memory clearing, publisher crash boundaries,
  LDAP ACL correctness, SQL privileges, and concurrent generation activation.
- Highest risk: migrating a live replicated LDAP schema and activating a new
  generation without exposing or partially publishing private material.

Measured effort is filled during closeout:

| Work Pack | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| Prompts 01-08 | 2026-08-01T10:50:31+02:00 | 2026-08-01T13:06:23+02:00 | 2h 15m 52s | not independently metered | Executed as one continuous implementation and production rollout; prompt boundaries were interleaved and no separate active-time clock was recorded. |

## Scope

In scope:

- native private-key custody for LDAP and PostgreSQL datasource generations;
- canonical PKCS#8 DER validation for RSA and Ed25519 keys;
- exact tenant, domain, profile-use, handle, algorithm, and public-SPKI binding;
- LDAP schema attribute/object-class allocation and generation subtree layout;
- PostgreSQL table, constraints, immutable-generation triggers, roles, and grants;
- bounded loader and publisher support in the existing datasource lifecycle;
- backend-specific configuration validation and protected-secret handoff;
- offline bootstrap and rollback publication after fresh DNS/SPKI proof;
- Mailstack OpenLDAP schema, ACL, runtime configuration, migration, and rollout;
- secret-safe documentation, tests, observability, and production evidence.

Out of scope:

- changes to `opendkim-manage-go`;
- REST or OpenAPI key-management endpoints;
- remote signing APIs, HSM, PKCS#11, KMS, or non-exportable key handles;
- automatic key generation or DNS mutation by the online daemon;
- weakening DKIM2 verification, signing, Milter, TLS, or datasource policy;
- accepting legacy OpenDKIM attributes during normal runtime loading.

## Runtime And Datasource Semantics

The datasource schema identifier becomes `dkim2-datasource-v2`. Version 1 is
not accepted by a native-custody network loader. This prevents silent startup
against a generation that contains no native key material.

Each key-material record contains exactly:

- generation;
- tenant identifier;
- canonical signing domain;
- profile use;
- opaque handle identifier;
- algorithm;
- canonical public SPKI DER;
- canonical unencrypted private-key PKCS#8 DER.

Every active credential selected by a policy must have exactly one matching
key-material record. Every key-material record must match exactly one declared
handle and credential. Duplicate handles, policies, bindings, keys, or
public/private mismatches are malformed data. Unknown attributes, algorithms,
uses, noncanonical PKCS#8, oversized values, missing keys, surplus keys, mixed
generations, or a moving current pointer fail closed before readiness.

The in-memory registry owns copied key values and clears retained private key
material on every failure and on close. Backend row or entry buffers are
cleared after registry construction. Signing never performs backend I/O.

LDAP layout adds `ou=key-material` below each immutable generation root. The
new `dkim2PrivateKeyPKCS8` octet-string attribute is single-valued and is used
only by `dkim2KeyMaterial`. Paging, byte, entry-count, and deadline limits apply
to key entries as they do to public records, with private bytes included in the
aggregate limit.

PostgreSQL adds `dkim2_datasource.key_material`. It participates in the same
read-only repeatable-read transaction and the same immutable-generation
triggers. The runtime role receives only `SELECT`; the publisher receives only
the fixed privileges required to stage and activate higher generations.

Publication stages and validates the complete generation before changing the
current pointer. A crash before pointer activation leaves only an unreachable
staging or committed generation. A pointer never moves backward. Rollback
copies prior logical public and private content into a strictly higher
generation and re-runs required DNS/SPKI proof.

No normal runtime path reads `DKIMKey`, legacy selector attributes, a local
network-backend manifest, or any fallback provider. The existing OpenDKIM
inventory is permitted only as an explicit offline bootstrap input.

## Package Boundaries

- `lib/`: unchanged DKIM2 protocol and provider-neutral dataset behavior.
- `cmd/dkim2d/internal/signingstore`: owns strict PKCS#8 parsing, in-memory
  signer construction, key destruction, and opaque signing.
- `cmd/dkim2d/internal/datasource/ldap`: owns LDAP entry mapping, paging,
  fenced loading, and construction of the native registry.
- `cmd/dkim2d/internal/datasource/postgresql`: owns SQL row mapping, keyset
  paging, stable-snapshot loading, and construction of the native registry.
- `cmd/dkim2d/internal/migration`: owns offline import, DNS proof, complete
  publication, and higher-generation rollback.
- `cmd/dkim2d/internal/config` and `internal/app`: own backend-specific
  protected configuration and lifecycle wiring.
- `cmd/dkim2-milter`, `cmd/dkim2ctl`, and OpenAPI-generated code: unchanged.

Provider-specific rows, entries, credentials, and drivers must not leak into
`lib/` or generated REST DTOs.

## Security And Privacy

Verified TLS, explicit authentication, caller deadlines, bounded connections,
and least-privilege principals remain mandatory. Anonymous bind, unverified
TLS, environment-derived SQL configuration, provider chaining, retry fallback,
and stale-generation serving remain forbidden.

The LDAP ACL must deny the private-key attribute to anonymous users, ordinary
directory readers, public migration readers, monitoring, and replication
consumers that do not require the signing dataset. Only the dedicated DKIM2
runtime principal, the publisher principal, and the minimum replication path
may read it. Schema/config database administrators retain unavoidable control.

Datasource and database backups now contain signing keys and must be treated as
key backups. The live migration requires a restorable pre-change snapshot,
controlled maintenance, protected secret handling, and rollback evidence.

Private keys, bind/database passwords, raw LDAP entries, SQL rows, LDAP DNs
derived from protected identities, key digests usable as correlators, and key
counts by tenant/domain must never appear in logs, traces, metrics, errors,
REST, CLI output, reports, or test failure messages.

## Observability

Existing datasource backend, lifecycle state, operation class, and bounded
error-class observations may remain. No new label or trace attribute may carry
a domain, tenant, handle, selector, DN, SQL value, generation contents, key
size, key fingerprint, or private-material fact. Readiness becomes false on
any incomplete or invalid native key generation.

## Required Tests

Unit tests:

- canonical PKCS#8 parsing, algorithm match, public-SPKI match, duplicate and
  surplus key rejection, close-time destruction, and secret-safe formatting;
- LDAP exact-attribute mapping, paging, size limits, generation fencing,
  missing/surplus/malformed keys, and connection cleanup;
- PostgreSQL row mapping, keyset paging, transaction fencing, missing/surplus/
  malformed keys, commit/rollback cleanup, and query-shape tests;
- config acceptance for native network custody and rejection of local manifest
  paths on LDAP/PostgreSQL;
- complete publication, concurrent-writer conflict, crash boundary, and
  higher-generation rollback tests including key material;
- privacy tests for formatting, JSON, errors, logs, traces, metrics, reports,
  and failing fixtures.

Integration or E2E tests:

- disposable OpenLDAP schema, ACL, publish, load, rotate, and denial proof;
- disposable PostgreSQL DDL, roles, publish, load, rotate, and denial proof;
- daemon signing with a native backend and no mounted private-key manifest;
- Mailstack live provider/consumer schema and replication proof, real outbound
  signing and external verification, queue health, restart recovery, and
  higher-generation rollback readiness.

Generated and documentation checks:

- schema/DDL drift checks and operator examples;
- OpenAPI unchanged/stale-output checks;
- container/rendered Mailstack configuration checks;
- architecture and migration documentation reconciled with native custody.

Final gates:

- focused datasource, migration, config, and app tests;
- `make guardrails`;
- Mailstack render, schema, ACL, compose, and hygiene guardrails;
- controlled production rollout proofs.

## Acceptance Criteria

- LDAP and PostgreSQL start and sign without `signing.private_manifest_file`.
- A network backend refuses v1, absent, duplicate, surplus, malformed, mixed,
  or public/private-mismatched key material before readiness.
- One publisher operation owns public data and key material and activates only
  a complete higher generation after DNS/SPKI proof.
- The normal REST/OpenAPI surface has no key-management operation.
- Mailstack LDAP stores the active DKIM2 keys under the v2 native schema with
  restrictive ACLs and the local key mount removed from DKIM2 runtime.
- Provider/consumer schema and replication, live signing verification, queues,
  restart recovery, backup, and rollback readiness are proven.
- Access credentials used for the rollout are rotated and the maintenance
  window is removed with evidence.
- `opendkim-manage-go` is unchanged.
- All guardrails pass and no protected material is present in Git or output.

## Completion Evidence

- Focused tests: LDAP, PostgreSQL, signing-store, configuration, application,
  publication, migration, rollback, privacy, and race tests passed. The LDAP
  publication-fence reproducer failed before the fix and passes afterward.
- Generated checks: OpenAPI remained unchanged; datasource schema, migration,
  OpenDKIM-bootstrap, image-publication, and Mailstack render checks passed.
- Guardrails: all module vet and lint checks passed with zero findings, and all
  product-module tests passed. The repository-wide `make guardrails` run then
  stopped in the pre-existing fixed reference-snapshot checks
  `TestBuildPrivateProxyIsDeterministicAndConfined` (`module_base`) and
  `TestCurrentSnapshotRequiresTheFixedBaseAndEmptyIndex` (`security_base`).
  The release authority was deliberately not rewritten as part of this
  datasource change.
- Live rollout: Provider and consumer expose committed
  `dkim2-datasource-v2` generation 3. The runtime principal sees 58 native key
  records; the inventory principal sees no private-key values. All four
  digest-pinned DKIM2 services load without a local manifest and remain
  healthy with zero restarts across refresh cycles.
- Mailflow: one DKIM2 field contained RSA-SHA256 and Ed25519-SHA256 signature
  sets, and a byte-preserving inbound MX loop produced `dkim2=pass`. Submission,
  MX, and relay queues were empty; both OpenDKIM services remained at `1/1`.
- Key-path closure: the active protected generation contains only the two
  capabilities, LDAP CA, and LDAP password. Three prior filesystem key
  generations and the former migration registry were moved into the exact
  root-only rollback archive.
- Operational safety: KVM snapshot and provider/target backups were retained,
  provider support credentials were rotated and verified, and no protected
  value entered Git, logs, reports, or command output.
- `git status --short`: clean after the implementation and publication-fence
  commits; this specification closeout is the only subsequent DKIM2 change.
- Skipped checks: none in scope. The two fixed release-snapshot failures above
  are recorded gate exceptions, not skipped checks.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Native LDAP/SQL custody; no OpenDKIM manager work | LDAP and PostgreSQL delivered; `opendkim-manage-go` untouched | done | Flat-file custody remains local by design. |
| Behavior | Atomic v2 generation contains public and private material | Complete immutable publication with atomic schema/generation fence | done | Live provider and consumer are committed at generation 3. |
| Tests | Unit, disposable integration, and live proofs exist | Focused, race, schema, render, and production mailflow proofs passed | done | Two unrelated fixed release-snapshot checks remain as documented above. |
| Security | Least privilege, fail closed, and secret safe | Attribute ACL split, TLS, exact principals, bounded loaders, key clearing, and protected backups proved | done | Inventory access to private values is denied. |
| Boundaries | No REST or protocol model leakage | OpenAPI unchanged; generated DTOs and protocol packages do not own key custody | done | No key-management endpoint was added. |
| Effort | Prompt timings are measured | Continuous wall-clock interval recorded; per-prompt active time was not instrumented | done | No unsupported precision is claimed. |

## Decisions And Open Questions

- Settled: LDAP and SQL use canonical unencrypted PKCS#8 DER inside the
  immutable generation.
- Settled: normal REST and OpenAPI remain unchanged.
- Settled: LDAP/SQL do not accept a local private manifest or legacy runtime
  fallback.
- Settled: flat-file retains its protected local manifest contract.
- Settled: the online daemon reads keys but never creates, rotates, publishes,
  or returns them.
- Settled: an established LDAP publication upgrades the current schema and
  generation under one committed v1-or-v2 assertion; changing only the
  generation would create a mixed metadata fence and is forbidden.
- Settled: `opendkim-manage-go` is a separate future repository change.
- Open: none that blocks implementation; exact live ACL principal names are
  resolved from the rendered Mailstack and current provider configuration.
