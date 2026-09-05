# Signing Datasource Backend Operations

For provisioning a new native signing domain, use the offline workflow in
[`docs/operator/native-domain-onboarding.md`](native-domain-onboarding.md).
It composes the v3 schema and grants documented here; direct LDAP or SQL edits
are not an onboarding substitute.

This is the canonical operator guide for `dkim2d` signing datasources. The
daemon selects exactly one signing backend. Replay storage is an independent
choice and is documented separately in
[`replay-store-valkey.md`](../replay-store-valkey.md).

The storage-neutral field model and failure semantics are defined in
[`datasource-ldap-sql-design.md`](../datasource-ldap-sql-design.md). LDAP object
classes, attributes, tree layout, and legacy isolation are explained in
[`ldap-schema-reference.md`](ldap-schema-reference.md). Initial OpenDKIM import
is documented in [`opendkim-migration.md`](opendkim-migration.md), while normal
generation replacement and key retirement are documented in
[`datasource-key-rotation.md`](datasource-key-rotation.md).

## Backend Selection Matrix

| `signing.backend` | Key custody | Runtime source | Publication authority | Intended use |
| --- | --- | --- | --- | --- |
| `disabled` | none | none | none | verification-only daemon |
| `flat_file` | protected local PKCS#8 children | confined `dkim2-datasource-v1` JSON plus private manifest | offline filesystem publisher | static or small deployment |
| `ldap` | native LDAP `dkim2PrivateKeyPKCS8` | one complete committed `dkim2-datasource-v2` or `dkim2-datasource-v3` subtree | separate snapshot, stager, and activator roles; isolated legacy v2 publisher | directory-backed production signing |
| `postgresql` | native `key_material.private_key_pkcs8` | one complete committed `dkim2-datasource-v2` or `dkim2-datasource-v3` transaction snapshot | separate snapshot, stager, and activator roles; isolated legacy v2 publisher | PostgreSQL-backed production signing |
| `mysql` | native `dkim2_key_material.private_key_pkcs8` | one complete committed `dkim2-datasource-v2` or `dkim2-datasource-v3` transaction snapshot | separate snapshot, stager, and activator accounts; isolated legacy v2 publisher | MySQL or MariaDB production signing |

MariaDB uses the exact `mysql` selector, configuration subtree, driver, schema
contract, and telemetry provider kind. The daemon has no generic DSN backend,
provider chain, automatic fallback, read replica, or key-management REST API.
The in-memory datasource implementation is a library reference provider and is
not a selectable `dkim2d` signing backend.

All network backends keep the provider-specific private bytes inside the daemon
adapter. The loader validates each private key against its public SPKI,
algorithm, opaque handle, tenant, domain, use, and generation before publishing
an in-memory signer. Signing itself performs no backend I/O. Flat-file is the
only backend with a local private manifest.

## Flat-File And Disabled Operation

Signing is disabled unless an operator explicitly selects a backend and
installs at least one route capability. Disabled signing loads no datasource or
private key.

Flat-file operation requires the datasource JSON, private manifest, and every
referenced PKCS#8 child below the same protected generation as the daemon
capabilities. The exact formats, ownership, modes, link-count checks, reload
behavior, and complete example are in
[`cmd/dkim2d/README.md`](../../cmd/dkim2d/README.md#flat-file-signing-and-revision).
Never mount those local key files for a network backend.

## LDAP Installation

1. Back up the configuration database and DKIM2 data suffix through the site's
   normal encrypted directory backup path.
2. Install [`rnsdkim2.schema`](../../contrib/schema/ldap/rnsdkim2.schema). Its
   allocation under `1.3.6.1.4.1.31612.1.7` is permanent: 23 attributes and
   eight object classes, including native private-key custody, v3 publication
   metadata, and the revisioned administration lock.
3. Adapt only the suffix in [`layout.ldif`](../../contrib/schema/ldap/layout.ldif)
   and add the empty `ou=dkim2` base with `dkim2AdministrationLock` and
   `dkim2AdminRevision: 1`, plus the empty `ou=generations` container. Do not
   create `cn=current`, a zero generation, a partial generation, or a
   hand-written key entry. The offline publication authority owns first
   publication.
4. Adapt the exact service DNs and suffix in
   [`acl.conf`](../../contrib/schema/ldap/acl.conf). Keep the private-attribute
   rule before the public datasource rule. Runtime receives read-only access to
   exact complete committed native v2 or v3 public and private data. Use
   separate snapshot, stager, and activator identities: snapshot is read-only;
   stager owns only the revisioned lock, inactive v3 staging/seal, and the
   closed read projections it requires; activator owns only monotonic
   was-active evidence and `cn=current`. The isolated legacy publisher retains
   only its exact v2 publication rights. Every other principal is denied native
   private key material.
   Grant any legacy `DKIMKey` import right only on the separate OpenDKIM source
   directory described by the migration runbook; it is not part of this native
   target ACL.
5. Add the performance-only equality indexes from
   [`indexes.conf`](../../contrib/schema/ldap/indexes.conf). Do not index private
   key bytes.
6. Validate the complete rendered server configuration with `slaptest -u`
   before restart, then bind separately as runtime, snapshot, stager,
   activator, legacy publisher, anonymous, monitoring, and an ordinary reader.
   Prove each documented positive and negative ACL outcome without printing
   returned key values.

LDAP transport is exactly authenticated `ldaps` or StartTLS with an explicit
address, separate verified server name, private CA, and one exact bind identity
per configured role connection.
Administrative role DNs use only simple RDNs in the exact sequence `cn`, one or
more `ou`, then one or more `dc`. Descriptors and values must be lowercase
ASCII; each value is a 1-to-63-byte letter-digit-hyphen label without a leading
or trailing hyphen, and the raw DN must match that reconstruction byte for
byte. OID or descriptor aliases, case changes, whitespace, escapes, Unicode,
multivalued RDNs, and other attribute types are not normalized and receive no
administration authority. This closed grammar deliberately makes no
schema-free claim about general LDAP DN equivalence. General runtime and legacy
migration connectors may still use another syntactically valid bind DN, but
they can never be supplied to `NewAdministrator`: it rejects their invalid
opaque authority or pairwise-equal snapshot, stager, and activator authorities
before LDAP I/O.
Each connector privately clones its configured password and CA trust pool, so
later caller mutation cannot change its authority or transport trust.
Anonymous bind, plaintext transport, referral following, alternate endpoints,
automatic failover, and a request-derived search base are unsupported.

An existing v1 schema installation is upgraded in place by installing the new
attribute and object class definitions before publishing the first complete v2
generation through the legacy migration publisher. LDAP runtime loading accepts
an exact complete committed v2 or v3 generation and rejects v1, mixed-version,
partially sealed, or missing native-key state. Native v3 administration stages
an inactive generation, seals it to committed, and changes only the current
pointer and monotonic old-current history under the documented assertions.

## PostgreSQL Installation

Fresh installations apply
[`001_dkim2_datasource.sql`](../../contrib/schema/postgresql/001_dkim2_datasource.sql)
and every ordered forward migration through
[`006_campaign_source_binding.sql`](../../contrib/schema/postgresql/006_campaign_source_binding.sql)
through a schema administrator. Existing v1 installations apply
[`002_native_key_custody.sql`](../../contrib/schema/postgresql/002_native_key_custody.sql),
then publish a complete higher v2 generation before restarting a v2 daemon.

The DDL creates runtime, compatibility-publisher, snapshot, staging, and
activation `NOLOGIN` roles. Create separate TLS-authenticated login roles
through the site's credential workflow and grant each login exactly one role.
Runtime receives read-only dataset access. The legacy publisher remains v2-only.
The five isolated lifecycle roles, including purge and the terminal-only closer,
invoke narrow fixed-search-path
`SECURITY DEFINER` lock primitives and receive no direct access to the
singleton lock table. Snapshot only observes; staging may physically lock,
claim, release, and write inactive v3 content under RLS; activation may
physically lock the singleton and exact committed candidate root, then perform
the fenced current transition. The candidate lock is bound to generation,
operation, digest, and claimed administration revision. The only nonowner
grantee of `candidate_root_for_update(generation_number,text,bytea)` is the
activation role; the function has a fixed
`search_path=pg_catalog, dkim2_datasource`. Audit all nine administration
definer primitives for exact owner, kind, signature, `SECURITY DEFINER`, fixed
search path, and the closed 23 role/routine `EXECUTE` pairs. Also prove that a
direct activation-role `SELECT ... FOR UPDATE` of the candidate root returns no
authorized row under RLS. Any missing or additional primitive, grantee, or
PUBLIC execution authority is a deployment failure. This data-layer
contract does not claim completion or release of the onboarding CLI.

The runtime connection is one explicitly configured TCP authority using
`verify-full`. Arbitrary DSNs, service files, environment-selected libpq
defaults, password commands, multi-host fallback, and TLS downgrade modes are
unsupported.

## MySQL And MariaDB Installation

Fresh installations apply
[`001_dkim2_datasource.sql`](../../contrib/schema/mysql/001_dkim2_datasource.sql)
and every ordered forward migration through
[`006_campaign_source_binding.sql`](../../contrib/schema/mysql/006_campaign_source_binding.sql)
inside one dedicated database. The exact disposable qualification versions are
MySQL 8.4 and MariaDB 10.11; see the
[`compatibility statement`](../reference/compatibility.md#qualified-storage-services)
before assuming another release is supported.

Create distinct runtime, compatibility-publisher, snapshot, staging,
activation, purge, and terminal-only closer site accounts with exact source restrictions, mandatory TLS,
independently managed passwords, and no global privileges. Replace every
placeholder in
[`002_least_privilege_grants.sql.example`](../../contrib/schema/mysql/002_least_privilege_grants.sql.example),
review the rendered account expressions and database identifier, and only then
apply it. The required grants are:

| Principal | Dataset access | Definer procedures | Explicitly absent |
| --- | --- | --- | --- |
| runtime | read-only seven dataset tables | none | publication lock, writes, administration |
| compatibility publisher | read-only dataset plus lock observation and no-op `UPDATE (singleton)` for its v2 locking read | fixed v2 publication only | v3 lock metadata columns, v3 procedures, direct content-table DML |
| snapshot | read-only seven dataset tables | lock observation only | physical lock, claim/release, writes |
| staging | read-only seven dataset tables | observe, physical lock, claim/release, fixed v3 staging/seal | direct lock/content writes, activation |
| activation | read-only seven dataset tables | observe, physical singleton/current locks, exact candidate-root lock, fixed activation | claim/release, direct lock/content writes |
| purge | exact generation/current/receipt readback only | fixed v3 purge procedure only | direct table delete, lock/current mutation, staging, activation |
| closer | terminal evidence readback only | fixed v3 terminal-record procedure only | generation/current/lock mutation and staging/activation/purge |

The migration owner remains the fixed definer of the closed procedures. None
of the five isolated lifecycle accounts receives direct privilege on
`dkim2_publication_lock`; a locking read is performed by the narrow definer
primitive. Read back `TABLE_PRIVILEGES`, `COLUMN_PRIVILEGES`, the exact
per-routine `Execute` rows from `mysql.procs_priv`, and each routine definer
before deploying credentials.
The activation account's candidate-root authority is exactly
`dkim2_v3_lock_candidate_root`; the procedure locks only a committed v3 row
matching generation, operation, digest, and lock owner/revision. Audit the
closed routine allowlists and fixed migration-owner definer for both fresh and
v2-upgraded databases. Unexpected routines, grants, definers, or direct
candidate/lock-table mutation authority fail deployment.
Candidate-root absence or authoritative metadata mismatch is a conflict;
backend, cancellation, deadline, serialization, and deadlock failures are
unavailable. In particular, PostgreSQL candidate-root SQLSTATE `40001` and
`40P01` do not become optimistic conflicts.
Disposable concurrency qualification captures the exact activation connection
identities and proves the server-side waiter-to-holder edge before releasing
the lock holder. PostgreSQL uses `pg_blocking_pids`, MySQL 8.4 uses Performance
Schema data-lock waits joined through `PROCESSLIST_ID`, and MariaDB 10.11 uses
InnoDB lock waits joined through `trx_mysql_thread_id`. Observer credentials
exist only in the disposable harness; connection identities are not operator
output or telemetry.
This data-layer contract does not claim completion or release of the onboarding
CLI.

The daemon constructs its connector from typed fields. It enables verified TLS
1.2 or newer and does not enable local infile, multi-statements, interpolation,
compression, cleartext-password fallback, old-password fallback, server-key
retrieval, Unix sockets, or multi-host failover.

## Daemon Configuration

Complete configuration files are committed and parsed by the real typed
configuration loader during `make check-operator-docs`:

- [`dkim2d-signing-ldap.yaml`](examples/dkim2d-signing-ldap.yaml);
- [`dkim2d-signing-postgresql.yaml`](examples/dkim2d-signing-postgresql.yaml);
- [`dkim2d-signing-mysql.yaml`](examples/dkim2d-signing-mysql.yaml).

Copy one example, replace the reserved documentation endpoint and identities,
and retain the hierarchy. `signing.reload_interval` is common to every enabled
backend; it is not a child of `ldap`, `postgresql`, or `mysql`. The default is
30 seconds and the accepted range is 1 second through 1 hour.

Network providers use these backend-specific fields:

| Backend | Required fields | Optional bounded fields |
| --- | --- | --- |
| LDAP | `address`, `server_name`, `ca_file`, `transport`, `bind_dn`, `password_file`, `base_dn` | `page_size`, `load_deadline` |
| PostgreSQL | `address`, `server_name`, `ca_file`, `database`, `user`, `password_file` | `page_size`, `load_deadline`, `max_connections`, `idle_connections` |
| MySQL/MariaDB | `address`, `server_name`, `ca_file`, `database`, `user`, `password_file` | `page_size`, `load_deadline`, `max_connections`, `idle_connections` |

The YAML file and every selected protected object must satisfy the owner, mode,
link-count, filesystem, direct-child, and generation rules in
[`cmd/dkim2d/README.md`](../../cmd/dkim2d/README.md#protected-generation).
Network backends keep only capabilities, CA, and password files locally.
Supplying `signing.datasource_file` or `signing.private_manifest_file` with a
network backend is rejected.

Validate through the final runtime identity and mounts before activation:

```text
dkim2d validate --config /etc/dkim2d/config.yaml
```

Validation is silent on success and intentionally content-free on failure.

## First Publication

A newly installed target contains only its schema and empty base containers or
tables. The first offline plan uses `expected_current: "0"` and a nonzero
candidate generation. Zero is only an administrative assertion that both the
current pointer and all generation data are absent; it is never a runtime
generation.

LDAP staging claims the revisioned administration lock, builds and seals the
candidate without a current placeholder, then activation proves pointer and
all generation content absent and creates `cn=current` through one atomic Add.
PostgreSQL proves empty tables and inserts the singleton pointer in one
serializable transaction. MySQL and MariaDB first lock the
permanent publication row, then prove empty state and publish in one
serializable transaction. A missing current pointer in a nonempty backend is
corruption, not a bootstrap opportunity. Concurrent publishers do not retry and
cannot both succeed.

### Delivery-status profiles for forwarding domains

The profile use is part of the published generation, not a runtime switch.
Every domain this deployment forwards mail under needs an active
`delivery_status` profile in addition to the `ordinary_transit` or
`next_domain_transit` profile that signs the forwarded copy. Draft-06
Section 12.1.1 propagation signs the rebuilt delivery-status notification
under the removed completion signature's own domain, so the outgoing
delivery-status authority that derives a domain from an embedded signature
does not apply and is not reachable through the propagation capability.

A local domain that holds a transit profile but no active `delivery_status`
profile is a permanent refusal, not a degraded mode: the propagation route
answers `permerror` with `propagation_failure: unprovisioned_domain`, the
disposition is `discard`, and the previous hop receives nothing. There is no
fallback to another profile use and no tempfail. Publish the profile, its
credential, and the selector's DNS record in the same generation that starts
forwarding under that domain, and treat a missing profile as a publication
defect rather than as a routing problem.

The same rule holds for every backend. Flat-file generations carry it in the
policy's `use` member, LDAP in `dkim2ProfileUse`, and PostgreSQL, MySQL, and
MariaDB in the equivalent policy column; the provider bridge maps all of them
to the same closed vocabulary and refuses an unknown value.

Use the dry-run-first workflow in
[`opendkim-migration.md`](opendkim-migration.md) when the source is an existing
OpenDKIM deployment. No normal runtime path reads a legacy object or local
network-backend manifest.

## Lifecycle, Readiness, And Monitoring

Startup loads and validates one complete committed generation before readiness
becomes true. Refresh work is serialized. Exact revalidation of the unchanged
current generation is a successful health no-op only if every public fact and
native key binding is byte-equivalent after validation.

Once backend work has started, any partial, mixed, backward, mutated-current,
key-mismatched, unavailable, or otherwise failed refresh marks the provider
degraded. Existing in-flight leases remain generation-pinned; new leases fail
closed. The daemon never silently serves the retained snapshot. Only a complete
higher generation restores readiness.

Monitor `/readyz` and `dkim2d_datasource_operations_total`. The metric labels
contain only the closed provider, operation, state, and result classes. Do not
add endpoints, identities, domains, selectors, handles, LDAP values, SQL text,
or raw errors to telemetry. Alert when readiness remains false beyond one
configured reload interval or datasource operations enter a non-success class;
correlate through bounded logs without widening redaction.

## Backup, Restore, And Rotation

Back up the complete committed generation and current pointer as one key-custody
unit. This includes LDAP `ou=key-material`, PostgreSQL
`dkim2_datasource.key_material`, or MySQL/MariaDB `dkim2_key_material`.
Backups, replicas, snapshots, dumps, and restore staging now contain private
signing material and require the same encryption, access, retention, audit, and
destruction controls as any other signing-key backup.

Restore never moves the current pointer backward. Validate retained logical
content and republish it as a complete strictly higher generation. Routine key
replacement, global campaigns, DNS overlap, activation, retention, purge, and
emergency recovery are in
[`datasource-key-rotation.md`](datasource-key-rotation.md).

## Troubleshooting

- Startup readiness remains false: verify the exact TLS identity and CA,
  credentials, selected base/database, exact committed v2/v3 current metadata
  and digest contract, native-key ACL/grants, and public/private SPKI equality.
- LDAP rejects a load: verify critical RFC 2696 paging, RFC 4528 publication
  support, page/deadline limits, referral denial, the 23-attribute/eight-class
  schema allocation, and exact committed v2/v3 current metadata.
- PostgreSQL rejects a load: verify `verify-full`, runtime grants, read-only
  repeatable-read behavior, fixed schema, and the singleton current row.
- MySQL/MariaDB rejects a load: verify the qualified server version, mandatory
  TLS account, exact server identity, dedicated database, runtime grants,
  effective `REPEATABLE READ` plus `READ ONLY`, InnoDB tables, triggers, and the
  singleton current row.
- Native key validation fails: verify exactly one key per selected credential
  and algorithm, canonical PKCS#8 DER, exact generation/tenant/domain/use/handle
  relations, and matching SPKI without printing any key or fingerprint.
- A refresh degrades the provider: repair or replace the candidate and publish
  a strictly higher complete generation. There is no hidden retry, fallback,
  or operator switch that authorizes stale signing.

Run the applicable focused checks after every schema, configuration, grant, or
documentation change:

```text
make check-operator-docs
make check-datasource-schema
make check-datasource-postgresql
make check-datasource-mysql
make test-datasource-services
make guardrails
```

`make test-datasource-services` requires Docker and runs four successful
digest-pinned qualification phases across OpenLDAP, PostgreSQL, MySQL, and
MariaDB: two seed-state passes, one SQL post-administration pass, and one
post-onboarding pass. The report distinguishes causal newly activated
candidate signing as `activated_runtime_signing` from the independent real
provider application-service check `app_signing_service_parity`; it does not
claim that the latter signs the same onboarding candidate. An unavailable
container runtime is a failed prerequisite, not a passing skip.

The generated evidence contract is
`dkim2.datasource-integration-report.v2`. Version 2 replaces the unreleased v1
shape: the reference collector deliberately rejects v1 rather than accepting a
permissive compatibility union. A published v2 PASS is current-candidate bound
and requires the exact pinned images, all 54 closed checks, four successful
qualification phases, and exactly one result for every backend and each of the
three result classes. Every invocation invalidates an older final report before
preflight; only a fully validated same-directory temporary file is atomically
installed after all checks succeed.

Native onboarding uses three distinct administration authorities in addition
to the runtime reader: snapshot, staging, and activation. Its v3 roots store
operation and candidate-content-digest metadata separately from lifecycle
state. Exact private readback reparses and canonicalizes PKCS#8, proves public
SPKI equivalence, and recomputes the digest; counts or public rows alone are
insufficient. Apply the PostgreSQL or MySQL-family
`003_native_domain_onboarding.sql` forward migration, or deploy the LDAP
schema, indexes, layout, and state-conditioned ACL bundle as one reviewed unit.
