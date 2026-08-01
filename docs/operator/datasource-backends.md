# Signing Datasource Backend Operations

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
| `ldap` | native LDAP `dkim2PrivateKeyPKCS8` | one committed `dkim2-datasource-v2` subtree | distinct LDAP publisher | directory-backed production signing |
| `postgresql` | native `key_material.private_key_pkcs8` | one committed `dkim2-datasource-v2` transaction snapshot | distinct SQL publisher | PostgreSQL-backed production signing |
| `mysql` | native `dkim2_key_material.private_key_pkcs8` | one committed `dkim2-datasource-v2` transaction snapshot | distinct SQL publisher | MySQL or MariaDB production signing |

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
   allocation under `1.3.6.1.4.1.31612.1.7` is permanent: 18 attributes and
   six object classes, including the native private-key attribute and key
   material class.
3. Adapt only the suffix in [`layout.ldif`](../../contrib/schema/ldap/layout.ldif)
   and add the empty `ou=dkim2` plus `ou=generations` containers. Do not create
   `cn=current`, a zero generation, a partial generation, or a hand-written key
   entry. The offline publisher owns first publication.
4. Adapt the exact service DNs and suffix in
   [`acl.conf`](../../contrib/schema/ldap/acl.conf). Keep the private-attribute
   rule before the public datasource rule. Runtime receives read-only access to
   native v2 public and private data, publisher receives the minimum write
   access, and every other principal is denied native private key material.
   Grant any legacy `DKIMKey` import right only on the separate OpenDKIM source
   directory described by the migration runbook; it is not part of this native
   target ACL.
5. Add the performance-only equality indexes from
   [`indexes.conf`](../../contrib/schema/ldap/indexes.conf). Do not index private
   key bytes.
6. Validate the complete rendered server configuration with `slaptest -u`
   before restart, then verify the runtime, publisher, anonymous, monitoring,
   and ordinary-reader ACL outcomes without printing returned key values.

LDAP transport is exactly authenticated `ldaps` or StartTLS with an explicit
address, separate verified server name, private CA, and one bind identity.
Anonymous bind, plaintext transport, referral following, alternate endpoints,
automatic failover, and a request-derived search base are unsupported.

An existing v1 schema installation is upgraded in place by installing the new
attribute and object class definitions before publishing the first complete v2
generation. The publisher advances `dkim2SchemaVersion`, generation, and state
under one critical RFC 4528 assertion. A v1 runtime generation, mixed fence, or
missing native key set is never loadable by a v2 daemon.

## PostgreSQL Installation

Fresh installations apply
[`001_dkim2_datasource.sql`](../../contrib/schema/postgresql/001_dkim2_datasource.sql)
through a schema administrator. Existing v1 installations apply
[`002_native_key_custody.sql`](../../contrib/schema/postgresql/002_native_key_custody.sql),
then publish a complete higher v2 generation before restarting a v2 daemon.

The DDL creates `dkim2_runtime` and `dkim2_publisher` as `NOLOGIN` roles. Create
separate TLS-authenticated login roles through the site's credential workflow
and grant each login exactly one role. Runtime receives `CONNECT`, schema usage,
and `SELECT`; it receives no insert, update, delete, DDL, ownership, or migration
authority. Publisher receives only the fixed staging, commit-state, and current
pointer privileges in the DDL.

The runtime connection is one explicitly configured TCP authority using
`verify-full`. Arbitrary DSNs, service files, environment-selected libpq
defaults, password commands, multi-host fallback, and TLS downgrade modes are
unsupported.

## MySQL And MariaDB Installation

Fresh installations apply
[`001_dkim2_datasource.sql`](../../contrib/schema/mysql/001_dkim2_datasource.sql)
inside one dedicated database. The exact disposable qualification versions are
MySQL 8.4 and MariaDB 10.11; see the
[`compatibility statement`](../reference/compatibility.md#qualified-storage-services)
before assuming another release is supported.

Create two distinct site accounts with exact source restrictions, mandatory
TLS, independently managed passwords, and no global privileges. Replace all
three placeholders in
[`002_least_privilege_grants.sql.example`](../../contrib/schema/mysql/002_least_privilege_grants.sql.example),
review the rendered account expressions and database identifier, and only then
apply it. The required grants are:

| Principal | `SELECT` | `INSERT` | `UPDATE` | Explicitly absent |
| --- | --- | --- | --- | --- |
| runtime | seven dataset tables | none | none | publication lock, writes, delete, DDL, `FILE`, global privileges |
| publisher | seven dataset tables plus publication lock | seven dataset tables | generation state, current pointer, publication lock | delete, DDL, `FILE`, global privileges |

The publisher needs `UPDATE` on `dkim2_publication_lock` solely because a
MySQL-family locking read requires that table-level privilege. Read back
`information_schema.TABLE_PRIVILEGES` and prove the exact grant matrix before
deploying either credential.

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

LDAP atomically claims and later activates the unique `cn=current` entry through
critical assertions. PostgreSQL proves empty tables and inserts the singleton
pointer in one serializable transaction. MySQL and MariaDB first lock the
permanent publication row, then prove empty state and publish in one
serializable transaction. A missing current pointer in a nonempty backend is
corruption, not a bootstrap opportunity. Concurrent publishers do not retry and
cannot both succeed.

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
replacement, DNS overlap, activation, retirement, and emergency recovery are in
[`datasource-key-rotation.md`](datasource-key-rotation.md).

## Troubleshooting

- Startup readiness remains false: verify the exact TLS identity and CA,
  credentials, selected base/database, v2 current fence, committed state,
  native-key ACL/grants, and public/private SPKI equality.
- LDAP rejects a load: verify critical RFC 2696 paging, RFC 4528 publication
  support, page/deadline limits, referral denial, 18/6 schema allocation, and a
  stable v2 current fence.
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

`make test-datasource-services` requires Docker and runs the digest-pinned
OpenLDAP, PostgreSQL, MySQL, and MariaDB qualification twice. An unavailable
container runtime is a failed prerequisite, not a passing skip.
