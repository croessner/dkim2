# Native MySQL and MariaDB Datasource Provider

## Status

This document records the implemented contract for MySQL and MariaDB in the
daemon-owned DKIM2 datasource providers. It extends the
implemented LDAP and PostgreSQL provider model without changing library,
protocol, Milter, Exim, or REST contracts.

## Provider Boundary

- `cmd/dkim2d/internal/datasource/mysql` owns the concrete `database/sql`
  driver boundary, verified TLS connection construction, fixed queries, and
  transaction adapter.
- `cmd/dkim2d/internal/datasource/sqlsnapshot` owns the shared SQL row model,
  immutable-generation loader, mapping, limits, key clearing, and typed
  provider failures used by PostgreSQL and MySQL/MariaDB.
- `lib/internal/datasource` remains storage-neutral and receives only complete
  provider datasets and opaque handle identifiers.
- Private PKCS#8 DER is read only inside the daemon provider, validated against
  the public SPKI and opaque handle context, installed into an in-memory signer
  registry, and cleared from detached row buffers.
- No key-management REST endpoint or local private-key manifest is added.

## Stable Configuration

The backend selector is `signing.backend: mysql`. The backend-specific subtree
is `signing.mysql.*` with direct `address`, separate TLS `server_name`, protected
`ca_file` and `password_file`, exact `database` and `user`, bounded `page_size`,
`load_deadline`, `max_connections`, and `idle_connections`.
The common `signing.reload_interval` controls refresh scheduling for every
enabled signing backend and is not a member of the MySQL subtree.

The driver is configured through typed fields, never a caller-provided DSN.
Only one direct TCP authority is accepted. TLS 1.2 or newer with hostname and
private CA verification is mandatory. Multi-statements, local infile, plaintext
authentication, server-key retrieval, interpolation, compression, and process
environment configuration are not enabled.

## SQL Contract

`contrib/schema/mysql/001_dkim2_datasource.sql` is qualified against the exact
digest-pinned MySQL 8.4 and MariaDB 10.11 service lines. Other releases and
compatible forks are unqualified until the same evidence passes. The schema
uses InnoDB, binary UTF-8 collation for exact
identifier ordering, `DECIMAL(20,0)` for the full unsigned generation range,
foreign keys for complete references, and triggers for immutable committed
generations.

One permanent singleton publication-lock row serializes first and subsequent
publishers. A publisher uses one serializable transaction, locks that row,
proves the expected current generation or an otherwise empty datasource,
inserts a complete staging generation, verifies exact row counts, changes only
that generation to `committed`, advances the singleton current pointer, and
commits. Conflicts are not retried.

Runtime loading uses one read-only repeatable-read transaction. It proves the
effective isolation and read-only state, reads the current committed fence,
uses fixed explicit keyset queries, rereads the fence, validates the public
dataset and native key registry as one generation, and only then commits and
publishes the candidate. No offset, wildcard, stale-snapshot, or partial-key
fallback exists.

## Failure and Privacy Contract

Context cancellation and deadline expiry retain their typed provider codes.
Missing, malformed, inconsistent, ambiguous, over-limit, unavailable,
unauthorized, weak-isolation, and failed-commit states fail closed. Driver and
server error strings, SQL text, endpoints, database names, users, domains,
selectors, handles, public keys, and private keys never enter errors, logs,
traces, metrics, REST output, CLI reports, or formatting methods.

The telemetry provider kind is the bounded value `mysql`; MariaDB uses the same
wire/provider kind because both share one exact driver and schema contract.

## Migration and Rotation

The offline OpenDKIM migration command accepts `target: mysql` plus one
`mysql_publish` protected authority. Its publication candidate is the same
provider-neutral SQL row set used for PostgreSQL. Apply and higher-generation
rollback preserve the existing inventory, key import, fresh DNS proof, report,
and explicit-generation contracts.

Normal DNS overlap, forward generation replacement, retirement, and emergency
recovery are documented in
[`../../operator/datasource-key-rotation.md`](../../operator/datasource-key-rotation.md).

## Required Evidence

- shared SQL mapper and loader unit, race, limit, context, missing-key, and
  privacy tests;
- MySQL driver tests for typed DSN construction, mandatory verified TLS,
  prohibited features, fixed queries, explicit isolation, and redaction;
- configuration tests for complete selection and every mixed-backend denial;
- DDL contract tests plus disposable MySQL and MariaDB installation, runtime
  read-only, immutable-generation, publication-fence, and parity tests;
- migration publisher tests for first publication, forward publication,
  conflict, rollback, partial failure, and secret-safe errors;
- focused Makefile targets followed by `make guardrails`.

## Non-Goals

- deploying or selecting MySQL/MariaDB in an existing production Mailstack;
- changing OpenDKIM or `opendkim-manage-go`;
- accepting generic DSNs, Unix sockets, multiple hosts, plaintext transport,
  read replicas, proxy failover, or provider chaining;
- adding SQL-backed replay storage.
