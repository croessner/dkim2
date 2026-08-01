# LDAP And PostgreSQL Datasources

The daemon supports one exact signing datasource backend at a time:
`flat_file`, `ldap`, or `postgresql`. LDAP and PostgreSQL use the native
`dkim2-datasource-v2` generation: public profile/policy data and canonical
PKCS#8 DER private keys are committed and fenced as one immutable unit.
Flat-file alone retains a protected local private manifest.

## Installation

Install the LDAP schema from
`contrib/schema/ldap/rnsdkim2.schema`, then adapt the reviewed layout, index,
and ACL examples in the same directory. Validate the resulting server
configuration with `slaptest` before restart. Keep schema administration,
runtime read, publisher, legacy inventory, and protected legacy-key import as
separate principals. The runtime principal receives read access to
`dkim2PrivateKeyPKCS8` only inside the DKIM2 generation subtree, but no write
access and no access to legacy `DKIMKey`. Anonymous, monitoring, and ordinary
directory-reader principals must not read native key material.

Install PostgreSQL with
`contrib/schema/postgresql/001_dkim2_datasource.sql` using a schema
administrator. The script creates `dkim2_runtime` and `dkim2_publisher`
NOLOGIN roles. Grant login roles to exactly one of them. Do not grant the
runtime role insert, update, delete, DDL, or migration authority.
Existing v1 installations first apply
`contrib/schema/postgresql/002_native_key_custody.sql`, then publish a complete
v2 generation before restarting a v2 daemon.

Both servers require verified TLS and one configured endpoint. LDAP supports
explicit `ldaps` or StartTLS. PostgreSQL uses `verify-full`. Plaintext,
anonymous LDAP, arbitrary SQL DSNs, service files, environment-selected
fallback hosts, and automatic endpoint failover are unsupported.

## Daemon Configuration

An LDAP signing selection uses this stable subtree:

```yaml
signing:
  backend: ldap
  ldap:
    address: 192.0.2.10:636
    server_name: ldap.example.test
    ca_file: /secure/0123456789abcdef0123456789abcdef/ldap-ca.pem
    transport: ldaps
    bind_dn: cn=dkim2-runtime,ou=services,dc=example,dc=test
    password_file: /secure/0123456789abcdef0123456789abcdef/ldap-password
    base_dn: ou=dkim2,dc=example,dc=test
    page_size: 128
    load_deadline: 5s
    refresh_interval: 1m
    response_bytes: 16777216
```

A PostgreSQL signing selection uses:

```yaml
signing:
  backend: postgresql
  postgresql:
    address: 192.0.2.20:5432
    server_name: postgresql.example.test
    ca_file: /secure/0123456789abcdef0123456789abcdef/postgresql-ca.pem
    database: dkim2
    user: dkim2_runtime
    password_file: /secure/0123456789abcdef0123456789abcdef/postgresql-password
    page_size: 128
    load_deadline: 5s
    refresh_interval: 1m
    response_bytes: 16777216
    max_connections: 2
    idle_connections: 1
```

The protected directory basename must equal `protected.generation`, be owned
by the daemon UID, and have mode `0500`. Selected child files must be regular,
owner-only mode `0600`, and must not be symlinks. Network backends require only
their capabilities, CA, and password files locally. Supplying
`signing.private_manifest_file` or `signing.datasource_file` with LDAP or
PostgreSQL is rejected.

A brand-new backend contains only its schema and LDAP base containers or its
empty SQL tables. Its first offline migration plan uses
`expected_current: "0"` and a nonzero candidate. Zero is never loadable by the
runtime. LDAP proves an absent current entry and empty generation container,
claims the unique current DN in staging state, and activates it with a critical
RFC 4528 assertion. PostgreSQL proves all datasource tables empty inside the
serializable publication transaction and uniquely inserts the singleton
pointer. A missing current pointer in a nonempty backend is corruption, not a
bootstrap opportunity, and concurrent first publishers cannot both succeed.

## Lifecycle And Monitoring

Startup loads one complete committed generation before readiness becomes true.
A refresh is serialized. A complete revalidation of the unchanged current
generation while ready is a successful no-op only when every immutable
dataset fact and native key binding remains exactly equal. Changed
facts under the current generation fail closed. Once backend work has started,
any failed, partial, mixed, backward, attempted-republication, or
key-mismatched result marks the datasource
degraded. New leases then fail closed; the daemon does not silently serve the
old snapshot. A later complete higher generation restores readiness.

Monitor the readiness endpoint and the closed
`dkim2d_datasource_operations_total` dimensions. Labels contain provider,
operation, state, and result classes only. They never contain endpoints,
domains, selectors, tenants, profiles, handles, LDAP values, SQL, or errors.

## Backup And Restore

Back up committed datasource generations, including `ou=key-material` or
`dkim2_datasource.key_material`, and the singleton current reference as key
material. Preserve encryption, access control, and audit policy. A restore is
not active until a complete v2 generation validates. Never restore by moving a
current pointer backward; republish retained logical public and private
content under a higher generation.

## Troubleshooting

- `readiness=false` after startup: verify TLS identity, CA, least-privilege
  credentials, current v2 metadata, committed state, native key ACLs, and
  public/private SPKI equality.
- `degraded` after refresh: repair the backend generation and publish a
  strictly higher complete generation. There is no hidden retry or fallback.
- LDAP load rejection: check critical RFC 2696 support, page and response
  limits, aliases/referrals, exact schema version, and current-fence stability.
- PostgreSQL load rejection: check `verify-full`, role grants, read-only
  repeatable-read behavior, fixed schema, and singleton current row.
- Native-key rejection: verify one key per credential/algorithm, canonical
  PKCS#8 DER, exact generation/tenant/domain/use/handle relationships, and
  matching SPKI. Never print private material while diagnosing.

Run `make check-datasource-schema`,
`make check-datasource-postgresql`, and `make guardrails` after schema,
configuration, or provider changes. `make test-datasource-services` performs
the optional Docker-backed qualification twice against the exact
digest-pinned disposable OpenLDAP and PostgreSQL images; an unavailable
container runtime is a failed prerequisite, not a passing skip.
