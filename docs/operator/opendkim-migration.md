# OpenDKIM Bootstrap And Rollback

`dkim2d datasource` is an offline administrative surface. It does not start
the HTTP server, Milter, replay store, metrics endpoint, tracing exporter, or
normal daemon provider. Dry-run is the safe default:

```text
dkim2d datasource bootstrap-opendkim --config /secure/migration.yaml
dkim2d datasource bootstrap-opendkim --config /secure/migration.yaml --machine
dkim2d datasource bootstrap-opendkim --config /secure/migration.yaml --apply
dkim2d datasource rollback --config /secure/migration.yaml --generation 43
```

`--dry-run=false` without `--apply`, conflicting `--dry-run` and `--apply`,
relative paths, missing generations, and interactive invocation are rejected.

The first publication into a brand-new target uses `generation: "1"` and the
exact fence `expected_current: "0"`. Zero is an administrative absence
assertion only: the publisher must prove that no current pointer and no
generation data exist. A missing current pointer in a nonempty target, an
unreadable target, or spellings such as `"00"` fail closed. Every later
publication and every rollback uses the exact nonzero current generation and a
strictly higher candidate.

## Protected Preparation

The configuration, password files, and CA files must be absolute regular
files, owned by the invoking UID, mode `0600`, and in the same directory. Use
separate inventory, key-import, and publication principals. Inventory cannot
read `DKIMKey`; only the key-import principal can read it. The target runtime
principal remains read-only.

The import principal reads each selected legacy key only after inventory and
plan validation. Apply writes canonical PKCS#8 DER directly into the target
v2 generation. No local registry root, private manifest, or private-key child
is created. Target backups and the publisher connection must therefore be
handled as key material.

Example LDAP-target configuration:

```yaml
version: dkim2-opendkim-migration-v2
deadline: 30s
source:
  address: 192.0.2.10:636
  server_name: ldap.example.test
  ca_file: /secure/legacy-ca.pem
  transport: ldaps
  bind_dn: cn=inventory,ou=services,dc=example,dc=test
  password_file: /secure/inventory-password
  base_dn: ou=opendkim,dc=example,dc=test
  page_size: 128
import:
  address: 192.0.2.10:636
  server_name: ldap.example.test
  ca_file: /secure/legacy-ca.pem
  transport: ldaps
  bind_dn: cn=protected-import,ou=services,dc=example,dc=test
  password_file: /secure/import-password
  base_dn: ou=opendkim,dc=example,dc=test
  page_size: 128
ldap_publish:
  address: 192.0.2.10:636
  server_name: ldap.example.test
  ca_file: /secure/legacy-ca.pem
  transport: ldaps
  bind_dn: cn=publisher,ou=services,dc=example,dc=test
  password_file: /secure/publisher-password
  base_dn: ou=dkim2,dc=example,dc=test
  page_size: 128
plan:
  generation: "42"
  expected_current: "41"
  target: ldap
  mappings:
    - domain: example.test
      source_selector: current
      selector: dkim2-current
      tenant_id: tenant-production
      profile_id: origin-example-net
      profile_use: originator
      handle_id: key-opaque-0042
      rollout: enforce
      compatibility: strict
limits:
  records: 4096
  response_bytes: 16777216
  report_bytes: 262144
```

For PostgreSQL, omit `ldap_publish` and add:

```yaml
postgresql_publish:
  address: 192.0.2.20:5432
  server_name: postgresql.example.test
  ca_file: /secure/postgresql-ca.pem
  database: dkim2
  user: dkim2_publisher_login
  password_file: /secure/postgresql-publisher-password
```

## Validation And Publication

Inventory requests no private key values. It requires complete active
OpenDKIM objects, canonical equal `DKIMDomain` and `associatedDomain`, unique
selectors, and one active domain/algorithm record. `DKIMIdentity` and LDAP
timestamps are count-only legacy facts and are not migrated.

The adapter accepts legacy ASCII selector spelling with uppercase letters
because selector DNS labels are case-insensitive. Inventory canonicalizes that
spelling to lowercase while protected import uses the exact original LDAP
value against the case-exact legacy schema. A mapping may declare a separate
canonical `source_selector` and DKIM2 `selector`: protected import resolves the
former and DNS proof plus the published credential use the latter. Omitting
`source_selector` preserves the same-selector migration behavior. This explicit
split is required when an inherited DKIM RSA record contains SPKI DER while
DNS-04 requires PKCS#1 `RSAPublicKey` DER; operators must publish a distinct
DKIM2 selector rather than replacing or weakening the existing DKIM record.
Other noncanonical selector or domain input remains rejected.

An inactive historical row may retain the exact legacy `DKIMDomain: *`
spelling when its single canonical `associatedDomain` identifies the counted
domain. It remains in inactive-history counts and can never become a mapping or
key import. An active wildcard row is ambiguous and still fails closed.

The protected phase then reads each key separately, accepts one bounded
unencrypted PKCS#8 RSA or Ed25519 key of the declared type and strength, and
normalizes an inherited unencrypted RSA PKCS#1 PEM key to canonical PKCS#8.
No other private-key compatibility input is accepted. It derives canonical
SPKI and performs a fresh lookup of the explicit DKIM2 selector through the
normal DNS key parser. Missing, ambiguous, invalid, revoked, mismatched,
timed-out, or unavailable DNS evidence prevents publication.

For an established target, LDAP publication creates and reads back a complete
staging subtree, marks its root committed, and changes `cn=current` with one
critical RFC 4528 assertion for the expected generation. First publication
atomically adds a unique staging `cn=current` claim before writing the
generation and activates it only through a critical assertion over the exact
schema, candidate generation, and staging state.

For an established target, PostgreSQL holds the singleton row lock in one
serializable transaction. First publication instead proves all datasource
tables empty in that transaction and uniquely inserts the singleton pointer
after inserting, validating, and committing the generation. Conflicts are not
retried, and concurrent first publishers cannot both commit. Public rows and
native private-key rows remain inert until the complete datasource generation
becomes current.

Machine and human reports contain closed states and counts only. They contain
no DN, domain, selector, tenant, profile, handle, path, endpoint, key, SPKI,
DNS text, SQL, LDAP filter, credential, or raw error.

## Rollback And Recovery

Rollback never points backward. Prepare an explicit plan containing the prior
logical mapping and keys, set `expected_current` to the current generation,
choose a strictly higher `generation`, rerun dry-run, then invoke `rollback`
with that same new generation. Keys and DNS are revalidated and the normal
publication protocol is used.

A failed or interrupted apply does not claim success. Unreferenced staging
backend generations are inert. Inspect them with protected authority. Remove
only a generation proven
not current, not committed for retention, and not needed for rollback. Never
delete by guessed age or identity, and never emit its contained identifiers.
An interrupted LDAP first publication may leave the unique current claim in
`staging`; runtime and later bootstrap then fail closed until an authorized
operator explicitly proves and repairs that state. Never reinterpret it as an
empty target or an implicit successful publication.
