# LDAP Datasource Schema Reference

This document explains the deployable RNS DKIM2 LDAP schema in
[`contrib/schema/ldap`](../../contrib/schema/ldap). It is an operator reference,
not a second schema definition: `rnsdkim2.schema` owns exact OIDs, LDAP syntax,
matching rules, cardinality, and object-class `MUST`/`MAY` sets.

## Allocation And Version

The permanent enterprise allocation is:

| Purpose | OID |
| --- | --- |
| RNS enterprise root | `1.3.6.1.4.1.31612` |
| RNS LDAP root | `1.3.6.1.4.1.31612.1` |
| DKIM2 schema root | `1.3.6.1.4.1.31612.1.7` |
| DKIM2 attributes | `1.3.6.1.4.1.31612.1.7.1` |
| DKIM2 object classes | `1.3.6.1.4.1.31612.1.7.2` |

The native network schema identifier is exactly `dkim2-datasource-v2`. A v2
loader does not accept v1, infer a version from entry shape, read a partially
upgraded generation, or fall back to legacy OpenDKIM entries.

## Tree Shape

The empty installation contains only the service base and generation
container. The offline publisher creates every generation-specific child and
the current fence:

```text
ou=dkim2,<suffix>
├── cn=current
└── ou=generations
    └── dkim2Generation=<N>
        ├── ou=handles
        │   └── cn=<storage-name>
        ├── ou=profiles
        │   └── cn=<storage-name>
        ├── ou=credentials
        │   └── cn=<storage-name>
        ├── ou=policies
        │   └── cn=<storage-name>
        └── ou=key-material
            └── cn=<storage-name>
```

`cn`, entry DNs, and subtree names are storage mechanics. They are not a tenant,
profile, selector, policy, handle, domain, or key identity. The corresponding
`dkim2*` attributes carry the validated domain identities.

`cn=current` and the generation root both use `dkim2Dataset`. The current entry
is the activation fence; it is not an alias or referral. All children of one
generation carry the same nonzero `dkim2Generation` value. Committed generation
entries are immutable.

## Object Classes

| Object class | OID suffix | One entry represents | Required DKIM2 facts |
| --- | ---: | --- | --- |
| `dkim2Dataset` | `RNSDKIM2oc:1` | current fence or generation metadata | schema version, generation, publication state |
| `dkim2Handle` | `RNSDKIM2oc:2` | one opaque handle declaration | generation, handle ID |
| `dkim2Profile` | `RNSDKIM2oc:3` | one signing profile | profile ID, domain, status, optional validity pair |
| `dkim2Credential` | `RNSDKIM2oc:4` | one public selector/algorithm binding | profile, algorithm, selector, public SPKI, handle |
| `dkim2Policy` | `RNSDKIM2oc:5` | one exact tenant/domain/use policy | tenant, domain, use, profile, status, rollout, compatibility |
| `dkim2KeyMaterial` | `RNSDKIM2oc:6` | one native private signing key binding | tenant, domain, use, handle, algorithm, public SPKI, private PKCS#8 |

The service validates relationships across all entries after loading. LDAP
schema acceptance alone does not make a generation valid. A policy must point
to a same-generation profile with the same domain. Every selected credential
must have one declared handle and exactly one matching key-material entry.
Duplicate or surplus objects reject the complete generation.

## Attributes

All 18 attributes are single-valued.

| Attribute | OID suffix | Representation | Meaning |
| --- | ---: | --- | --- |
| `dkim2SchemaVersion` | `RNSDKIM2at:1` | exact IA5 text | `dkim2-datasource-v2` |
| `dkim2Generation` | `RNSDKIM2at:2` | LDAP integer | nonzero unsigned 64-bit generation |
| `dkim2DatasetState` | `RNSDKIM2at:3` | exact IA5 text | closed staging or committed publication state |
| `dkim2HandleID` | `RNSDKIM2at:4` | exact IA5 text | provider-neutral opaque signing handle |
| `dkim2ProfileID` | `RNSDKIM2at:5` | exact IA5 text | immutable administrative profile identity |
| `dkim2SigningDomain` | `RNSDKIM2at:6` | exact IA5 text | canonical lowercase ASCII signing domain |
| `dkim2RecordStatus` | `RNSDKIM2at:7` | exact IA5 text | `active` or `disabled` |
| `dkim2NotBefore` | `RNSDKIM2at:8` | canonical UTC RFC3339Nano | optional half-open validity start |
| `dkim2NotAfter` | `RNSDKIM2at:9` | canonical UTC RFC3339Nano | optional half-open validity end |
| `dkim2Algorithm` | `RNSDKIM2at:10` | exact IA5 text | `rsa-sha256` or `ed25519-sha256` |
| `dkim2Selector` | `RNSDKIM2at:11` | exact IA5 text | canonical lowercase ASCII DNS selector |
| `dkim2PublicKeySPKI` | `RNSDKIM2at:12` | octet string | canonical public SubjectPublicKeyInfo DER |
| `dkim2TenantID` | `RNSDKIM2at:13` | exact IA5 text | exact administrative tenant identity |
| `dkim2ProfileUse` | `RNSDKIM2at:14` | exact IA5 text | `originator`, `ordinary_transit`, or `next_domain_transit` |
| `dkim2Rollout` | `RNSDKIM2at:15` | exact IA5 text | `enforce`, `observe`, or `off` |
| `dkim2Compatibility` | `RNSDKIM2at:16` | exact IA5 text | currently exactly `strict` |
| `dkim2FeedbackRouteID` | `RNSDKIM2at:17` | exact IA5 text | optional opaque future-service route |
| `dkim2PrivateKeyPKCS8` | `RNSDKIM2at:18` | octet string | canonical unencrypted private-key PKCS#8 DER |

Validity attributes are both absent or both present and require
`not_before < not_after`. Public and private binary attributes are DER bytes, not
PEM and not Base64 text in the application model. LDIF represents an octet
string with the normal double-colon Base64 transport syntax; that encoding does
not change the stored value into a textual key format.

`dkim2HandleID` is deliberately opaque. Do not derive it from a DN, path,
selector, key digest, database key, tenant, or domain. A handle grants no
authority by itself; the exact policy, profile, credential, DNS publication,
and route capability must also authorize signing.

## Publication And Read Semantics

The publisher builds a new generation below `ou=generations`, validates exact
entry counts and relationships, marks the generation committed, and only then
advances `cn=current` with a critical RFC 4528 assertion over the expected
schema, generation, and state. It never edits a committed generation in place
or moves the pointer backward.

The runtime reads the current fence, loads every required class through critical
RFC 2696 paging from that exact generation subtree, validates the public and
private facts as one bounded snapshot, rereads the fence, and publishes an
in-memory provider only if both fence reads agree. A failed initial load
prevents readiness. A failure after refresh work starts degrades the provider
and blocks new signing leases until a complete higher generation loads.

## ACL Model

Keep four authorities separate:

| Authority | Legacy `DKIMKey` | Native public v2 data | Native private v2 key | Writes v2 |
| --- | --- | --- | --- | --- |
| runtime | deny | read | read | deny |
| publisher | deny unless separately required | read plus bounded add/fence change | read plus add | forward publication only |
| legacy inventory | deny | deny unless explicitly needed | deny | deny |
| protected legacy import | read | deny unless explicitly needed | deny | deny |

Anonymous, monitoring, ordinary authenticated directory readers, and unrelated
service accounts must not read either private-key attribute. Place the
`dkim2PrivateKeyPKCS8` ACL before the broader public subtree ACL so a later
general read rule cannot widen access. Replication consumers and backups that
carry the DKIM2 subtree become key-custody systems even when their normal
application role is read-only.

Bootstrap additionally needs only the LDAP add privilege (`=a`) on the
`children` pseudo-attribute of the native base container so the publisher can
create `cn=current`. Do not widen that rule to write or delete: committed
generations and the current fence are forward-only publication state.

The example uses explicit privileges for the publisher. `=dcsra` permits
disclosure, compare, search, read, and add without delete; `=dcsraz` is
restricted to the dataset-state and current-fence attributes that
must replace a value. No rule gives the publisher delete privilege on an entry
or on a parent's `children` pseudo-attribute.

The reviewed native-target starting point is
[`contrib/schema/ldap/acl.conf`](../../contrib/schema/ldap/acl.conf). Replace
only the example suffix and exact service DNs; retain the rule order and denial
boundaries. Prove access with count- or presence-only assertions. Never print a
private attribute value during validation or troubleshooting.

The legacy source directory needs its own separately reviewed rule granting
`DKIMKey` read access only to the protected-import principal. Do not add the
legacy attribute or its ACL to the native DKIM2 schema bundle.

## Legacy OpenDKIM Isolation

Legacy objects are an offline migration source, never a runtime compatibility
model:

| Legacy fact | DKIM2 treatment |
| --- | --- |
| `associatedDomain` plus `DKIMDomain` | must agree canonically before mapping to `dkim2SigningDomain` |
| `DKIMSelector` | source lookup fact; the plan assigns an explicit DKIM2 target selector |
| `DKIMKeyType` | maps only to the closed DKIM2 algorithm after key validation |
| `DKIMActive` | inventory status; it does not authorize rollout by itself |
| `DKIMKey` | read only inside protected import and written as canonical native PKCS#8 DER |
| `DKIMIdentity` | never mapped to numeric DKIM2 `i=` |
| LDAP create/modify timestamps | audit facts only; never inferred as profile validity |

Normal loading never requests `DKIMKey`, follows a legacy DN, accepts a legacy
attribute alias, or falls back from v2. See
[`opendkim-migration.md`](opendkim-migration.md) for the bounded dry-run-first
import workflow.

## Installation Verification

Run:

```text
make check-datasource-schema
make test-datasource-services
```

The first target verifies the permanent 18/6 allocation plus committed layout
and ACL contracts. The Docker-backed qualification installs the schema in a
disposable OpenLDAP service and proves v2 load, native-key validation,
publication fencing, bounded paging, provider parity, and denial behavior. A
production installation additionally requires site-specific rendered-config,
replication, backup, restore, runtime/publisher ACL, readiness, and real signing
proofs.
