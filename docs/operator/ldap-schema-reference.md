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

The native network schema identifiers are exactly `dkim2-datasource-v2` and
`dkim2-datasource-v3`. A loader does not accept v1, infer a version from entry
shape, mix v2/v3 metadata, read a partially upgraded generation, or fall back
to legacy OpenDKIM entries. V2 remains a read-only source for one forward v3
publication; all new administrative publication uses v3.

## Tree Shape

The empty installation contains only the service base and generation
container. The offline publisher creates every generation-specific child and
the current fence:

```text
ou=dkim2,<suffix> [dkim2AdministrationLock]
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

`cn=current` and the generation root both use `dkim2Dataset`. V3 roots and
current additionally use `dkim2AdministrativeMetadata`; roots require operation
and digest while current requires digest and forbids operation/history. The
current entry is the activation fence, not an alias or referral. All children
of one generation carry the same nonzero `dkim2Generation` value. Committed
generation entries are immutable.

## Object Classes

| Object class | OID suffix | One entry represents | Required DKIM2 facts |
| --- | ---: | --- | --- |
| `dkim2Dataset` | `RNSDKIM2oc:1` | current fence or generation metadata | schema version, generation, publication state |
| `dkim2Handle` | `RNSDKIM2oc:2` | one opaque handle declaration | generation, handle ID |
| `dkim2Profile` | `RNSDKIM2oc:3` | one signing profile | profile ID, domain, status, optional validity pair |
| `dkim2Credential` | `RNSDKIM2oc:4` | one public selector/algorithm binding | profile, algorithm, selector, public SPKI, handle |
| `dkim2Policy` | `RNSDKIM2oc:5` | one exact tenant/domain/use policy | tenant, domain, use, profile, status, rollout, compatibility |
| `dkim2KeyMaterial` | `RNSDKIM2oc:6` | one native private signing key binding | tenant, domain, use, handle, algorithm, public SPKI, private PKCS#8 |
| `dkim2AdministrativeMetadata` | `RNSDKIM2oc:7` | auxiliary v3 generation/current metadata | digest plus generation-root operation and optional history evidence |
| `dkim2AdministrationLock` | `RNSDKIM2oc:8` | auxiliary backend mutation lock on the DKIM2 base | revision and optional operation owner |

The service validates relationships across all entries after loading. LDAP
schema acceptance alone does not make a generation valid. A policy must point
to a same-generation profile with the same domain. Every selected credential
must have one declared handle and exactly one matching key-material entry.
Duplicate or surplus objects reject the complete generation.

## Attributes

All 23 attributes are single-valued.

| Attribute | OID suffix | Representation | Meaning |
| --- | ---: | --- | --- |
| `dkim2SchemaVersion` | `RNSDKIM2at:1` | exact IA5 text | `dkim2-datasource-v2` or `dkim2-datasource-v3` |
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
| `dkim2ProfileUse` | `RNSDKIM2at:14` | exact IA5 text | `originator`, `ordinary_transit`, `next_domain_transit`, or `delivery_status` |
| `dkim2Rollout` | `RNSDKIM2at:15` | exact IA5 text | `enforce`, `observe`, or `off` |
| `dkim2Compatibility` | `RNSDKIM2at:16` | exact IA5 text | currently exactly `strict` |
| `dkim2FeedbackRouteID` | `RNSDKIM2at:17` | exact IA5 text | optional opaque future-service route |
| `dkim2PrivateKeyPKCS8` | `RNSDKIM2at:18` | octet string | canonical unencrypted private-key PKCS#8 DER |
| `dkim2CandidateDigest` | `RNSDKIM2at:19` | octet string | exact 32-byte canonical v3 candidate-content digest |
| `dkim2OperationID` | `RNSDKIM2at:20` | exact IA5 text | canonical protected onboarding operation binding on a v3 generation root |
| `dkim2WasActive` | `RNSDKIM2at:21` | LDAP boolean | optional exact `TRUE` monotonic history evidence on a generation root |
| `dkim2AdminLockOwner` | `RNSDKIM2at:22` | exact IA5 text | optional canonical owner of the persistent administration lock |
| `dkim2AdminRevision` | `RNSDKIM2at:23` | LDAP integer | nonzero revision of the persistent administration lock |

Validity attributes are both absent or both present and require
`not_before < not_after`. Public and private binary attributes are DER bytes, not
PEM and not Base64 text in the application model. LDIF represents an octet
string with the normal double-colon Base64 transport syntax; that encoding does
not change the stored value into a textual key format.

`delivery_status` is the profile use for null-reverse-path delivery-status
notifications. Every domain this deployment forwards mail under needs an
active `delivery_status` profile in addition to the transit profile that signs
the forwarded copy, because Draft-06 Section 12.1.1 propagation signs the
rebuilt notification under the removed completion signature's own domain. A
local domain that holds a transit profile but no active `delivery_status`
profile is a permanent refusal: the propagation route answers `permerror` with
`propagation_failure: unprovisioned_domain` and no notification reaches the
previous hop. It never falls back to another profile use and never tempfails.

`dkim2HandleID` is deliberately opaque. Do not derive it from a DN, path,
selector, key digest, database key, tenant, or domain. A handle grants no
authority by itself; the exact policy, profile, credential, DNS publication,
and route capability must also authorize signing.

## Publication And Read Semantics

The v3 stager builds a new generation below `ou=generations`, reads every public
and private value back canonically, validates the content digest, and seals only
the exact operation/digest-bound staging root. It does not move `cn=current`.
After a fresh committed readback, the activator marks the exact old current root
`dkim2WasActive=TRUE` and advances an existing current entry with a critical
RFC 4528 assertion over its complete metadata. Empty bootstrap uses one atomic
Add and has no placeholder current. Ambiguous outcomes require reconciliation;
no committed content is retried or edited.

The runtime reads the current fence, loads every required class through critical
RFC 2696 paging from that exact generation subtree, validates the public and
private facts as one bounded snapshot, rereads the fence, and publishes an
in-memory provider only if both fence reads agree. A failed initial load
prevents readiness. A failure after refresh work starts degrades the provider
and blocks new signing leases until a complete higher generation loads.

## ACL Model

Keep the runtime and six administrative authorities separate:

| Authority | Native public data | Native private key | Mutation authority |
| --- | --- | --- | --- |
| runtime | read current generation | read | none |
| snapshot | read bounded inventory/snapshots | read | none |
| stager | read | read/write only while exact v3 root is staging | lock claim/release, candidate Add, exact seal |
| activator | read | read for fresh canonical inspection | monotonic old-root history plus current Add/Modify only |
| purger | exact noncurrent committed target/current/lock/receipt readback | read only while reconciling an exact target | leaf-first/root-last deletion of an exact noncurrent target only |
| legacy v2 publisher | read v2 staging data | read/add only under exact v2 staging root | v2 forward publication; all v3 metadata writes denied |
| protected legacy import | deny native unless separately required | deny | legacy `DKIMKey` read only in the source directory |

Anonymous, monitoring, ordinary authenticated directory readers, and unrelated
service accounts must not read either private-key attribute. Place the
`dkim2PrivateKeyPKCS8` ACL before the broader public subtree ACL so a later
general read rule cannot widen access. Replication consumers and backups that
carry the DKIM2 subtree become key-custody systems even when their normal
application role is read-only.

Bootstrap additionally gives only LDAP add privilege (`=a`) on the relevant
`children` and `entry` pseudo-attributes. Current attribute replacement is a
separate activator rule; neither activator nor legacy publisher has current
entry delete/rename authority. Generation descendants use the captured numeric
root and a `set.expand` predicate over exact schema, generation, staging state,
operation, and digest. Once sealed, the predicate becomes empty.

`=dcsra` permits disclosure, compare, search, read, and add without delete;
`=dcsraz` is restricted to attributes whose old value must be replaced. No
entry or parent-children rule grants delete (`z`) to a publication principal.
Only the distinct purger has state-conditioned delete access below one exact
committed noncurrent v3 root; it cannot delete the current subtree or mutate a
current pointer, lock, candidate content, or activation history.
The DKIM2 base carries `dkim2AdminRevision` and optional lock owner; critical
RFC 4528 claim/release makes crash-held ownership persistent and same-operation
only.

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

The first target verifies the permanent 23/8 allocation plus committed layout
and ACL contracts. `make test-datasource-ldap` also starts a disposable
OpenLDAP service and binds every role to prove state-conditioned positive and
negative ACL behavior, RFC 4528 lock/current fences, bootstrap one-winner,
post-commit immutability, and v2 publisher/v3 denial. The Docker-backed
qualification proves provider parity, native-key validation, bounded paging,
and legacy migration behavior. A
production installation additionally requires site-specific rendered-config,
replication, backup, restore, runtime/publisher ACL, readiness, and real signing
proofs.
