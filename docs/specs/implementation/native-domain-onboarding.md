# Native Domain Onboarding

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-06 authority is the migration disposition
> and current durable architecture.

Status: implementation closeout candidate. Prompt 01-10 implementation and
replacement reviews are complete. Prompt 11 operator documentation and
release-proportional validation are complete; the fresh independent final
review remains required.

This specification defines the first native operator workflow for adding a
DKIM2 signing domain to an existing LDAP, PostgreSQL, MySQL, or MariaDB
datasource. The workflow is an offline privileged control plane under
`dkim2d datasource domain`; it does not add an administrative REST API and it
does not widen `dkim2ctl` beyond its generated-client conformance role.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`;
- `docs/specs/implementation/datasource-providers.md`;
- `docs/specs/implementation/ldap-sql-datasource-legacy-migration.md`;
- `docs/specs/implementation/native-datasource-key-custody.md`;
- `docs/specs/implementation/mysql-mariadb-datasource.md`;
- `docs/specs/implementation/dns-key-resolver.md`;
- `docs/specs/implementation/observability-foundation.md`;
- `docs/specs/implementation/security-hardening.md`;
- `docs/specs/spec-and-prompt-template.md`;
- `docs/operator/datasource-key-rotation.md`;
- `docs/specs/openapi/dkim2d.yaml` as an explicitly unchanged boundary;
- `draft-ietf-dkim-dkim2-spec-04` and `draft-chuang-dkim2-dns-04`;
- RFC 4511, RFC 2696, and RFC 4528 for LDAP publication;
- the documented PostgreSQL, MySQL, and MariaDB transaction contracts;
- `Makefile` and repository guardrails.

If this specification conflicts with a governing source, implementation stops
until the durable contract is reconciled.

## Original Gap

Before M23, the online daemon could read complete native datasource
generations and sign through their opaque handles, while the offline OpenDKIM
migration command could publish one complete generation from an explicitly
mapped legacy inventory. No native workflow let an operator safely add a new
domain, generate its signing keys, export the required DNS records, prove the
configured resolver path, and atomically activate the resulting complete
generation. The implementation candidate closes that gap through the offline
command family specified here.

The current publisher owns only `Current` and one coupled `Publish` operation.
It cannot read the complete current generation for cloning, retain an inactive
candidate across a DNS-change boundary, inspect that candidate, or activate it
later under a digest and expected-current fence. The publication candidate and
backend implementations also live under the OpenDKIM-specific `migration`
package even though their invariants are provider administration, not legacy
migration.

Direct LDAP or SQL inserts are not a supported workaround. The current
generation is immutable and complete; adding a domain by mutating it in place
would create mixed state and bypass datasource validation, key equivalence,
DNS proof, conflict fencing, and exact readback.

## Operator Goal

An operator supplies a small declarative domain intent and a protected backend
configuration. The tool derives collision-resistant selectors and opaque IDs,
generates RSA and Ed25519 keys, creates a complete higher candidate generation,
exports deterministic DNS-04 records, proves the configured fresh resolver path
against the staged public keys, and activates the candidate only when every fence still
matches.

The safe path is resumable and reports the next explicit action. Repeating a
completed step is a bounded no-op only when operation identity, plan digest,
candidate digest, current generation, and backend state still agree. There is
no `--force`, fallback provider, partial activation, backward pointer move, or
implicit acceptance of changed state.

## Delivery Shape

1. Freeze the administrative trust boundary, intent schema, states, limits,
   identifiers, reports, and stable CLI vocabulary.
2. Extract reusable snapshot, candidate, validation, and protected readback
   ownership from the OpenDKIM migration package while retaining its existing
   v2 one-shot publication contract.
3. Add collision-resistant selector allocation and native RSA/Ed25519 key
   generation with canonical PKCS#8 and public SPKI validation.
4. Add a protected atomic operation journal, deterministic plan and candidate
   digests, resumability, status, and non-destructive abort semantics.
5. Add deterministic DNS export and fresh exact DNS/SPKI proof.
6. Implement the strict domain-onboarding state machine.
7. Implement complete-generation read, stage, inspect, and activate behavior
   for LDAP.
8. Implement equivalent PostgreSQL, MySQL, and MariaDB behavior through shared
   SQL contracts.
9. Add the offline Cobra surface, protected configuration, bounded reports,
   and secret-safe observations.
10. Add abuse, concurrency, crash, disposable-provider, and runtime signing
    evidence.
11. Complete architecture, operator documentation, examples, release gates,
    and unchanged-OpenAPI proof.
12. Run a fresh independent finding-first review, fix every in-scope finding,
    and reproduce the final candidate twice unchanged.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | very large |
| Estimated wall-clock effort | 6 to 14 hours excluding production DNS changes |
| Highest-risk area | resumable secret-bearing full-generation staging and activation |
| Expected prompt count | 11 implementation prompts plus one independent review prompt |
| Required final gate | focused disposable provider tests and `make guardrails` |

Risk notes:

- Low risk: `lib/`, Milter, Exim, OpenAPI, and `dkim2ctl` remain unchanged.
- Medium risk: stable operator CLI, protected journal handling, and bounded
  machine reports.
- High risk: cloning native private-key rows, key generation, DNS encoding,
  crash recovery, and abandoned staging generations.
- Highest risk: activating a partial, stale, mismatched, or concurrently
  superseded candidate.

Measured effort is filled during closeout. Exact prompt timings and candidate
identities live in the ignored execution ledger to avoid a self-referential
tracked digest.

| Prompt | Started At | Completed At | Wall-Clock Duration | Notes |
| --- | --- | --- | --- | --- |
| Prompts 01-10 | 2026-08-02T13:41:00+02:00 | 2026-08-03 before Prompt 11 | retained per-prompt in ignored ledger | implementation and correction cycles complete; final Prompt 10 dual replacement APPROVE |
| Prompt 11 | retained in ignored ledger | retained in ignored ledger | retained in ignored ledger | documentation and release-gate closeout complete; candidate identities remain outside tracked content |
| Independent final review | pending | pending | pending | separate Prompt 12 authority |
| Orchestrator review | pending | pending | pending | no commit or release authority implied |

## Scope

In scope:

- a provider-neutral administrative snapshot and candidate model;
- complete current-generation reads including native key material;
- `dkim2-datasource-v3` operation/digest metadata in LDAP and SQL schemas plus
  runtime digest verification and v2-to-v3 forward publication;
- full `N` to a selected higher `C` clone-and-add behavior;
- one or both RSA-SHA256 and Ed25519-SHA256 credentials per new profile;
- native key generation through `crypto/rand`;
- deterministic DNS-04 export and fresh DNS/SPKI proof;
- protected resumable operation journals;
- `plan`, `prepare`, `dns export`, `prove`, `activate`, `status`, `reconcile`,
  and `abort`;
- LDAP, PostgreSQL, MySQL, and MariaDB parity;
- forward-only activation and existing higher-generation rollback compatibility;
- bounded reports, privacy tests, operator documentation, and guardrails.

Out of scope:

- REST or OpenAPI administration endpoints;
- administrative extensions to `dkim2ctl`;
- automatic PowerDNS, RFC 2136, registrar, or cloud-DNS mutation;
- HSM, PKCS#11, KMS, remote signing, or non-exportable keys;
- wildcard, suffix, alias, tenant-default, or provider-chain onboarding;
- mutation of an active generation;
- selector reuse, automatic old-selector retirement, or generation garbage
  collection;
- production DNS changes, Mailstack rollout, or release publication without a
  separate explicit authorization.

## Administrative Trust Boundary

`dkim2d serve` remains an online reader and signer. Native onboarding is a
one-shot offline command that never starts Fx, HTTP listeners, metrics
exporters, or daemon lifecycle state. It uses dedicated least-privilege
snapshot, publisher, and DNS-read authorities. Runtime credentials do not gain
publication rights and publication credentials do not cross into daemon
configuration.

The normal REST/OpenAPI surface remains unchanged. An operator with a signing
or revision capability cannot provision domains. An operator with datasource
administration authority cannot bypass fresh DNS proof through the daemon.

## Domain Intent

The protected intent document has a closed versioned schema. It contains only
operator decisions:

```yaml
version: dkim2-domain-intent-v1
domain: example.test
tenant_id: outbound
profile_use: originator
algorithms:
  - ed25519-sha256
  - rsa-sha256
rollout: enforce
compatibility: strict
```

Domain, tenant, use, algorithms, rollout, and compatibility use the same
canonical validation as datasource records. Unknown fields, duplicate
algorithms, unsafe RSA sizes, unsupported uses, invalid domains, empty values,
oversized documents, trailing YAML, aliases, anchors, merge keys, multiple
documents, symlinks, hard links, group/world-writable files, and noncanonical
paths fail closed.

Operators do not supply generation, selector, profile ID, handle ID, key bytes,
public key, DNS record, operation ID, or plan digest. Those are owned by the
administrative workflow.

## Operation Identity, Digest, And Journal

Every onboarding operation receives a cryptographically random identifier.
Identity generation and claimed collision allocation are separate operations.
The allocator first creates the operation identity without reading or mutating
the backend. The command then performs only a read-only administration-lock
observation and may proceed only from an ownerless exact revision `R`. Before
any administration-lock claim, it atomically syncs an internal owner-only
planning receipt at the final operation path. The
receipt binds its format version, backend class, canonical authority
descriptor, canonical intent and DNS policy, operation identity, expected
administration revision, monotonic receipt revision, and one closed internal
phase: `claim_pending`, `allocating`, `release_required`, `unresolved`, or
`closed`. It contains no
allocated generation, profile, handle, selector, plan digest, candidate
digest, or key material.

`claim_pending` means no claim is durably accepted yet; `plan` may observe
ownerless `R`, Claim, and then sync `allocating`. `allocating` means exact owner
`operation,R` was proven and plan retry may call `AllocateClaimed` or promote a
complete plan. Before any cleanup Release, the command must durably transition
to `release_required`; after that transition only explicit `reconcile` may
observe or retry the exact Release, and `plan` must never resume allocation.
`unresolved` retains foreign, skipped-revision, malformed, or unavailable
evidence and permits only read-only status plus explicit reconcile. `closed`
records durable ownerless cleanup or pre-claim abort, is retained as an
idempotent tombstone, and permits no mutation for its old operation.

The operation file is a closed tagged union of exactly one planning receipt or
one full operation journal. A loader rejects mixed, duplicated, unknown, or
trailing variants. The receipt carries the backend-free identity created by
`IdentityAllocator.NewOperation`. After receipt sync and exact Claim proof,
that identity passes to `IdentityAllocator.AllocateClaimed`, which owns
collision inventory plus generation/profile/handle/selector allocation. The
complete key-free plan atomically replaces the receipt only after all plan
facts validate. This promotion is the sole transition into the public
`planned` state; the receipt is internal pre-plan recovery evidence and is not
an `OperationState`.

The preflight plan digest binds a canonical versioned encoding of:

- operation compatibility version `dkim2-domain-operation-v1` and target
  datasource schema `dkim2-datasource-v3`;
- target backend class and protected canonical authority descriptor;
- expected current generation followed by the complete canonical current
  snapshot projection encoded directly into the plan preimage;
- canonical intent;
- allocated profile and handle IDs plus algorithm-specific selectors;
- one bounded race-safe candidate generation selected from currently unused
  higher generations;
- DNS proof policy encoded as resolver class, ordered canonical resolver
  endpoints, DNS export TTL seconds, and proof-lifetime seconds;
- operation identifier.

`plan` stores the canonical intent and these derived public facts in the
protected journal; it does not generate a key or claim a candidate digest.
There are exactly two operation-digest domains. `PlanDigest` covers the
key-free plan projection above. `CandidateContentDigest` covers the immutable
complete candidate projection below. Prepared-candidate and staged-readback
evidence are distinct typed phases carrying the same
`CandidateContentDigest`; they are not independently domain-separated hashes.

Both digests use SHA-256. Their exact initial domain strings are the ASCII bytes
`DKIM2-DOMAIN-PLAN-V1` and `DKIM2-CANDIDATE-CONTENT-V1`, each followed by one
zero octet. Generation, DNS export TTL seconds, and proof-lifetime seconds are
fixed-width big-endian `uint64`; counts and byte lengths are fixed-width
big-endian `uint32`. Required strings and byte values are encoded as
`uint32 length || bytes`; nullable values use one zero or one octet followed,
when present, by the same framed value. Strings are already canonical UTF-8 or
closed ASCII before framing. Counts precede row sequences.

After the plan domain string, fields appear exactly in the bullet order above.
Backend class is one closed ASCII enum. The authority descriptor begins with a
random deployment-unique 128-bit `authority_id` encoded as lower-case base32,
then an endpoint count and each ordered endpoint's framed scheme, host,
canonical unsigned decimal port, and TLS server name. Provider-specific fields
then contain LDAP base plus snapshot/staging/activation principals or SQL
database/schema plus snapshot/staging/activation roles,
ordered SHA-256 trust-anchor certificate fingerprints, and optional public
client-certificate fingerprint. Passwords, tokens, client private keys, and
generic DSNs are excluded. The descriptor is protected journal state and is
re-derived from protected config and compared before every backend command;
same-class or same-snapshot substitution is a conflict.

The current snapshot begins with one byte: zero means the proven entirely empty
backend and is followed by no snapshot fields; one means a source snapshot and
is followed by the fields below. Intent fields are version, domain, tenant ID,
profile use, algorithm count plus algorithm-sorted values, rollout, and
compatibility. DNS resolver endpoints preserve configured order after canonical
host/port validation; resolver class `system` requires an empty endpoint list,
while explicit recursive resolution requires at least one endpoint. TTL and
proof lifetime are `uint64` seconds. Operation ID is the final framed ASCII
field.

The plan preimage follows the bullet order above. Its embedded source snapshot
contains source schema, generation, exact committed state, every public row,
and for native key material only tenant, domain, use, handle, algorithm, and
public SPKI; private PKCS#8 is deliberately omitted. This key-free projection
directly supports the current v2 source without inventing a third snapshot
digest. Source and candidate rows use the fixed class order `handles`,
`profiles`, `credentials`, `policies`, `key_material`. Rows exclude their already-framed common generation
and are sorted respectively by handle ID; profile ID; profile ID then
algorithm; tenant ID then signing domain then profile use; and handle ID.
Within a row, fields follow the exact logical column order declared by the
corresponding `sqlsnapshot` row type: handle ID; profile ID, signing domain,
record status, nullable not-before, nullable not-after; profile ID, algorithm,
selector, public SPKI, handle ID; tenant ID, signing domain, profile use,
profile ID, record status, rollout, compatibility, nullable feedback-route ID;
and tenant ID, signing domain, profile use, handle ID, algorithm, public SPKI,
canonical private PKCS#8. The source key-material row ends after public SPKI and omits only the final
private PKCS#8 field. Allocated plan facts encode profile ID followed by
algorithm-sorted tuples of algorithm, handle ID, and selector. Golden vectors
cover empty/source-v2, RSA/Ed25519, nullable policy
fields, sort-order independence, one-byte changes, and prepared/readback
equality. Any encoding revision requires new domain tags and compatibility
tests; stored v3 digests are never reinterpreted.

`prepare` first records a write-ahead `preparing` state, then generates keys,
builds and validates the complete candidate, computes its protected content
digest, and atomically advances the journal to `prepared` before the backend
write. Stage stores that digest and the operation binding with the candidate.
Exact backend readback computes the same content digest independently,
requires equality with the prepared value, seals the complete generation as
immutable `committed` without changing current, and only then records the
operation state `staged`. Public SPKI values and their identity-like digests
are re-derived from protected backend readback and are not journal fields.

Digest inputs are length-delimited and domain-separated. Map iteration,
filesystem metadata, YAML formatting, and policy-external timestamps are not
inputs. The candidate content digest covers schema version, generation,
operation binding, and every canonical public and private row, including
canonical PKCS#8 bytes. It excludes its own stored digest field, mutable
publication lifecycle state, and monotonic `was active` evidence. Those remain
separately fenced metadata. The
digest therefore remains stable when one complete generation moves from
writable `staging` to sealed `committed` and later becomes current. Candidate
digests are protected correlators and never appear in generic output or
telemetry.

The operation journal is a regular owner-only file in an owner-only directory.
A separate owner-only sibling lock file has a stable inode and is never
renamed or replaced. Commands acquire and descriptor-verify that lock before
opening the journal and hold it through backend readback and the final journal
sync. Creation and replacement use directory-relative file descriptors,
reject symlinks, hard links, wrong owners, unsafe modes, and inode replacement,
compare a monotonic journal revision before replacement, use same-directory
temporary files, `fsync` file and directory where supported, and atomic rename.
The journal inode itself is never the lock target; atomic rename alone is not
concurrency control.
The same protected store and stable sibling lock own the planning-receipt/full-
journal union. A receipt save that returns an ambiguous post-rename result
poisons that store instance: the command performs no backend claim or other
backend mutation, closes the store, reopens it, and loads the union
authoritatively. An absent file permits a new receipt attempt; an exact receipt
permits resume; an exact full journal follows normal lifecycle handling. A
definite pre-rename receipt failure likewise performs no backend mutation.

Once a synced receipt exists, pre-plan crash recovery compares only its exact
operation and expected revision with authoritative administration-lock
readback. Ownerless revision `R` means no claim is held and permits an explicit
plan retry to claim. Exact owner `operation,R` permits the same plan retry to
resume allocation. Ownerless `R+1` proves that cleanup release succeeded but
its receipt update was lost and permits an atomic receipt-revision repair.
Foreign ownership, any other revision, malformed readback, or unavailable
authority atomically records or retains `unresolved` and never permits
allocation, release, or promotion. Release is attempted only for the exact
receipt operation and revision and only after `release_required` is known
durable. An ambiguous release leaves that phase recoverable; a later explicit
reconciliation observes whether exact ownership remains or ownerless `R+1`
proves release. There is no blind retry.

The closed pre-plan crash and release matrix is:

| Durable local evidence | Authoritative lock evidence | Permitted result |
| --- | --- | --- |
| Receipt save definitely failed before rename | not read | Return failure; perform no backend mutation |
| Receipt save outcome ambiguous | not read until reopen/load | Close the poisoned store; perform no backend mutation; accept only exact absent, receipt, or full-journal reload |
| `claim_pending` at revision `R` | ownerless `R` | `plan` may Claim the receipt operation, sync `allocating`, and continue |
| `claim_pending` or `allocating` at revision `R` | exact owner `operation,R` | Sync or retain `allocating`; `plan` may resume `AllocateClaimed` |
| `release_required` at revision `R` | exact owner `operation,R` | Only explicit `reconcile` may issue the exact Release; `plan` and `abort` are mutation-free |
| `release_required` at revision `R` | ownerless `R` | Retain `release_required`; absence of the owner without the revision increment does not prove Release and must not close the receipt |
| `release_required` at revision `R` | ownerless `R+1` | Record successful cleanup as retained `closed` with revision `R+1`; never retry Release |
| `unresolved` at revision `R` | ownerless `R` | Explicit `reconcile` may use the typed ownerless-recovery transition directly to `closed`; it performs no Release and never passes through `release_required` |
| `unresolved` at revision `R` | ownerless `R+1` | Retain `unresolved`; without prior durable cleanup lineage the skipped revision is not attributed to this operation |
| Any open receipt at revision `R` | foreign owner, another revision, malformed, or unavailable | Persist or retain `unresolved`; permit only status and reconcile |
| `closed` at revision `R` | ownerless `R` | Status and abort are idempotent; a later `plan` may CAS-replace it with a new-operation `claim_pending` receipt |
| Receipt-to-journal promotion outcome ambiguous | not read until reopen/load | Perform no further backend mutation; exact receipt resumes pre-plan recovery, exact full journal resumes at public `planned` |
| `release_required`; exact same-operation Release returned success but receipt update was lost | ownerless `R+1` | Record retained `closed` revision `R+1`; never issue another Release |
| `release_required`; exact same-operation Release returned ambiguous | exact owner `operation,R` | Preserve `release_required`; only explicit reconciliation may issue another exact Release after this readback |
| `release_required`; exact same-operation Release returned ambiguous | ownerless `R+1` | Record retained `closed`; never retry Release |

No case authorizes a release from backend owner evidence without the matching
protected receipt. No case after an ambiguous protected-store result proceeds
using only the command's in-memory copy.

The journal contains no private key, password, token, CA document, raw LDAP
entry, SQL row, DNS TXT value, or backend credential. It records only bounded
canonical intent, the nonsecret protected authority descriptor and public
certificate fingerprints, derived IDs and selectors, state, generation
numbers, digests, algorithm classes, phase outcomes, and expiry. The journal is
protected identity-bearing state and is never generic CLI or telemetry output.

## Selector Allocation And Native Keys

Selectors are canonical lower-case ASCII and differ per algorithm. They combine
a stable DKIM2 prefix with at least 128 bits of `crypto/rand` entropy encoded in
a closed DNS-label-safe alphabet. Time alone is never a selector and failed or
aborted selectors are never reused automatically.

RSA generation uses the configured approved modulus size and exponent policy.
Ed25519 generation uses the standard library. Every key is immediately
serialized as canonical unencrypted PKCS#8 DER, reparsed through the existing
native-key validator, and checked against canonical public SPKI. Invalid,
unsupported, duplicate, mismatched, over-limit, or partially generated key
sets are cleared and rejected.

Private bytes exist only in bounded in-memory owners and the inactive backend
candidate. They never enter intent, journal, DNS export, stdout, stderr, logs,
traces, metrics, REST, generated DTOs, test diagnostics, Git, or temp prompt
artifacts.

## DNS Export And Proof

MVP DNS integration is export-only. `dns export` writes an explicit regular
file selected by the operator and refuses stdout for record material unless a
future protected-output contract explicitly permits it. The export includes
only the canonical owner names, TTL policy, algorithm, selector, and public
DNS-04 record.

RSA `p=` contains the draft-required PKCS#1 public DER representation.
Ed25519 `p=` contains exactly the raw 32-byte public key. Stored SPKI is never
copied directly into `p=`. Export uses a documented RFC 1035 zone-file
presentation with deterministic quoting and chunks of at most 200 ASCII octets;
all chunks belong to exactly one TXT RR. A realistic RSA record must therefore
round-trip as one RR containing multiple character strings. Multiple RRs remain
fail-closed ambiguity. Exported records must round-trip through the repository
DNS key parser and reproduce the staged public SPKI.

`prove` constructs a fresh process-local provider over the explicitly
configured operational recursive-resolver path and requires exactly one usable
matching record for every staged credential. This is a fresh resolver-path
DNS/SPKI proof, not a claim that the tool contacted an authoritative server or
bypassed the recursive resolver's positive or negative cache. The operator must
separately confirm authoritative publication and honor TTL/negative-cache
policy before invoking proof. NXDOMAIN or NODATA as exposed by the transport,
multiple records,
malformed records, revoked keys, algorithm mismatch, SPKI mismatch, timeout,
transport failure, or cancellation fails without state advancement. Proofs
expire after a bounded configured duration. `activate` always repeats proof
from the staged candidate immediately before activation; a prior journaled
proof is never sufficient by itself.

## Complete Candidate Construction

For an established backend, `plan` reads one stable current generation `N`.
It performs a bounded inspection of higher generation identifiers, rejects
`MaxUint64`, enforces a configured outstanding-candidate limit no greater than
eight, and selects an unused identifier. Stage still uses create-if-absent
semantics; a concurrent winner conflicts and requires a new plan. Abandoned
candidates therefore cannot block all later work, and unbounded key
accumulation fails closed.

An outstanding candidate is every noncurrent `staging` generation, every
noncurrent `committed` generation without backend-durable exact `was active`
evidence regardless of journal terminality or generation ordering, and every
generation whose state cannot be classified exactly. Current is active by
pointer. Before an established current pointer moves, the activation authority
monotonically marks that exact old current root as `was active`; the marker can
only move from absent or false to true and is not a content-digest input. A
noncurrent committed generation with that marker is retained rollback history
and does not consume this onboarding ceiling. Aborted staging generations
remain outstanding because their private material is retained. Reaching the
ceiling intentionally blocks new preparation until a separately authorized
cleanup contract resolves the retained state.

`prepare` reads and fences `N` again, clones every public and native-key row
into the selected higher candidate `C`, adds the new domain's handles, profile, credentials,
policy, and key material, and validates the entire candidate through the same
dataset, native-key, binding, resolver, limit, and readiness construction used
by the runtime.

Existing rows must be logically identical except for their generation field.
Existing private PKCS#8 bytes are copied only within protected owners and are
cleared after staging. The builder exposes domain operations such as
`AddDomain`; it does not expose arbitrary row mutation.

An empty backend may bootstrap generation `1` only through an explicit
expected-current zero proof that also proves no pointer, generation, public
row, or key-material row exists. Candidate generations must be nonzero and
strictly greater than current. Gaps are allowed because prior unused or
abandoned candidate identifiers are never reused automatically; backward or
equal activation is forbidden.

## Backend-Neutral Administration

`cmd/dkim2d/internal/datasourceadmin` owns:

- version-neutral protected `Snapshot` and `CandidateContent` values with
  `Close` erasure;
- canonical candidate validation and digesting;
- `SnapshotReader` for stable complete generation reads;
- `GenerationPublisher` for `Current`, bounded generation inspection, `Stage`,
  `Inspect`, `Activate`, and exact outcome inspection;
- `AdministrationLocker` for backend-wide claim/revision/release metadata where
  the provider lacks a transactional singleton lock;
- typed closed error classes;
- provider-neutral stage state and exact readback contracts.

Formatting and JSON marshaling of protected owners return constant redacted
representations. Provider-specific connection, row, LDAP entry, transaction,
DN, and query types do not escape their concrete packages.

V3 onboarding wraps `CandidateContent` in a separate operation-bound
publication envelope. Version-neutral content never requires or synthesizes an
operation ID. `cmd/dkim2d/internal/migration` retains legacy inventory, mapping, import,
reports, and its existing coupled v2 one-shot publisher. It consumes the
shared protected content, validation, and provider readback primitives, but
does not silently acquire the resumable v3 operation protocol. Migrating the
legacy publisher itself to v3 requires a separate stable operation journal and
reconciliation contract; M23 neither invents an ephemeral operation ID nor
changes migration's external behavior.

## LDAP Semantics

LDAP snapshot reads use the existing verified connection, exact current/root
fence, critical bounded paging, byte and entry limits, final-current recheck,
and key-material clearing. Administrative reads return a protected common
snapshot only after full mapping and key equivalence validation.

M23 allocates `RNSDKIM2at:19` as the exact 32-byte
`dkim2CandidateDigest`, `RNSDKIM2at:20` as the canonical random
`dkim2OperationID`, `RNSDKIM2at:21` as the single-valued boolean
`dkim2WasActive`, `RNSDKIM2at:22` as the canonical optional
`dkim2AdminLockOwner`, `RNSDKIM2at:23` as the unsigned
`dkim2AdminRevision`, `RNSDKIM2oc:7` as the auxiliary
`dkim2AdministrativeMetadata` v3
metadata class allowing the operation ID, digest, and was-active evidence. The LDAP schema cannot
express the closed cross-field combinations, so application validation requires
both fields on every v3 generation root and requires only the digest while
forbidding the operation ID and `dkim2WasActive` on `cn=current`.
`RNSDKIM2oc:8` is the auxiliary `dkim2AdministrationLock` class on the
configured DKIM2 base, allowing lock owner and requiring revision. The v2
`dkim2Dataset` class gains only `dkim2WasActive` as an additive `MAY` attribute;
its existing MUST set and content semantics do not change.
This avoids changing the MUST-set of the deployed v2 structural object class.
`dkim2-datasource-v3` generation roots carry both values; `cn=current` carries
the active digest without an operation identity. The digest field itself is
excluded from its framed digest input, avoiding self-reference; schema,
generation, operation binding, every public row, and every canonical private
row are included. Publication state and `dkim2WasActive` are excluded from the
digest and fenced separately.

Existing noncurrent v2 generations have no trustworthy activation provenance
and conservatively count as outstanding forever in M23. There is no automatic
backfill from generation ordering. During the one forward v2-to-v3 activation,
the exact v2 current root may receive only the monotonic `dkim2WasActive=TRUE`
attribute through the additive v2 schema rule before current moves. Runtime v2
mapping accepts absent or exact true lifecycle evidence but ignores it for
signing content. If the inherited v2 baseline already consumes the ceiling,
onboarding is unavailable until a separately authorized classification or
destruction workflow exists; M23 does not guess history.

The DKIM2 base carries one persistent administration lock with revision and
optional owner. Before LDAP Stage or Activate, the operation uses critical RFC
4528 to claim an ownerless exact revision with its operation ID, then rechecks
the bounded inventory/current and performs the backend critical section. It
clears the same-owner lock and increments revision only after exact readback and
journal sync. A crash leaves the lock owned and blocks other mutations; only
the same protected operation may resume. `status` remains read-only, while
explicit `reconcile` may release this lock metadata only after exact candidate,
current, journal, and outcome classification. It never retries candidate or
pointer mutation. Stale-plan and concurrent-stage tests must prove the ceiling
cannot be exceeded.

Planning uses the same revisioned lock without opening the pre-journal orphan
window. The protected receipt is synced before Claim. A crash after Claim but
before allocation, after allocation but before plan construction, or during
receipt-to-journal promotion therefore always leaves a locally trusted
operation identity and expected revision. If the receipt remains visible, a
plan retry resumes only under exact owner/revision evidence and may allocate
new public identifiers because no plan or candidate was published. If the
full journal is visible, normal `planned` handling applies. Cleanup does not
discard or overwrite the receipt until ownerless exact revision evidence has
been durably recorded.

Stage creates a higher generation below `ou=generations` with state `staging`,
operation binding, and prepared content digest, then creates the complete
children. It reads every class and key value back, reparses every canonical
PKCS#8 value, proves private/public/algorithm equivalence and exact canonical
encoding, and recomputes the content digest. One assertion-protected root
modify then changes exact same-operation, same-digest `staging` metadata to
`committed`. That transition seals the complete noncurrent candidate before
DNS export; it does not change `cn=current`. A crash after the prepared journal
revision but before any backend write cannot regenerate identical lost keys
and therefore fails this operation closed, requiring a new plan. A complete
same-operation candidate may reconcile; a partial or mismatched LDAP subtree
becomes `reconcile_required` and is never filled with newly generated keys.

LDAP uses separate snapshot, staging, and activation bind identities; the
legacy v2 publisher identity is explicitly denied v3 metadata and v3 subtree
mutation. The staging authority may write content only while the root is
`staging` and may perform only the exact staging-to-committed seal transition.
The deployable OpenLDAP policy uses a `set.expand` state-conditioned ACL that
resolves the captured generation root for every target entry and grants staging
rights only when that root has exact v3 schema, matching generation, operation,
digest, and state `staging`. After the root becomes `committed`, the same
authority has no add, modify, rename, or delete access to the root, containers,
children, or key material. The separate activation authority may only set
`dkim2WasActive` monotonically on the exactly observed old current root and
create or modify `cn=current`; it cannot change candidate content or other root
metadata. The old unconditional publisher ACL is replaced, not layered beneath
the v3 rules. `slaptest` plus disposable positive and negative bind tests are a
release gate; if the state-conditioned policy cannot be proven on supported
OpenLDAP, LDAP onboarding remains unavailable rather than relying on runtime
detection alone.
Activation freshly inspects the already committed candidate, proves its
operation binding and digest, monotonically marks the exactly observed old
current root `dkim2WasActive=TRUE`, then advances `cn=current` to the candidate
generation and digest through one critical RFC 4528 assertion that applies
only to the exact prior fields of the `cn=current` entry. The marker is
truthful even if a concurrent pointer move wins first because that root was
current when observed; repeating the marker is an exact no-op. There is no
candidate-root mutation in the activation path. The assertion does not claim
to predicate over another LDAP entry or subtree. The runtime recomputes the v3 content digest after loading
and fails readiness if it does not match both root and current metadata.
Committed-subtree immutability, separate authorities, exact current-entry
fencing, and runtime verification jointly close the subtree/pointer TOCTOU
boundary without claiming an LDAP multi-entry transaction. Any ambiguous
result becomes
`reconcile_required`, never success. There is no automatic retry.

For empty LDAP bootstrap, after generation `1` is committed and DNS proof
passes, the activation authority uses one LDAP Add to create absent
`cn=current` with exact v3 schema, generation, committed state, content digest,
and digest-only auxiliary metadata. Add is the atomic first-writer fence:
`entryAlreadyExists` is a conflict, while timeout or disconnect is
`reconcile_required` until exact readback proves whether the entry was created.
No placeholder or staging current entry is used. Concurrent first publications
have exactly one winner.

## PostgreSQL, MySQL, And MariaDB Semantics

SQL snapshot reads use one read-only repeatable-read or serializable
transaction and the existing fixed keyset queries. They return a protected
common snapshot only after final fence, complete mapping, native-key
equivalence, and commit.

M23 SQL schema revisions store the 32-byte operation-bound content digest
with generation metadata, a monotonic `was_active` boolean, and the active
32-byte digest with current. Operation
identifiers use one closed canonical ASCII representation with length checks;
PostgreSQL uses `bytea` and the MySQL family uses fixed `BINARY(32)` for the
digest. Constraints require v3 rows to carry the exact metadata and prevent
partial null combinations.
Versioned forward upgrade artifacts alter deployed v2 schemas without editing
historical bootstrap migrations. They define locking and transactional limits,
constraints for existing rows, least-privilege grants, nonrollbackable steps,
and PostgreSQL/MySQL/MariaDB upgrade tests before any v3 write is enabled.
Snapshot, staging, and activation use pairwise-distinct SQL authorities.
Singleton observation, physical locking, claim, and release are fixed
definer-owned primitives; administration roles receive no direct singleton
table privilege. Observation is available to all three roles, physical locking
only to staging and activation, and claim/release only to staging. Collision
inventory is not a snapshot-role exception: it runs through the staging
connector in one serializable read-write transaction, holds the physical lock
while reading complete current/outstanding candidates, and rechecks the exact
owner and revision before commit. PostgreSQL content writes remain constrained
by narrow grants, RLS, and immutable transition triggers; MySQL and MariaDB
content writes remain fixed operation-bound procedures.
Stage uses one serializable transaction and backend-specific singleton lock,
inserts the complete higher generation in staging state, reads it back, checks
canonical content and digest, marks that generation committed, and commits
without changing current. Repeated staging is a same-operation,
same-content-digest no-op or a conflict.

Activation locks the singleton, re-reads current and the already committed
candidate, checks schema, state, expected generation, operation, and digest,
marks an established old current generation `was_active=true`, and advances
current in the same transaction. For an empty backend it instead inserts the
unique singleton current row after re-proving absence; exactly one concurrent
insert wins. PostgreSQL, MySQL, and
MariaDB must satisfy one shared parity corpus; driver differences must not
change administrative semantics.

For an established SQL backend, the normative activation lock order is the
physical administration singleton, the current pointer, the exact candidate
root, the canonical full-generation readback, and only then mutation. Current
metadata is validated centrally before any write: v2 forbids operation, root
digest, and pointer digest metadata; v3 requires a valid operation plus equal,
nonzero 32-byte root and pointer digests. The candidate-root fence binds the
planned generation, operation, digest, and claimed administration revision.
PostgreSQL implements that fence through one fixed-search-path
`SECURITY DEFINER` function whose only nonowner grantee is the activation role;
MySQL and MariaDB use one fixed `SQL SECURITY DEFINER` procedure. A missing or
changed root, foreign operation, stale revision, or malformed current fails
before full readback and before mutation. The subsequent current update also
compares the locked old pointer digest. Separate physical connectors racing
from the same current must therefore produce exactly one winner and one typed
`CodeConflict` loser, never two successes. Reconcile is reserved for ambiguous
mutation or commit outcomes and is not an accepted lock-contention result.

Pointer and candidate-root fences keep operation and digest bytes behind
bounded callbacks over detached copies. Constant-redacted formatting and
rejected JSON serialization prevent accidental disclosure, and callback-owned
copies are cleared on return. Authoritative absence or metadata mismatch is a
typed conflict; backend read, lock, cancellation, deadline, deadlock, and
generic serialization failures are unavailable. PostgreSQL SQLSTATE `40001`
is a conflict only at the locked administration/current fence read of a live
activation transaction with a live context. Candidate-root `40001` and
`40P01`, and every nonactivation or unlocked read, remain unavailable.

## CLI And Output Contract

The stable offline surface is:

```text
dkim2d datasource domain plan --config /abs/admin.yaml --intent /abs/domain.yaml --operation /abs/op.json
dkim2d datasource domain prepare --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain dns export --config /abs/admin.yaml --operation /abs/op.json --output /abs/records.txt
dkim2d datasource domain prove --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain activate --config /abs/admin.yaml --operation /abs/op.json --apply
dkim2d datasource domain status --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain reconcile --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain abort --config /abs/admin.yaml --operation /abs/op.json
```

Mutation defaults remain closed. `activate` requires explicit `--apply`; no
other spelling disables safe mode. Paths are absolute, clean, protected, and
nonoverlapping. Commands never assemble or start the daemon.

Human and machine complete-operation reports contain schema, tool version,
operation state, backend class, expected and candidate generations, bounded
credential and algorithm counts, phase booleans, result, and closed failure
class. Current generation has separate explicit presence: success and full
status require an authoritative value, including an explicitly present zero
for proven-empty first publication, while failures without an authoritative
observation omit the field entirely. Full status preserves an authoritative
third-party current. A successful terminal-conflict `reconcile` also preserves
the exact observed third-party current and requires it to differ from both the
expected and candidate generations; every other successful nonactivated
workflow requires the expected generation. Receipt reports contain no
operation state, generation, count, revision, or identity fact.
Identity-bearing details and DNS record material appear only in the explicitly
requested protected export, not general reports.

`runtime_smoke_required=true` is an exact closed post-activation invariant. It
is present if and only if the complete result is successful, state is
`activated`, and the command is `activate` or `reconcile`. A successful
activation-recovery reconciliation therefore cannot lose the required external
mailflow smoke, while nonactivated results and unrelated commands cannot claim
it.

## State Machine And Resume

The canonical public progression is:

```text
planned -> preparing -> prepared -> staged -> dns_exported -> dns_proven -> activating -> activated
```

The internal planning receipt precedes this progression but is not a public
lifecycle state. `status` may report only bounded `plan_complete=false`,
receipt-present, backend class, and lock-relation facts; it does not synthesize
`planned` or expose the operation identity, authority, path, or revision.
`reconcile` may repair ownerless `R+1` receipt knowledge or release exact
same-operation `R` ownership after authoritative observation, but it cannot
allocate identifiers, construct a plan, stage a candidate, or change current.
The sole direct recovery exception closes `unresolved` only from authoritative
ownerless exact `R`; it performs no Release and is a distinct typed transition.
An ownerless exact `R` never closes `release_required`, because that phase
requires either exact owned `R` cleanup or ownerless `R+1` release proof.
`abort` on a receipt is non-destructive and idempotent. Before a held-claim
cleanup it must sync `release_required` and then direct the operator to
explicit `reconcile`; it does not itself retry an ambiguous Release. After
exact ownerless proof or exact reconciled Release plus revision update, it
retains the receipt as `closed`. It does not delete the recovery authority and
does not create the public terminal `aborted` state because no public operation
was planned. A later `plan` may CAS-replace an exact `closed`, ownerless receipt
with a new-operation `claim_pending` receipt. An unavailable, foreign,
malformed, or ambiguous lock observation records or retains `unresolved` and
requires explicit reconciliation.

Operator `plan` retry semantics are exact. A synced receipt with ownerless
revision `R` in `claim_pending` may claim and continue; exact owner
`operation,R` in `claim_pending` or `allocating` may sync or retain
`allocating` and resume; `release_required` or `unresolved` permits no plan
progress; ownerless `R+1` cleanup is recorded as `closed`; a full `planned`
journal returns exact idempotent success. A new plan may CAS-replace only exact
closed ownerless receipt evidence. An ambiguous receipt save is resolved by
reopening and loading before any backend mutation. That fresh readback owns the
receipt phase reported in command results and bounded telemetry even when it
differs from the attempted in-memory transition. A differing phase reports
`reconcile_required` and forbids further backend mutation. No retry reuses
backend evidence without the matching protected receipt. If reopening, reading,
or validating the fresh union fails, or it contains a journal where a receipt
save was attempted, the result claims neither receipt presence nor phase; it
remains `reconcile_required` and mutation-free.

Ambiguous receipt-to-journal promotion has a stronger recovery identity than
an idempotent operator request. A loaded planned journal is accepted as the
attempted promotion only when its plan digest, typed operation binding,
administration-lock revision, backend authority, and pristine planned state all
match the attempted journal exactly; the monotonic operation-document revision
may differ because it is the CAS result. A loaded receipt is authoritative only
when its complete recovery phase matches the attempted allocating receipt.
Same intent and DNS policy alone are insufficient. Any valid mismatch reports
neither the foreign journal state nor foreign receipt presence or phase and
remains mutation-free under `reconcile_required`.

`conflict`, `failed`, and `aborted` are terminal operation states.
`reconcile_required` is nonterminal but permits only `status` and `reconcile`.
`status` is read-only; `reconcile` may update the protected journal and release
same-operation administration-lock metadata after exact classification, but
never mutates candidate content or current. Runtime verification is an external postcondition, not a persisted
onboarding state. The initial CLI documents existing `dkim2ctl` smoke/sign
fixtures as the proof path and must not invent mailflow success.

Each transition validates journal, backend, current generation, candidate
digest, and required prior evidence. A crash before a journal update is
recovered by inspecting backend state. A crash after a journal update cannot
claim a backend transition not proven by readback. Resume never skips DNS or
activation fences. `preparing` binds operation, generation, intent, IDs, and
selectors before key generation. `prepared` adds the exact content digest
before any backend write; the staged generation stores the same operation and
digest so a crash before the post-stage journal update can be reconciled
without guessing ownership. Because private keys are not escrowed locally, a
crash with prepared evidence but no backend candidate cannot recreate the same
candidate and ends that operation as terminal `failed` with closed failure
class `key_recovery_unavailable`; the operator starts a new plan.

Immediately after the fresh activation-time DNS proof and all backend fences,
but before any activation mutation, the command syncs `activating` write-ahead
evidence containing expected current, candidate generation/content digest,
administration-lock revision/owner, proof-completion time, proof lifetime, and
the required old-current was-active or empty-bootstrap branch. It contains no
raw DNS or identity fields. This lineage is mandatory for ambiguous-result
reconciliation.

`reconcile` never retries a mutation. If current equals the committed candidate
and the v3 content digest matches, it records `activated` only from exact prior
`activating` lineage and, for an established backend, exact backend-durable
old-current was-active evidence. A pointer move observed from any earlier
journal state is out-of-band and remains `reconcile_required` or becomes
`conflict`; it is never laundered as workflow success. If current remains
expected and the same complete committed candidate exists, reconciliation
records `staged`, releases a same-operation administration lock, and requires a
new DNS proof plus explicit activation. A still-`staging` LDAP root is accepted
only for inspection: exact complete same-operation, same-digest content moves
the journal back to `prepared`; a later explicit `prepare` may seal it. Partial,
missing, or mismatched content stays `reconcile_required` and is never completed
with regenerated keys. If a third
generation is current, the operation becomes `conflict`. Unknown or
historically ambiguous state remains `reconcile_required` for operator
investigation.

`abort` marks an operation terminal only before backend staging or when an
exact noncurrent `staging` candidate is bound to the operation. A committed
candidate, unknown state, activation write-ahead state, or any historical
ambiguity requires reconciliation instead. The initial implementation does not delete
staging generations or private material automatically because current backend
ACLs and retention policy do not grant a safe garbage-collection contract.
The outstanding-candidate limit bounds retained material. A separately
authorized future purge workflow must prove noncurrent history, retention,
backup, and destruction authority before deleting anything.

## Concurrency, Conflict, And Rollback

At most one concurrent operation may activate from the same current
generation. The loser receives `conflict`, rereads authoritative state, and
must create a new operation. Serialization failures, assertion failures,
deadlocks, disconnects, timeouts, and uncertain commits are not retried.

Candidate digest mismatch, missing rows, extra rows, partial staging, changed
current generation, DNS drift, expired proof, journal mismatch, or unknown
state fails closed. There is no stale-candidate activation.

Rollback remains a new complete generation greater than the current one. The
current pointer never moves backward. Onboarding does not delete prior
generations or selectors and does not shorten DNS overlap policy.

## Package Boundaries

- `lib/`: unchanged DKIM2 protocol and provider-neutral runtime contracts.
- `cmd/dkim2d/internal/datasourceadmin`: shared offline administration.
- `cmd/dkim2d/internal/domainadmin`: domain intent, keys, DNS, journal, and
  onboarding state machine.
- `cmd/dkim2d/internal/migration`: legacy OpenDKIM source adapter, reports, and
  unchanged v2 one-shot publication orchestration.
- `cmd/dkim2d/internal/datasource/{ldap,postgresql,mysql,sqlsnapshot}`:
  concrete stable reads, staging, inspection, and activation.
- `cmd/dkim2d/internal/command`: thin Cobra translation and exit boundary.
- `cmd/dkim2ctl`, `cmd/dkim2-milter`, `cmd/dkim2-exim`, OpenAPI-generated code:
  unchanged.

## Security And Privacy

All I/O is context-aware and bounded. TLS verification, exact server identity,
least privilege, protected-path validation, secret erasure, no environment DSN,
no generic URL, and no fallback remain mandatory.

Private keys, PKCS#8, passwords, CA documents, tokens, raw DNS TXT, tenant,
domain, selector, handle, profile, LDAP DN, SQL value, operation path, key
digest usable as a correlator, and protected config never appear in logs,
traces, metrics, generic CLI output, REST, errors, formatting, JSON, panic
messages, or test failures. Error strings are constant and reports use bounded
closed classes.

Here, `JSON` means generic formatting, reports, APIs, and operator output. The
owner-only operation journal's bounded internal JSON codec is the sole explicit
exception for its specified canonical intent, authority descriptor, IDs,
selectors, and operation digests. Journal values never flow through generic
marshalers, formatting, reports, telemetry, errors, or stdout/stderr; private
keys, credentials, CA bytes, raw DNS, provider rows, and key/SPKI digests remain
forbidden even in that codec.

Filesystem abuse coverage includes symlink and hard-link substitution,
permission races, path overlap, replacement across directories, oversized and
multi-document YAML, journal truncation, stale temporary files, and concurrent
writers. Key and snapshot owners clear all retained byte slices on every
failure and on close.

## Observability

Offline administration emits no Prometheus endpoint and creates no OTLP
exporter. Bounded local observations may use only operation class, state,
backend class, algorithm family, result class, failure class, duration bucket,
and count bucket. No identity, path, digest, generation contents, DNS record,
provider address, or raw error is a label or attribute.

The online daemon's existing readiness and datasource refresh observations are
unchanged. Activation is not considered runtime verification until each daemon
has reloaded the new generation and existing external signing evidence passes.

## Required Tests

Unit tests:

- closed intent parsing, canonicalization, limits, and toxic YAML;
- deterministic plan/candidate digests and domain separation;
- selector entropy/alphabet/collision handling;
- RSA/Ed25519 generation, PKCS#8/SPKI equivalence, DNS encoding, and erasure;
- protected journal creation, atomic replacement, resume, and filesystem abuse;
- receipt-before-Claim ordering, closed receipt/journal union loading, atomic
  promotion, ambiguous receipt-save no-mutation, and exact pre-plan
  observe/release crash recovery;
- full `N` to higher `C` clone preserving old logical rows and key bytes;
- duplicate domain/ID/selector, limits, invalid state, and digest conflicts;
- strict state transitions, idempotent same-state retries, and no skipped step;
- DNS parser round trips and every missing/ambiguous/mismatch/expiry failure;
- CLI shape, offline-only dependencies, stable reports, and privacy.

Integration and E2E tests:

- disposable OpenLDAP stage/readback/resume/activate/conflict/crash behavior;
- disposable PostgreSQL, MySQL, and MariaDB parity for the same corpus;
- concurrent operators where only one activation wins;
- real PostgreSQL, MySQL, and MariaDB races using separate physical connectors,
  with a build-tag-only deterministic gate that captures both physical
  connection identities and pauses the holder after its ordered reads; a
  separate privileged disposable observer must prove the exact server-side
  waiter-to-holder lock edge before release, followed by exact winner,
  `CodeConflict` loser, and coherent post-race current/readback assertions;
- PostgreSQL `pg_blocking_pids` plus lock-wait proof, MySQL 8.4 Performance
  Schema data-lock-wait proof, and MariaDB 10.11 InnoDB lock-wait proof, all
  joined through the exact captured connection identities and publication-lock
  object where the backend exposes it;
- fence formatting, serialization, callback detachment/clearing, and complete
  backend error-taxonomy matrices including PostgreSQL mode/lock/context and
  SQLSTATE boundaries;
- exact PostgreSQL definer owner, kind, signature, fixed search path, and ACL
  audits plus direct candidate-root-lock denial for the activation login;
- cancellation and uncertain-commit handling;
- runtime reload/readiness and controlled signing after activation;
- existing OpenDKIM bootstrap and rollback regression coverage.

Generated and documentation checks:

- OpenAPI generated output remains unchanged and current;
- architecture, daemon CLI docs, backend docs, key-rotation runbook, examples,
  help text, package inventory, and release claims agree;
- prompt manifest and ignored ledger are valid and `temp/` remains unstaged.

Final gates:

- focused `go test` and race tests for all touched packages;
- disposable provider integration targets where available;
- `make test`, `make lint`, `make race`, and `make guardrails`;
- `git diff --check`, secret scans, generated checks, and repeated unchanged
  candidate identity.

## Acceptance Criteria

- An operator can plan, prepare, export DNS, prove, activate, inspect status,
  reconcile uncertain outcomes, and abort one native onboarding operation
  without direct LDAP/SQL edits.
- Every backend claim, including pre-plan allocation, has a previously synced
  protected operation identity; no crash can leave an unauthenticated orphan
  claim, and the public lifecycle still begins at `planned`.
- Existing domains and keys survive `N` to higher `C` unchanged in logical content.
- New RSA and Ed25519 credentials round-trip through DNS-04 and native custody.
- No active generation is delta-mutated and no activation bypasses current,
  digest, state, readback, or fresh DNS fences.
- LDAP, PostgreSQL, MySQL, and MariaDB implement the same administrative model.
- Journals and reports are resumable, bounded, fail-closed, and secret-safe.
- Runtime, OpenAPI, Milter, Exim, and `dkim2ctl` contracts remain unchanged.
- Independent review and orchestrator review report no unresolved in-scope
  findings.
- Final guardrails pass on the same unchanged candidate.

## Completion Evidence

Prompt 01-10 evidence is complete in the ignored execution ledger. It includes
focused normal and race tests, hostile filesystem and ambiguity reproducers,
real LDAP/SQL concurrency, digest-pinned disposable LDAP/PostgreSQL/MySQL/
MariaDB onboarding plus activated runtime signing, independent application
signing-service parity, the closed candidate-bound v2 integration report, and
dual independent replacement approval. Exact candidate, tree, raw-diff, report,
timing, and rejected-predecessor identities intentionally remain only in that
ignored ledger to avoid tracked self-reference.

Prompt 11 adds the native onboarding runbook, protected parser-checked example
configuration, cross-document navigation, and a repository-owned documentation
gate. Focused schema, provider, OpenDKIM, documentation, OpenAPI-owner,
boundary, lint, test, race, vulnerability, disposable-service, report, and
candidate-reproduction evidence is retained in the ignored execution ledger.
The known dirty-candidate `module_base` and `security_base` fixed-snapshot
checks remain explicit stops rather than being rewritten or called green.
Fresh independent final review remains pending.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Offline native onboarding only | implemented without REST, `dkim2ctl`, Milter, Exim, or library expansion | done | final release approval remains separate |
| Intent and state | Closed, versioned, resumable | receipt/journal union and public state machine implemented | done | no persisted verified state |
| Datasource | Full clone, stage, inspect, activate | provider-neutral owners plus exact backend adapters | done | active generations remain immutable |
| Keys and DNS | Native keys and fresh exact DNS proof | RSA/Ed25519 generation, protected export, recursive-path proof | done | no DNS mutation or authoritative-query claim |
| Backends | LDAP and SQL-family parity | real LDAP, PostgreSQL, MySQL, and MariaDB evidence | done | exact service report retained outside Git |
| Security | Fail-closed and secret-safe | abuse, ambiguity, redaction, least-privilege, and cleanup evidence | done | final security review remains Prompt 12 scope |
| Tests | Unit, abuse, race, disposable integration | release-proportional Prompt 11 gates and unchanged-byte service evidence complete | done | exact commands, stops, report, and candidate identities retained in ignored ledger |
| Boundaries | `lib`, OpenAPI, clients unchanged | checked throughout implementation | done | OpenAPI remains the unchanged REST authority |
| Effort | Prompt timings retained | exact known spans and honest missing timestamps in ignored ledger | done | variance includes multiple review correction cycles |
| Review | Independent and orchestrator approvals | Prompt 01-10 gates approved; Prompt 11 self-review complete; final independent closeout review not started | partial | no commit or release authority |

## Decisions And Open Questions

- Settled: native onboarding is offline under `dkim2d datasource domain`.
- Settled: `dkim2ctl` and normal OpenAPI remain unchanged.
- Settled: active generations are never delta-mutated.
- Settled: DNS is export-only in this milestone.
- Settled: private keys live in inactive candidate generations, not journals.
- Settled: activation repeats DNS proof and exact backend fences.
- Settled: abort does not delete staging generations in the first release.
- Settled: all four network backends share one administrative semantic model.
- Open: none that blocks implementation.
