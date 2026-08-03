# Native Domain Onboarding

This runbook provisions one exact signing domain into an LDAP, PostgreSQL,
MySQL, or MariaDB native datasource. It uses the offline privileged
`dkim2d datasource domain` command family. It does not start the daemon, add a
REST administration route, update DNS, or authorize a release.

The durable behavior contract is
[`docs/specs/implementation/native-domain-onboarding.md`](../specs/implementation/native-domain-onboarding.md).
Backend installation remains in
[`docs/operator/datasource-backends.md`](datasource-backends.md), and existing
generation rotation and rollback remain in
[`docs/operator/datasource-key-rotation.md`](datasource-key-rotation.md).

## Safety Model

The public operation lifecycle starts at `planned`:

```text
planned -> preparing -> prepared -> staged -> dns_exported -> dns_proven -> activating -> activated
```

Before `planned`, the protected operation path may contain an internal
planning receipt. This receipt-before-Claim ordering durably records the
operation and expected administration revision before any backend lock claim.
The receipt is not a public lifecycle state. It is one member of a closed
receipt/journal union and never contains private keys, selectors, allocated
generations, profile or handle identifiers, plan digests, or candidate
digests.

The internal receipt phases are `claim_pending`, `allocating`,
`release_required`, `unresolved`, and `closed`. A `closed` receipt is retained
as an idempotent recovery tombstone. A later `plan` may replace it only through
an exact ownerless-revision compare-and-swap for a newly allocated operation.
Receipt status, reconcile, and abort output is bounded and identity-free.

There are exactly two SHA-256 digest domains. `PlanDigest` binds the key-free
plan, complete source projection, authority, DNS policy, allocated identifiers,
and operation. `CandidateContentDigest` binds the complete v3 candidate,
including canonical private PKCS#8. Prepared and staged evidence are separate
types carrying equal candidate-content-digest bytes. Lifecycle state and
monotonic `was active` history are separately fenced metadata and are not
digest inputs. Exact framing and golden-vector compatibility are owned by the
durable specification and repository tests.

No onboarding state represents runtime or mailflow verification: there is no persisted verified state.
`runtime_smoke_required=true` in a successful
`activate` or activation-recovery `reconcile` report is an instruction to run
external post-activation verification, not a claim that it already passed.

## Prerequisites

Before starting:

1. Install the v3 schema and least-privilege grants described in the backend
   guide. PostgreSQL and MySQL-family deployments must apply their forward
   `003_native_domain_onboarding.sql` upgrade; LDAP must deploy the complete
   schema, indexes, and state-conditioned ACL bundle together.
2. Provision three different administration credentials: snapshot, staging,
   and activation. They must use different principals or roles and different
   password bytes. Runtime and legacy publisher credentials are not substitutes.
3. Back up the current pointer, every retained generation, native key material,
   schema metadata, administration-lock metadata, and protected operation
   directory. Test restore before relying on it.
4. Confirm the backend has capacity for another outstanding candidate. The
   default hard ceiling is eight and ambiguity counts as outstanding.
5. Select a stable deployment-unique `authority_id`. Do not change it, the
   endpoint, TLS identity, base/database/schema, role identities, or trust
   anchors during an operation. Such configuration drift is a conflict, even
   if it names the same backend content.
6. Prepare an owner-only local directory on an approved local filesystem.
   Directories are mode `0700`; configuration, intent, secrets, journal, and
   DNS export files are mode `0600`. Symlinks, hard links, unsafe parents,
   network filesystems, relative paths, and path aliases are rejected.

Start from the parser-checked examples:

- [`docs/operator/examples/dkim2d-domain-admin-ldap.yaml`](examples/dkim2d-domain-admin-ldap.yaml)
- [`docs/operator/examples/dkim2d-domain-intent.yaml`](examples/dkim2d-domain-intent.yaml)

The LDAP administration example is a shape example. Replace its documentation
address, CA path, suffix, principals, passwords, and deployment-unique
authority ID. Equivalent SQL documents use `backend: postgresql`, `mysql`, or
`mariadb` and the exact database, schema, and three roles documented in the
backend guide. Configuration scalar environment placeholders are expanded
once before typed validation; missing values and placeholders in map keys fail
closed.

## End-to-End Procedure

The examples below use these protected absolute paths:

```sh
admin=/run/dkim2/domain-admin/admin.yaml
intent=/run/dkim2/domain-admin/domain.yaml
operation=/run/dkim2/domain-admin/operation.json
records=/run/dkim2/domain-admin/records.zone
```

The variables are illustrative shell conveniences. Every CLI argument is still
an absolute, clean path.

### 1. Plan

```sh
dkim2d datasource domain plan \
  --config "$admin" --intent "$intent" --operation "$operation" --machine
```

`plan` observes the administration revision, syncs the internal receipt before
Claim, claims with the receipt operation, inventories collisions and bounded
higher generations, and atomically promotes the receipt to a key-free
`planned` journal. It performs no key generation or candidate stage.

An exact retry may resume `claim_pending` or `allocating`, or return the
matching `planned` journal. `release_required` and `unresolved` never resume
allocation. After an ambiguous protected save, the command reopens the union
and trusts only the fresh exact receipt or journal; it performs no backend
mutation from the stale in-memory phase.

### 2. Inspect Status

```sh
dkim2d datasource domain status \
  --config "$admin" --operation "$operation" --machine
```

`status` is read-only. Before planning completes it reports only bounded
receipt presence, phase, backend class, and lock relation. It does not expose
the operation, authority, revision, path, domain, selector, digest, or DNS
material and does not synthesize `planned`.

### 3. Prepare And Stage

```sh
dkim2d datasource domain prepare \
  --config "$admin" --operation "$operation" --machine
```

`prepare` records `preparing`, generates the requested keys in memory, builds a
complete higher-generation clone, records `prepared` with its content digest,
stages the complete candidate, performs canonical private/public readback, and
seals it `committed` before reporting `staged`. The backend stores v3 operation
and content-digest metadata. Active generations are never delta-mutated.

The prepared-without-backend crash case is intentionally not recoverable from
the journal because private keys are not escrowed there. If prepared evidence
exists but the exact backend candidate does not, reconciliation ends the
operation as `failed` with `key_recovery_unavailable`; create a new plan and
new keys.

### 4. Export DNS

```sh
dkim2d datasource domain dns export \
  --config "$admin" --operation "$operation" \
  --output "$records" --machine
```

The output is a protected file, never stdout. It contains deterministic
DNS-04 zone-file presentation with TXT chunks no longer than 200 ASCII octets.
All chunks for a key form one TXT RR. RSA uses PKCS#1 public DER in `p=`;
Ed25519 uses the raw 32-byte public key. The exporter round-trips the record
through the repository DNS parser and back to the staged SPKI.

Publish the records through separately authorized DNS tooling. Confirm the
authoritative data and wait for positive and negative cache policy before the
next step. The onboarding command neither mutates DNS nor claims direct
authoritative success.

### 5. Prove The Resolver Path

```sh
dkim2d datasource domain prove \
  --config "$admin" --operation "$operation" --machine
```

`prove` creates a fresh process-local resolver provider and requires exactly
one usable matching key for every staged credential. It proves the configured
fresh recursive resolver path; it is not an authoritative DNS query and does
not claim cache bypass. NXDOMAIN, NODATA, multiple RRs, malformed or revoked
records, algorithm/SPKI mismatch, timeout, cancellation, or transport failure
does not advance state.

### 6. Activate Explicitly

```sh
dkim2d datasource domain activate \
  --config "$admin" --operation "$operation" --apply --machine
```

The bare `--apply` token is mandatory. Activation repeats the fresh resolver
proof, rechecks current, committed state, exact canonical readback, candidate
digest, operation, administration lock, proof lifetime, and forward generation.
It syncs `activating` lineage before the pointer mutation. For an established
backend it first records backend-durable `was active` evidence for the exact old
current. Empty-backend first publication uses one atomic current insert or LDAP
Add after proving there is no pointer, generation, public row, or key row.

### 7. Verify Externally

```sh
dkim2d datasource domain status \
  --config "$admin" --operation "$operation" --machine
```

Require `activated`, exact current equals candidate, success, and
`runtime_smoke_required=true` from the activation result. Then wait for every
daemon to reload the new generation and run controlled external signing and
mailflow verification using the existing generated-client or deployment smoke
workflow. Record that evidence outside the onboarding journal.

## Recovery And Reconciliation

Use `status` first, then use `reconcile` only against the same protected config
and operation path:

```sh
dkim2d datasource domain reconcile \
  --config "$admin" --operation "$operation" --machine
```

Reconciliation observes before deciding and never blindly retries Stage or
Activate. The pre-plan rules are deliberately asymmetric:

- `release_required` is write-ahead evidence. Only explicit `reconcile` may
  retry exact same-operation `Release` after authoritative exact-owner proof.
- Ownerless unchanged `R` never closes `release_required`; owner absence without
  revision advance is not release proof.
- Ownerless `R+1` closes `release_required` without another release attempt.
- Explicit reconcile may close `unresolved` plus authoritative ownerless exact
  `R`; this performs no `Release` and does not transition through
  `release_required`.
- Unattributed ownerless `R+1` keeps `unresolved`, because no durable lineage
  attributes that revision advance to the operation.
- Foreign ownership, malformed evidence, another revision, or unavailable
  authority remains `unresolved` and mutation-free.

For a public operation, exact activating lineage plus current candidate and
matching digest may reconcile to `activated`. Without that write-ahead lineage,
an out-of-band pointer move is never accepted as success. If current is still
expected and the exact committed candidate remains, reconcile returns to
`staged`, releases only an exact same-operation administration lock, and
requires a new proof and explicit activation. A third current becomes
`conflict`. Exact LDAP `staging` content may return to `prepared` for an
explicit later seal; partial or mismatched content remains
`reconcile_required`.

LDAP administration-lock recovery is revisioned. Claim and Release use the
root `dkim2AdminLockOwner` and `dkim2AdminRevision` assertion contract; receipt
classification never infers success from owner absence alone. SQL backends use
the equivalent row-lock and revisioned routines.

## Abort, Conflict, And Retry

```sh
dkim2d datasource domain abort \
  --config "$admin" --operation "$operation" --machine
```

`abort` is non-destructive. It may mark a planned operation or an exact
noncurrent staging candidate `aborted`, but it does not delete generations or
private material. A committed candidate, `activating`, ambiguous history, or
unknown state requires reconcile. Before pre-plan claim cleanup, abort first
syncs `release_required` and directs the operator to explicit reconcile.

`conflict`, `failed`, and `aborted` are terminal public states.
`reconcile_required` is nonterminal and permits only status and reconcile. A
concurrent loser does not reuse its plan; start a new plan from the new current.
There is no `--force`, fallback provider, stale-candidate activation, selector
reuse, automatic deletion, or backward pointer movement.

## Candidate Retention And Rollback

Outstanding candidates include noncurrent `staging`, never-active noncurrent
`committed`, and any generation that cannot be classified exactly.
Conservative v2 history without exact backend-durable `was active` evidence is
outstanding indefinitely. Aborted candidates still count because their key
material remains. A noncurrent committed v3 generation with exact `was active`
evidence is retained rollback history and does not consume the onboarding
ceiling.

Cleanup is not part of onboarding. When the ceiling is reached, stop and use a
separately reviewed retention/destruction procedure with verified backups.
Rollback is always higher-generation rollback: republish known-good prior
content under a new generation greater than current through the documented
`dkim2d datasource rollback` workflow. Never move the pointer backward and
never edit a retained generation.

## Backend And Credential Notes

- LDAP requires the schema, indexes, layout, and state-conditioned ACLs to be
  deployed as one reviewed unit. Snapshot reads complete native private
  material; staging can create and seal only exact v3 staging content;
  activation can mark old-current history and move current but cannot write
  candidate content. The legacy v2 publisher cannot write v3 metadata.
- PostgreSQL uses the v3 upgrade routines and exact definer/search-path/ACL
  contract. MySQL and MariaDB use fixed definer routines and exact routine
  grants. Direct table writes and direct candidate-root locks are denied.
- Private readback is canonical: PKCS#8 is reparsed, re-encoded, matched to
  canonical public SPKI, and included in the independently recomputed content
  digest. Count-only or public-only inspection is insufficient.
- Authority-ID lifecycle is operational state. Rotating an authority ID,
  endpoint, TLS name, CA, LDAP base, database/schema, or role identity while an
  operation exists is configuration drift and requires investigation rather
  than bypass.

## Privacy And Evidence

Generic reports and telemetry never contain domains, tenants, selectors,
profile/handle/operation IDs, authority IDs, paths, digests, raw DNS, LDAP DNs,
SQL text, endpoints, credentials, private keys, or unbounded errors. Only the
explicit protected DNS export contains DNS records. Default observations are
bounded enum, phase, result, failure, duration, and count facts.

Retain for review: the exact command sequence and exit statuses, bounded
machine reports, protected backup/restore evidence, DNS change approval,
external runtime/mailflow smoke result, datasource service qualification
report, candidate identity, and release gates. Do not copy protected operation
files, raw DNS exports, private material, or credentials into Git or generic
logs.
