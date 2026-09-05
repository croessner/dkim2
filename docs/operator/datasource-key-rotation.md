# Native Datasource Key Rotation

This runbook defines the supported generation replacement, DNS overlap, key
retirement, bounded retention, and recovery contract for LDAP, PostgreSQL,
MySQL, and MariaDB signing datasources. It does not grant an online mutation
surface.

`dkim2d` is an online reader and signer. It never generates keys, edits DNS,
publishes datasource records, or returns private material through REST. For a
previously absent domain, the primary native key-generation and publication
workflow is
[`docs/operator/native-domain-onboarding.md`](native-domain-onboarding.md)
under the offline `dkim2d datasource domain` command. It does not rotate an
already-present domain or retire an old selector automatically. The protected
OpenDKIM import below remains a separate legacy bridge for explicitly mapped
existing key custody. Direct hand-written LDAP or SQL mutation remains
unsupported.

## Rotation States

| State | DNS | Datasource | Runtime |
| --- | --- | --- | --- |
| prepare | old selector remains valid; new selector is published | current generation remains unchanged | signs with old generation |
| prove | the configured recursive resolver path returns one valid new key | complete candidate is dry-run validated but inactive | remains ready on old generation |
| activate | old and new DNS records overlap | strictly higher complete generation becomes current | refreshes atomically to new generation |
| observe | both selectors remain published | new generation remains current; old generation retained | signs only with new generation |
| retire | old DNS record is removed after the approved overlap | old generation retained or archived under key policy | remains on new generation |

Never reuse a selector with different key material. Never move the datasource
pointer backward, edit a committed generation, repair an active key in place,
or remove the old DNS record before the new generation is proven active.

## Scheduled Global Campaign

`dkim2d datasource rotation run` is the offline normal rotation path. It
freezes every eligible active binding from one exact current generation,
prepares and seals one complete higher immutable candidate, then exports and
proves its DNS records in bounded batches. DNS batches never create additional
generations. `current` advances exactly once only after every frozen binding
has fresh proof; a partial batch, stale proof, changed current pointer, or
ambiguous backend result stops in reconciliation and cannot activate.

The command is dry-run by default. A normal mutation requires both
`--automatic` and one bare `--apply`. The separately named `emergency` command
requires one exact binding, a closed incident reason, and one bare `--apply`.
It never becomes normal-campaign progress. A fresh datasource administration
lock serializes normal and emergency ownership, so either path conflicts while
the other remains open.

## Preconditions

Before any mutation:

1. Record the exact current schema version and generation through a
   secret-safe count/state readback.
2. Confirm daemon health and readiness, successful recent datasource refresh,
   empty or understood mail queues, and working external DNS resolution.
3. Create restorable encrypted backend and configuration backups. Treat them as
   signing-key backups.
4. Establish the deployment's required maintenance/change window and identify
   rollback authority.
5. Prepare distinct inventory, protected-import, DNS publication, datasource
   publisher, and runtime credentials. Do not broaden the runtime principal.
6. Choose a candidate generation strictly greater than current and an explicit
   expected-current fence equal to the observed current generation.
7. Choose a new canonical selector. The new private key, public SPKI, DNS
   record, handle ID, and datasource credential must all refer to that exact
   selector and key pair.

## Legacy OpenDKIM-Bridge Procedure

The legacy bridge imports a selected active OpenDKIM key through the protected
offline boundary. Use it only when OpenDKIM remains the authorized source of
the exact key being migrated; use native onboarding for a previously absent
domain. The bridge does not create a legacy runtime path:
the bridge continues to publish native v2 generations. LDAP, PostgreSQL,
MySQL, and MariaDB runtime loading accepts exact complete committed native v2
or v3 generations. Neither workflow authorizes in-place rotation of an active
generation.

1. Generate and stage the new key through the authorized OpenDKIM key lifecycle
   system. Keep its private material confined to the existing protected source.
2. Publish a distinct DKIM2 DNS record for the explicit target selector. Do not
   overwrite the old selector. The record must use the DKIM2 DNS format and
   public-key representation expected by the pinned DNS draft.
3. Separately confirm authoritative publication, then wait until the recursive
   resolver path used by the administrative command returns exactly one valid
   new record. The command creates a fresh process-local provider but does not
   claim to bypass positive or negative caches inside that resolver. Honor the
   site's DNS TTL and negative-cache policy; do not substitute a local hosts
   entry or unverified resolver result.
4. Prepare a new migration plan based on
   [`opendkim-migration.md`](opendkim-migration.md):
   - set `generation` to the strictly higher candidate;
   - set `expected_current` to the exact active generation;
   - select the target backend;
   - set `source_selector` to the exact new OpenDKIM source selector;
   - set `selector` to the explicit new DKIM2 DNS selector;
   - assign new opaque handle IDs and complete explicit policy facts.
5. Run the default dry-run and machine report. Require complete inventory,
   mapping, protected key import, public/private equivalence, DNS/SPKI proof,
   candidate validation, and expected-current validation. Reports contain only
   bounded counts and closed states.
6. Review the candidate and invoke the same plan with `--apply`. Do not modify
   the plan between approved dry-run and apply.
7. The publisher stages and reads back the complete public and private v2
   generation, commits it, and advances the backend-specific current fence.
   Any conflict, cancellation, partial write, uncertain commit, or readback
   mismatch fails without retry.

Example command sequence:

```text
dkim2d datasource bootstrap-opendkim --config /secure/rotation.yaml
dkim2d datasource bootstrap-opendkim --config /secure/rotation.yaml --machine
dkim2d datasource bootstrap-opendkim --config /secure/rotation.yaml --apply
```

The configuration and every selected CA/password file remain owner-only
protected files. Do not place private keys in the plan or command line.

## Activation Proof

After apply:

1. Read back only the current schema, generation, committed state, and bounded
   object counts from the authoritative backend.
2. Wait for each daemon instance to complete a successful refresh. Require
   `/readyz` success and no degraded datasource operation.
3. Send a controlled outbound message through every signing route. Verify that
   the emitted selector and algorithms match the candidate and that external
   DKIM2 verification passes.
4. Verify the inbound preservation/verification path where deployed and check
   queues, Milter health, daemon restarts, and bounded datasource metrics.
5. Repeat readiness and signing proof after at least one additional configured
   reload interval. Do not treat a single startup load as rotation stability.

The old generation and DNS record remain available during this observation
period. Runtime signing never mixes generations: an operation leases exactly
one immutable local snapshot.

### Delivery-status profiles during rotation

A forwarding domain's `delivery_status` profile rotates under exactly the same
overlap, higher-generation, and retirement rules as its transit profile. Roll
them in the same campaign: a generation that activates a new transit selector
while retiring the old `delivery_status` selector leaves the domain able to
sign forwarded copies but unable to propagate a delivery-status notification
back to the previous hop, which the propagation route reports as `permerror`
with `propagation_failure: unprovisioned_domain`.

A previous hop's own key rotation is outside this deployment's control and is
a documented limit rather than a failure to repair. Propagation verifies the
previous hop's signature over the reconstructed state, with the Draft-06
Section 8.4 window evaluated at the completion signature's `t=`, before that
hop's `mf=` may become a recipient. If the previous hop rotated its key away
between forwarding and the arrival of the notification, propagation is refused
permanently; retrying, relaxing verification, or delivering unsigned is not
offered.

## Retirement

Remove the old DNS selector only after all of these are true:

- every active signer has loaded and repeatedly revalidated the new generation;
- externally observed signatures use the new selector and pass verification;
- the approved overlap covers mail queue delay, DNS TTL, negative caching,
  retry, delayed verification, and incident rollback requirements;
- no active route or retained queued message still depends on the old selector;
- a restorable protected backup and higher-generation rollback plan exist.

Datasources are never deleted by guessed age or as an activation side effect.
Use `dkim2d datasource rotation purge plan` to create a protected, read-only
plan from an exact inventory, then separately review it before
`dkim2d datasource rotation purge apply --plan <path> --apply`. Purge requires
its own distinct provider authority, the exact plan and inventory/current
fence, verified backups, and compact receipt reconciliation. It cannot select
the current generation, an open/partial/foreign generation, required rollback
history, or legacy history without explicit compatibility policy. LDAP removes
only exact noncurrent subtrees leaf-first; SQL invokes one fixed definer
routine and reconciles uncertain commits through exact target/receipt readback.
No automatic periodic purge is claimed by this reference candidate.

An operator can retire a verified nonactivating campaign only with
`dkim2d datasource rotation abort --config <path> --journal <path> --apply`.
The bare `--apply` token is required; it first records exact immutable terminal
abort evidence through the closer authority, then persists the journal abort.

## Backend Activation Fences

- LDAP publishes the complete generation subtree and advances `cn=current`
  through a critical RFC 4528 assertion over exact expected schema, generation,
  and state.
- PostgreSQL uses one serializable transaction, singleton row lock, complete
  staging/readback, commit-state transition, exact committed candidate-root
  lock, and forward current-pointer update.
- MySQL and MariaDB first lock `dkim2_publication_lock`, then perform the same
  empty-or-expected proof, lock the exact committed candidate root through the
  fixed activation procedure, perform canonical readback, and advance the
  pointer in one serializable transaction.

For established SQL backends, require this observed order in test or audit
evidence: physical singleton lock, locked current read, exact candidate-root
lock, canonical full-generation readback, mutation. A v2 current pointer must
carry no operation or digest metadata. A v3 current pointer must match the
root's valid operation and equal nonzero 32-byte root/pointer digests. A stale
current digest, missing candidate root, foreign operation, changed candidate
digest, or stale administration revision must fail before mutation. Qualify
each SQL family with two simultaneous activators on separate physical
connectors. Qualification must deterministically observe the holder after the
ordered reads, capture both physical transaction identities, dispatch the
waiter's locked read, and use a separate disposable privileged connection to
prove the exact server-side waiter-to-holder edge before releasing the holder.
Use `pg_blocking_pids` plus lock-wait state on PostgreSQL, Performance Schema
data-lock waits on MySQL 8.4, and InnoDB lock waits on MariaDB 10.11. Exactly
one may win, the loser must return `CodeConflict`, and the committed current
and candidate readback must remain coherent. PostgreSQL may classify SQLSTATE
`40001` as that conflict only for the live locked administration/current fence
read of an activation transaction. Candidate-root, unlocked, nonactivation,
canceled, deadline-expired, deadlock, and generic backend failures remain
unavailable.

Publishers do not automatically retry conflicts, serialization failures,
disconnects, deadlocks, or uncertain commits. Re-read authoritative state and
prepare a new explicit operation instead of assuming success or absence.

## Rollback And Emergency Recovery

Rollback is a new forward publication of previously approved logical content:

1. Keep or restore the prior DNS selector.
2. Set `expected_current` to the currently active generation.
3. Choose a new generation greater than both the current and the failed
   candidate.
4. Reconstruct the prior mapping and protected keys through an authorized
   source, then rerun fresh DNS/SPKI proof.
5. Dry-run, review, and invoke:

```text
dkim2d datasource rollback --config /secure/rotation.yaml --generation <new-generation>
```

6. Repeat the complete activation proof. Never point `cn=current` or a SQL
   singleton back to the old generation number.

If a publisher stops after staging but before activation, the unreachable
generation is inert. If authoritative state is uncertain, stop further
publication, retain evidence, and inspect through protected authority. A
pointerless nonempty backend or an LDAP first-publication current entry left in
`staging` is corruption requiring explicit repair; it is not an empty target or
implicit success.

If private material may have been exposed, treat the event as key compromise:
stop affected signing, revoke access, create a new key and selector, publish a
new DNS record, activate a higher generation, remove the compromised DNS record
under the incident policy, rotate credentials, audit replicas/backups, and do
not reuse the compromised key.

## Native Domain-Onboarding Operator Boundary

The boundary below is implemented by the offline
[`docs/operator/native-domain-onboarding.md`](native-domain-onboarding.md)
workflow. Its implementation candidate still requires independent closeout
review and does not itself authorize a release or production rollout.

The native domain-onboarding operator surface can replace the temporary
OpenDKIM import source only when it owns all of the following as one reviewed
operation:

- protected RSA/Ed25519 key generation and storage;
- canonical public SPKI and private PKCS#8 production;
- distinct selector allocation and DNS publication;
- separately confirmed authoritative publication and fresh recursive-path
  DNS/SPKI proof;
- complete provider-neutral profile, policy, credential, handle, and key rows;
- backend-specific atomic publication and exact readback;
- dry-run, approval, audit, bounded reporting, conflict handling, and
  higher-generation rollback.

It does not add a normal REST key API, write through the online daemon, accept a
generic DSN, create a legacy runtime fallback, or emit private material.
Native-only key creation outside the documented offline workflow remains
unsupported rather than silently delegated to manual LDAP/SQL edits.
