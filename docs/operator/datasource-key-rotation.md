# Native Datasource Key Rotation

This runbook defines the supported generation replacement, DNS overlap, key
retirement, and recovery contract for LDAP, PostgreSQL, MySQL, and MariaDB
signing datasources. It does not grant a new mutation surface.

`dkim2d` is an online reader and signer. It never generates keys, edits DNS,
publishes datasource records, or returns private material through REST. The
repository currently provides one end-to-end administrative publisher:
`dkim2d datasource`, whose protected input is an explicitly mapped OpenDKIM
LDAP inventory. A future native key manager may implement the same publication
contract, but direct hand-written LDAP or SQL mutation is unsupported.

## Rotation States

| State | DNS | Datasource | Runtime |
| --- | --- | --- | --- |
| prepare | old selector remains valid; new selector is published | current generation remains unchanged | signs with old generation |
| prove | authoritative DNS serves one valid new key | complete candidate is dry-run validated but inactive | remains ready on old generation |
| activate | old and new DNS records overlap | strictly higher complete generation becomes current | refreshes atomically to new generation |
| observe | both selectors remain published | new generation remains current; old generation retained | signs only with new generation |
| retire | old DNS record is removed after the approved overlap | old generation retained or archived under key policy | remains on new generation |

Never reuse a selector with different key material. Never move the datasource
pointer backward, edit a committed generation, repair an active key in place,
or remove the old DNS record before the new generation is proven active.

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

## Current OpenDKIM-Bridge Procedure

Until the separate key-management project publishes native DKIM2 generations,
the supported repository workflow imports a selected active OpenDKIM key through
the protected offline boundary. This does not create a legacy runtime path:
normal LDAP/SQL loading still accepts only native v2 records.

1. Generate and stage the new key through the authorized OpenDKIM key lifecycle
   system. Keep its private material confined to the existing protected source.
2. Publish a distinct DKIM2 DNS record for the explicit target selector. Do not
   overwrite the old selector. The record must use the DKIM2 DNS format and
   public-key representation expected by the pinned DNS draft.
3. Wait until the authoritative DNS service and the resolver path used by the
   administrative command return exactly one valid new record. Honor the site's
   DNS TTL and negative-cache policy; do not substitute a local hosts entry or
   unverified resolver result.
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

## Retirement

Remove the old DNS selector only after all of these are true:

- every active signer has loaded and repeatedly revalidated the new generation;
- externally observed signatures use the new selector and pass verification;
- the approved overlap covers mail queue delay, DNS TTL, negative caching,
  retry, delayed verification, and incident rollback requirements;
- no active route or retained queued message still depends on the old selector;
- a restorable protected backup and higher-generation rollback plan exist.

Datasource generations are not deleted by guessed age. Retain or archive them
according to the signing-key retention policy. A deletion tool or manual DBA
action must independently prove that the generation is not current, not needed
by an in-flight load, not retained for rollback or audit, and authorized for
destruction. This repository provides no automatic generation garbage
collector.

## Backend Activation Fences

- LDAP publishes the complete generation subtree and advances `cn=current`
  through a critical RFC 4528 assertion over exact expected schema, generation,
  and state.
- PostgreSQL uses one serializable transaction, singleton row lock, complete
  staging/readback, commit-state transition, and forward current-pointer update.
- MySQL and MariaDB first lock `dkim2_publication_lock`, then perform the same
  empty-or-expected proof, staging/readback, commit transition, and forward
  pointer update in one serializable transaction.

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

## Native Key-Manager Boundary

A future key manager can replace the temporary OpenDKIM import source only if it
owns all of the following as one reviewed operation:

- protected RSA/Ed25519 key generation and storage;
- canonical public SPKI and private PKCS#8 production;
- distinct selector allocation and DNS publication;
- authoritative fresh DNS/SPKI proof;
- complete provider-neutral profile, policy, credential, handle, and key rows;
- backend-specific atomic publication and exact readback;
- dry-run, approval, audit, bounded reporting, conflict handling, and
  higher-generation rollback.

It must not add a normal REST key API, write through the online daemon, accept a
generic DSN, create a legacy runtime fallback, or emit private material. Until
that owner exists, native-only key creation outside the documented offline
publisher is unsupported rather than silently delegated to manual LDAP/SQL
edits.
