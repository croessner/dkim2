# Replay Store And Valkey Provider

> Superseded provider record. The directly addressed Valkey provider
> (`cmd/dkim2d/internal/replay/valkey`, valkey-go, auditor principal,
> attestation, revalidation) has been removed and replaced by the
> Redis-compatible provider specified in
> [`replay-store-redis.md`](replay-store-redis.md), with the operator contract
> in [`../../replay-store-redis.md`](../../replay-store-redis.md) and the
> configuration migration in
> [`../../operator/replay-redis-migration.md`](../../operator/replay-redis-migration.md).

The storage-neutral sections that remained current (result states, error
taxonomy, identity derivation, retention, memory provider, disabled provider,
result aggregation, store failure matrix, and privacy) were moved into
[`replay-store-redis.md`](replay-store-redis.md#storage-neutral-contract),
which is the authority conformance cases cite. The historical Valkey provider,
attestation, auditor, and revalidation record is available in the repository
history only and has no current authority.

Language: English.
