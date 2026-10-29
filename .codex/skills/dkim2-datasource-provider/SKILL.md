---
name: dkim2-datasource-provider
description: Design and review DKIM2 datasource and replay-store providers. Use when work touches signing profiles, selector-to-key mapping, private-key handles, domain or tenant policy, Redis/Valkey replay storage, flat-file, LDAP, PostgreSQL, MySQL, or MariaDB providers, provider errors, context bounds, redaction, or fail-closed datasource behavior.
---

# DKIM2 Datasource Provider

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`, especially
`Datasource Provider Model` and `Replay Store Model`.

## Boundary Rules

- Keep datasource interfaces in library/domain-owned contracts.
- Keep concrete providers in service modules or explicit provider packages.
- Do not leak LDAP, SQL, flat-file, Valkey, Redis, or driver-specific types into
  protocol packages.
- Expose private keys through signing handles or callbacks, not raw bytes,
  except isolated test fixtures.
- Make all operations context-aware, bounded, typed, observable, and
  secret-safe.
- Missing, ambiguous, malformed, unauthorized, unavailable, degraded, and
  inconsistent states must be distinguishable.

## Replay Store Rules

- Default production replay backend is the Redis-compatible provider
  (`cmd/dkim2d/internal/replay/redisstore`, go-redis v9; Redis 7.0+ or
  Valkey 7.2+ in standalone, Sentinel, or cluster) behind a storage-neutral
  interface. It is the only package that may import go-redis.
- Use intent-level operations such as `CheckAndRemember`, not Redis-shaped
  APIs in domain code.
- Keep every networked write retry-safe: embed the per-operation nonce from
  the library value grammar and treat a previous value equal to the own value
  as the operation's own commit; keep unprovable outcomes `indeterminate`.
- Keep the value grammar (`v2:<nonce>`, `pending:<expiry-ms>:<nonce>`,
  `committed`, legacy `v1` and `pending:<expiry-ms>`) in `lib/internal/replay`.
- Use single-key commands only, pinned through explicit argument vectors
  (`PX`, never `EX`); no pipelines, transactions, or standalone reads.
- Use privacy-preserving replay keys with algorithm/version markers.
- Store no raw messages, raw recipients, raw local parts, private keys, tokens,
  protected config, or raw provider keys.
- Treat Redis/Valkey async replication and failover windows as operational
  risk handled by local policy, not as protocol behavior.

## Provider Test Expectations

- Fake providers for deterministic unit tests.
- Table-driven tests for every typed provider state.
- Integration tests may use real provider processes when useful.
- Abuse tests for slow providers, ambiguous records, malformed records,
  unauthorized data, and degraded replay storage.

## Completion Check

Report the provider boundary, error states, redaction decisions, and tests run.
