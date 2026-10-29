# Replay Store Migration: Valkey Provider To Redis Provider

This guide moves a `dkim2d` deployment from the removed `valkey` replay
backend to the `redis` backend introduced with release v0.2.0. The new
backend uses go-redis v9 and supports standalone, Sentinel, and cluster
topologies of Redis 7.0+ or Valkey 7.2+. The operator contract is
[`../replay-store-redis.md`](../replay-store-redis.md).

v0.2.0 is a breaking configuration change. A v0.1.x configuration that
selects `valkey`, sets any `replay.valkey.*` key, or sets
`replay.revalidate_interval` is refused at startup with
`config_removed_field` and a message naming this guide. There is no automatic
translation and no fallback backend.

Replay semantics do not change: key derivation, epoch, retention, first-seen
and replayed results, the propagation reservation and commit contract, and the
error mapping toward policy stay the same.

## What Changes

- `replay.backend: redis` replaces `valkey` and is the new default.
- Configuration lives under `replay.redis`, shaped like a common
  `storage.redis` block: `mode`, per-mode addresses, `auth`, `tls`, pool,
  timeouts, `retries`, and `health`.
- The auditor principal, the `ACL GETUSER`/`ACL DRYRUN` audit, the operator
  attestation, and the periodic revalidation are removed. Startup instead
  checks reachability, the server version floor, and `noeviction`, and a
  `PING` health probe drives readiness.
- Writes may be retried and may follow Sentinel failover and cluster
  redirects. Every write carries a per-operation nonce so a retry recognizes
  its own earlier commit.
- TLS defaults to a TLS 1.2 minimum (the Valkey provider required TLS 1.3),
  accepts DNS names as addresses, and may be disabled explicitly for a private
  network.

## Key Mapping

| v0.1.x key | v0.2.0 key | Notes |
| --- | --- | --- |
| `replay.backend: valkey` | `replay.backend: redis` | `redis` is the default and may be omitted. |
| `replay.valkey.address` | `replay.redis.standalone.address` | With `replay.redis.mode: standalone` (the default). DNS names are now allowed. |
| `replay.valkey.server_name` | `replay.redis.tls.server_name` | Optional now; empty verifies the dialed host. |
| `replay.valkey.ca_file` | `replay.redis.tls.ca_file` | Optional now; empty selects the system roots. |
| `replay.valkey.application_username` | `replay.redis.auth.username` | Optional; empty authenticates as `default`. |
| `replay.valkey.application_password_file` | `replay.redis.auth.password_file` | Same protected-file rules. |
| `replay.valkey.dial_timeout` | `replay.redis.dial_timeout` | Default `2s`. |
| `replay.valkey.connection_write_timeout` | `replay.redis.write_timeout` | Default `2s`; see also `read_timeout`. |
| `replay.revalidate_interval` | `replay.redis.health.interval` | Different meaning: a `PING` probe cadence, default `5s`. |
| (TLS 1.3 only) | `replay.redis.tls.min_tls_version: TLS1.3` | Set it to keep the previous policy. |
| (no retries) | `replay.redis.retries.max_attempts: 1` | Optional; the default is `3`. |

Environment variables follow the paths: `DKIM2D_REPLAY_VALKEY_ADDRESS`
becomes `DKIM2D_REPLAY_REDIS_STANDALONE_ADDRESS`, and so on. Every
`DKIM2D_REPLAY_VALKEY_*` variable and `DKIM2D_REPLAY_REVALIDATE_INTERVAL`
must be removed from the environment, because their presence alone fails
startup.

## Removed Keys Without Replacement

Delete these keys; they have no v0.2.0 equivalent:

- `replay.valkey.auditor_username`, `replay.valkey.auditor_password_file`;
- `replay.valkey.tcp_keepalive` (the client default applies);
- every `replay.valkey.attestation.*` key: `persistence_mode`,
  `append_fsync_policy`, `save_schedule`, `min_replicas_to_write`,
  `min_replicas_max_lag_seconds`, `loss_window_acceptance`, `rotation_state`,
  `no_global_exactly_once_claim`, `dedicated_deployment`,
  `dedicated_database_zero`, `direct_ip_authority`,
  `no_endpoint_substitution`, `standalone_authority`, `shared_draft`,
  `shared_algorithm`, `shared_namespace`, `shared_epoch`,
  `shared_secret_set`, `shared_retention`.

The facts the attestation declared remain operator responsibilities and are
documented in [`../replay-store-redis.md`](../replay-store-redis.md):
persistence, the asynchronous-replication loss window, the drain-only
rotation rule, and the shared epoch, secret, retention, and namespace across
instances.

## ACL Changes

The auditor user is no longer used; remove it from the server ACL and leave
its password out of the new protected generation.

The application user needs more grants than the previous `+ping +set`:

```text
ACL SETUSER application on resetkeys resetchannels >password-from-protected-file \
  -@all +hello +auth +ping +info +set +get +eval +evalsha \
  ~dkim2:replay:*
```

- `+info` for the startup version and `noeviction` checks;
- `+eval +evalsha +get` for the single-key lease-takeover script (ACL rules
  apply to the `GET` inside the script);
- `+hello +auth` for the RESP3 handshake;
- a key pattern that includes the configured `key_prefix`; the previous
  `~dkim2:replay:v1:*` pattern still covers the unprefixed keys, and
  `~dkim2:replay:*` is the documented form.

Any container or orchestrator health check that used the auditor user must
switch to another user, for example the application user running `PING`.

## Example: Existing Standalone Valkey With TLS

A dedicated Valkey reached over loopback with a private CA and an ACL
application user, previously configured as:

```yaml
replay:
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  valkey:
    address: 127.0.0.1:6380
    server_name: replay.dkim2.internal
    ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/ca
    application_username: application
    application_password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/application-password
    auditor_username: auditor
    auditor_password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/auditor-password
    attestation:
      persistence_mode: rdb
      # ...
```

becomes, in a new protected generation without the auditor password:

```yaml
replay:
  backend: redis
  hmac_key_file: /var/lib/dkim2d/protected/fedcba9876543210fedcba9876543210/hmac
  epoch: 1
  redis:
    mode: standalone
    standalone:
      address: 127.0.0.1:6380
    auth:
      username: application
      password_file: /var/lib/dkim2d/protected/fedcba9876543210fedcba9876543210/application-password
    tls:
      ca_file: /var/lib/dkim2d/protected/fedcba9876543210fedcba9876543210/ca
      server_name: replay.dkim2.internal
      min_tls_version: TLS1.3
    retries:
      max_attempts: 1
```

Keep the same `epoch`, the same HMAC bytes, `database_number: 0` (the
default), and an empty `key_prefix` (the default). Then every record already
in the store stays authoritative: a legacy `v1` first-seen record is still
reported `replayed`. Setting a `key_prefix` here would silently start a new,
empty namespace. `retries.max_attempts: 1` is optional; it keeps the previous
single-attempt behavior and lets a server error reply be reported as
`unavailable` instead of `indeterminate`.

## Example: Shared Plaintext Valkey With `requirepass`

A mail stack that already runs one shared Valkey service on an internal
overlay network, protected by `requirepass` and without ACL users, and whose
`dkim2d` instances used `replay.backend: memory`:

```yaml
replay:
  backend: redis
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  redis:
    mode: standalone
    standalone:
      address: valkey:6379
    auth:
      password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-password
    key_prefix: "mailstack:"
    tls:
      enabled: false
```

- Copy the bytes of the existing Valkey password secret into each daemon's
  new protected generation as `redis-password`; the file must not end with a
  newline.
- `tls.enabled: false` is an explicit plaintext choice for the private
  overlay network only.
- `auth.username` is omitted, so the client authenticates as `default`.
- `key_prefix` separates dkim2d keys from the other applications on the same
  instance. Every daemon that must see the other's replays uses the same
  prefix, epoch, and HMAC secret.
- A Valkey without `maxmemory` runs with the default `noeviction` policy and
  passes the startup check. If the shared instance must evict for other
  applications, it cannot hold replay state.
- Moving from `memory` to `redis` starts with an empty replay memory; the
  in-process records of the previous run are not migrated.

## Rolling Upgrade

The key derivation is unchanged, and v0.2.0 reads the values written by
v0.1.x: legacy `v1` first-seen records are reported `replayed`, and legacy
`pending:<expiry-ms>` propagation records are honored as live leases,
re-served after expiry, and committed. Existing entries therefore stay
authoritative, and daemons can be upgraded one at a time.

The reverse direction is only partly compatible while old and new daemons
share a store; see [Rollback](#rollback). Upgrade every daemon that serves the
propagation routes (`server.dsn_propagate_capability_file`) in one step;
daemons that only serve `/v1/process` may be rolled.

Each upgraded daemon needs:

1. a new immutable protected generation with the data password (and CA or
   client certificate, if used) and without the auditor password;
2. the v0.2.0 configuration above, selecting that generation;
3. the extended application ACL on the server before the daemon starts;
4. a restart, then a `/readyz` check.

## Rollback

v0.1.x cannot read the v0.2.0 configuration: `replay.redis` is an unknown key
and the old default backend requires `replay.valkey`. Roll back by restoring
the previous image, the previous YAML file, the previous protected generation
(including the auditor password), and the previous ACL with the auditor user.

Records written by v0.2.0 behave as follows under a v0.1.x daemon on the same
store:

- First-seen records (`v2:<nonce>`): the old provider sends
  `SET NX PX` without `GET` and treats any existing key as a replay, so these
  records are correctly reported `replayed`.
- `committed` propagation records: identical in both versions.
- Nonce-bearing pending records (`pending:<expiry-ms>:<nonce>`): the old
  value parser does not accept this form. A v0.1.x reservation that meets such
  a record fails as `inconsistent` (temporary failure) and marks the old store
  restart-degraded, so its `/readyz` stays not ready until restart; the same
  happens again on the next encounter. A v0.1.x commit that meets such a
  record still overwrites it with `committed` (the write executes before the
  reply is parsed) but reports `inconsistent`; later operations on that
  coordinate see `committed`.

A nonce-bearing pending record lives until it is committed or until the
replay retention expires; a normally completed propagation commits its record
within `dsn_propagation.pending_lease`. Only coordinates whose propagation
never committed (for example a failed or abandoned propagation) keep the new
pending form, so the exposure after a rollback is limited to those coordinates
and ends with their retention. A rollback never makes a v0.1.x daemon report a
replayed message as first seen.
