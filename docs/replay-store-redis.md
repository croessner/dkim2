# Replay Store And Redis Operations

DKIM2 replay detection is local delivery policy (Draft-08 Section 15.1). It
composes the final Draft-08 authentication result while leaving message-local
signature, hash, recipe, custody, and envelope evidence immutable. Unexpected
replay produces final `FAIL` with reason `duplicate_message_without_exploded`;
ambiguity produces `TEMPERROR`. Only messages carrying more than one
DKIM2-Signature are counted unless `replay.count_direct_deliveries` is set; a
direct delivery carrying only the originator's `i=1` signature reports
`not_eligible` and performs no store command.

The library exposes the storage-neutral `CheckAndRemember` and two-phase
propagation contracts with bounded memory and disabled implementations. The
networked production provider is owned by
`cmd/dkim2d/internal/replay/redisstore`, uses `github.com/redis/go-redis/v9`,
and is selected with `replay.backend: redis`, which is also the default
backend. It speaks to any Redis-compatible server at or above the version
floor below, in standalone, Sentinel, or cluster topology. The provider
semantics are specified in
[`specs/implementation/replay-store-redis.md`](specs/implementation/replay-store-redis.md).
Operators moving from the removed `valkey` backend follow
[`operator/replay-redis-migration.md`](operator/replay-redis-migration.md).

## Server Requirements

- Redis 7.0 or later, or Valkey 7.2 or later. Every first-seen and
  reservation write is `SET ... NX GET PX`, which needs that floor. At startup
  the daemon reads `redis_version` from `INFO server` on every primary and
  refuses to start below 7.0.0; Valkey reports a compatible `redis_version`.
- `maxmemory-policy noeviction` on every primary (see
  [Memory and eviction](#memory-and-eviction)).
- The ACL grants listed in [Required ACLs](#required-acls).
- Scripting enabled for the authenticated user: the lease-takeover
  compare-and-set is a single-key Lua script run through `EVALSHA`, falling
  back to `EVAL` only on `NOSCRIPT`.

The real-server harness (`make test-redis`) runs against the exact
`valkey-server` binary pinned in `build/ci/toolchain.json` (currently 9.1.2).
Other servers above the floor are supported by contract but are not covered by
that evidence; see [`reference/compatibility.md`](reference/compatibility.md).

## Topologies

`replay.redis.mode` selects exactly one topology; keys that belong to another
mode are refused (`config_invalid_backend_matrix`), judged by explicit
presence, never by defaults.

| Mode | Required keys | Behavior |
| --- | --- | --- |
| `standalone` (default) | `standalone.address` | One directly addressed primary. |
| `sentinel` | `sentinel.master_name`, `sentinel.addresses` | The client asks Sentinel for the current master and follows failover. Writes and reads always go to the master; replicas are never used. |
| `cluster` | `cluster.addresses` | Seed nodes; the client discovers slots with `CLUSTER SLOTS`, follows `MOVED`/`ASK` up to `cluster.max_redirects`, and never reads from replicas. `database_number` must be 0. |

Addresses are canonical `host:port` values: a canonical IP literal (IPv6 in
brackets) or a lowercase DNS name, and a decimal port 1 through 65535. DNS
names are resolved by the client. `sentinel.addresses` and
`cluster.addresses` are one comma-separated scalar string
(`host:port,host:port`); elements are trimmed, and empty elements, duplicates,
more than 32 Sentinel or 64 cluster entries, or an element over 255 bytes fail
closed. This is the scalar-only form of a list, used because the strict
configuration pipeline accepts scalars only; the environment overrides
(`DKIM2D_REPLAY_REDIS_SENTINEL_ADDRESSES`,
`DKIM2D_REPLAY_REDIS_CLUSTER_ADDRESSES`) use the same spelling.

### Standalone with TLS and an ACL user

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  backend: redis
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  redis:
    mode: standalone
    standalone:
      address: 10.20.0.5:6380
    auth:
      username: dkim2-replay
      password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-password
    tls:
      ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-ca.pem
      server_name: replay.dkim2.internal
      min_tls_version: TLS1.3
```

`tls.enabled` defaults to `true`; omitting `tls.ca_file` selects the system
roots.

### Sentinel

```yaml
replay:
  backend: redis
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  redis:
    mode: sentinel
    sentinel:
      master_name: dkim2-replay
      addresses: 10.20.0.11:26379,10.20.0.12:26379,10.20.0.13:26379
      username: dkim2-sentinel
      password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-sentinel-password
    auth:
      username: dkim2-replay
      password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-password
    tls:
      ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-ca.pem
      server_name: replay.dkim2.internal
```

The Sentinel password and the data password must be different secrets; the
protected loader refuses equal passwords across roles
(`config_protected_content`). A Sentinel without ACL users may be addressed
with `sentinel.password_file` alone; `sentinel.username` requires
`sentinel.password_file`. The same TLS policy, including `server_name`,
applies to Sentinel connections and to the master connection.

### Cluster

```yaml
replay:
  backend: redis
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  redis:
    mode: cluster
    cluster:
      addresses: 10.20.1.1:6379,10.20.1.2:6379,10.20.1.3:6379
      max_redirects: 8
    auth:
      username: dkim2-replay
      password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-password
    tls:
      ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/redis-ca.pem
      server_name: replay.dkim2.internal
```

Every replay operation touches exactly one key, so keys spread across all
slots and no hash tag is used. `key_prefix` cannot contain `{` or `}` and
therefore can never pin every key to one slot.

### Plaintext on an internal network

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
    key_prefix: "mail:"
    tls:
      enabled: false
```

Plaintext is an explicit operator choice (`tls.enabled: false`). It is
acceptable only on a private network segment that carries no untrusted
traffic, such as an encrypted overlay or a host-local bridge. With TLS
disabled every other explicit `tls.*` key, including
`insecure_skip_verify`, is refused. A password without `auth.username`
authenticates as the server's `default` user (`requirepass`).

## Configuration Reference

All paths are below `replay.redis`; each has the environment override
`DKIM2D_REPLAY_REDIS_<PATH>` with dots replaced by underscores and upper-case
letters (for example `DKIM2D_REPLAY_REDIS_TLS_SERVER_NAME`). `replay.redis.*`
is refused with `replay.backend: memory` and `disabled`.

| Path | Default | Rule |
| --- | --- | --- |
| `mode` | `standalone` | `standalone`, `sentinel`, or `cluster` |
| `standalone.address` | none | required in standalone |
| `sentinel.master_name` | none | required in sentinel; 1 to 128 bytes of `[A-Za-z0-9._-]` |
| `sentinel.addresses` | none | required in sentinel; 1 to 32 comma-separated `host:port` |
| `sentinel.username` | none | optional; requires `sentinel.password_file` |
| `sentinel.password_file` | none | optional protected path |
| `cluster.addresses` | none | required in cluster; 1 to 64 comma-separated `host:port` |
| `cluster.max_redirects` | `8` | 1 to 16 |
| `auth.username` | none | optional ACL user; requires `auth.password_file` |
| `auth.password_file` | none | optional protected path |
| `database_number` | `0` | 0 to 15; must be 0 in cluster |
| `key_prefix` | empty | 0 to 64 bytes of `[A-Za-z0-9._:-]` |
| `protocol` | `3` | RESP `2` or `3` |
| `tls.enabled` | `true` | `false` selects plaintext |
| `tls.ca_file` | none | optional protected path; empty selects system roots |
| `tls.cert` / `tls.key` | none | optional client certificate pair, both or neither |
| `tls.server_name` | none | optional verification name for every node |
| `tls.min_tls_version` | `TLS1.2` | `TLS1.2` or `TLS1.3` |
| `tls.insecure_skip_verify` | `false` | only with TLS enabled; startup warning |
| `pool_size` | `20` | 1 to 1024 connections per node |
| `min_idle_connections` | `2` | 0 to `pool_size` |
| `pool_timeout` | `2s` | 1ms to 30s |
| `dial_timeout`, `read_timeout`, `write_timeout` | `2s` | 100ms to 30s |
| `retries.max_attempts` | `3` | 1 to 10 attempts per command |
| `retries.min_backoff` | `50ms` | at most `max_backoff` |
| `retries.max_backoff` | `500ms` | at most 5s |
| `health.interval` | `5s` | 1s to 60s |
| `health.timeout` | `2s` | at least 100ms and below `interval` |
| `health.failure_threshold` | `3` | 1 to 10 consecutive failures |
| `require_noeviction` | `true` | see below |

`replay.hmac_key_file`, `replay.epoch`, `replay.retention` (default `336h`,
1s to 720h), `replay.limits.*`, and `replay.count_direct_deliveries` keep their
meaning and are shared by all backends. The removed `replay.valkey.*`,
`replay.revalidate_interval`, and backend value `valkey` fail with
`config_removed_field`.

## Required ACLs

The data user needs exactly the commands the provider sends plus the command
run inside its script. Replace `<prefix>` with the configured `key_prefix`
(empty by default):

```text
ACL SETUSER dkim2-replay on resetkeys resetchannels >password-from-protected-file \
  -@all +hello +auth +ping +info +set +get +eval +evalsha \
  ~<prefix>dkim2:replay:*
```

Add `+select` when `database_number` is greater than zero and `+cluster|slots`
in cluster mode. The individual grants are needed for:

- `+hello`, `+auth`: connection handshake. Without `+hello` a RESP3 client is
  refused and the session would silently fall back to RESP2.
- `+ping`: startup reachability and the health probe.
- `+info`: the startup version and eviction-policy checks.
- `+set`: every replay write.
- `+eval`, `+evalsha`, `+get`: the single-key lease-takeover script. ACL
  rules apply to commands called from scripts; the provider itself never sends
  a standalone `GET`.

No `CLIENT SETNAME`, `CLIENT SETINFO`, `CLIENT MAINT_NOTIFICATIONS`,
`READONLY`, `SCRIPT LOAD`, `MULTI`/`EXEC`, `WATCH`, `EXPIRE`, `DEL`, `KEYS`,
`SCAN`, or administrative command is sent. A `NOPERM` reply to the startup
`INFO` fails start with a message naming the required grants. A `NOPERM` on the
script path is reported as a failed operation and makes the store
restart-degraded, so grant `+get` before the first expired propagation lease is
re-served.

The Sentinel user (when Sentinel ACLs are enabled) needs:

```text
ACL SETUSER dkim2-sentinel on resetchannels >sentinel-password-from-protected-file \
  -@all +hello +auth +ping +sentinel|get-master-addr-by-name +sentinel|sentinels \
  +subscribe &+switch-master &+replica-reconf-done
```

The client subscribes to the `+switch-master` and `+replica-reconf-done`
channels to learn about failover; with `acl-pubsub-default resetchannels` (the
Redis 7 default) those channel grants are required. The Sentinel user never
needs replay-key access.

## Memory And Eviction

Eviction would turn a remembered replay into a false `first_seen`, so the
daemon requires `maxmemory-policy noeviction`. At startup it reads
`maxmemory_policy` from `INFO memory` on every primary (the current master in
Sentinel mode, every master in cluster mode) and refuses to start when any
primary uses another policy; the error reports how many primaries violate the
rule. `require_noeviction: false` disables this check and logs one startup
warning (`replay.config.warning`, `config_warning=noeviction_unchecked`); use it only when the server is managed by a platform that hides
`INFO memory` and the operator has verified the policy out of band.

Under `noeviction` a full server answers writes with `OOM`. The daemon reports
that as a temporary replay failure (`TEMPERROR`), never as `first_seen`. Size
`maxmemory` for the replay retention (default 14 days) times the peak rate of
counted messages and propagation coordinates; each record is one key of
`len(key_prefix) + 68` bytes with a value of at most 41 bytes.

Replicas are not checked. A replica that may be promoted by Sentinel or a
cluster failover must use the same policy.

## Persistence, Replication, And The Loss Window

`SET NX GET PX` is atomic only on the primary that executes it. Asynchronous
replication, Sentinel or cluster failover, partitions, backup restore,
active-active products, and operator deletion can lose a successful replay
record; after such a loss the next copy of the message is reported
`first_seen` once more. An indeterminate write may also have committed. The
daemon therefore makes no global exactly-once claim, and neither may a
deployment built on it.

The operator owns the durability choice. Recommended settings:

- RDB, AOF (`appendfsync everysec` or `always`), or both, so a restart does
  not drop the replay memory;
- `min-replicas-to-write` and `min-replicas-max-lag` where a replica exists,
  to narrow the failover loss window;
- backups that are restored only into a stopped replay deployment, accepting
  that records written after the backup are lost.

The daemon does not inspect or attest persistence, replication, or topology
settings; the removed Valkey attestation keys have no replacement.

## Retries And Idempotent Writes

go-redis retries a command after connection loss, dial failure, pool timeout,
or read timeout, and the cluster and Sentinel clients re-route after topology
changes. A blind `SET NX` whose first attempt committed but whose reply was
lost would then observe its own record and report `replayed` for a genuine
first delivery. The provider prevents this by making every write
self-identifying:

- every logical operation draws a 64-bit nonce from `crypto/rand` and embeds
  it in the value it writes (`v2:<nonce>` or
  `pending:<expiry-ms>:<nonce>`);
- every client-level attempt of that operation carries exactly the same
  bytes;
- the write returns the previous value (`GET` option), and a previous value
  equal to the operation's own value proves the operation's own earlier
  commit, which is reported as `first_seen` or `reserved`, never as a replay.

`retries.max_attempts` bounds the attempts per command (`1` disables
retries). `retries.min_backoff` and `retries.max_backoff` bound the
exponential backoff between attempts. When every attempt failed after the
command may have been dispatched, the outcome stays `indeterminate`
(`TEMPERROR`). With more than one attempt, or in cluster mode where redirects
re-send independently of the attempt budget, even a server error reply cannot
prove that no earlier attempt committed, so availability errors are also
reported as `indeterminate`.

## Health Probe And Readiness

Startup is synchronous and must pass before readiness is published:

1. `PING` every primary;
2. `INFO server` on every primary: `redis_version` at least 7.0.0;
3. `INFO memory` on every primary: `maxmemory_policy` is `noeviction`, unless
   `require_noeviction: false`.

Authentication (`NOAUTH`, `WRONGPASS`), permission (`NOPERM`), version,
eviction-policy, malformed-reply, and reachability failures each fail start
with a content-free message that never contains an address, username, or
server text.

After publication a start-to-start health loop sends `PING` to every primary
every `health.interval`, bounded by `health.timeout` (cluster: one `PING` per
current master; any failing master counts as one probe failure). The probe
never writes a replay key.

`/readyz` performs no I/O. The replay authority is ready while the store is
open and carries no recovery fact:

- a transient fact is set after `health.failure_threshold` consecutive probe
  failures and by a replay operation that failed with a recoverable condition
  (network failure, timeout, `OOM`, `READONLY`, `LOADING`, `MASTERDOWN`,
  `CLUSTERDOWN`, `TRYAGAIN`, `BUSY`, unresolved `MOVED`/`ASK`, the
  connection-limit rejection `ERR max number of clients reached`, and
  similar);
  it is cleared by the next successful probe or successful replay operation,
  so `/readyz` returns to ready without a restart once the server is
  reachable again;
- a restart fact is set by authentication or permission failures, replies
  outside the closed value grammar, other server errors, and internal
  invariant failures (including a contained panic during a health probe); it
  is sticky until the daemon restarts.

While not ready the HTTP readiness probe fails, and replay-counted requests
that still reach the daemon fail closed with `TEMPERROR`.

## Key Prefix And Shared Instances

Every storage key is `key_prefix` followed by the 68-byte derived key
`dkim2:replay:v1:<epoch>:<digest>`. A shared Redis or Valkey instance may
serve dkim2d and other applications when:

- dkim2d uses its own ACL user restricted to `~<prefix>dkim2:replay:*`, or the
  instance is trusted as a whole;
- the instance runs with `noeviction` (a shared cache that needs eviction must
  not hold replay state);
- daemon instances that must detect each other's replays use the same
  `key_prefix`, `database_number`, epoch, HMAC secret, and retention.

Changing `key_prefix` or `database_number` makes every existing record
unreachable, exactly like an epoch change; see
[Secret and epoch rotation is drain-only](#secret-and-epoch-rotation-is-drain-only).

## TLS

- `tls.server_name` is one verification name used for every node the client
  connects to: the standalone primary, every Sentinel, the Sentinel-reported
  master, and every cluster node. Each certificate must carry that name as a
  SAN.
- When `tls.server_name` is empty, each connection verifies the host part of
  the address it dials. Sentinel-reported masters and cluster nodes are
  usually announced by IP address, so their certificates then need IP SANs
  for every announced address.
- `tls.ca_file` is a protected CA bundle; empty selects the system roots.
- `tls.cert` and `tls.key` configure an optional client certificate for
  mutual TLS; the pair must match and the leaf must be currently valid.
- `tls.min_tls_version` is `TLS1.2` by default. The removed Valkey provider
  required TLS 1.3; set `TLS1.3` to keep that policy.
- `tls.insecure_skip_verify: true` disables certificate verification. It is
  accepted only with TLS enabled, logs one startup warning
  (`replay.config.warning`, `config_warning=tls_insecure_skip_verify`) without
  any address, username, or secret, and is meant for short diagnostics, never
  production.

## Credentials

Passwords, the CA bundle, and the client certificate pair are children of the
protected generation (`config_protected_content` on malformed or inconsistent
material). Password files contain 1 through 1,024 opaque bytes without NUL,
CR, or LF. The data password, the Sentinel password, and the datasource
password must be pairwise distinct, and none may equal a 32-byte key.

Residency in daemon memory:

- The data password stays as bytes in a provider-owned vault. go-redis asks
  for it on every dial; it then exists as a Go string only for that handshake.
  `Close` clears the vault and refuses later dials.
- The Sentinel password is accepted by go-redis only as a string option, so it
  remains as an immutable string for the life of the store. This is an
  accepted residual.
- The parsed client private key stays inside the TLS configuration for the
  life of the store.

No credential, address, key, value, or raw server error appears in logs,
traces, metrics, REST output, or error text; go-redis internal logging is
discarded.

## Replay Identity Contract

The single key represents the authenticated `m=1` Message-Instance hash
declarations (SHA-256 preferred, SHA-512 only when no SHA-256 pair exists),
not a recipient or terminal route. The key is derived with HMAC-SHA-256 under
the deployment-local 32-byte `replay.hmac_key_file` secret and the nonzero
`replay.epoch`, and has the fixed shape `dkim2:replay:v1:<epoch>:<digest>`
(68 ASCII bytes, eight lowercase hexadecimal epoch digits, 43-character
base64url digest). Authenticated `exploded` changes a successful store result
to the accepted `exploded` class, but the seen fact is still retained. The
synchronous implementation accepts the first unmarked copy and rejects later
unmarked copies during retention; expiry, process-local memory, asynchronous
replication, restore, and cross-site separation prevent any global
exactly-once claim.

Delivery-status propagation records share the store, namespace, epoch,
secret, retention, and key shape, but are derived under the distinct
`dkim2-replay-propagation-v1` frame, so a `/v1/process` record and the
propagation record of the same notification never collide.

The key derivation did not change with the Redis provider. Records written by
the removed Valkey provider stay authoritative under the same epoch, secret,
`database_number: 0`, and empty `key_prefix`; their legacy values (`v1`,
`pending:<expiry-ms>`) are read as foreign records.

### Draft upgrades are in place

A draft upgrade, such as Draft-07 to Draft-08, keeps the replay epoch and HMAC
secret and is the supported, non-disruptive path: replace the daemon release
with the same shared epoch and secret and keep serving traffic. No drain,
quiescent retention wait, or epoch change is required.

This is safe because the draft identifier is a length-delimited field of the
replay HMAC frame (`replayHMACFrame` in `lib/internal/replay/deriver.go`) for
both the `dkim2-replay-v2` first-seen frame and the
`dkim2-replay-propagation-v1` propagation frame. The provider prepends only
the configured `key_prefix` to the derived key. Under one secret and epoch, a
key written by one draft and a key looked up by another draft therefore differ
unless HMAC-SHA-256 collides. `TestReplayKeysSeparateDrafts` pins this
separation against the production deriver. Records of the previous draft are
never misread and never overwritten; they stay in the same namespace until
their own TTL expires, bounded by the configured retention.

The only protection lost is continuity with records written before the
upgrade:

- A message first seen under the previous draft and replayed after the upgrade
  can be reported `first_seen` once more, and only if it still verifies and
  passes policy under the new draft. A message that no longer verifies never
  reaches the store. The second acceptance writes a new-draft record, so every
  later copy is detected as a replay again. The exposure ends when the
  previous draft's record would have expired.
- A delivery-status propagation coordinate reserved or committed under the
  previous draft is not visible after the upgrade, so a notification already
  propagated before the upgrade may be propagated once more. Propagation is
  at-least-once, so this stays inside its contract.

Upgrade every daemon instance that shares the store as one release. Instances
of different drafts sharing a store cannot corrupt each other's records, but
while both run each draft detects replays only among its own records. Keep that
overlap to the restart itself. A rollback to the previous draft is the same
in-place operation in reverse, with the same bounded continuity loss.

### Secret and epoch rotation is drain-only

Changing the HMAC secret, the epoch, the `key_prefix`, or the
`database_number` makes every existing record unreachable. When the change
must not lose replay continuity, it is drain-only:

1. stop all replay traffic;
2. keep the drained deployment, epoch, and secret authoritative and quiescent
   for the complete thirty-day hard maximum retention;
3. restart every active instance with the new shared settings; and
4. resume traffic only after the drain and restart are complete.

Instant, partial, mixed-instance, dual-epoch, fallback, and online rotation
states are unsupported. Rotating early creates a replay detection gap bounded
by the configured retention for every message seen before the rotation.

Moving between topologies (for example standalone to cluster) is a data
migration of the operator's server estate, not a dkim2d feature: copy keys
with their remaining TTL, or accept the same bounded continuity gap.

## Local Verification

```text
make test
make race
make test-redis
make guardrails
```

`make test-redis` requires the pinned `valkey-server` binary; a missing or
wrong binary fails rather than skipping. The harness runs private temporary
servers with synthetic users and protected keys and covers standalone with TLS
and an ACL user, Sentinel with a forced failover, and a three-primary cluster
with keys on all slots, plus the provider-parity and propagation suites. The
Guardrails workflow runs the same target in its `redis-integration` job
against a TLS-enabled build of the pinned Valkey commit; see
[`ci.md`](ci.md).

## Dependency And Supply-Chain Boundary

The library module has no Redis, Valkey, or daemon dependency. The
`github.com/redis/go-redis/v9` dependency is pinned to `v9.22.0` (BSD-2-Clause)
with its transitive `go.uber.org/atomic` `v1.11.0` (MIT), vendored
reproducibly, and imported only by `cmd/dkim2d/internal/replay/redisstore`
(`github.com/redis/go-redis/v9` and its `maintnotifications` package).
`TestRedisDependencyBoundary` pins the version, module checksums, vendor
section, license hashes, and import ownership. Client-side caching,
OpenTelemetry instrumentation (`redisotel`), maintenance notifications, and
`CLIENT SETINFO` are not used.

Use these gates for current evidence rather than treating this document as a
permanent vulnerability assertion:

```text
make check-vendor
make govulncheck
GOFLAGS=-mod=readonly go list -m all
```

Dependency upgrades require explicit review of retry and redirect behavior,
reply and error typing, credential handling, licensing, vendored output, and
vulnerability results.
