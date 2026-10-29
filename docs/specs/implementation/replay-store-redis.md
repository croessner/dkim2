# Replay Store Redis Provider

Status: current implementation specification for the replay store: the
storage-neutral library contract, the memory and disabled providers, daemon
result aggregation, and the networked `dkim2d` Redis-compatible provider. It
supersedes the removed Valkey provider record
[`replay-store-valkey.md`](replay-store-valkey.md), whose still-valid
storage-neutral sections now live under
[Storage-Neutral Contract](#storage-neutral-contract).

Language: English.

## Source Documents

- `AGENTS.md` and `POLICY.md`;
- `docs/ARCHITECTURE.md` Section 7.5 and resolved decision 10;
- `docs/replay-store-redis.md` (operator contract);
- `docs/operator/replay-redis-migration.md` (configuration migration);
- `docs/specs/implementation/replay-store-valkey.md` (superseded provider
  record stub).

## Scope

In scope:

- `cmd/dkim2d/internal/replay/redisstore`: the go-redis v9 provider
  implementing `dkim2.ManagedReplayStore` and
  `dkim2.ReplayPropagationStore` for standalone, Sentinel, and cluster
  topologies;
- the nonce-bearing value grammar owned by `lib/internal/replay` and exposed
  through the root facade (`NewReplayNonce`, `ReplayFirstSeenValue`,
  `ParseReplayFirstSeenValue`, `ReplayPropagationPendingValue`,
  `ParseReplayPropagationValue`);
- the `replay.redis` configuration subtree in `cmd/dkim2d/internal/config`
  and the removed-field guidance for the Valkey provider.

Out of scope: protocol semantics, Prometheus pool metrics, client-side
caching, and replica reads. The storage-neutral contract below is shared by
every provider and is not changed by the Redis provider.

## Storage-Neutral Contract

Replay detection is local policy outside DKIM2 cryptographic correctness. The
library (`lib/internal/replay`, exposed through the root facade) owns the
replay identity, key derivation, retention, closed results and errors, and
the memory and disabled providers. Providers never see raw message,
signature, or envelope facts; they see only the protected storage key.

### Closed Results And Errors

`ReplayCheck` has exactly the successful states `first_seen` (the store
atomically created the record with its retention), `replayed` (the record
already existed and its retention was not changed), and `disabled` (an
explicitly disabled provider performed no storage operation). `disabled` is
not equivalent to `first_seen`.

The replay error taxonomy is exactly `invalid_request`, `misconfigured`,
`limit_exceeded`, `unavailable`, `indeterminate`, `inconsistent`,
`cancelled`, `deadline_exceeded`, `closed`, and `internal_invariant`.
`ReplayStoreState` is exactly `ready`, `degraded`, `disabled`, `closing`, and
`closed`. Every operation returns either one valid result and a nil error or
a zero result and one typed replay error; a nonzero result with an error, a
zero result without one, an unknown enum, or a contained panic is a contract
violation. Errors format only as their stable code and never wrap raw client,
server, network, address, credential, key, or context text. Once a write may
have been dispatched, a timeout, cancellation, connection loss, client close,
panic, or other non-authoritative failure is `indeterminate` and never
unwraps to caller cancellation.

### Identity Derivation

One Draft-08 replay identity is message-wide: it represents the authenticated
`m=1` Message-Instance hash declarations (SHA-256 preferred, SHA-512 only
when no SHA-256 pair exists), not a recipient or terminal route. It exists
only for an aggregate current PASS and is constructed only from the
verifier's sealed projection; callers cannot build it from public values or
digests. The authenticated `exploded` bit is a bounded policy fact; messages
authenticated only by the originator's `i=1` signature are direct deliveries
and are counted only when `replay.count_direct_deliveries` is enabled.

The deriver uses HMAC-SHA-256 (`dkim2-replay-hmac-sha256-v2`) with one
exactly 32-byte non-zero deployment-local secret and one non-zero 32-bit
epoch. The HMAC input is the domain-separation label, `0x00 0x02`, then the
length-delimited fields `0x01 uint32be(len) draft-identifier` and
`0x02 uint32be(32) origin-digest`. First-seen keys use the label
`dkim2-replay-v2`; delivery-status propagation keys use
`dkim2-replay-propagation-v1`, so the two record families never collide. The
draft identifier is a frame field, so keys of different drafts are unrelated
under one secret and epoch. The storage key is exactly
`dkim2:replay:v1:<epoch>:<digest>`: eight lowercase hexadecimal epoch digits
and the 43-character unpadded base64url HMAC, 68 ASCII bytes in total. A
provider may prepend only its configured `key_prefix`.

The protected key has no exported bytes or string accessor. The only backend
seam is `UseReplayStorageKey`, which invokes a pre-dispatch command builder
exactly once, contains callback panics as `internal_invariant`, and passes
only typed replay errors. Changing the secret, epoch, `key_prefix`, or
`database_number` makes every existing record unreachable; rotation is
drain-only as documented in `docs/replay-store-redis.md`.

### Retention

Retention is an explicit validated value: positive, an exact whole number of
milliseconds, at least one second, at most thirty days, and fourteen days by
default. Conversion to signed 64-bit milliseconds and in-memory expiry
addition are checked for overflow. Zero, negative, sub-millisecond,
over-limit, and overflowing values fail as `invalid_request` before store
access. A replay never extends or replaces the original expiry. At the exact
expiry boundary the old observation is expired and the next atomic operation
may become first seen. The Redis provider additionally enforces its
configured minimum and maximum retention window before dispatch.

### Memory Store

The memory provider is deterministic, bounded, and process-local:

- one map indexed by protected key plus an expiry min-heap, one-to-one, so
  cleanup never scans the whole map;
- an injected nondecreasing clock, read exactly once per admitted
  operation; a nil clock is `misconfigured`, and a zero reading, panic, or
  backwards reading is `internal_invariant` before mutation and publishes
  degraded state;
- default and hard caps: entries 65,536 / 1,048,576, waiters 1,024 / 65,536,
  prune budget 4,096 / 65,536 heap removals per operation; zero selects the
  default and out-of-range values are `misconfigured`;
- context-aware serialization of only the short map and heap critical
  section, rechecked after acquisition, with no provider goroutine;
- expired entries (expiry not after the operation time) are pruned before
  capacity is evaluated; at capacity the operation is `limit_exceeded` and
  never evicts an unexpired entry;
- concurrent same-key calls have exactly one `first_seen` winner and only
  `replayed` successes afterwards;
- a result that linearized before cancellation or close stays
  authoritative; Close publishes closing, rejects new work as `closed`,
  drains admitted work within its context, and clears map and heap exactly
  once.

### Disabled Policy

`replay.backend: disabled` selects the explicit disabled provider. While open
it answers every valid request with `disabled` without key derivation,
caller-proportional allocation, clock access, network I/O, or mutation, and it
requires no HMAC secret or epoch. A nil or terminal context still fails before
the disabled success. Close is idempotent. It never returns `first_seen`. The
daemon coordinator with a disabled backend derives no key, calls no store, and
reports the replay class `disabled` with the unchanged policy disposition.

### Result Aggregation

`ReplayCoordinator` maps one domain result to exactly one replay class and
final disposition:

- not applicable or not an aggregate current PASS: `not_checked`, no store
  call;
- disabled backend: `disabled`, policy disposition;
- not counted by local policy: `not_eligible`, policy disposition, no store
  call;
- every key is derived before the first store call; an identity or
  derivation failure is `indeterminate` (`tempfail`) with no store call;
- otherwise the keys are checked sequentially, and the batch is never
  stopped early by an ordinary result. Any indeterminate check makes the
  aggregate `indeterminate` (`tempfail`); else an authenticated `exploded`
  message is `exploded` with the policy disposition; else any `replayed`
  check makes the aggregate `replayed` (`reject`); else the aggregate is
  `first_seen` with the policy disposition.

A `disabled` or zero result from an enabled store is a contradiction and is
`indeterminate`. The outcome records whether a store mutation may have
occurred, which decides whether a later caller cancellation may still surface
as a transport error (no possible mutation) or must be reported as
`indeterminate` (possible mutation).

### Store Failure Matrix

The coordinator classifies each store failure without retaining the raw
error. Every failure yields `indeterminate` with `tempfail`; only the
possible-mutation fact differs:

| Store result | Possible mutation |
| --- | --- |
| `limit_exceeded`, `unavailable`, `closed` | no |
| `invalid_request`, `misconfigured`, `indeterminate`, `inconsistent`, `internal_invariant` | yes |
| `cancelled` / `deadline_exceeded` matching the caller context | no, the caller error is returned |
| `cancelled` / `deadline_exceeded` not matching the caller context | yes |
| a non-taxonomy error, or a nonzero result together with an error | yes |

Raw store errors never reach logs, REST output, or the returned error.


## Redis Store

### Boundary

The provider is the only package that imports `github.com/redis/go-redis/v9`
(and its `maintnotifications` package, used only to disable the feature). It
depends on the root `github.com/croessner/dkim2` facade and the standard
library only; it never imports `lib/internal` or the daemon configuration
package. The daemon builds a plain `redisstore.Config` and borrows
`redisstore.Secrets` from the protected generation; `NewStore` copies what it
retains. `Config`, `Secrets`, `Store`, and the nonce render one constant
string under every formatting verb and refuse text and JSON marshaling.

### Client construction

One concrete client per store, selected by mode:

- standalone: `redis.NewClient`;
- Sentinel: `redis.NewFailoverClient` with `ReplicaOnly`, `RouteByLatency`,
  `RouteRandomly`, and `UseDisconnectedReplicas` all false, so commands go to
  the Sentinel-reported master only;
- cluster: `redis.NewClusterClient` with `ReadOnly`, `RouteByLatency`, and
  `RouteRandomly` false, `DisableRoutingPolicies` true (no `COMMAND` fetch),
  and `MaxRedirects` from `cluster.max_redirects`.

Every client sets `DisableIdentity` (no `CLIENT SETINFO`), an empty client
name, `ContextTimeoutEnabled`, the configured RESP protocol, pool, timeout,
and backoff options, `MaxRetries = max_attempts - 1` (`-1` for one attempt),
and disables maintenance notifications (the Sentinel client hard-wires
`ModeDisabled`). Credentials come from `CredentialsProviderContext`, which
reads the data password from a provider-owned vault on every dial. The
Sentinel password is passed as the `SentinelPassword` string option. The
go-redis process logger is replaced once, at package initialization, by a
discarding logger, because go-redis log lines carry addresses and raw error
text.

The store reaches the client only through a narrow internal seam: `Do` for
pinned argument vectors, the `redis.Scripter` subset required by
`redis.Script.Run`, `PING` on every primary, a sequential per-primary `INFO`
callback, and `Close`. No pipeline, transaction, `WATCH`, `EXPIRE`, `DEL`,
standalone `GET`, or `SetArgs` builder is used; a source guard test enforces
the allowed builders.

### Commands

Every key is `key_prefix` concatenated with the 68-byte storage key obtained
through `dkim2.UseReplayStorageKey`. Retention and lease values are whole
milliseconds; `PX` is always spelled out because `SetArgs` would emit `EX` for
whole seconds.

```text
first seen:   SET <key> v2:<nonce> NX GET PX <retention-ms>
reserve:      SET <key> pending:<expiry-ms>:<nonce> NX GET PX <retention-ms>
takeover:     EVALSHA <sha> 1 <key> <observed> <replacement> <retention-ms>
              (EVAL with the same source only after NOSCRIPT)
commit:       SET <key> committed XX GET KEEPTTL
```

The takeover script is single-key and therefore cluster-safe:

```lua
local current = redis.call('GET', KEYS[1])
if current == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
end
return current
```

It replaces the record only when it still holds the exact observed value and
always returns the value it found.

### Value grammar

`lib/internal/replay` owns the closed grammar; the provider only renders and
parses through the facade.

| Family | Written form | Accepted forms |
| --- | --- | --- |
| first seen | `v2:<nonce>` | `v2:<nonce>`, legacy `v1` |
| propagation pending | `pending:<expiry-ms>:<nonce>` | nonce form, legacy `pending:<expiry-ms>` |
| propagation committed | `committed` | `committed` |

`<nonce>` is exactly 16 lowercase hexadecimal characters encoding 8 non-zero
bytes from `crypto/rand`; uppercase digits are refused so equality of the
rendered string is a sound own-value test. `<expiry-ms>` is a positive
decimal Unix millisecond instant of at most 16 digits with no sign or leading
`+`. Every other string, and every reply over 4 KiB, is outside the grammar.
Legacy forms are never written; they are accepted only as foreign records so
that entries written by the removed Valkey provider stay authoritative.

### Nonce and own-value rule

Each logical operation draws one nonce before command construction and
builds one immutable argument vector. All client-level attempts, redirects,
and failover re-sends of that command carry identical bytes. A previous value
equal to the operation's own value therefore proves that an earlier attempt of
the same operation committed. A failing nonce source is an internal invariant
(restart fact) and nothing is dispatched.

### First seen

`CheckAndRemember` validates the retention against the configured minimum and
maximum, then maps the `SET NX GET PX` reply:

- nil reply: `first_seen`;
- own value: `first_seen` (own earlier attempt committed);
- any other valid first-seen value (`v1` or a foreign `v2:<nonce>`):
  `replayed`; the existing TTL is never extended;
- any other value: `inconsistent`, restart fact.

### Propagation reserve and takeover

`ReservePropagation` stamps the lease expiry in UTC wall time and maps the
first write:

- nil or own value: `reserved`;
- `committed`: `already_committed`, no further write;
- valid pending value with a live lease: `pending`;
- valid pending value with an expired lease: run the takeover script against
  exactly the observed value;
- anything else: `inconsistent`, restart fact.

Takeover reply mapping:

- the observed value or the operation's own replacement: `reserved`;
- nil: `indeterminate`, transient fact (the record expired between the two
  writes and nothing provable was reserved);
- another valid propagation value: the competitor's state (`pending` or
  `already_committed`), never `reserved`;
- anything else: `inconsistent`, restart fact.

### Commit rule

`CommitPropagation` issues `SET committed XX GET KEEPTTL`:

- any syntactically valid propagation value (legacy or nonce pending, own or
  foreign, or `committed`): `committed`, so a retried commit is idempotent;
- nil: `commit_unresolved` (the daemon answers `409`);
- anything else: `inconsistent`, restart fact.

Residual: a retried commit whose earlier attempt committed but whose record
then expired before the retry reports `commit_unresolved`.

### Error and recovery mapping

Recovery facts are independent bits. A transient fact is cleared by the next
successful operation or successful health probe; a restart fact is sticky for
the life of the store.

| Condition | Replay error | Recovery |
| --- | --- | --- |
| context cancelled or past deadline before dispatch | `cancelled` / `deadline_exceeded` | none |
| store closing or closed | `closed` | none |
| admission queue full | `limit_exceeded` | none |
| invalid retention, lease, or nil request | `invalid_request` | none |
| non-server error after possible dispatch (dial, pool timeout, timeout, EOF, context during I/O, closed client) | `indeterminate` | transient |
| server `NOAUTH`, `WRONGPASS`, `NOPERM` | `unavailable` | restart |
| server `OOM`, `READONLY`, `MASTERDOWN`, `CLUSTERDOWN`, `LOADING`, `NOREPLICAS`, `MISCONF`, `TRYAGAIN`, `BUSY`, `MOVED`, `ASK` | `unavailable` | transient |
| server `ERR max number of clients reached` (matched on that constant prefix) | `unavailable` | transient |
| any other server error, or an error token that is not 1 to 32 bytes of `[A-Z][A-Z0-9_]*` | `inconsistent` | restart |
| reply type or value outside the grammar | `inconsistent` | restart |
| panic after dispatch | `indeterminate` | restart |
| builder, callback, or nonce-source failure before dispatch | `internal_invariant` | restart |

A server error reply proves only that its own attempt did not execute.
`unavailable` is therefore reported only when the client can dispatch the
write at most once, that is `retries.max_attempts: 1` outside cluster mode.
With more attempts, or in cluster mode where the client re-routes network
failures independently of `MaxRetries`, every `unavailable`-class server
error is reported as `indeterminate` with the same recovery class, because an
earlier attempt may have committed. The error kind is the leading token of the
server message; the suffix is never inspected or rendered. The single
exception is the connection-limit rejection, which shares the generic `ERR`
token and is recognized only by its constant prefix; go-redis retries it like
the other transient kinds.

### Admission and lifecycle

The admission gate bounds concurrent operations by
`replay.limits.max_in_flight` and waiting callers by
`replay.limits.max_admission_waiters`. `Close` publishes closing, rejects new
work, waits for admitted work to drain within the caller context, closes the
client once, and clears the credential vault. Construction and cleanup panics
are contained as `internal_invariant`. `State` and `AuthorityReady` are
lock-free and perform no I/O; `AuthorityReady` is lifecycle ready with no
recovery fact.

### Startup checks

`NewStore` runs the checks synchronously and returns a store only when all
pass; on failure it closes the client.

1. `PING` every primary (standalone: the address; Sentinel: the reported
   master; cluster: every master through `ForEachMaster`).
2. For every primary, sequentially and in address order: `INFO server`
   (`redis_version` must parse as `major.minor.patch` with major at least 7)
   and, unless `require_noeviction` is false, `INFO memory`
   (`maxmemory_policy` must be `noeviction`). `INFO` replies over 64 KiB or
   without the field are malformed. Violations of one requirement are counted
   across all primaries before failing, so the reported count is
   deterministic.

Failures are a `*redisstore.StartupError` with a closed reason
(`unavailable`, `authentication`, `permission`, `unsupported_version`,
`eviction_policy`, `malformed_reply`), a violation count, and a constant
message. The permission message names the required data-user grants. The
error unwraps to `unavailable` for reachability and to `misconfigured` for
every other reason.

### Health probe

`Store.Probe` runs one `PING` on every primary under `health.timeout` without
consuming a replay admission slot. Success resets the consecutive-failure
count and clears the transient fact; the `health.failure_threshold`-th
consecutive failure sets the transient fact. A panic inside the probe, or a
missing client, is contained as `internal_invariant` and publishes the restart
fact, as for write dispatch. A restart fact is never cleared.
The daemon drives `Probe` from a start-to-start loop at `health.interval`
that keeps the lifecycle ordering of the previous revalidation loop
(construct, activate, publish, stop and join before the store closes). Probe
failures never terminate the loop; only cancellation or an internal invariant
does.

### Configuration mapping

`cmd/dkim2d/internal/config` validates `replay.redis` and exposes it through
the redacted `RedisConfig` view; the daemon copies it into
`redisstore.Config`. Mode-dependent presence is judged by explicit operator
presence (`config_invalid_backend_matrix`), typed values by
`config_invalid_field`. The provider validates the same invariants again in
`Config.Validate` and refuses violations as `misconfigured`. Protected roles
are `protectedRedisPassword`, `protectedRedisSentinelPassword`,
`protectedRedisClientCertificate`, and `protectedRedisClientKey`, each
selected only when configured, plus the shared CA role for `tls.ca_file`. The
loader proves the configured inventory exactly, a matching and currently
valid end-entity client certificate pair, and pairwise-distinct passwords.

Removed configuration fails with `config_removed_field` and guidance naming
`docs/operator/replay-redis-migration.md`:

- the `replay.valkey` subtree in YAML and every `DKIM2D_REPLAY_VALKEY_*`
  environment variable;
- `replay.revalidate_interval` and `DKIM2D_REPLAY_REVALIDATE_INTERVAL`;
- the value `valkey` of `replay.backend` from YAML, environment, or the
  `--replay-backend` flag.

### Privacy

Replay inputs and storage artifacts are protected metadata. No raw message,
header, body, sender, recipient, `Message-ID`, Message-Instance,
DKIM2-Signature, selector, nonce, protected or hashed replay key, HMAC secret,
or raw store error appears in replay storage values, logs, traces, metrics,
REST or CLI output, or test failure output. The coordinator, its outcome, the
deriver, keys, identities, and every store render as constant redacted text
and refuse JSON and text serialization; one coordinator is safe for
concurrent reuse. HMAC provides keyed pseudonymization and domain separation
only while the secret stays protected; it does not make an exposed key safe
to log.

For the Redis provider: keys, values, nonces, addresses, usernames, passwords, certificates, and raw
server or client errors never appear in logs, traces, metrics, REST or CLI
output, or error strings. Errors are the closed replay taxonomy or the
constant startup messages above. Replay runtime construction emits one
`WARN` record `replay.config.warning` through the central observability
logger for each of `tls.insecure_skip_verify: true`
(`config_warning=tls_insecure_skip_verify`) and `require_noeviction: false`
(`config_warning=noeviction_unchecked`), before the store connects; the
records carry only allowlisted closed fields and never an address, username,
path, or secret.
Credential residency (password bytes per dial, the Sentinel password as an
immutable string residual, the parsed client key inside the TLS
configuration) is documented in `docs/replay-store-redis.md`.

## Required Tests

- lib grammar: rendering, parsing, legacy forms, rejection matrix, and fuzzed
  parsers;
- provider unit tests against an in-process fake: the full reply and error
  mapping matrix, own-value recognition for all three operations, takeover
  outcomes, admission and close, privacy, panic containment, and the
  forbidden-source guard;
- retry reproducer: a transport that commits and then drops the reply must
  yield `first_seen`, `reserved`, or `committed` through the real go-redis
  retry loop, never `replayed`, including the expired-lease takeover through
  `EVALSHA` and the `NOSCRIPT`-to-`EVAL` fallback; an EOF followed by a dial
  error yields `indeterminate`; a connection-limit rejection is retried, and
  exhausted rejections are `indeterminate` with only the transient fact,
  which a successful probe clears;
- daemon composition test with log capture: one `replay.config.warning` per
  weakened setting and no configured address, username, or secret in the
  logs;
- startup and probe threshold tests;
- configuration tests for every path, matrix rule, protected role, and
  removed-field source;
- `make test-redis` (build tag `redisintegration`) against the pinned
  `valkey-server`: standalone with TLS and an ACL user, Sentinel with a forced
  failover, and a three-primary cluster.
