# Replay Store And Valkey Operations

DKIM2 replay detection composes the final Draft-06 authentication result while
leaving message-local signature, hash, recipe, custody, and envelope evidence
immutable. Unexpected replay produces final `FAIL` with reason
`duplicate_message_without_exploded`; ambiguity produces `TEMPERROR`.

The library exposes a storage-neutral `CheckAndRemember` contract with bounded
memory and disabled implementations. The production implementation is owned by
`cmd/dkim2d/internal/replay/valkey` and uses one atomic, non-retryable command:

```text
SET <protected-key> v1 NX PX <retention-milliseconds>
```

An `OK` reply means first-seen and a null reply means replayed. A replay never
extends the existing TTL. Once dispatch may have occurred, a transport failure
is indeterminate and is never retried or followed by a compensating read.

The single key represents the independently reconstructed `m=1` canonical
header and body inputs, not a recipient or terminal route. Authenticated
`exploded` changes a successful store result to the accepted `exploded` class,
but the seen fact is still retained. The synchronous implementation accepts the
first unmarked copy and rejects later unmarked copies during retention; expiry,
process-local memory, asynchronous replication, restore, and cross-site
separation prevent any global exactly-once claim.

## Production Topology

The supported production authority is exactly one directly addressed
standalone Valkey primary:

- use one canonical IP-literal endpoint and database zero;
- do not use DNS aliases, load balancers, Sentinel, Unix sockets, cluster
  routing, replica reads, redirects, or endpoint substitution;
- use Valkey's standalone client mode with retries, client caching, tracking,
  and optional client initialization disabled;
- require TLS 1.3 with exact peer-name verification and an explicit private
  root set;
- use separate authenticated application and auditor principals; and
- dedicate the deployment and database to replay storage.

Cluster production is unsupported. A dependency-managed redirect or topology
refresh could select an authority that was not covered by the current security
audit. Authoritative `MOVED` and `ASK` replies therefore fail closed without
retry.

The production compatibility floor is the database-permission capability
shipped by Valkey 9.1. The auditor proves the exact `ACL GETUSER databases`
field instead of trusting a version banner. The mandatory integration harness
is intentionally pinned to exactly Valkey `9.1.0`.

## Required ACLs

The application principal must have exactly:

```text
on sanitize-payload
-@all +ping +set
~dkim2:replay:v1:*
db=0
```

It must have one password hash, no selectors, and no channel patterns. `AUTH`
and `HELLO` are Valkey pre-authentication behavior, not application grants.
`CLIENT SETINFO`, `SELECT`, `READONLY`, cluster commands, scripts,
transactions, pipelines, reads, TTL mutation, and administrative commands are
not granted. Disabling the default user is recommended defense in depth but is
not part of the production eleven-command readiness proof. The hermetic
integration harness does disable it.

The separate ephemeral auditor principal must be able to authenticate and
perform only the closed security plan:

```text
ROLE
CONFIG GET
INFO
ACL GETUSER
ACL DRYRUN
```

Its effective positive grants are `+role`, `+config|get`, `+info`,
`+acl|getuser`, and `+acl|dryrun` after `-@all`, with database zero selected.
It needs no replay-key grant. Auditor credentials cannot choose or replace the
endpoint, TLS name, root set, dial policy, database, or topology.

The auditor runs one `AUTH` plus ten probes, under two-second command deadlines
and a thirty-second whole-audit deadline. It validates the exact application
ACL structurally and uses `ACL DRYRUN` to prove PING, an in-namespace SET, and
out-of-namespace denial. Its RESP2 parser is bounded and duplicate-preserving;
raw replies and password hashes are discarded without diagnostic rendering.

## Memory, Persistence, And Replication

Configure:

- `maxmemory-policy noeviction`;
- positive finite `maxmemory` from 16 MiB through 1 TiB; and
- free headroom of at least the larger of 16 MiB or ten percent of
  `maxmemory`, rounded upward.

Eviction would convert a previously remembered replay into a false first-seen
result, so an OOM or failed headroom proof degrades the store and requires a
successful revalidation.

Persistence must be explicitly attested as RDB, AOF, or both:

- RDB requires a nonempty exact save schedule and healthy last background save;
- AOF requires `appendfsync always` or `appendfsync everysec`, plus healthy
  last write and background rewrite status; and
- combined mode requires both sets of evidence.

The configured `min-replicas-to-write` value is limited to zero through three.
The maximum accepted replica lag is one through 3,600 seconds. Live CONFIG,
ROLE, and INFO evidence must agree with the operator attestation and show the
required number of healthy replicas.

`SET NX PX` is atomic only on the primary that executes it. Asynchronous
replication, failover, partitions, backup restore, active-active products, and
operator deletion can lose a successful replay record. An uncertain write may
also have committed. The deployment must explicitly acknowledge this loss
window and must not claim global exactly-once behavior.

## Evidence, Recovery, And Rotation

Construction succeeds only after local configuration, credential-free operator
assertions, and the complete privileged audit all pass. The application client
is created only after the auditor is closed.

Security evidence is valid for exactly five minutes. The daemon configuration
and lifecycle layer must call `Revalidate` at least every sixty seconds. Stale
evidence prevents dispatch. Ordinary transient refusals may recover after a
later authoritative success; ACL, authority, topology, persistence,
replication, OOM, and stale-evidence failures require revalidation. Application
credential drift and internal contract failures require provider reconstruction
or process restart.

Draft-05 to Draft-06 migration and every later secret or epoch rotation is
drain-only. The draft identifier is authenticated inside the replay HMAC
frame, so Draft-04 records are intentionally unreachable from Draft-06 even
when the namespace and fixed 68-byte storage-key shape stay unchanged:

1. stop all replay traffic;
2. keep the drained Draft-05 deployment, epoch, and secret authoritative and
   quiescent for the complete thirty-day hard maximum retention;
3. restart every active instance with the new shared epoch and secret set; and
4. resume traffic only after the drain and restart are complete.

Instant, partial, mixed-draft, mixed-instance, dual-epoch, fallback, and online
migration states are unsupported and fail closed. Starting Draft-06 before the
Draft-05 retention window drains creates a bounded replay-detection gap for
old records; it is not a compatible rolling-upgrade mode and must be treated as
an operator policy violation.

## Ownership Of Later Runtime Work

- The daemon configuration and Fx lifecycle layer loads protected
  configuration and trust material, constructs this exact replay store,
  schedules revalidation, and aggregates readiness. It must not create a
  parallel Valkey client or weaken the attestation.
- The central observability runtime adds secret-safe logs, traces, and
  low-cardinality metrics. Replay keys, recipients, endpoints, credentials,
  raw replies, and raw errors are forbidden telemetry attributes and labels.
- The library authenticator composes the final replay state. Milter and Exim
  consume daemon authority and never recompute identity or `exploded`.

## Local Verification

Run the default repository gate and the explicit real-server integration
separately:

```text
make test
make race
make test-valkey
make guardrails
```

`make test-valkey` requires `valkey-server` exactly `9.1.0`; a missing or wrong
binary fails rather than skipping. The target starts a private temporary Unix
socket with TCP disabled, synthetic users and protected keys, finite
noeviction memory, RDB persistence, and no external authority. It executes the
production RESP2 audit plan and provider-parity checks, then terminates the
process and removes its directory on success, failure, timeout, or signal.

## Dependency And Supply-Chain Boundary

The library module has no Valkey or daemon dependency. The
`github.com/valkey-io/valkey-go` dependency is pinned to `v1.0.77`, licensed
under Apache-2.0, vendored reproducibly, and used only by the daemon-owned
Valkey provider. Command modules import the public library facade and never
`lib/internal`.

Use these gates for current evidence rather than treating this document as a
permanent vulnerability assertion:

```text
make check-vendor
make govulncheck
GOFLAGS=-mod=readonly go list -m all
```

Dependency upgrades require explicit review of retry behavior, standalone
routing, result/error provenance, simple-string cache layout, licensing,
vendored output, and vulnerability results.
