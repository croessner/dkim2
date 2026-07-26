# dkim2d

`dkim2d` is the local HTTP/JSON daemon around the standalone DKIM2 library.
The current API is inbound-only: it performs verification, local policy
evaluation, replay coordination, and disposition projection. It does not sign
or revise messages.

The daemon is a thin adapter. Raw RFC 5322/RFC 6532 message bytes, SMTP
envelope evidence, DKIM2 verification, policy, and replay semantics remain
owned by `github.com/croessner/dkim2`. The authoritative REST contract is
[`docs/specs/openapi/dkim2d.yaml`](../../docs/specs/openapi/dkim2d.yaml).

## Local Security Boundary

Run one daemon instance under a dedicated, unprivileged service UID. The
effective UID, local root, and the kernel are trusted. Other local UIDs and
processes that can merely reach localhost are not trusted.

The listener accepts exactly one canonical loopback IP literal and nonzero
port. The default is `127.0.0.1:8080`. Hostnames, wildcard or unspecified
addresses, non-loopback addresses, IPv4-mapped IPv6, zone identifiers, Unix
sockets, port zero, and multiple listeners are rejected. There is no remote
plaintext compatibility mode.

`/v1/process` additionally requires `X-DKIM2-Capability`. The value is the
canonical unpadded Base64url encoding of the exact 32 raw bytes in the current
generation's capability file. Missing, duplicate, malformed, noncanonical, or
mismatching values all receive the same closed `403` response before
readiness, body, DNS, policy, or replay work. `/healthz` and `/readyz` do not
use this header.

Grant capability-file access only to the daemon UID and approved local
adapters. Do not place capability bytes or their encoded form in arguments,
environment variables, logs, traces, metrics, diagnostics, or ordinary
configuration. The current repository does not yet provide the protected
client-side capability loader; that adapter-side owner is a separate delivery.

Loopback HTTP is deliberately plaintext and HTTP/1-only. Do not put a reverse
proxy, TCP forwarder, TLS terminator, container port publication, or other
reachability expansion in front of it.

## Command And Exit Status

Run:

```text
dkim2d serve --config /absolute/path/to/dkim2d.yaml
```

The command accepts no positional arguments. The only configuration flags are:

```text
--listen
--policy-mode
--replay-backend
```

Exit status is `0` for help or a clean shutdown, `2` for command-shape and flag
errors, and `1` for configuration, startup, dependency, serve, or shutdown
failure. Runtime diagnostics are stable and content-free; the daemon does not
print an effective configuration or raw dependency errors.

## Configuration Sources

The required YAML version is:

```yaml
config:
  version: dkim2d-config-v1
```

Configuration precedence is typed defaults, YAML, explicitly bound
environment variables, then the three flags above.
`config.version` and `protected.generation` are YAML-only. Every other stable
path has one explicit `DKIM2D_...` environment name, for example
`DKIM2D_SERVER_LISTEN` and `DKIM2D_REPLAY_HMAC_KEY_FILE`. Arbitrary
environment names are ignored.

Scalar string values may contain one nonrecursive `${NAME}` expansion pass.
Map keys are never expanded. Missing variables fail closed. Secret bytes are
never configuration or environment values; only protected absolute paths may
be supplied.

### Explicitly disabled replay

This is the smallest valid document:

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  backend: disabled
```

Disabled replay is explicit local policy. It loads no replay HMAC, constructs
no replay deriver, and does not silently fall back to another backend.

### Process-local memory replay

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  backend: memory
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
```

Memory replay is bounded but process-local. Restart, multiple daemon instances,
and failover do not share its state.

### Production Valkey replay

Valkey is the default backend, but missing authority or attestation fields
fail configuration; there is no fallback. A complete shape is:

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  valkey:
    address: 127.0.0.1:6379
    server_name: replay.example
    ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/ca
    application_username: application
    application_password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/application-password
    auditor_username: auditor
    auditor_password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/auditor-password
    attestation:
      persistence_mode: rdb
      append_fsync_policy: inactive
      save_schedule: "60 1"
      min_replicas_to_write: 0
      min_replicas_max_lag_seconds: 30
      loss_window_acceptance: asynchronous_acknowledged
      rotation_state: unchanged
      no_global_exactly_once_claim: true
      dedicated_deployment: true
      dedicated_database_zero: true
      direct_ip_authority: true
      no_endpoint_substitution: true
      standalone_authority: true
      shared_draft: true
      shared_algorithm: true
      shared_namespace: true
      shared_epoch: true
      shared_secret_set: true
      shared_retention: true
```

The supported authority is one directly addressed standalone Valkey primary,
database zero, with TLS 1.3, exact peer identity, private roots, separate
application and auditor principals, no retries, and no endpoint substitution.
Cluster, Sentinel, redirects, DNS authority selection, replicas, load
balancers, Unix sockets, active-active products, and automatic failover are
unsupported. See
[`docs/replay-store-valkey.md`](../../docs/replay-store-valkey.md) for the ACL,
persistence, replication, loss-window, and rotation contract.

## Protected Generation

The YAML file and every protected object are owned by the daemon's effective
UID. The YAML file is mode `0400` or `0600`, is outside the generation
directory, has one link, and is inode-distinct from every protected child.

The generation directory:

- is absolute and ends with the exact 32-character lowercase hexadecimal
  `protected.generation` value;
- is mode `0500`, owned by the daemon UID, and has no nontrivial ACL;
- contains every selected protected path as a direct child; and
- is immutable after publication and never reused.

The capability and HMAC files contain exactly 32 raw nonzero bytes, with no
hex, Base64, delimiter, or stripped newline. Password files contain 1 through
1,024 opaque bytes with no NUL, CR, or LF. Secret files are mode `0400` or
`0600`. The CA file contains only the bounded accepted PEM CA set and may use
the documented read-only modes.

Protected loading is supported only where descriptor-native ownership, ACL,
and local-filesystem checks are implemented: Linux on ext4, XFS, Btrfs, or
tmpfs, and Darwin with cgo on APFS or HFS. Network, FUSE, OverlayFS, unknown
filesystems, Darwin without cgo, and other platforms fail closed.

Create a complete new read-only generation directory, then atomically replace
only the YAML file that selects it. There is no hot reload. Activation requires
a process restart.

## HTTP API

Exactly these paths are routable:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/metrics` | Bounded process-local Prometheus exposition |
| `GET`, `HEAD` | `/healthz` | In-process liveness; no dependency I/O |
| `GET`, `HEAD` | `/readyz` | No-I/O readiness snapshot |
| `POST` | `/v1/process` | Verification, policy, replay, disposition |

Health and readiness support their declared strong-ETag conditional behavior.
Readiness is `200` only after immutable configuration and protected loading,
dependency construction, listener and serve ownership, open process
admission, and replay authority are ready. Valkey readiness uses the
provider-owned unexpired audit evidence and performs no Valkey call.

The process request carries bounded Base64 message bytes and separate SMTP
reverse/forward path spellings. After JSON and Base64 validation, the adapter
passes the exact decoded message and UTF-8 envelope spellings to the library;
it does not normalize headers, MIME, EAI, SMTPUTF8, or envelope values.
Malformed mail-domain evidence is represented by the library's bounded domain
result rather than repaired by the HTTP layer.

Every application response has `Connection: close`. Connection reuse,
pipelining, HTTP/2, h2c, generic path cleaning, and redirects are not supported.
All request, connection, body, JSON, envelope, DNS, replay, admission, and
shutdown work is bounded. Error output uses closed status/code mappings and
does not include request bytes, protected values, endpoints, or raw errors.

## Observability

Every daemon instance owns one central JSON `slog` provider, one fresh
Prometheus registry, and one OpenTelemetry provider. None of these use global
registration. Telemetry is nonnormative and cannot change protocol, policy,
replay, HTTP, health, or readiness results.

The secure default uses `info` logging, all debug modules disabled, and no
trace exporter:

```yaml
observability:
  logging:
    level: info
  debug:
    message_shape: false
    dns: false
    replay: false
  tracing:
    exporter: none
```

OTLP/HTTP tracing is explicit and loopback-only:

```yaml
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://127.0.0.1:4318/v1/traces
    ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/otlp-ca
    sample_per_million: 10000
    export_timeout: 5s
```

The endpoint must be canonical loopback HTTPS with `/v1/traces`. The CA is a
protected generation child. TLS 1.3 is required; proxies, redirects, arbitrary
headers, environment-driven exporter configuration, compression overrides,
and remote authorities are rejected.

`GET /metrics` is public on the same loopback listener and does not require
readiness or the process capability. It accepts no body, query, conditional,
trace, or capability input. Scrapes are untraced and nonrecursive, use the
Prometheus 0.0.4 text format, and are capped at 256 KiB. `HEAD /metrics`
returns `405` with `Allow: GET`.

Logs, trace attributes, and metric labels use closed allowlists. They never
contain message bytes, headers, identities, domains, selectors, recipients,
client addresses, request/session/trace IDs, endpoints, DNS payloads, replay
keys, protected paths or values, certificates, credentials, hashes, or raw
errors. Debug modules add only documented bucket or result classes; they do
not enable payload logging. Prometheus labels are fixed low-cardinality enums,
and the registry deliberately omits standard process/runtime collectors.

## Lifecycle And Recovery

Startup publishes readiness only after all selected owners and loops are live.
The outer startup bound is 115 seconds, including a 100-second acquisition
budget, ten-second reverse rollback budget, and five-second orchestration
margin. Any ambiguous or incomplete startup fails without readiness.

Shutdown first withdraws readiness and closes admission, then joins the
listener and serve loop, performs the configured graceful drain, and uses a
bounded forced close when graceful drain or handler quiescence is not proven.
Only after handlers join does it stop revalidation, cancel DNS, close replay,
flush the instance telemetry provider within five seconds, and release
protected material. If an accept or handler owner cannot be joined, the daemon
reports failure and deliberately retains dependencies rather than tearing
them down underneath live work.

Valkey is audited before readiness and revalidated at the configured interval,
which must be 10 through 60 seconds. Calls do not overlap. Evidence is valid
for strictly less than five minutes. Authority loss, stale evidence, or
revalidation-clearable degradation withdraws readiness; restart-only
credential and contract failures require provider reconstruction or process
restart.

## Deliberately Unsupported

The current daemon does not provide:

- signing or revision endpoints;
- Milter or Exim action application;
- a protected generated-client capability loader;
- remote HTTP exposure, TLS serving, proxy trust, Unix sockets, or multiple
  listeners;
- OAuth, bearer tokens, request-selected policy, or remote authentication;
- HTTP/2, h2c, persistent connections, or effective-config output;
- hot configuration, secret, certificate, capability, or replay-key reload;
- Valkey cluster, Sentinel, redirects, endpoint discovery, automatic failover,
  or global exactly-once replay claims.

## Verification

From the repository root:

```text
make test
make vet
make lint
make race
make check-openapi
make check-vendor
make test-valkey
make guardrails
```
