# dkim2-dsn-propagator

`dkim2-dsn-propagator` is the MTA-neutral delivery-status propagation adapter
for the DKIM2 reference implementation. It receives one delivery-status
notification over LMTP, asks `dkim2d` to evaluate, rebuild, and sign the
notification the previous hop of a forwarded message must receive, re-injects
the signed notification through a trusted local submission listener, commits
the reserved propagation coordinate, and only then acknowledges the LMTP
transaction.

The adapter is transport glue. It never parses DKIM2 fields, never rewrites a
message, never chooses a recipient, and never falls back to the outgoing
delivery-status signing route or to the originator route. Every protocol rule
lives in the library and the daemon. The implemented behavior is pinned to
`draft-ietf-dkim-dkim2-spec-06` and the repository's historical
`draft-chuang-dkim2-dns-04` baseline.

This document is the runtime and configuration reference. The complete
operator deployment procedure, including the MTA routing rule, the
single-recipient transport, and the dedicated re-injection listener, lives in
the operator guide and is completed separately.

## Deployment prerequisites

The adapter assumes three MTA-side properties, stated without MTA-specific
parameter names:

1. Mail addressed to the local return-path addresses of forwarded messages,
   and only that mail, is routed to the adapter's LMTP socket with one
   recipient per transaction and with the recipient address handed to LMTP
   unrewritten. The daemon compares that address byte-wise against the signed
   `mf=` apart from domain case.
2. A trusted internal null-sender submission listener is available for
   re-injection with no DKIM2 signing route attached, and it supports
   `SMTPUTF8` when a previous hop address is non-ASCII and `8BITMIME` when the
   signed notification carries eight-bit content.
3. The MTA's minimum retry interval for the LMTP transport exceeds the
   daemon's `dsn_propagation.pending_lease`. A retry that lands inside a live
   lease is deferred once more before it can be served.

## Runtime requirements

The production listener is an absolute Unix-socket path. The socket parent
must be owned by root or the effective service identity and must deny mutation
to other identities. Startup rejects symlinked ancestry, an existing target,
unsafe directory permissions, ownership drift, and unsupported platforms. The
process creates the socket with the configured `0660` mode under a restrictive
umask and removes only the inode it created.

The daemon endpoint must be a canonical literal-loopback HTTP URL such as
`http://127.0.0.1:8080`. The re-injection endpoint must be a canonical
literal-loopback SMTP URL such as `smtp://127.0.0.1:10025`. Hostnames, remote
addresses, redirects, proxies, cookies, ambient credentials, user information,
query strings, and fragments are rejected on both endpoints.

The propagation capability is a 32-byte protected regular file in an exact
`0500` parent. The file must be owned by the effective identity, have mode
`0400` or `0600`, and have one link. It is confined to the two propagation
operations of the configured daemon origin: the process, originator-signing,
revision, and delivery-status signing routes never receive it. Never place the
capability in a command line, environment value, log, or configuration value.

Protected-file loading uses the same portable descriptor, owner, mode, link,
size, and no-follow rules on Linux and macOS as the other adapters. It has no
cgo, ACL, xattr, mount, or filesystem-type dependency.

Before activation, validate the strict configuration and its exact route
capability without opening a socket or contacting the daemon:

```text
dkim2-dsn-propagator validate --config /absolute/path/to/dkim2-dsn-propagator.yaml
```

Validation is silent on success. It uses the same protected-file loader as the
runtime and never creates, repairs, changes ownership of, or rewrites either
file.

After activation, the container probe is:

```text
dkim2-dsn-propagator probe --config /absolute/path/to/dkim2-dsn-propagator.yaml
```

It reloads the strict configuration and checks that its configured socket is a
single-link Unix socket owned by the effective UID with no permissions for
other users. It does not open an LMTP session or contact the daemon.

## LMTP surface

The receiver implements the RFC 2033 subset the contract needs: `LHLO`,
`MAIL`, `RCPT`, `DATA`, `RSET`, `NOOP`, and `QUIT`. It advertises the
mandatory `PIPELINING` and `ENHANCEDSTATUSCODES` extensions, plus `SIZE` with
the configured message limit, `8BITMIME`, and `SMTPUTF8`, because forwarded
mail may be EAI mail. `HELO` and `EHLO` are answered `500` because the socket
is not an SMTP server. `CHUNKING`, `STARTTLS`, `AUTH`, `XCLIENT`, `XFORWARD`,
and `DSN` are neither advertised nor accepted; an unadvertised command is
answered `502` and an unadvertised parameter `555`.

Exactly one transaction with `MAIL FROM:<>` and exactly one `RCPT TO` is
accepted. A non-null sender is refused `550 5.7.1` because the address class
is reserved for delivery-status notifications. A second recipient is refused
`452 4.5.3`, which keeps one notification per daemon request. After `DATA` the
receiver returns exactly one reply for the single accepted recipient.

## Reply mapping

| Daemon outcome | LMTP reply |
| --- | --- |
| accept, re-injection `250`, commit `200` | `250` |
| discard | `250` |
| reject, `permanent_failure_reply: reject` | `550 5.7.1` |
| reject, `permanent_failure_reply: discard` | `250` |
| tempfail | `451 4.7.1` |
| re-injection refused, deferred, or interrupted | `451 4.4.1` |
| commit failure, including `409` | `451 4.4.1` |
| transport, validation, or capability failure | `451 4.7.1` |

Nothing is acknowledged before the re-injection listener's own `250` and the
commit operation's `200`. There is no fail-open mode.

## Configuration

The configuration document is one strict YAML file under the frozen root
`version: dkim2-dsn-propagator-config-v1`. Unknown keys, duplicate keys,
anchors, aliases, tags, null scalars, and multiple documents are rejected.
Every stable path may also be supplied through its single declared environment
name, formed by upper-casing the path and replacing `.` with `_` behind the
`DKIM2_DSN_PROPAGATOR_` prefix. A value present in both the document and the
environment is a configuration error. Scalar values may contain `${NAME}`
placeholders, which are expanded before typed validation, never in map keys,
and fail closed when the variable is absent.

| Path | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | string | required | Frozen configuration root version. |
| `server.socket` | string | required | Absolute LMTP Unix-socket path. |
| `server.socket_mode` | string | `0660` | Exact created socket mode. |
| `server.shutdown_timeout` | duration | `10s` | Cooperative drain budget. |
| `server.max_connections` | integer | `128` | Concurrent connection bound. |
| `server.max_in_flight_transactions` | integer | `64` | Concurrent transaction bound. |
| `daemon.endpoint` | string | required | Canonical loopback HTTP origin of `dkim2d`. |
| `daemon.capability_file` | string | required | Protected 32-byte propagation capability. |
| `daemon.request_timeout` | duration | `5s` | Propagation-call deadline. |
| `daemon.commit_timeout` | duration | `2s` | Commit-call deadline. |
| `daemon.pending_lease` | duration | `120s` | Operator-declared value of the daemon's `dsn_propagation.pending_lease`. |
| `reinjection.endpoint` | string | required | Canonical loopback SMTP origin of the submission listener. |
| `reinjection.connect_timeout` | duration | `5s` | Re-injection dial deadline. |
| `reinjection.command_timeout` | duration | `5s` | Re-injection per-command deadline. |
| `reinjection.data_timeout` | duration | `30s` | Re-injection DATA-transfer deadline. |
| `propagation.tenant` | string | required | Tenant that owns local-authority resolution. |
| `propagation.reporting_mta` | string | required | Canonical lowercase reporting MTA name. |
| `propagation.permanent_failure_reply` | string | `reject` | The single policy knob: `reject` or `discard`. |
| `limits.message_bytes` | integer | `33554432` | Advertised and enforced message limit. |
| `observability.logging.level` | string | `info` | `debug`, `info`, `warn`, or `error`. |
| `observability.metrics.endpoint` | string | unset | Optional loopback metrics authority. |

The sum of `daemon.request_timeout`, the three re-injection timeouts, and
`daemon.commit_timeout` must stay below `daemon.pending_lease`, so one
complete attempt finishes before the reservation expires. Configuration
loading refuses a document that violates this bound.

`propagation.permanent_failure_reply` governs every daemon `reject`, that is a
verification failure and the misrouting case where the notification is not
ours. It never affects `discard`, `tempfail`, or `accept`. It exists because a
`550` answer to a null-sender notification cannot be bounced: an MTA either
discards it, notifies postmaster, or freezes it. An operator who prefers
silence sets `discard`.

### Minimal example

```yaml
version: dkim2-dsn-propagator-config-v1
server:
  socket: /run/dkim2/propagator.sock
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /etc/dkim2/propagate.key
reinjection:
  endpoint: smtp://127.0.0.1:10025
propagation:
  tenant: default
  reporting_mta: mta.example.com
```

## Observability

The adapter exports exactly three counters on closed outcome sets, plus
process lifecycle and readiness:

- `dsn_propagator_transactions_total{outcome}` with `outcome` in `accepted`,
  `rejected`, `discarded_terminal_origin`, `discarded_not_failure`,
  `discarded_null_previous_sender`, `discarded_unsupported_chain`,
  `discarded_not_reconstructable`, `discarded_unprovisioned_domain`,
  `discarded_committed`, `deferred`, and `contract_failure`.
- `dsn_propagator_reinjection_total{outcome}` with `outcome` in `accepted`,
  `deferred`, `failed`, and `smtputf8_unavailable`.
- `dsn_propagator_commit_total{outcome}` with `outcome` in `committed` and
  `deferred`.

Structured logs use the same closed values. No log record, metric label,
error string, or command output ever carries an address, host, queue
identifier, capability, commit token, or message content.
