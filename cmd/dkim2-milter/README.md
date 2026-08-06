# dkim2-milter

`dkim2-milter` is the Unix-socket SMTP adapter for the DKIM2 reference
implementation. It collects one bounded Milter-v6 callback transaction,
reconstructs an explicitly identified RFC 5322 representation, calls exactly
one generated `dkim2d` operation at end of message, validates the complete
response, and applies only the admitted append-only action plan.
For inbound reporting it also performs the bounded RFC 8601 sanitization
described below before inserting the daemon-owned trace field.

The adapter is operational glue. DKIM2 parsing, verification, signing,
revision, recipe, replay, and datasource rules remain in the library and
daemon. The implemented behavior is pinned to
`draft-ietf-dkim-dkim2-spec-04` and the repository's historical
`draft-chuang-dkim2-dns-04` baseline.

## Runtime requirements

The production listener is an absolute Unix-socket path. The socket parent
must be owned by root or the effective service identity and must deny mutation
to other identities. Startup rejects symlinked ancestry, an existing target,
unsafe directory permissions, ownership drift, and unsupported platforms.
The process creates the socket with the configured `0660` mode under a
restrictive umask and removes only the inode it created.

The daemon endpoint must be a canonical literal-loopback HTTP URL such as
`http://127.0.0.1:8080`. Hostnames, remote addresses, redirects, proxies,
cookies, ambient credentials, user information, query strings, and fragments
are rejected. The mode-specific capability is a 32-byte protected regular
file in an exact `0500` parent. The file must be owned by the effective
identity, have mode `0400` or `0600`, and have one link. Never place the
capability in a command line, environment value, log, or configuration value.

On macOS the production protected-file loader requires the native cgo build so
ACLs can be inspected. A `CGO_ENABLED=0` Darwin binary builds for portability
evidence but fails protected loading closed. Linux production builds remain
pure Go and support amd64 and arm64.

Before activation, validate the strict configuration and its exact route
capability without opening a socket or contacting the daemon:

```text
dkim2-milter validate --config /absolute/path/to/dkim2-milter.yaml
```

Validation is silent on success. It uses the same protected-file loader as the
runtime and never creates, repairs, changes ownership of, or rewrites either
file.

After activation, the container probe is:

```text
dkim2-milter probe --config /absolute/path/to/dkim2-milter.yaml
```

It reloads the strict configuration and checks that its configured socket is a
single-link Unix socket owned by the effective UID with no permissions for
other users. It does not open a Milter session or contact the daemon.

## Configuration

The stable root is `dkim2-milter-config-v1`. Configuration is strict: unknown
or duplicate keys, weak YAML scalar forms, conflicting environment sources,
missing placeholders, unsafe paths, and invalid conditional fields fail
startup. Scalar placeholders are expanded before typed validation. The
canonical environment prefix is `DKIM2_MILTER_`.

Minimal inbound example:

```yaml
version: dkim2-milter-config-v1
server:
  socket: /run/dkim2/milter.sock
  socket_mode: "0660"
  shutdown_timeout: 10s
  max_connections: 128
  max_in_flight_messages: 64
  max_buffered_bytes: 268435456
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /etc/dkim2/protected/process-capability
  request_timeout: 2s
mode: inbound
failure:
  mode: tempfail
limits:
  message_bytes: 33554432
  header_bytes: 1048576
  header_count: 2000
  header_field_bytes: 65536
  recipient_count: 2000
observability:
  logging:
    level: info
```

Static originator mode additionally requires:

```yaml
mode: originator
signing:
  tenant: tenant-a
  domain: example.test
  dsn_domain: dsn.example.test
  allow_recipient_group: false
```

Ordinary-transit mode uses the same tenant and static `domain`, but forbids
`dsn_domain` because it revises existing messages rather than originating new
messages.

Postfix delivery-status mode uses the separately protected daemon DSN
capability and one fixed delivery-status signing identity:

```yaml
daemon:
  capability_file: /etc/dkim2/protected/dsn-sign-capability
mode: postfix_dsn
signing:
  tenant: tenant-a
  domain: dsn.example.test
failure:
  mode: tempfail
```

This mode requires the Postfix `postfix-dsn-evidence-v1` patch described in
`docs/specs/implementation/postfix-dsn-evidence.md`. It rejects fail-open,
ordinary null-sender submission, absent or malformed EOH evidence, and more
than one outer DSN recipient.

An originator instance that serves multiple exact LDAP signing domains may
derive the domain from the already validated ASCII SMTP reverse-path while
retaining one fixed tenant:

```yaml
mode: originator
signing:
  tenant: tenant-a
  domain_source: envelope_sender
  dsn_domain: dsn.example.test
  allow_recipient_group: false
```

`domain_source` defaults to `static`. `envelope_sender` is accepted only for
`originator`, requires `domain` to be absent, lowercases ASCII DNS-domain
casing, and performs no alias, wildcard, parent-domain, header, tenant, or
datasource fallback. Every originator configuration also retains one exact
canonical `dsn_domain` as a stable, reserved prerequisite for future DSN
support. It is not signing authority by itself.

The originator adapter tempfails every null reverse-path before daemon I/O.
Generic Milter callbacks remain insufficient evidence. Only a separate
`postfix_dsn` instance may accept `MAIL FROM <>`, after exact Postfix-only EOH
evidence validation; do not route null senders to the originator socket.

For non-null senders, an address literal or otherwise unsupported SMTPUTF8
envelope is not applicable and continues without daemon I/O or mutation,
including on a static-domain route. Malformed Milter callback syntax remains a
fail-closed adapter-contract failure.

`allow_recipient_group` is reserved and must remain false. Signing stays
single-recipient until the adapter has trustworthy per-message Bcc
classification; `true` fails configuration validation.

`max_buffered_bytes` is an aggregate process budget, not only a retained
message-size limit. Body collection accounts for slice capacity, and EOM
reserves concurrent raw, Base64, JSON, and HTTP transport copies plus a fixed
response, DTO, and Milter-frame working set through the terminal socket write.
The aggregate budget is at least 32 MiB, and configuration proves that it can
carry twice the configured maximum message, five request copies of that
message and the maximum envelope, the retained maximum envelope, and the fixed
response working set. The defaults admit one maximum 32 MiB message plus the
maximum allowed SMTP envelope while concurrent requests continue to share the
same cap.

Inbound `Authentication-Results` reporting is disabled by default. When
enabled, it requires a canonical lower-case RFC 8601 `authserv_id`:

```yaml
authentication_results:
  enabled: true
  authserv_id: mx.example.test
```

The only emitted value is
`<authserv-id>; dkim2=<pass|fail|permerror|temperror>`. Pre-existing fields
claiming the configured service are deleted in descending field-index order
for every accepted inbound message, including unsigned messages for which
DKIM2 processing is not applicable. This mandatory RFC 8601 trust-boundary
scrub remains separate from the daemon action plan. Applicable messages then
receive the daemon-owned local result field at the top. Fields from other services
are preserved. A forged local field disables fail-open.

An inbound HTTP 204 response is the separate `not_applicable` variant for a
message containing neither DKIM2 protocol field family. The adapter accepts it
only with the exact bodyless daemon response contract, emits one Milter EOM
continue response, requests no DKIM2 result action, and never fabricates
`dkim2=none` as a four-state verification result. Mandatory removal of a
pre-existing local `Authentication-Results` field still occurs at the RFC 8601
trust boundary. Partial or malformed DKIM2 state continues through the normal
fail-closed HTTP 200 result contract.

An originator HTTP 204 response is independently the authoritative absent or
inactive exact-profile variant. It maps to `none`/`continue` with zero actions.
Availability, ambiguity, malformed active data, and signing failures remain
HTTP 200 failure results or transport failures. HTTP 204 is invalid for
revision, and malformed no-content responses fail closed.

## Modes and actions

| Mode | Generated daemon operation | Allowed accepting action sequence |
| --- | --- | --- |
| `inbound` | `POST /v1/process` | none, or one configured `Authentication-Results` |
| `originator` | `POST /v1/sign` | `Message-Instance`, then `DKIM2-Signature` |
| `ordinary_transit` | `POST /v1/revise` | `DKIM2-Signature`, optionally preceded by `Message-Instance` |
| `postfix_dsn` | `POST /v1/dsn/sign` | `Message-Instance`, then `DKIM2-Signature` |

The adapter negotiates only the Milter-v6 callbacks it needs and the add-header
and change-header mutation capabilities. A `postfix_dsn` instance additionally
requires standard symbol-list negotiation for its three EOH macros. It rejects
peers that cannot preserve after-colon leading whitespace or perform RFC 8601
sanitization. Arbitrary
header deletion or replacement, body replacement, envelope mutation,
recipient mutation, quarantine, discard, and arbitrary SMTP replies are not
supported.

Every daemon response and complete action plan is validated and serialized
before the first MTA write. Values containing CR, LF, or NUL are rejected.
Each Milter action frame is bounded by 65,536 bytes and the complete plan by
three such frames. A transport failure after any possible mutation byte is an
indeterminate MTA-side outcome: the connection closes and fail-open is
forbidden.

## Message fidelity

The adapter preserves ordered SMTP envelope callback bytes, including
recipient duplicates. It does not trim paths, case-fold, normalize Unicode,
perform IDNA conversion, or derive envelope facts from message headers.
SMTPUTF8 paths are supported for inbound processing. In originator mode a valid
SMTPUTF8 envelope reaches the applicability boundary and continues unchanged
because the pinned signing baseline requires an entirely ASCII envelope.
Ordinary-transit mode remains fail-closed for SMTPUTF8 until revision signing
can preserve and verify that evidence.

Headers remain an ordered sequence with duplicate fields and original field
name casing. Negotiated callback folding is reconstructed as CRLF without
otherwise normalizing header or body bytes. Body chunks are concatenated in
callback order. The ordinary daemon input fidelity is
`milter_reconstructed_crlf`; a validated Postfix DSN uses
`postfix_dsn_milter_reconstructed_crlf`. Neither is represented as original
raw SMTP wire evidence.

## Failure policy

The default `failure.mode: tempfail` maps local ambiguity and dependency
failure to:

```text
451 4.7.1 DKIM2 service unavailable
```

An explicit daemon rejection maps to:

```text
550 5.7.1 DKIM2 policy rejection
```

`failure.mode: fail_open` is a compatibility policy, not a verification
result. It may accept only an unmodified message after a proven pre-write
daemon unavailability, a timeout before response bytes, or local overload
before operation start. It never overrides an explicit daemon refusal,
malformed response, fidelity failure, a forged local reporting assertion,
signing ambiguity, replay indeterminacy, or possible mutation write. Enabling
it produces a mandatory bounded startup warning and a low-cardinality outcome
metric.

## Postfix-style integration

After starting the service and verifying the socket owner, group, and mode,
configure the MTA to use the Unix socket. A typical Postfix-style declaration
is:

```text
smtpd_milters = unix:/run/dkim2/milter.sock
non_smtpd_milters = unix:/run/dkim2/milter.sock
milter_protocol = 6
milter_default_action = tempfail
```

Apply the adapter only at the SMTP trust boundary matching its configured
mode. Use separate instances and separate route capabilities for inbound,
originator, ordinary-transit, and Postfix DSN paths. Do not share a signing or
DSN capability with another adapter mode. MTA socket permissions should grant
connection access only to the intended service group.

Postfix simulates Milter callbacks for `non_smtpd_milters` with unbracketed
envelope mailboxes. The adapter validates those mailbox bytes with its full RFC
5321 path grammar and adds only the missing outer angle brackets before calling
DKIM2. A simulated empty reverse-path becomes `<>`; an empty recipient and
partial, embedded, or mixed bracket forms fail closed. SMTP callbacks that
already contain RFC path brackets remain byte-for-byte unchanged.

Private-key generation ownership belongs to `dkim2d`, not this adapter.
Signing-enabled daemon configuration loads the signing-profile datasource,
private-key manifest, and PKCS#8 children as one confined immutable generation.
The Milter receives only the final generated action plan and never opens
private keys, selects a key, or receives an opaque key handle.

## Observability

Logs are bounded JSON records with closed event and value vocabularies.
Prometheus metrics, when configured, bind only to a canonical loopback
authority. Labels never contain sender, recipient, tenant, domain, message ID,
session ID, endpoint, socket peer, capability, key identity, raw error, header,
body, signature, or message bytes. Debug settings cannot enable mail-data or
secret output.

`message.completed` exposes the processed domains needed for local operation.
Inbound records use distinct canonical ASCII DNS recipient domains with mailbox
local parts removed. Originator and ordinary-transit records use the exact
selected signing domain. `processed_domains` renders at most eight domains;
`processed_domain_count` and `processed_domains_truncated` retain explicit
multi-domain state. These values are local log fields only and never become
Prometheus labels or remote trace attributes.

Readiness means validated configuration, protected capability ownership, the
public listener, admission controls, and required local resources are live. It
does not claim that the daemon is reachable at that instant.

## Troubleshooting

- Startup failure: inspect ownership and modes of every configuration,
  capability, and socket-parent component; reject symlinks and pre-existing
  socket targets. On macOS verify that the production binary was built with
  native cgo ACL support.
- Negotiation disconnect: confirm Milter protocol v6, `add_header`, and
  leading-header-space support at the MTA.
- Fixed 451 reply: check daemon availability and operation metrics. The SMTP
  reply intentionally contains no endpoint, path, identity, or raw error.
- Signing tempfail: verify that the instance mode, route capability, tenant,
  domain, recipient-group policy, and daemon signing generation agree. Do not
  copy private material into the adapter to diagnose it.
- Socket left after a crash: verify the inode before removal. A running
  instance deliberately preserves a replacement inode it does not own.
- Shutdown timeout: find slow MTA connections or daemon requests. Shutdown
  withdraws readiness first, then closes the listener, cancels remaining
  workers within the configured bound, and removes only the owned socket.

## Developer verification

The `internal/integration` suite builds the real executable once, starts an
OpenAPI-generated loopback daemon fixture, and drives the public Unix socket
with an independent MTA-side frame oracle. It covers all modes, ordered
actions, exact generated requests, abort and connection reuse, malformed
frames, overload, slow partial input, daemon unavailability and timeout,
response overflow, shutdown, cleanup, capability routing, and output privacy.

The owning package suites additionally cover socket replacement, protected-file
races, immutable signing reload, callback and client panics, partial writes,
action admission, bounded metrics, and race-safe shutdown. Fuzz targets cover
wire frames and negotiation, callback sequences, reconstruction, daemon
actions, SMTPUTF8 envelopes, strict configuration, and private manifests.
Run repository checks from the root:

```text
make test
make vet
make lint
make race
make check-openapi
make check-workspace
make check-vendor
make check-protected-platforms
make govulncheck
make guardrails
```
