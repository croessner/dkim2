# Milter Adapter Implementation Specification

Status: implementation-ready planning baseline.

Implementation base: `bf627cd81d2a46df35d5c42dde06e0f447cf017c`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` baseline. This increment adds the first
production HTTP signing and revision surface and the first SMTP/Milter adapter.
It does not change the pinned draft behavior.

## Scope And Authority

This increment delivers:

- daemon `sign` and `revise` operations plus a closed response action plan;
- action-plan support on the existing inbound `process` operation;
- an M11-datasource-to-M10-signing bridge and a confined private-key backend;
- a production `dkim2-milter` executable, configuration loader, lifecycle, and
  Unix-socket server;
- byte-accounted Milter-v6 callback collection and deterministic RFC 5322
  reconstruction;
- a generated OpenAPI client used by the adapter at end of message;
- validation and application of a small, ordered Milter action subset;
- optional trust-boundary `Authentication-Results` reporting;
- fixed SMTP outcome mapping, an explicit fail-open policy, and secret-safe
  adapter observability; and
- unit, protocol-peer, subprocess, fuzz, race, platform, and abuse evidence.

Authority order is:

1. the pinned DKIM2 and DNS drafts for protocol meaning;
2. RFC 5321, RFC 5322, RFC 6376, RFC 6531, RFC 6532, and RFC 8601 for SMTP,
   message, DKIM-heritage, internationalized-mail, and reporting behavior;
3. the authoritative OpenAPI document for the daemon HTTP contract;
4. the architecture and completed M10 through M15 specifications for ownership;
5. this document for adapter, transport, deployment, and local policy.

The Milter wire protocol is an adapter protocol, not an IETF DKIM2 rule.
Callback sequencing, reconstruction metadata, action admission, timeout
mapping, socket ownership, and fail-open behavior below are explicit local
policy. They must not be presented as normative DKIM2 requirements.

Exim integration, remote daemon transport, TCP Milter listeners, systemd socket
activation, arbitrary Milter actions, message-body replacement, LDAP or SQL
providers, and general operator key management remain out of scope.

## Product And Dependency Boundaries

`lib/` continues to own protocol parsing, verification, recipe behavior,
signing, revision, and public domain results. It must not import Milter,
OpenAPI, Cobra, Viper, Fx, HTTP, Prometheus, OpenTelemetry exporters, or daemon
packages.

`cmd/dkim2d` owns:

- OpenAPI adapters and generated server types;
- concrete datasource and private-signing construction;
- translation between generated DTOs and library domain types;
- sign, revise, and process action-plan projection;
- HTTP lifecycle, deadlines, response limits, logging, traces, and metrics.

`cmd/dkim2-milter` owns:

- the Milter-v6 wire boundary and callback state machine;
- SMTP envelope and message-byte collection;
- the generated daemon client used at end of message;
- action-plan validation and Milter action application;
- local failure policy, socket lifecycle, and adapter observability.

The adapter must not import daemon-internal or library-internal packages. Core
domain packages must not import generated DTOs. Handwritten REST DTOs or a
parallel client model are forbidden.

The existing client output is private to `dkim2ctl`. This increment generates a
separate adapter-owned client from the same authoritative OpenAPI document.
Mechanical generated duplication is accepted at the two command boundaries;
handwritten contract duplication is not. Generation and stale-output checks
must cover server, test client, and Milter client together.

No cgo or libmilter dependency is introduced. The adapter owns a small,
bounded, pure-Go Milter-v6 wire implementation limited to the negotiated
callbacks and actions in this document. This decision avoids an unbounded or
lossy third-party parser and keeps Linux cross-builds reproducible.

## Daemon HTTP Operations

OpenAPI adds:

```text
POST /v1/sign
POST /v1/revise
```

The existing `POST /v1/process` response gains the same closed action-plan
container. Operation IDs, schemas, examples, generated server/client output,
limits, error envelopes, media types, and stale checks are authoritative in
OpenAPI from the first implementation slice.

All three requests carry:

- `api_version` and the exact pinned `draft`;
- message bytes as bounded `raw_rfc5322_base64`;
- bounded ordered SMTP envelope facts required by the selected operation; and
- a closed operation-specific context object.

`MessageInput` gains an optional closed `fidelity` member so existing process
clients remain compatible. Absence retains the current direct-raw API meaning.
The Milter adapter must always send `milter_reconstructed_crlf`. This is an
adapter evidence fact and must not be silently relabeled as original raw wire
fidelity. Sign and revise require an explicit supported fidelity. The daemon
decodes the provided base64 into the ordinary raw-message library boundary.

The sign request also carries the configured tenant, signing domain, and
ordered SMTP recipients. It does not accept a selector, key handle, profile ID,
private key, arbitrary recipe, arbitrary field name, or caller-selected
algorithm. The daemon resolves policy and signing material through M11.

The revise request carries the configured tenant and local signing domain plus
two explicit envelope sets: required `incoming_smtp` is inherited verification
evidence, while `smtp` is outgoing route/signature authority. The daemon first
calls M10 `VerifyForRevision` on the exact submitted message and incoming
envelope and may sign only with the sealed `VerifiedRevisionInput` returned by
that call; the resulting signature uses only the outgoing envelope. A bare
PASS result is never revision authority. The Milter adapter currently supplies
the same callback envelope for both sets and therefore safely supports only
unchanged-envelope transit; other generated clients can represent forwarding
without conflating evidence and authority.

The process request may carry only an optional closed reporting context with a
validated canonical `authserv_id`. It is accepted solely on the
capability-authenticated process route and lets the daemon construct, rather
than the adapter synthesize, the exact bounded report action.

This initial service and Milter mode use M11 `ordinary_transit` policy for
revision. M10 next-domain transit remains a library capability because its
published-next-domain and out-of-band route authorizations do not yet have a
service trust contract. A later service extension must specify those
capabilities explicitly rather than treating ordinary Milter receipt as OOB
authorization.

Request identity fields are strictly bounded scalar values. Unknown fields,
duplicate JSON members, invalid base64, absent required values, version drift,
invalid SMTP mailbox bytes, unsupported fidelity, and limit excess fail before
protocol work with the existing bounded error-envelope policy.

### Response Facts And Disposition

Successful operation responses contain:

- exact API and draft versions;
- the operation kind;
- a closed result and disposition;
- only bounded non-secret protocol facts already owned by the library result;
  and
- one ordered action plan.

The closed dispositions are `accept`, `reject`, `tempfail`, and `continue`.
`continue` means no final SMTP refusal or terminal policy decision. At EOM the
adapter maps it to successful completion. For inbound processing it may carry
the sole daemon-owned `Authentication-Results` reporting action and still
performs mandatory local trust-boundary scrubbing when configured. Other modes
must carry no action on `continue`. A response cannot contain both a rejecting
disposition and mutation actions.

Sign, revise, and delivery-status operation result and disposition form one
exact matrix:

| Result | Allowed disposition |
| --- | --- |
| `pass` | `accept` or `continue` |
| `fail` | `reject` |
| `permerror` | `reject` |
| `temperror` | `tempfail` |

Inbound process responses instead bind verification state to the selected
policy and replay result. In `testing`, every coherent applicable verification
state uses non-terminal `continue`; strict and permissive modes retain their
documented terminal policy behavior.

Only `accept`, plus inbound `continue` with the exact authoritative reporting
action, may carry a mutation plan. Other `continue`, `reject`, and `tempfail`
outcomes must carry no actions. Both daemon construction and adapter admission
enforce the same matrix independently.

Protocol and policy failures are represented by their operation response when
the operation was evaluated. JSON/contract failures retain the existing HTTP
mapping. HTTP status alone never authorizes a message mutation.

Responses never contain a private key, opaque key handle, datasource record,
raw message, raw header value, raw identity, raw signature input, recipe
internals, route ticket, replay key, DNS TXT, or raw error.

### Operation Capabilities

The existing `server.capability_file` remains the process capability and stable
path. Signing-enabled daemon configuration adds protected direct-child
`server.sign_capability_file`, `server.revise_capability_file`, and optional
`server.dsn_sign_capability_file`. Each is
exactly scoped to one route and must be distinct from every other capability,
private key, replay secret, datasource credential, and protected token.

The common bounded preflight authenticates the route-specific capability in
constant time before readiness, body allocation, datasource lookup,
verification, replay, or signing. Delivery-status signing uses
`X-DKIM2-DSN-Sign-Capability`; the other Milter operations use
`X-DKIM2-Capability`. Missing, malformed, duplicated, cross-route, and
mismatched credentials produce the same closed 403 shape. The header is
removed before generated handlers run. A Milter instance loads only the
capability for its fixed mode, so compromise of an inbound adapter cannot
authorize sign, revise, or delivery-status signing. Originator continues to
tempfail `<>`; only `postfix_dsn` may load and use the DSN capability.

## Closed Action Plan

The action-plan schema is an ordered array of discriminated entries. The only
entry implemented here is:

```text
type = add_header
name = one allowed exact field name
value = one unfolded field body without CR, LF, or NUL
```

Allowed field names are exactly:

- `Message-Instance`;
- `DKIM2-Signature`;
- `Authentication-Results`.

No case variants or arbitrary extensions are accepted. DKIM2 protocol fields
remain append-only. The sole bounded exception is RFC 8601 trust-boundary
sanitization: before inserting a local `Authentication-Results` trace field at
index zero, the adapter deletes untrusted occurrences that claim the
configured local `authserv-id`. Arbitrary header change/delete, body
replacement, envelope mutation, recipient mutation, quarantine, discard,
arbitrary reply, and full-message replacement are unsupported and fail closed.

The daemon constructs plans only from successfully completed domain results:

- originator signing emits `Message-Instance` then `DKIM2-Signature`;
- unchanged revision emits only the new `DKIM2-Signature`;
- changed revision emits `Message-Instance` then `DKIM2-Signature`;
- inbound processing emits exactly one fixed `Authentication-Results` action
  only when the capability-authenticated request supplied a validated
  `authserv-id`, reporting is enabled, and the disposition is `accept` or
  non-terminal `continue`.

M10 returns complete deterministically folded fields, while Milter
`add_header` accepts a field name and one logical value. One daemon-owned
projection removes the exact expected name/colon and terminal CRLF, unfolds
only legal `CRLF WSP` by deleting the CRLF while retaining the WSP, and rejects
every other CR/LF/NUL or framing shape. It then proves the projected field has
the same DKIM2 canonical form as the M10 result. It does not reimplement field
grammar or formatting in DTO code. Each value and the total plan have explicit
OpenAPI, daemon, and adapter bounds below the negotiated Milter frame maximum.

Before writing any mutation, the adapter validates the full response and full
plan: versions, operation, disposition, count, order, field-name matrix, value
grammar, individual length, aggregate length, and operation-specific
combination. Validation is side-effect free.

After validation the adapter serializes the complete mutation batch and
terminal response before its first write. Writes preserve action order. Milter
does not provide transactional rollback after bytes reach the MTA, so the
adapter must not claim rollback atomicity: a transport failure after a partial
write is an indeterminate MTA-side outcome. It closes the connection and never
uses fail-open after the first possible mutation byte.

## Datasource And Private Signing Backend

Signing is disabled by default. Existing inbound-only daemon configurations
continue to work without opening signing datasource or key files.

The stable daemon surface adds:

| Path | Default | Contract |
| --- | --- | --- |
| `signing.backend` | `disabled` | `disabled` or `flat_file` |
| `signing.datasource_file` | absent | M11 flat-file direct child |
| `signing.private_manifest_file` | absent | same-generation direct child |
| `signing.reload_interval` | `30s` when enabled | 1s..1h |
| `server.sign_capability_file` | absent | required when signing is enabled |
| `server.revise_capability_file` | absent | required when signing is enabled |

Disabled signing forbids the signing-only paths and opens none of them. Enabled
signing requires the whole conditional set under the selected protected
generation. Existing strict merge, stable-path, placeholder, provenance,
same-generation, and redacted-error rules apply.

The initial signing provider is `flat_file`. It composes:

- the M11 immutable flat-file datasource generation;
- one protected private-key manifest in that same generation; and
- direct-child private-key files referenced only through manifest entries.

The manifest binds exactly one M11 opaque `KeyHandleID`, declared algorithm/use,
and public SPKI identity to one private-key child. Duplicate handles, paths,
keys, or conflicting bindings fail the whole generation. The loader resolves
the M11 profile and policy through the existing storage-neutral contracts; it
must not implement a profile-ID selection shortcut, selector fallback, or a
parallel provider model.

Private-key children:

- are opened descriptor-first as direct children of the protected generation;
- are regular files owned by the effective user with link count one;
- have mode 0400 or 0600;
- are bounded and read with exact-EOF checks;
- reject symlinks, hard links, path replacement, special files, trailing data,
  encrypted PEM, multiple PEM blocks, and unknown block types; and
- contain exactly one PKCS#8 `PRIVATE KEY` for RSA or Ed25519.

The derived public key, algorithm family, and declared use must match the M11
public signing profile before an immutable generation is published. A reload
publishes the complete datasource/private-key generation atomically; requests
already holding the old immutable generation may complete on it.

The concrete signer accepts only an opaque comparable handle and M10's digest
contract. Raw private-key bytes never cross a domain or HTTP boundary. Temporary
encoded buffers are cleared on a best-effort basis after parsing. Logs, traces,
metrics, REST, CLI, error strings, formatting, and panic output must not reveal
key paths, handles, DER, PEM, public-key fingerprints, or protected content.

A minimal reviewed bridge projects an M11 resolved policy/profile into M10's
public signing facade. Profile validation, handle mapping, and algorithm/use
compatibility each have one source of truth. The bridge must not export
provider-specific structs or move daemon dependencies into `lib/`.

Route authority and recipient authorization are request-scoped or explicitly
bounded. They may not accumulate long-lived route tickets. The local authorizer
permits only the exact resolved tenant/domain/use policy. Signing is
single-recipient in this increment. The stable
`signing.allow_recipient_group` path remains reserved and must be `false`
because Milter callbacks do not prove which recipients are blind; a global
group switch could violate the draft's Bcc non-disclosure MUST. Ambiguous
routes, recipients, policies, keys, algorithms, or signer state fail closed.

An originator route may select its signing domain from the strictly validated
ASCII SMTP reverse-path while retaining one statically configured tenant.
`postfix_dsn` instead requires `domain_source: verified_embedded` and no
configured domain. The bounded Postfix origin enum authorizes only the route;
the daemon verifies the complete embedded object, derives the canonical
authenticated highest `d=`, and only then resolves the exact tenant/domain
`delivery_status` policy. No outer-envelope or caller-selected domain can
participate in that lookup.

Every originator route also retains one separate canonical
`signing.dsn_domain`. This stable configuration path is a reserved prerequisite
for future DSN support, not sufficient signing authority.

The originator adapter tempfails every exact null reverse-path `<>`. The
separate `postfix_dsn` adapter accepts only exact `internal` provenance from
`{postfix_dsn_origin}` and then delegates RFC 3462 and Draft-04 Section 12
evidence checks to the daemon. External or absent provenance never authorizes
signing.

## Authentication-Results Policy

`Authentication-Results` is non-normative DKIM2 reporting at the SMTP trust
boundary. It records the daemon's inbound outcome; it never becomes protocol
state, replay input, route evidence, recipe input, or signing authorization.

Reporting is disabled by default. When enabled, configuration requires one
canonical lower-case RFC 8601 `authserv-id`. The exact emitted field value is:

```text
<authserv-id>; dkim2=<pass|fail|permerror|temperror>
```

No comment, reason text, raw identity, property clause, selector, domain,
address, message ID, request ID, trace ID, or vendor diagnostic is appended.
The result vocabulary is a closed local projection of the daemon's bounded
outcome.

For every accepted inbound message, including a not-applicable unsigned
message, the adapter finds every pre-existing
`Authentication-Results` field with the configured `authserv-id`, records its
one-based field-name occurrence index, and pre-serializes deletion in
descending index order. When DKIM2 is applicable, it then inserts its own field
at index zero. This implements RFC 8601 Sections 4.1 and 5 without reordering
fields from other authentication services. If required change/insert
capabilities are absent,
or any replacement write is indeterminate, the adapter fails closed. A forged
local field also disables fail-open because accepting the original message
would preserve a spoofed trust assertion.

## Executable And Configuration

The command is a Cobra executable composed with Fx and configured through
Viper using the same strict, typed, provenance-aware, placeholder-before-
validation pattern as `dkim2d`. Its stable root is
`dkim2-milter-config-v1`. Unknown keys, ambiguous aliases, duplicate inputs,
noncanonical scalars, missing placeholders, aggregate limit excess, and
protected-value leakage fail closed.

The initial stable paths include:

| Path | Default | Contract |
| --- | --- | --- |
| `server.socket` | required | absolute Unix-socket path |
| `server.socket_mode` | `0660` | exact safe socket mode |
| `server.shutdown_timeout` | `10s` | 1s..30s |
| `server.max_connections` | `128` | 1..4096 |
| `server.max_in_flight_messages` | `64` | 1..1024 |
| `server.max_buffered_bytes` | `268435456` | 32 MiB..1 GiB |
| `daemon.endpoint` | required | canonical loopback-literal HTTP URL |
| `daemon.capability_file` | required | protected direct child |
| `daemon.request_timeout` | `2s` | 100ms..10s |
| `mode` | required | `inbound`, `originator`, `ordinary_transit`, `postfix_dsn` |
| `signing.tenant` | conditional | required for signing/revision modes |
| `signing.domain` | conditional | required for static originator/transit routes; absent for envelope-derived originator and verified-embedded Postfix DSN routes |
| `signing.domain_source` | `static` | `static`, `envelope_sender` for originator only, or explicit `verified_embedded` for `postfix_dsn` only |
| `signing.dsn_domain` | originator required | reserved legacy originator prerequisite; forbidden in other modes and never sufficient to authorize null-sender signing |
| `signing.allow_recipient_group` | `false` | reserved; `true` is rejected until per-message Bcc evidence exists |
| `authentication_results.enabled` | `false` | inbound mode only |
| `authentication_results.authserv_id` | absent | required exactly when enabled |
| `failure.mode` | `tempfail` | `tempfail` or `fail_open`; `postfix_dsn` requires `tempfail` |
| `limits.message_bytes` | `33554432` | may only narrow |
| `limits.header_bytes` | `1048576` | may only narrow |
| `limits.header_count` | `2000` | may only narrow |
| `limits.header_field_bytes` | `65536` | may only narrow |
| `limits.recipient_count` | `2000` | may only narrow |
| `observability.logging.level` | `info` | closed slog level |
| `observability.metrics.endpoint` | absent | optional loopback HTTP listener |

Environment bindings use `DKIM2_MILTER_` plus the canonical uppercased
underscore path. Flags may select a config file and expose `version`; they must
not accept capabilities, private keys, secrets, message content, daemon URLs,
or policy overrides.

The capability file inherits the M14 protected-file ownership and exact-token
contract. The daemon transport forbids proxy use, redirects, cookies, ambient
credentials, userinfo, query, fragments, hostnames, mapped IPv6, non-loopback
addresses, and response bodies beyond the operation cap. It uses fixed headers
and per-request contexts. Response errors remain content-free.

## Milter Wire Runtime

The production listener is Unix-domain only. Startup validates the parent and
target path, creates the socket under a restrictive umask, verifies the bound
inode and requested mode, and publishes readiness only after all dependencies
and the accept loop are live. Cleanup removes only the inode created by this
instance. A symlink, pre-existing non-socket, ownership mismatch, path
replacement, or unsafe parent fails closed.

Socket creation runs during quiescent startup because umask is process-global.
The path trust boundary treats root and the effective process identity as
administrative peers; every other identity must be denied directory mutation
by filesystem permissions. Runtime cleanup compares the created inode identity,
not mutable permission bits, so it removes the owned socket after same-inode
mode drift while preserving any replacement inode.

The wire parser validates the four-byte frame length before allocation. Frame
and command-specific caps are fixed; body frames cannot exceed the negotiated
limit. Unknown commands, unsupported actions, malformed NUL fields, truncated
frames, integer overflow, and negotiation mismatch terminate the connection
without reflecting raw input.

Negotiation requires Milter protocol v6 and only the callbacks needed by this
document. It requires the `SMFIP_HDR_LEADSPC` protocol flag so exact bytes after
the colon remain observable. It advertises add-header and change-header
mutation capability. DKIM2 fields still use only add-header responses;
change-header and insert-header responses are confined to RFC 8601 reporting.
If the peer cannot negotiate these fidelity/action requirements, the adapter
does not process the message and returns a temporary failure.

The connection state machine accepts:

```text
negotiate -> connect -> helo -> mail -> rcpt* -> header* -> eoh -> body* -> eom
```

`connect` and `helo` are bounded shape/diagnostic facts only. SMTP evidence
comes from `MAIL FROM` and ordered `RCPT TO` callbacks. Abort resets the current
transaction without ending the connection; an empty abort after HELO and before
MAIL is an idempotent Postfix cleanup event and returns the connection to the
HELO-ready state. A subsequent bounded HELO restart is permitted only while no
MAIL transaction is live. Successful or failed EOM also resets transaction
state. Quit ends the connection. Illegal order, duplicate singleton callbacks
other than that pre-MAIL HELO restart, callbacks after EOM, nested
transactions, excess recipients, and live-message state reuse fail closed.
Connection-owned state has no package-level mutable data.

Admission is bounded before launching per-connection work. A process-wide byte
reservation is acquired before message collection and grows only within the
configured aggregate cap. Connection count, in-flight messages, headers,
recipients, individual fields, total headers, message bytes, frame bytes, and
daemon response bytes all have independent limits. Deadline and cancellation
release reservations exactly once.

Body callback storage is charged at twice its retained payload to cover slice
capacity. At EOM, the adapter additionally reserves five times the raw message
plus envelope input while raw, Base64, protected-scalar JSON, request JSON, and
HTTP transport copies may coexist. It also reserves seven times the 4 MiB
daemon-response limit for the response body, generated and strict DTOs,
structural-validation copies, and final adapter result, plus the maximum three
65,536-byte Milter action frames. This response working set remains charged
through the terminal socket write. The aggregate process budget is at least
32 MiB. Configuration computes the checked sum of twice the configured maximum
message, the retained maximum envelope, five copies of that message plus the
maximum configured envelope, and the fixed response working set, then rejects
any process cap below that sum. The default 256 MiB cap therefore admits one
32 MiB message with the maximum configured 2,000 256-byte recipients and one
256-byte reverse path, while concurrent work still competes for the same
aggregate budget.

## Message And Envelope Fidelity

Envelope sender and recipient mailbox bytes are preserved in callback order,
including recipient duplicates. An RFC 5321-bracketed callback path is retained
exactly. Postfix emits an unbracketed mailbox, or an empty reverse-path field,
when it simulates Milter callbacks for non-SMTP submission. The adapter accepts
that form only when adding the missing outer angle brackets yields a complete
valid RFC 5321 path under the same grammar; it maps the empty reverse-path to
`<>`, rejects an empty recipient and every partial, embedded, or mixed bracket
form, and then supplies the normalized RFC path to DKIM2. No mailbox byte is
otherwise changed. Angle-bracket stripping, Unicode normalization, case
folding, IDNA conversion, mailbox reparsing, and lossy string trimming are
forbidden. SMTPUTF8 octets are preserved for inbound processing under RFC
6531/6532, but the pinned M10 signing baseline supports ASCII SMTP paths only.
An originator non-null, non-ASCII reverse path cannot select an exact signing
domain and is therefore not applicable; it continues before daemon,
datasource, or private-key access. Every null sender fails closed before those
boundaries until the trusted DSN evidence gate exists. Ordinary-transit mode
still fails closed on every non-ASCII
envelope path before those boundaries because revision cannot discard inherited
custody evidence.

Headers are stored as an ordered sequence, never in `textproto.MIMEHeader` or a
map. Duplicate fields and original name casing are preserved. For each callback
the reconstructed bytes are:

```text
field-name ":" callback-value CRLF
```

The negotiated leading-space flag makes `callback-value` include the exact
after-colon whitespace delivered by a conforming MTA. The libmilter callback
form represents a legal folded field boundary as `LF WSP`; the adapter maps
that protocol-defined boundary to `CRLF WSP` while constructing the explicitly
declared `milter_reconstructed_crlf` evidence. It also accepts an already
represented `CRLF WSP` boundary, validates field-name grammar, prohibits NUL,
bare CR, and every other bare LF, and enforces the 998-octet physical-line
limit. It inserts exactly one final CRLF after the header block.

Body callback chunks are concatenated byte-for-byte in order. No line-ending,
dot-stuffing, transfer-encoding, MIME, charset, trailing-CRLF, or Unicode
normalization occurs. The MTA is responsible for presenting the post-SMTP body
stream defined by its Milter protocol.

The exact reconstructed bytes are the daemon message. Reconstruction tests use
independent byte oracles with duplicate fields, empty bodies, folded headers,
leading whitespace, binary body octets, SMTPUTF8, chunk-boundary variation,
and messages at every limit. Any state in which byte fidelity cannot be proven
maps to temporary failure; it is never relabeled as raw-wire fidelity.

## End-Of-Message Flow

Mode selects exactly one daemon operation:

| Mode | Operation | Mutation |
| --- | --- | --- |
| `inbound` | `process` | optional `Authentication-Results` |
| `originator` | `sign` | M10-generated originator fields |
| `ordinary_transit` | `revise` | M10-generated revision fields |
| `postfix_dsn` | `delivery_status` | validated DSN signing fields |

At EOM the adapter freezes immutable envelope/message input, releases no bytes
until the operation completes, calls the generated client under the configured
deadline, validates the bounded response, validates and pre-serializes the full
action plan, applies actions in order, writes one terminal Milter response, and
then clears transaction state.

Only the daemon result authorizes actions. The adapter cannot synthesize a
signature, Message-Instance, recipe, report, or inbound result. It cannot retry a
sign/revise/process request after an indeterminate transport outcome because
the operation may have consumed signing or replay authority.

The generated-client boundary records content-free transport progress for each
attempt. Any possible request write or observed response byte makes an
otherwise incomplete operation indeterminate. Only a proven pre-write
availability failure or deadline can enter the narrow fail-open allowlist.
Every explicit response, including a non-success status or malformed success,
is complete operation evidence and maps to a contract failure instead.

## SMTP Outcomes And Failure Policy

Daemon dispositions map deterministically:

| Disposition | Milter result | Reply |
| --- | --- | --- |
| `accept` | apply validated actions, then accept | none |
| `continue` | apply the exact inbound report action when present, then accept | none |
| `reject` | reject unchanged | `550 5.7.1 DKIM2 policy rejection` |
| `tempfail` | temporary failure unchanged | `451 4.7.1 DKIM2 service unavailable` |

### Canonical multi-instance policy response

The `v1/process` response represents authenticated policy evidence from the
entire verified chain, not only the current instance. Consequently its closed
policy enums contain the reachable `not_requested`, `violated`,
`indeterminate`, and `complete` states where the OpenAPI schema allows them.
A valid multi-instance result can therefore be `PASS`, `testing`,
`not_checked`, and `continue`. When inbound reporting is enabled, that result
carries the exact daemon-owned `Authentication-Results` action while delivery
remains non-terminal.

This is the single current Draft-04 contract, not an alternate compatibility
mode. It has no deprecated aliases, version fallbacks, or caller-selectable
schema. Deploy the daemon and every generated `v1/process` client as one
digest-pinned change. Rollback likewise restores the complete prior
daemon-and-adapter set.

Local contract, fidelity, timeout, cancellation, malformed-response,
indeterminate-operation, capacity, or dependency errors default to the same
fixed 451 reply. No raw error, endpoint, path, identity, or protocol input
enters an SMTP reply.

`failure.mode=fail_open` is an explicit operator compatibility policy. It may
accept the original unmodified message only when:

- no daemon response with explicit `reject` or `tempfail` was received;
- no Milter mutation byte was written or might have been written;
- no forged local `Authentication-Results` occurrence was observed; and
- the failure class is explicitly allowlisted as daemon unavailable, timeout
  before response bytes, or local overload before operation start.

Fail-open never converts malformed success, version mismatch, invalid action,
fidelity loss, private-signing ambiguity, replay indeterminacy, or an explicit
daemon refusal into acceptance. Once any mutation write begins, fail-open is
impossible; the connection closes on an indeterminate write.

Fail-open is visible in effective redacted configuration, emits a bounded
startup warning, and increments a low-cardinality outcome metric. It is
disabled by default.

## Observability And Privacy

The adapter uses a central bounded JSON slog provider and a process-local
Prometheus registry. It may reuse daemon-owned policy patterns but not daemon
internal packages or global telemetry state. Required facts are operation,
mode, disposition, result class, failure class, callback/state class,
duration/size/recipient buckets, readiness, connection admission, action kind,
fail-open use, and the bounded processed-domain projection needed by local
operators. Inbound records use canonical distinct ASCII DNS recipient domains;
originator and ordinary-transit records use the exact selected signing domain.
At most eight domains are rendered while the exact distinct count and a
truncation flag preserve multi-domain visibility.

Local bounded JSON logs may contain only those validated canonical domains and
their closed role/count metadata. They never contain mailbox local parts,
complete sender or recipient paths, tenant values, message/header/body,
signature, Message-Instance, Authentication-Results, capability, key
handle/path/material, daemon URL, socket peer, client address,
request/session/queue/trace ID, protected config, raw error, or another
arbitrary string. Metrics never contain raw or hashed sender, recipient,
domain, or tenant values; Prometheus labels remain on the unchanged closed
low-cardinality allowlist. Debug modules cannot enable additional mail-data or
secret output.

The observation sink is non-authoritative and cannot block or alter protocol
decisions. Its bounded dispatcher remains dormant until socket ownership and
process-global umask work are complete, then starts after the Milter listener
is bound. Producers never block and discard excess records as one bounded
local observability failure. Shutdown stops admission first, drains active
workers, closes observation delivery, and joins the dispatcher only within the
shared shutdown budget before stopping telemetry.

The optional metrics listener uses canonical loopback literal authority,
strict Host/target/method rules, deterministic capped output, no trace-context
input, and no protocol side effects. Adapter readiness means validated
configuration, daemon capability, listener ownership, admission runtime, and
required local dependencies are live; it does not claim the daemon is
currently reachable.

## Lifecycle And Platform Support

Startup order is config and protected inputs, observability, generated client,
byte/admission controls, socket validation/bind, accept loop, then readiness.
Shutdown clears readiness, stops admission, closes the listener, drains active
transactions within the configured budget, cancels remaining requests, joins
workers, and removes only the owned socket inode.

SIGTERM and SIGINT share one idempotent stop path. Panics at callback, client,
action, logger, or metric seams are contained, release reservations, close the
affected connection, and cannot leave readiness falsely high.

Production support is Linux amd64 and arm64. macOS is development/test parity.
Other platforms either pass explicitly maintained build-and-test evidence or
fail at build/configuration with a clear bounded unsupported-platform result.
The module remains `CGO_ENABLED=0` compatible.

## Tests And Verification

Unit tests cover:

- OpenAPI DTO mapping, version gates, request/response/action limits, generated
  drift, and domain-type isolation;
- M11 policy/profile projection, request-scoped route authority, authorizer
  rules, private manifest/loading, public/private match, immutable reload, and
  redaction;
- strict config merge, environment placeholders, conditional presence,
  protected capability, endpoint grammar, limits, and stable paths;
- every callback transition, abort/reset/quit, illegal ordering, admission,
  reservation release, deadline, and panic path;
- independent envelope/header/body byte reconstruction oracles;
- action matrix/order/serialization, pre-write validation, partial-write
  handling, SMTP replies, and fail-open exclusions;
- Authentication-Results grammar and trust-boundary conflict handling;
- lifecycle, socket ownership/replacement, readiness, shutdown, logging,
  metrics, cardinality, and marker non-disclosure.

A repo-owned MTA-side Milter-v6 protocol peer drives the public Unix socket in
tests. It is independent of production parser/state code and proves
negotiation, callback framing, reconstruction, generated-client EOM calls,
ordered actions, fixed replies, abort/reuse, malformed frames, chunk
boundaries, backpressure, disconnects, and partial writes. Subprocess tests
start the real executable and a loopback daemon fixture generated from the
OpenAPI server boundary. Optional real-Postfix smoke coverage may be added but
does not replace the hermetic wire peer.

Fuzz targets cover at least:

1. frame decoding and negotiation;
2. callback state-machine sequences;
3. header/message reconstruction;
4. daemon response and action-plan admission;
5. envelope/SMTPUTF8 validation;
6. config/private-manifest parsing.

Run every affected target for at least ten seconds after the last change.
Abuse tests exercise maximum messages, headers, fields, recipients, frames,
connections, aggregate reservations, slow clients/daemon, cancellation,
malformed JSON, response overflow, symlink/hard-link/path races, and privacy
markers. Race tests cover connection state, admission, immutable datasource
reload, shutdown, and observability.

Final unchanged-snapshot gates include focused normal/race tests, all fuzz
targets, Linux amd64/arm64 cross-builds, macOS tests, `CGO_ENABLED=0` builds,
OpenAPI generation/stale checks, module/workspace synchronization, vendor
checks, dependency boundaries, `make test`, `make vet`, `make lint`,
`make race`, vulnerability checks, and `make guardrails`.

## Completion Conditions

Independent review must find no unresolved draft/RFC mismatch, message-fidelity
loss, unsafe signing bridge, key leakage, action confusion, mutation
indeterminacy, reply-policy defect, fail-open expansion, transport bypass,
resource leak, unbounded allocation/cardinality, global state, lifecycle race,
generated drift, or module-boundary violation.

Completion requires:

- all review findings fixed at their root with stable reproducers where
  practical;
- two independent approvals of one unchanged candidate snapshot;
- exactly one project-formatted commit containing only durable implementation
  and documentation paths;
- a clean index and worktree after commit; and
- the ignored prompt pack and execution ledger remaining untracked under
  `temp/`.
