# Exim Adapter Implementation Specification

Status: implementation-ready planning baseline.

Implementation base: `487ad434d106954e72d1cd241de543918c0fd260`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` identifier. This increment adds an Exim
adapter family around the existing daemon contract. It does not change the
pinned DKIM2 or DNS semantics.

## Scope And Authority

This increment delivers:

- an inbound, source-linked Exim `local_scan()` module that observes the Exim
  header chain, body descriptor, SMTP envelope and receive-session facts;
- a separately testable Go adapter service that owns local IPC, generated
  daemon calls, failure policy, evidence persistence and observability;
- an outbound Go `transport_filter` helper that performs complete-message
  signing or revision rewrites;
- exact, distinct incoming and outgoing SMTP-envelope evidence for revision;
- closed daemon-disposition and action mapping for both hook families;
- release packaging that compiles the real C module into each supported Exim
  source baseline instead of shipping an unverified universal object;
- reproducible upstream, Debian and Ubuntu compatibility evidence; and
- focused, integration, fuzz, race, abuse, privacy and guardrail proof.

Authority order is:

1. the pinned DKIM2 and DNS drafts for protocol meaning;
2. RFC 5321, RFC 5322, RFC 6531, RFC 6532, RFC 8601, RFC 9110 and the
   authoritative daemon OpenAPI document;
3. the official Exim documentation and the exact source/package baseline being
   built;
4. `docs/ARCHITECTURE.md` and the completed signing, datasource, replay,
   daemon, test-client, observability and Milter specifications;
5. this document for Exim hook, IPC, packaging and local failure policy.

Exim hook behavior is local adapter policy, not normative DKIM2 behavior.
Message fidelity must state what Exim exposed; it must never claim that a
`local_scan()` or `transport_filter` representation is the original SMTP DATA
octet stream.

Milter code reuse, a libmilter dependency, Exim structures in `lib/`, a
handwritten REST model, daemon-internal imports, dynamic Exim module loading,
arbitrary Exim header/recipient mutation, remote daemon transport, LDAP/SQL
work, next-domain transit and general key management are out of scope.

## Source Documents

Repository authority:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`, especially Exim Adapter Design, the dependency graph
  and resolved Exim compatibility decision
- `docs/specs/spec-and-prompt-template.md`
- `docs/specs/implementation/signing-and-revision.md`
- `docs/specs/implementation/datasource-providers.md`
- `docs/specs/implementation/replay-store-valkey.md`
- `docs/specs/implementation/openapi-daemon-foundation.md`
- `docs/specs/implementation/openapi-test-client.md`
- `docs/specs/implementation/observability-foundation.md`
- `docs/specs/implementation/milter-adapter.md`
- `docs/specs/openapi/dkim2d.yaml`
- `Makefile`, `go.work` and `.gitignore`

Protocol authority:

- `https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/04/`
- `https://datatracker.ietf.org/doc/draft-chuang-dkim2-dns/04/`
- `https://www.rfc-editor.org/rfc/rfc5321.html`
- `https://www.rfc-editor.org/rfc/rfc5322.html`
- `https://www.rfc-editor.org/rfc/rfc6531.html`
- `https://www.rfc-editor.org/rfc/rfc6532.html`
- `https://www.rfc-editor.org/rfc/rfc8601.html`
- `https://www.rfc-editor.org/rfc/rfc9110.html`

Official Exim and distribution sources, checked 2026-07-27:

- `https://www.exim.org/` identifies upstream Exim 4.99.5 as the current
  security release.
- `https://www.exim.org/exim-html-current/doc/html/spec_html/ch-adding_a_local_scan_function_to_exim.html`
  defines the `local_scan(int, uschar **)` source-link contract, body
  descriptor ownership, return codes, exported variables, header chain and
  supported header functions.
- `https://www.exim.org/exim-html-current/doc/html/spec_html/ch-generic_options_for_transports.html`
  defines `transport_filter` stdin/stdout, LF line endings, direct command
  execution, non-zero deferral and timeout behavior.
- `https://www.exim.org/exim-html-current/doc/html/spec_html/ch-main_configuration.html`
  defines `local_scan_timeout` and the `spool_wireformat` fidelity hazard.
- `https://www.exim.org/exim-html-current/doc/html/spec_html/ch-string_expansions.html`
  defines `$local_scan_data`, `$pipe_addresses`, receive-time
  `$sender_address` and outgoing `$return_path`.
- `https://sources.debian.org/src/exim4/4.98.2-1+deb13u3/` preserves the
  architecture-baseline Debian 13 stable security source package
  `exim4 4.98.2-1+deb13u3`. Release closeout refreshes the current official
  Debian security revision and tests it in addition when it has advanced.
- `https://packages.ubuntu.com/en/resolute/exim4` identifies Ubuntu 26.04 LTS
  `exim4 4.99.1-1ubuntu1.3` from the official security archive.

The distribution revisions above freeze the architecture release-test inputs.
A newer authenticated security revision adds a required release row without
changing the DKIM2 behavior baseline. Each release refresh records the
retrieval date, source URL, package revision, source checksum or OCI digest and
test result.

## Original Gap

The repository has a production daemon and Milter adapter but no Exim product
boundary. Exim cannot use the Milter state machine as a substitute:

- inbound `local_scan()` sees an Exim-owned header chain and body descriptor
  after receive-time processing;
- outbound `transport_filter` receives an LF-terminated complete message on
  stdin and runs concurrently in Exim's delivery pipeline;
- `local_scan()` is source-linked into an exact Exim build rather than loaded
  as a stable external plugin ABI;
- inbound rejection and outbound delivery deferral have different semantics;
- header mutation and full-message rewrite have different atomicity limits;
- queue-time revision requires inherited incoming-envelope evidence distinct
  from the current transport batch; and
- official distribution binaries cannot be assumed to contain a custom
  `local_scan()` implementation.

A production conclusion based only on a fake `local_scan()` stub, a Go unit
test, or the Milter implementation would therefore be false.

## Goal

The Exim adapter must provide a real, bounded path:

```text
receive
  -> source-linked C local_scan()
  -> versioned Unix-socket IPC
  -> dkim2-exim inbound service
  -> generated POST /v1/process client
  -> closed decision and safe header actions
  -> Exim accept/reject/temporary reject

delivery
  -> Exim transport_filter LF stream
  -> dkim2-exim sign or revise helper
  -> generated POST /v1/sign or /v1/revise client
  -> prevalidated action plan
  -> complete LF message rewrite on stdout
  -> Exim delivery or deferral
```

The product is one new Go module, `cmd/dkim2-exim`, plus a small C source
integration under that module. The C code owns only Exim ABI access, bounded
observation, IPC framing and application of the approved inbound decision.
The Go code owns configuration, secure resources, message projection,
generated HTTP calls, action validation, full-message rewriting, evidence
records, lifecycle and observability.

There is no cgo or Go shared-library boundary. There is no universal
precompiled `local_scan` object. Every supported Exim build compiles the C
source against that exact release's `local_scan.h`; compiler probes and a
release manifest bind the required declarations and source version.

## Delivery Shape

1. Add the module, generated-client boundary, Exim fidelity enums, closed IPC
   and adapter-domain contracts.
2. Implement and test the real C `local_scan()` module, inbound Unix service,
   observed-message reconstruction and inbound action mapping.
3. Implement evidence persistence, originator signing, ordinary-transit
   revision and atomic-before-stdout full-message rewrite.
4. Add strict configuration, capability ownership, lifecycle, packaging and
   secret-safe observability.
5. Prove the public product against real current upstream Exim and the official
   Debian/Ubuntu baselines, then run complete guardrails.
6. Perform an independent fresh review and fix every finding before staging.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 4-10 agent-days including real package builds |
| Highest-risk area | real Exim ABI, observed-byte fidelity, revision evidence and partial output |
| Expected prompt count | 5 implementation prompts plus 1 independent review |
| Required final gate | real Exim matrix plus `make guardrails` |

Risk notes:

- Lower risk: generated-client wiring and closed daemon disposition mapping
  reuse the completed OpenAPI contract.
- Medium risk: typed config, protected files, socket ownership, telemetry and
  complete LF rewrite have established repository patterns.
- Highest risk: Exim source ABI drift, spool representation, local-scan header
  mutation, persistent incoming evidence, Bcc-safe transport batching and
  concurrent filter output.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| Adapter contracts |  |  |  |  |  |
| Inbound local scan |  |  |  |  |  |
| Outbound filter |  |  |  |  |  |
| Runtime and packaging |  |  |  |  |  |
| Matrix and closeout |  |  |  |  |  |
| Independent review |  |  |  |  |  |

## Product And Package Boundaries

`lib/` remains unchanged unless an independently demonstrated core defect
requires a reproducer-first fix. It owns all DKIM2 parsing, verification,
signing, revision and policy behavior. It must not import Exim, C, cgo,
OpenAPI, command or adapter types.

`cmd/dkim2d` remains the sole service-side protocol and datasource owner.
Only the authoritative OpenAPI fidelity enum and generated outputs may need
extension. No Exim route or Exim DTO is added to the daemon.

`cmd/dkim2-exim` owns:

- Cobra/Viper/Fx command composition;
- one generated client produced from `docs/specs/openapi/dkim2d.yaml`;
- Exim-specific config and protected resources;
- the C-to-Go local IPC protocol;
- Exim observed-message projection and LF/CRLF conversion;
- local-scan disposition and header-action projection;
- transport-filter evidence lookup and full-message rewrite;
- adapter lifecycle, metrics and structured logs;
- Exim build integration, fixtures and compatibility reports.

`cmd/dkim2-exim/exim/` contains the source-linked C module, compile probes and
build snippets. C headers and structs do not escape this directory. The Go IPC
codec uses adapter-owned primitive fields, never `header_line`,
`recipient_item` or pointers.

`cmd/dkim2-milter` is not imported and is not copied wholesale. Small
transport-neutral rules such as strict daemon action admission may be moved to
a new explicit command-boundary package only if that removes real duplication
without introducing Milter or Exim models into `lib/`. Otherwise the Exim
module owns an independently tested admission implementation against the same
OpenAPI contract.

Generated REST DTOs stop at the generated-client adapter. Handwritten request
or response models that duplicate OpenAPI are forbidden.

## Exim ABI, IPC And Ownership

### Source-linked ABI

The production C module defines exactly:

```c
#define LOCAL_SCAN
#include "local_scan.h"
extern int local_scan(int fd, uschar **return_text);
```

Build integration sets `HAVE_LOCAL_SCAN=yes`,
`LOCAL_SCAN_SOURCE=Local/dkim2_local_scan.c` and
`LOCAL_SCAN_HAS_OPTIONS=yes`. Packaging keeps the reusable settings in an
included fragment, but writes `LOCAL_SCAN_HAS_OPTIONS=yes` directly into every
generated daemon `Local/Makefile`: Exim's `config.h` generation reads that
file before Make resolves included fragments. A package build is accepted only
after `exim -bP local_scan` lists the DKIM2 options. The module is copied into
an exact, verified Exim source tree and compiled as part of that Exim binary.
It is never loaded
into an arbitrary system binary.

A configure probe compiles against the exact target headers and verifies the
prototype, `SPOOL_DATA_START_OFFSET`, return codes, exported header and
recipient structures, `header_add_at_position`, `header_remove`,
`header_testname`, `expand_string`, `log_write` and memory functions actually
used. It first emits the build-ID-free
`cmd/dkim2-exim/exim/generated/probe-contract-v1.txt`. That deterministic LF
file has a fixed ordered `name=value` grammar for the exact Exim version,
source checksum, feature booleans, probed prototypes, types and constants; it
contains no path, timestamp, build ID or environment value. Missing or changed
members, prototypes or constants fail the build. The C source must not guess a
numeric ABI from an unrelated release.

The embedded build ID is exactly 64 lowercase hexadecimal characters: the
SHA-256 of the byte concatenation
`dkim2-exim-build-v1 NUL exim-version NUL source-sha256 NUL
probe-contract-sha256 NUL c-source-sha256 NUL
transport-filter-patch-sha256 NUL ipc-schema-sha256 NUL`.
`probe-contract-sha256` hashes the exact build-ID-free file above,
`c-source-sha256` hashes `cmd/dkim2-exim/exim/dkim2_local_scan.c`,
`transport-filter-patch-sha256` hashes the exact source-matched patch at
`cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch`, and
`ipc-schema-sha256` hashes `cmd/dkim2-exim/internal/ipc/schema-v1.txt`. `NUL`
means one zero octet; the
version is the exact source version and every digest is 64 lowercase ASCII
hexadecimal characters over the exact named file bytes. Those fields contain
no NUL. Only after computing the ID does the build generate
`cmd/dkim2-exim/exim/generated/build-id-v1.h` and the compatibility manifest;
neither output is an input to the ID. Both outputs carry the same value. The
Go service accepts only IDs in required
`inbound.allowed_build_ids`; this is a unique list of 1 through
16 exact 64-character values loaded before socket bind. A mismatch is rejected
after only the fixed IPC prefix and bounded build-ID bytes are read, before
mail allocation or daemon access. The build ID is compatibility evidence, not
authentication; mutual peer credentials remain mandatory.

The compatibility probe also records the relevant build features. Production
matrix builds require Exim internationalized-mail support so SMTPUTF8/EAI tests
exercise the real path; a build without that feature may be an optional
ASCII-only diagnostic row but does not satisfy a required release row.

The official Debian and Ubuntu binary packages remain valid
`transport_filter` targets. Inbound support requires rebuilding their official
source package with the C module or installing a project-produced,
source-matched custom Exim package. Merely installing `exim4-dev` or copying a
`.so` is not supported.

### Local IPC

Inbound C code connects to one absolute AF_UNIX `SOCK_STREAM` path. The Go
service owns socket creation, safe parent validation, restrictive umask,
inode identity, mode, peer-credential admission, readiness and cleanup.
Production support is Linux amd64 and arm64.

The first release runs the service under the same effective UID as Exim and
uses socket mode 0600. Admission is mutual: the service accepts only that exact
peer UID through `SO_PEERCRED`, while the C module checks the connected server
credential and owned socket inode against its own effective UID before sending
mail data. A group-shared or root-service compatibility mode is not inferred.

The versioned binary protocol has:

- fixed magic and version;
- canonical big-endian unsigned lengths;
- one closed request kind and one closed response kind;
- an exact total-frame cap;
- bounded scalar, header, recipient and message counts;
- no native pointers, struct layouts, machine-sized integers or C strings
  without explicit length;
- no unknown mandatory fields in version 1;
- full request/response validation before allocation or mutation; and
- one request and one response per connection.

Version 1 uses one positional frame, not extensible TLV. Every integer is
unsigned canonical network byte order:

```text
frame =
  4 octets magic "DXI1"
  1 octet  version = 1
  1 octet  kind = 1 request | 2 response
  2 octets reserved = 0
  4 octets payload length
  payload
```

The request payload is:

```text
u16 build_id_length
u8  source = 1 (exim_local_scan_observed)
u8  session_flags (0 local | 1 SMTP | 2 BSMTP)
u16 recipient_count
u16 header_count
u16 peer_length
u16 peer_port (zero only when peer is absent)
u16 helo_length
u16 received_protocol_length
u16 mail_from_length
build_id bytes
peer bytes
helo bytes
received_protocol bytes
mail_from bytes
recipient_count * (u16 length, bytes)
header_count * (u32 length, bytes)
u32 body_length
body bytes
```

Lengths are capped at: build ID exactly 64, peer 64, HELO 255, received protocol 32,
reverse path 256, each recipient 256, each header 65,536, 2,000 recipients,
2,000 headers, 1 MiB aggregate headers and 32 MiB reconstructed message.
Aggregate reconstructed-message accounting includes the one LF header/body
separator that is not carried as an independent field. The exact hard-cap
formula is `18 scalar + 671 bounded scalar bytes + 516000 recipient bytes +
8000 header-length bytes + 4 body-length bytes + 33554431 transmitted
header/body bytes`. The request payload cap is therefore exactly 34,079,124
octets and the complete frame cap is 34,079,136 octets. Exact-cap and
one-over-cap fixtures must be generated independently in C and Go. Narrowed
configuration reduces the admitted semantic limits; it never increases the
hard frame cap.

The response payload is:

```text
u8  decision = 1 accept | 2 reject | 3 tempfail
u8  reason = closed reason code
u16 removal_count
u16 add_name = 0 none | 1 Authentication-Results
u16 add_value_length
u16 removal occurrence * removal_count
add value bytes
32 locator bytes when an evidence locator is present, otherwise no bytes
```

Reason codes are `none`, `policy_reject`, `service_unavailable`, `timeout`,
`invalid_request`, `fidelity`, `contract`, `resource` and `internal`, assigned
contiguous values zero through eight. Locator presence is derived strictly:
exactly 32 unpadded base64url octets may follow only an accepting response;
any other trailing byte is invalid. Removal occurrences are non-zero, unique
and strictly descending. `removal_count` cannot exceed the request
`header_count`, 2,000, or the number of original eligible
Authentication-Results occurrences, and every occurrence must identify one of
those original eligible occurrences. `add_name=0` requires zero add length.
The response payload formula is `8 scalar + 4000 removal-index + 65535
add-value + 32 locator` octets, so the payload cap is exactly 69,575 octets and
the complete response frame cap is 69,587 octets. Accept requires `none`;
reject requires `policy_reject`; tempfail requires one of the remaining seven
non-zero non-policy reasons.
Reject/tempfail require no removals, add value or locator.

EOF is required immediately after the declared frame. Reserved bits, unknown
enums, noncanonical combinations, length disagreement and trailing input fail
before allocation or mutation. A future field requires a new protocol version.
The C projection gives BSMTP precedence: when `smtp_batched_input` is true it
emits only value 2, otherwise when `smtp_input` is true it emits only value 1,
otherwise value 0. Value 3 is invalid even though Exim also reports
`smtp_input=TRUE` during BSMTP. Independent C and Go fixtures freeze that
normalization.

The request carries:

- exact build-compatibility identifier;
- source `exim_local_scan_observed`;
- SMTP versus non-SMTP and BSMTP flags;
- envelope sender and ordered accepted recipient bytes;
- peer address, HELO and received-protocol observations when present;
- ordered non-deleted header bytes exactly as Exim exposed them;
- the body bytes from the caller-owned descriptor; and
- bounded shape facts needed for fidelity and diagnostics.

The C module never closes the Exim body descriptor. It seeks using
`SPOOL_DATA_START_OFFSET`, reads with checked short-read/error handling and
restores the required position. It excludes headers already marked deleted,
preserves duplicate order and internal folding, and never uses a generic mail
parser.

`spool_wireformat=true` is unsupported in the first release because the
official Exim documentation explicitly changes the data-file representation
but the public `local_scan()` API does not expose a per-message representation
fact. This is therefore an explicit deployment invariant rather than a
runtime-detection claim. The trusted local-scan option
`dkim2_spool_format=unix_lf` is mandatory; the C module returns a temporary
failure before reading the body when it is absent or has any other value.
Supported deployment examples set `spool_wireformat=false` and
`dkim2_spool_format=unix_lf`. The deployment validator independently reads
`exim -bP spool_wireformat` and `exim -bP local_scan`, requires those exact
paired values and rejects unknown or contradictory configuration. Real-Exim
matrix tests prove the invariant. Runtime drift after successful validation is
unsupported and requires operator revalidation; the module never pretends it
can infer the main option through an unavailable public ABI.

The response carries only:

- `accept`, `reject` or `tempfail`;
- one closed bounded reason class;
- zero or more exact Authentication-Results removal occurrences;
- zero or one bounded add-header field; and
- an optional opaque evidence locator for accepted messages.

It never carries raw daemon errors, a raw message, recipients, peer/HELO,
capability, key material or arbitrary SMTP reply text.

## Message And Session Projection

The adapter's projection is exact and explicit:

| Exim evidence | Adapter representation | Daemon representation |
| --- | --- | --- |
| non-deleted `header_list` plus body descriptor | observed LF message with source metadata | CRLF reconstruction in `MessageInput.raw_rfc5322_base64` |
| transport-filter stdin | exact LF stream with source metadata | CRLF reconstruction in `MessageInput.raw_rfc5322_base64` |
| local-scan sender | byte-preserved reverse path | `SMTPInput.mail_from` |
| local-scan recipients | byte-preserved ordered vector, duplicates retained | `SMTPInput.rcpt_to` |
| filter sender argument | byte-preserved current outgoing reverse path | outgoing `SMTPInput.mail_from` |
| `$pipe_addresses` | exact current delivery batch | outgoing `SMTPInput.rcpt_to` |
| stored receive envelope | immutable protected evidence record | `ReviseRequest.incoming_smtp` |
| peer address and HELO | bounded adapter evidence, absence explicit | not transmitted; OpenAPI has no such policy field |
| SMTP/local/BSMTP and received protocol | closed adapter fidelity facts | not transmitted; never invented as DKIM2 state |

The OpenAPI `MessageInput.fidelity` enum adds
`exim_local_scan_observed_crlf` and `exim_transport_filter_crlf`. The suffix
describes the bytes submitted after deterministic adapter conversion; the
source prefix prevents a claim of original raw-wire fidelity.

Exim generates its first `Received` field before the data ACL and
`local_scan()`, then rewrites only that field's timestamp after the hook
returns to record final reception completion. The inbound daemon input
therefore truthfully contains the pre-acceptance Exim observation. Real-delivery
qualification requires both phase representations to start with `Received`,
removes exactly that first field including its continuations from each
comparison projection, and then requires byte-identical remaining headers,
boundary, and body. It never removes later `Received` fields or normalizes any
other field. This is protocol-safe because DKIM2 header hashing excludes
`Received`; the full observed input remains protected and is still supplied to
the daemon.

LF conversion is streaming and deterministic: in the body, an LF not already
preceded by CR becomes CRLF, an existing CRLF remains one CRLF, bare CR is
retained and NUL is preserved. Body bytes are otherwise unrestricted and
binary-safe. Exim-observed header fields contain no NUL or CR, end in exactly
one LF, and use any interior LF only for folding immediately followed by SP or
HTAB. Envelope and session scalar fields contain no NUL, CR or LF. The
transport-filter header section obeys the same LF grammar; its body remains
binary-safe. Conversion is reversed for transport-filter output by requiring
legal CRLF daemon-added fields and rendering each field with LF in the Exim
stream. Header/body-boundary and exact-limit cases have independent oracles.
Illegal or ambiguous structural input tempfails/defers rather than being
normalized silently.

Peer and HELO observations are bounded and validated but do not enter protocol
or policy inputs because the current OpenAPI contract has no such authority.
They are never logged raw. Adding daemon policy based on them requires an
OpenAPI-first, separately reviewed contract.

SMTPUTF8 bytes are preserved in inbound envelope paths and RFC 6532 message
content. The adapter performs no Unicode normalization, case folding, IDNA
conversion, address rewriting or ASCII downgrade. The M10/M16 signing and
ordinary-transit revision contract currently admits only ASCII outgoing
envelope paths: `filter sign` and `filter revise` reject a non-ASCII
`$return_path` or recipient before evidence access, datasource access or any
daemon authority. UTF-8 and NUL body octets remain legal on those paths.
Invalid structure, NUL in a header/envelope/session scalar or lossy Exim
expansion fails closed.

## Inbound `local_scan()` Semantics

The Go service always calls generated `POST /v1/process`. It may request the
daemon-owned RFC 8601 action only when reporting is explicitly enabled with a
canonical configured `authserv-id`.

The exact mapping is:

| Daemon disposition | C return | Mutation |
| --- | --- | --- |
| `accept` | `LOCAL_SCAN_ACCEPT` | apply the fully validated inbound plan |
| `continue` | `LOCAL_SCAN_ACCEPT` | none |
| `reject` | `LOCAL_SCAN_REJECT_NOLOGHDR` | none |
| `tempfail` | `LOCAL_SCAN_TEMPREJECT_NOLOGHDR` | none |

`*return_text` ownership and meaning are exact. On accept with evidence the C
module copies the 32-character locator into Exim's permanent store and assigns
that pointer, causing Exim to expose precisely that value as
`$local_scan_data`. On accept without evidence it assigns `NULL`. Reject and
temporary-reject assign only the corresponding fixed Exim-store string:

- `DKIM2 policy rejected the message`
- `DKIM2 service temporarily unavailable`

Exim owns the corresponding 550 versus 451 SMTP status through the selected
return macro; the module does not call `smtp_printf()` or embed a second status
code in `return_text`. No daemon, message or identity text is reflected. The
NOLOGHDR variants are required so Exim does not copy raw rejected headers into
its reject log.

Inbound mutation is limited to the RFC 8601 trust-boundary behavior already
specified for the Milter adapter:

- remove only untrusted `Authentication-Results` occurrences that claim the
  configured local `authserv-id`;
- use the already reviewed canonical A-label/U-label-equivalent authserv-id
  comparison, without applying that normalization to SMTP mailbox bytes;
- remove in descending one-based occurrence order;
- add exactly one daemon-generated `Authentication-Results` field at the
  specified top position;
- pass all action text to Exim header APIs only as data through a constant
  format string, never as a `printf`-family format;
- never change/delete DKIM2 protocol fields or replace the body; and
- reject any other action, order, field, framing or count before the first
  header mutation.

The C module applies only the closed response produced by the Go adapter after
the Go adapter independently validates the generated daemon response. It also
validates IPC counts, names, occurrences and values. If Exim terminates the
module after partial in-memory header mutation, the message is not accepted;
the crash/timeout path is never a successful acceptance. Official Exim
semantics differ by ingress: SMTP input receives a temporary rejection, while
non-SMTP input is dropped and Exim exits non-zero after logging the local-scan
failure. The adapter documents and tests both outcomes and never describes a
retry guarantee for local submission. No partially mutated accepted message
may be claimed.

Every value retained by Exim, including `return_text` and added header bytes,
is copied into the correct Exim store pool before the IPC buffer is cleared.
No pointer into a socket, stack or temporary heap buffer survives
`local_scan()`.

The default failure mode is temporary reject. Explicit
`failure.inbound=fail_open` is evaluated only by a successfully reached Go
service after it has parsed the complete request. C-to-Go connection,
credential, framing or timeout failures always return temporary failure and
never fail open. The service may return accept-unchanged only when:

- no mutation has started;
- no forged local Authentication-Results claim was observed;
- the declared Exim-observed fidelity was proven;
- no daemon response was received;
- the daemon failure is exactly connect-unavailable or
  deadline-before-response;
- when revision evidence is enabled, the immutable evidence record was
  successfully published and its locator is returned; and
- the mandatory low-cardinality fail-open warning was successfully recorded.

Malformed responses, version drift, contract errors, policy results, replay
indeterminacy, representation ambiguity, local state failure and any
post-mutation failure never fail open.

## Incoming Revision Evidence

Ordinary-transit revision requires the exact receive-time envelope to remain
distinct from the outgoing transport envelope. On an accepting local-scan
path, the Go service stores one immutable evidence record. `DXE1` is the only
accepted v1 framing, all integers are unsigned big-endian, and fields are
positional:

```text
4 bytes magic = DXE1
u8  version = 1
u8  flags: bit 0 SMTP, bit 1 BSMTP, all other bits zero
u64 created_at Unix seconds
u64 expires_at Unix seconds
u8  source/fidelity = 1 exim_local_scan_observed_crlf
24 bytes random locator
u16 incoming mail-from length
u16 incoming recipient count
mail-from bytes
recipient_count * (u16 length, recipient bytes)
32 bytes HMAC-SHA256
```

The locator is generated from a cryptographically secure random source and
rendered as exactly 32 unpadded base64url characters. The direct-child filename
is exactly `<locator>.ev1`; the decoded filename must equal the 24 locator bytes
inside the record. Incoming paths retain the IPC limits of 256 octets each and
1 through 2,000 recipients. The flag combinations are exactly zero for local,
bit 0 alone for SMTP and bit 1 alone for BSMTP; both bits set is invalid. The
record hard cap is exactly 516,339 octets, and exact-cap and one-over tests use
independently constructed fixtures.

The key file contains exactly 32 opaque random bytes followed immediately by
EOF; hexadecimal, base64, text line endings and additional bytes are rejected.
Key rotation is outside the initial Exim adapter release. HMAC-SHA256 covers
every record octet preceding the MAC, including authenticated creation, expiry,
source and locator fields.
The bounded parser locates the terminal MAC only after overflow-safe structural
validation and compares it in constant time before returning any envelope
value. `created_at < expires_at` is required, construction checks addition
overflow, and `expires_at = created_at + configured retention`. A record is
expired exactly when the injected wall clock reports `now >= expires_at`.

The record is written descriptor-first beneath one protected 0700 state root,
as a direct regular child with link count one and mode 0600. Publication uses
the exact reserved temporary-child grammar `.put-<locator>-<nonce>`, where
`locator` is the 32-character locator and `nonce` is 128 random bits rendered
as 22 unpadded base64url characters. It uses `O_CREAT|O_EXCL|O_NOFOLLOW`,
write/fsync, `renameat2(RENAME_NOREPLACE)` to the final name, and directory
fsync. A final
name collision never replaces data: the owned temporary inode is removed,
fresh locator generation is retried at most eight times, then inbound
tempfails as a resource error. `renameat2` no-replace support is probed before
readiness; there is no weaker production fallback. Startup recovery handles
only the exact reserved publication-name grammar through descriptor/inode
validation. Symlinks, hard links, special files, path replacement, unsafe
ownership/mode, malformed records, duplicate locators and expired evidence
fail closed.

The opaque locator is returned as `local_scan_data`; it contains no recipient,
sender, queue ID, tenant, domain, digest or policy data and is not daemon or
signing authority. Exim persists it with the queue message. It is still
forbidden from logs, traces, metrics and errors.

Records remain immutable across retry and recipient batches. A successful
filter run does not delete them because another batch or retry may still need
the same incoming evidence. Admission accounts both record count and actual
record bytes; the default aggregate byte cap is 536,870,912. Capacity
exhaustion tempfails inbound before acceptance when revision evidence is
required.

A bounded service-owned sweeper snapshots only direct children, opens each
through the already validated directory descriptor, and parses and
authenticates it with an injected wall clock. Publication and GC are serialized
inside the sole service writer. To remove an expired record on Linux, GC first
atomically moves the current directory entry to a fresh service-private
quarantine name with exact grammar `.gc-<locator>-<nonce>`, where `locator` is
the record's 32-character value and `nonce` is 128 random bits rendered as 22
unpadded base64url characters. It uses `renameat2(RENAME_NOREPLACE)`, then
compares the quarantined inode with the already validated descriptor. It
unlinks the
quarantine name only when identity still matches and expiry is authenticated.
On mismatch it never unlinks the moved entry, attempts a no-replace restoration
and degrades readiness. A new replacement at the original name is untouched.

A reader that already owns and validated a descriptor may finish using its
immutable record while GC removes the quarantined directory entry. Startup
recovery recognizes only the exact bounded quarantine-name grammar. It
authenticates each quarantined record: an expired matching record may be
removed; an unexpired record is restored only with no-replace semantics;
collision, mismatch or malformed quarantine state degrades readiness.
Unexpected children, unsafe metadata, malformed records, locator disagreement
or invalid MAC degrade evidence readiness and force evidence-dependent inbound
and revision requests closed until operator remediation; they are never
silently deleted. Record-count, aggregate-byte, quarantine-count and scan-work
bounds apply at startup and on every sweep. Default retention is 14 days;
configuration may narrow it to 1 hour through 14 days.

The sole service writer additionally owns a dedicated external
`evidence.readiness_file` beneath its own protected 0700 local-filesystem
parent. The parent is descriptor-distinct from the evidence root, evidence-key
parent, configuration and capability parents. An exclusive nonblocking
lifetime lock on that retained parent prevents a second writer. The fixed
`DXR1` marker is a 0600, link-count-one, exact-EOF record authenticated with a
domain-separated HMAC under the evidence key. It binds the format version,
monotonic nonreused generation, `DIRTY`, `CLEAN` or `CLOSED` state, evidence
root device/inode and mtime/ctime fingerprint, plus informational live
record-count and byte-accounting state.

`DXR1` is exactly 112 octets. Every integer is canonical big-endian; signed
timestamp components use their 64-bit two's-complement representation:

```text
offset  width  value
0       4      magic "DXR1"
4       1      version = 1
5       1      state = 1 CLEAN | 2 DIRTY | 3 CLOSED
6       2      reserved = 0
8       8      non-zero monotonic generation
16      8      evidence-root device
24      8      evidence-root inode
32      8      evidence-root mtime seconds
40      8      evidence-root mtime nanoseconds
48      8      evidence-root ctime seconds
56      8      evidence-root ctime nanoseconds
64      8      informational live-record count
72      8      informational live-record bytes
80      32     HMAC-SHA256
```

The MAC input is the exact ASCII domain string
`DKIM2-EXIM-READINESS-V1` followed by one NUL octet, followed by marker octets
0 through 79. The marker key is the exact evidence HMAC key. A marker must be a
direct regular file owned by the MTA UID, mode 0600, link count one and exact
EOF at octet 112; trailing or missing bytes fail closed. Device and inode are
non-zero, timestamp seconds are positive, nanoseconds are in
`0..999999999`, and the bounded count/byte pair must be jointly zero or jointly
non-zero.

Before every root mutation, including no-replace probing, publication
temporaries and retry cleanup, recovery and GC, the writer atomically publishes
and fsyncs `DIRTY` outside the evidence root. It publishes `CLEAN` only after
root fsync and complete writer-owned validation, using an exact bounded
temporary, file fsync, atomic rename over the fixed marker, parent fsync and
post-publish descriptor/byte verification. Shutdown publishes and fsyncs
`CLOSED` before releasing the lifetime lock. A marker I/O failure terminally
releases/invalidate the authority so an older `CLEAN` marker cannot remain live.
Crash residue, torn or forged markers, stale generations, unsafe marker
metadata, arbitrary marker-parent children and a missing live writer lock fail
closed.

Atomic marker publication creates one mode-0600 direct temporary named exactly
`.ready-<nonce>`, where `nonce` is 128 random bits rendered as 22 unpadded
base64url characters. Creation uses `O_CREAT|O_EXCL|O_NOFOLLOW`, with at most
eight fresh-name attempts. The writer accepts only the fixed marker as prior
state and no residual temporary. A reader may tolerate at most one exact live
temporary beside the fixed marker while the sole writer lock is held; a second,
malformed or arbitrary child fails closed. A generation is consumed
immediately after successful rename even when a later fsync or verification
fails, so a later publication never reuses it.

Each one-shot reader retains both the evidence-root and readiness-parent
descriptors. It verifies two identical authenticated `CLEAN` snapshots, the
live sole-writer lock and matching root fingerprint with exact target-descriptor
acquisition between those snapshots. The second unchanged snapshot is the
authorization linearization point. The target descriptor is therefore already
owned before authorization completes. Its immutable metadata, HMAC, source,
locator and expiry validation may then finish across cooperative GC
quarantine/unlink; the writer never replaces a final locator. This makes the
filter target-bounded rather than scanning the complete evidence manifest.
The marker proves the last complete cooperative-writer snapshot and detects
directory-entry changes in O(1); counts and bytes are informational to the
reader. It cannot detect an unrelated record's in-place content corruption
between service-owned bounded sweeps. The protected directories, marker key
and lifetime lock share the explicit sole trusted MTA-UID boundary; replay by a
hostile process already running as that UID is outside this filesystem trust
model.

The filter receives `$local_scan_data` as one exact command argument. It reads
the record through the same protected owner and validates integrity, expiry,
mode, source and locator before constructing `incoming_smtp`. Missing or
invalid evidence always defers revision.

## Outbound `transport_filter` Semantics

The executable has fixed subcommands:

```text
dkim2-exim filter sign
dkim2-exim filter revise
```

Mode is selected by the trusted Exim transport configuration, not message
content. Tenant, domain, endpoint and capability come only from typed protected
configuration.

The Exim command is direct and absolute, never `/bin/sh`. Exim supplies the
current outgoing reverse path from the separately quoted,
source-matched `$dkim2_transport_filter_return_path` token and
`$pipe_addresses` as separate arguments. The token is an exact direct-argv
item added by the source-matched Exim patch: only the SMTP transport-filter
call path recognizes it, copies the already selected current return path, and
does not invoke general expansion or permit any other tainted argument.
`$sender_address` is the receive-time sender and is explicitly forbidden here.
This is the only supported transport-filter interface for exact delivery-batch
recipients. An unmodified Exim binary cannot support outbound filtering in this
release.
The implementation validates all arguments before daemon access, clears
mutable copies best-effort and never logs or echoes them. Operators must treat
the Exim user and local process table as one MTA trust boundary; shell
interpolation and user-controlled command selection are forbidden.

The command layouts are positional after an explicit option terminator:

```text
/absolute/dkim2-exim --config /absolute/sign.yaml filter sign -- \
  "$dkim2_transport_filter_return_path" "$pipe_addresses"
/absolute/dkim2-exim --config /absolute/revise.yaml filter revise -- \
  "$local_scan_data" "$dkim2_transport_filter_return_path" "$pipe_addresses"
```

No untrusted expansion can be parsed as a flag, command, config path or mode.
Sign requires exactly two positional values after `--`; revise requires
exactly three. Empty reverse path is legal. Locator and recipient are non-empty
and exact-count validated. The config validator requires the literal quoted
expansions above, rejects `$sender_address`, and proves that the empty bounce
path remains one empty argv. A real-Exim case deliberately makes the incoming
sender and router-derived outgoing return path differ and proves the daemon
receives only the latter.

Originator signing sends `POST /v1/sign`. Ordinary-transit revision sends
`POST /v1/revise` with:

- stored receive-time evidence as `incoming_smtp`; and
- the current sender and exact current `$pipe_addresses` batch as `smtp`.

These structures are never aliased or substituted for each other. Revision
does not fall back to the outgoing envelope when evidence is missing.

Recipient batching defaults and release examples require one address per
transport-filter invocation. Multiple `$pipe_addresses` fail closed because
Exim does not expose message-specific To/Cc/Bcc disclosure authority through
this hook. A future multi-recipient mode requires a new explicit evidence
contract; a global compatibility switch is forbidden.

The helper reads stdin to a bounded private spool file before daemon access.
It verifies exact LF framing, headers, body, byte limits and terminal newline
policy, then creates the CRLF daemon input. It validates the complete generated
response and complete ordered plan before creating output.

The supported production filter is attached to an SMTP transport. If Exim's
input lacks a final LF, the helper appends exactly one LF to its private
pre-signing representation and emits that same final LF; this accounts for the
official Exim behavior that otherwise supplies a missing final newline after
the filter, which would invalidate a signature calculated without it. It never
adds a second newline. Non-SMTP transport use is rejected by configuration
rather than silently applying different terminal-line behavior.

The signed/revised bytes must be final network form before dot-stuffing and
LF-to-CRLF conversion. Supported Exim transports therefore forbid post-filter
`headers_add`, `headers_remove`, `headers_rewrite`, `delivery_date_add`,
`envelope_to_add`, `return_path_add` or another content filter/rewrite. The
SMTP transport must not assign the envelope-changing `return_path` option;
otherwise its ordering relative to filter argument expansion could make the
signed reverse path differ from the MAIL FROM sent on the wire. The packaging
validator inspects rendered transport settings through `exim -bP transport`
and the raw named transport blocks through `exim -bP config`, then fails
deployment validation when those settings could mutate signed bytes or
outgoing envelope authority.
The initial supported SMTP transport requires `size_addition < 0`, so Exim
does not send a MAIL FROM `SIZE` parameter computed before filter growth. The
validator rejects zero or positive `size_addition`; estimating a positive
allowance is outside this release.

The exact result mapping is:

| Daemon result | Disposition | Filter behavior |
| --- | --- | --- |
| `pass` | `accept` | write the transformed complete message, exit 0 |
| `pass` | `continue` | write the original complete message, exit 0 |
| `fail` or `permerror` | `reject` | write no message, exit 75 |
| `temperror` | `tempfail` | write no message, exit 75 |

Any incoherent pair is a contract failure and exits 75 with zero output.
Transport filters cannot bounce a message; official Exim behavior defers on
non-zero status. Outbound fail-open is not supported: delivering an unsigned
or un-revised message is not a safe compatibility action.

Only `Message-Instance` and `DKIM2-Signature` add-header actions are valid.
Originator signing requires the exact M16 order. Revision accepts only the
exact unchanged/changed plan shape. Authentication-Results, deletion, change,
recipient mutation and body-only replacement are invalid on this path.

The filter inserts the ordered fields at the end of the inherited header block,
immediately before the existing header/body separator, matching the M10
insertion position and action order. Each action is rendered exactly as
`name + ":" + value + LF`; the OpenAPI value already contains the exact
post-colon bytes, including required legal leading SP or HTAB folding
whitespace. Missing or illegal post-colon folding whitespace is a contract
failure. Independent tests prove byte and canonical equivalence with the M16
action value and detect any added or removed whitespace. The value is the
daemon-proved canonical-equivalent legal unfolding, not the original folded
M10 bytes. The
adapter does not prepend, reorder or refold inherited fields. A header-only
message remains header-only unless the authoritative completed-message proof
requires otherwise; the adapter never invents a body separator independently.

Full output is assembled and reparsed in a confined temporary file. The helper
proves the CRLF form corresponding to the final LF output matches the
daemon-authorized additions before its first stdout byte. It then streams the
whole LF message to stdout. stdout is protocol data; logs and diagnostics must
never use stdout or stderr because Exim joins filter stderr with stdout.

A stdout short write, broken pipe, cancellation or process failure after the
first byte is `partial_output_indeterminate`. The helper exits non-zero, never
retries the daemon request and never switches to original-message output.
Exim is expected to defer and retry delivery; tests must prove the remote sink
does not receive a falsely successful delivery.

## Configuration And Protected Capabilities

The stable root is `dkim2-exim-config-v1`. Cobra/Viper/Fx loading follows the
existing strict typed, provenance-aware, placeholder-before-validation model.
Unknown keys, aliases, duplicate source values, unexpanded variables,
noncanonical scalars and conditional drift fail closed.

Initial paths:

| Path | Default | Contract |
| --- | --- | --- |
| `inbound.socket` | required for service | absolute AF_UNIX path |
| `inbound.socket_mode` | `0600` | fixed same-UID mode |
| `inbound.peer_uid` | required | exact Exim/service effective UID |
| `inbound.allowed_build_ids` | required | 1..16 unique exact generated IDs |
| `inbound.request_timeout` | `3s` | 100ms..10s, below Exim timeout |
| `inbound.max_connections` | `128` | 1..4096 |
| `inbound.max_in_flight_messages` | `64` | 1..1024 |
| `inbound.max_buffered_bytes` | `268435456` | validated aggregate minimum..1 GiB |
| `daemon.endpoint` | required | canonical loopback-literal HTTP URL |
| `daemon.process_capability_file` | inbound conditional | protected direct child |
| `daemon.sign_capability_file` | sign conditional | protected direct child |
| `daemon.revise_capability_file` | revise conditional | protected direct child |
| `daemon.request_timeout` | `2s` | 100ms..10s |
| `signing.tenant` | sign/revise conditional | closed validated tenant |
| `signing.domain` | sign/revise conditional | canonical domain |
| `authentication_results.enabled` | `false` | inbound only |
| `authentication_results.authserv_id` | absent | exact conditional value |
| `failure.inbound` | `tempfail` | `tempfail` or `fail_open` |
| `evidence.enabled` | `false` | required for revise-capable inbound service |
| `evidence.root` | absent | protected direct state root |
| `evidence.key_file` | absent | distinct protected direct child |
| `evidence.readiness_file` | absent | required external authenticated readiness marker |
| `evidence.retention` | `14d` | 1h..14d |
| `evidence.max_records` | `100000` | 1..1000000 |
| `evidence.max_bytes` | `536870912` | 1 MiB..1 GiB actual-record aggregate |
| `limits.message_bytes` | `33554432` | may only narrow |
| `limits.header_bytes` | `1048576` | may only narrow |
| `limits.header_count` | `2000` | may only narrow |
| `limits.header_field_bytes` | `65536` | may only narrow |
| `limits.recipient_count` | `2000` | may only narrow; outbound effective maximum 1 |
| `observability.logging.level` | `info` | closed slog level |
| `observability.logging.destination` | mode-dependent | `stderr` for service; `none` or protected Unix datagram for filter |
| `observability.metrics.endpoint` | absent | optional loopback listener |

The three capability files are distinct and route-scoped. The evidence key is
distinct from all daemon capabilities, signing keys, replay secrets and other
protected material. Disabled features forbid and do not open their protected
paths.

Capability loaders, evidence ownership and the generated HTTP transport inherit
the M14/M16 descriptor confinement, exact-EOF, loopback-only, proxy-free,
redirect-free, cookie-free, ambient-credential-free and bounded-response
rules. Raw causes and protected paths remain absent from errors.

The C local-scan option table is intentionally smaller and alphabetically
ordered:

- `dkim2_failure_mode`;
- `dkim2_max_message_bytes`;
- `dkim2_socket`;
- `dkim2_spool_format`;
- `dkim2_timeout`.

It contains no daemon endpoint, capability, evidence key or signing policy.
`dkim2_failure_mode` is an invariant declaration and accepts only `tempfail`:
only a successfully reached Go service may apply its separately validated
fail-open policy after emitting the mandatory warning.
`dkim2_spool_format` has no default and accepts only the exact trusted value
`unix_lf`; it declares the deployment invariant validated independently
against `exim -bP spool_wireformat=false`. The socket is the sole C-to-Go
authority boundary.

## Resource, Timeout And Concurrency Limits

Every count and byte limit is checked before allocation with overflow-safe
arithmetic. Exact limit succeeds; one-over fails closed.

The adapter accounts independently for:

- IPC frame and scalar lengths;
- headers, header bytes and individual fields;
- body and complete message bytes;
- incoming and outgoing recipients;
- LF and CRLF representations;
- base64, JSON and generated DTO copies;
- daemon response and action-plan bytes;
- evidence records and state-directory entries;
- temporary input, transformed output and stdout copy; and
- connections, active requests and aggregate buffered bytes.

The same conservative seven-message-copy and fixed response-working-set model
used by the Milter adapter is the minimum starting point. The configuration
validator computes the exact worst case for the selected service/filter mode
and rejects an aggregate cap that cannot admit one configured maximum message.

The validated service and filter deadlines remain at most 10 seconds. The
packaged C module and transport-filter outer boundaries are exactly 11 seconds,
and `local_scan_timeout` is exactly 12 seconds. Consequently daemon request
timeout is shorter than service/filter ownership, every configured service
deadline finishes before the C boundary, and the C boundary finishes before
Exim's global local-scan boundary. Zero/unbounded timeout configuration is
forbidden.

No retry occurs inside an authoritative process/sign/revise request because
request-write ambiguity can duplicate replay or signing work. Exim owns
delivery retry after a filter deferral.

## Observability And Privacy

The Go service uses a central bounded JSON slog provider and process-local
Prometheus registry. The one-shot filter defaults to no logging and may use
only a configured protected Unix-datagram sink; it never writes diagnostics to
stdout or stderr. The C module writes only closed reason-class messages through
`log_write`; C debug output never includes message or identity data.

Allowed facts are:

- hook `local_scan` or `transport_filter`;
- operation `process`, `sign` or `revise`;
- fidelity class;
- result/disposition/failure class;
- action kind;
- fail-open boolean;
- readiness, admission and evidence-store state;
- duration, message-size, header-count and recipient-count buckets;
- Exim baseline class `upstream`, `debian_stable` or `ubuntu_lts`; and
- adapter/IPC compatibility version.

Logs, traces, metrics, C logs, errors, test failure output and compatibility
reports must not contain raw or hashed sender/recipient/domain/tenant,
peer/HELO, queue or message ID, raw headers/body, Authentication-Results,
Message-Instance, DKIM2-Signature, evidence locator/key/record, capability,
daemon URL, socket peer, paths to protected material, key material, raw
arguments or raw errors.

Labels use closed low-cardinality values only. No debug module may enable mail
data. Sink failure/panic is contained and never changes protocol results,
except the mandatory inbound fail-open warning: if that warning cannot be
recorded, fail-open is not permitted.

## Lifecycle And Packaging

Inbound service startup order is:

1. strict config and protected-input validation;
2. evidence-store validation and bounded recovery;
3. generated daemon client and admission construction;
4. quiescent socket bind and inode verification;
5. observability activation;
6. accept loop;
7. readiness publication.

Shutdown clears readiness, stops admission, closes the owned socket, drains
active requests, cancels remainder within the configured budget, joins
observation/evidence workers and removes only the socket inode created by this
process.

The transport helper is one-shot and never starts a listener. It opens only the
mode-specific capability and evidence resources, owns all temporary files and
unlinks them on every path. Signal, panic and cancellation paths close
descriptors and return non-zero without diagnostics on stdout/stderr.

Packaging provides:

- the Go executable for Linux amd64/arm64;
- C source and build probe;
- upstream `Local/Makefile` snippet;
- Debian/Ubuntu source-package integration patches and documented rebuild
  commands;
- Exim runtime configuration examples for local_scan options and distinct sign
  and revise transports;
- explicit `spool_wireformat=false`, `dkim2_spool_format=unix_lf`,
  `max_rcpt=1`, separately quoted `$dkim2_transport_filter_return_path` and
  `$pipe_addresses`,
  no SMTP-transport `return_path` assignment, absolute filter command,
  no post-filter header rewrite, negative `size_addition`, timeouts, user/group,
  state/socket ownership and rollback notes; and
- a generated compatibility report containing no machine-specific paths or
  mail data.

## Compatibility Matrix And CI Contract

The initial release matrix, verified from official sources on 2026-07-27, is:

| Baseline | Version | Inbound local_scan | Outbound filter | Release status |
| --- | --- | --- | --- | --- |
| current upstream | Exim 4.99.5 | source build required | required | required |
| Debian 13 architecture baseline | 4.98.2-1+deb13u3 | official source-package rebuild required | official binary/package required | required |
| Ubuntu 26.04 LTS security | 4.99.1-1ubuntu1.3 | official source-package rebuild required | official binary/package required | required |

No PPA, backport, testing, unstable, third-party or vendor-unmaintained package
defines support. Release closeout must refresh official Debian security
metadata; if the revision is newer than the frozen architecture baseline, the
new revision is an additional mandatory authenticated row and the durable
compatibility evidence is updated before release. Optional older supported
releases may be smoke-tested but do not lower the support floor.

Hermetic per-change CI must prove:

- Go domain, IPC, framing, conversion, admission, rewrite and evidence tests;
- a repo-owned independent local-scan ABI harness;
- compilation of the C module against checked-in, license-attributed public-API
  fixtures for every matrix family;
- subprocess tests using the real Go executable and generated daemon server;
- container tests with pinned image digests already present in CI; and
- no network-dependent `latest` resolution.

These hermetic tests are necessary but are not production completion. Release
and milestone closeout additionally require one recorded successful real Exim
run for every matrix row:

- fetch the exact official signed source/package metadata;
- verify pinned checksum/signature or immutable image digest;
- build Exim with the real C module for inbound;
- run an interactive SMTP receive through real `local_scan()`;
- run originator sign and ordinary-transit revise through real
  `transport_filter`;
- prove exact decisions, header order, LF/CRLF behavior, evidence separation,
  Bcc-safe single-recipient batching, daemon timeout, malformed response,
  partial output and delivery deferral; and
- record version/date/digest/result in the durable compatibility report.

If an official package artifact is temporarily unavailable for a CI
architecture, that architecture may be marked unavailable with exact evidence,
but the required amd64 row cannot be waived for completion. A fake local-scan
stub never substitutes for the real upstream/source-package builds.

## Required Tests

Unit tests:

- canonical IPC encode/decode, unknown version, truncation, length overflow,
  duplicate fields, allocation bounds and zeroization;
- canonical BSMTP precedence, generated build-ID derivation, bounded
  allowlist/mismatch and response-removal eligibility bounds;
- C response admission and Go request admission from independent fixtures;
- header order, duplicates, deleted fields, folding, empty body, binary body,
  bare CR/LF, CRLF preservation, inbound SMTPUTF8 preservation and exact
  boundaries;
- body NUL/CR/LF preservation and rejection of NUL/CR/illegal LF in
  header/envelope/session fields;
- SMTP/local/BSMTP, peer/HELO presence and received-protocol projection;
- generated process/sign/revise requests and exact fidelity enums;
- complete disposition/action matrix and malformed combination rejection;
- RFC 8601 local-claim detection, descending removal and top insertion;
- exact accept locator/NULL versus fixed reject/tempfail `return_text`
  assignment and Exim-store lifetime;
- evidence creation, integrity, retry reuse, expiry, capacity, ownership,
  exact key/record framing, constant-time MAC validation, authenticated expiry,
  byte/count capacity, symlink/hard-link/path race, read/GC replacement race,
  cancellation and GC;
- incoming/outgoing revision envelope non-aliasing and no fallback;
- source-matched `$dkim2_transport_filter_return_path`, empty bounce path,
  rejection of ordinary/concatenated `$return_path`, `$sender_address`, lookup
  output, shell execution and every other tainted direct argument, divergent
  incoming/outgoing sender proof, and rejection of any explicit SMTP transport
  `return_path` assignment;
- non-ASCII outgoing envelope rejection before evidence/datasource/daemon
  authority while UTF-8 message octets remain supported;
- one-recipient success and multi-recipient/Bcc-safe rejection;
- complete output rewrite, pre-output validation, short write, broken pipe and
  partial-output indeterminacy;
- fail-open allowlist/exclusions and mandatory warning failure;
- strict config, protected paths, conditional capabilities, redaction,
  lifecycle, readiness, admission and shutdown;
- no-replace publication collision/retry, crash-leftover recovery and atomic
  quarantine GC under path replacement; and
- negative `size_addition` acceptance and zero/positive deployment-validator
  rejection.

Integration tests:

- independent C ABI harness driving the actual `local_scan()` function;
- public Unix socket with a C-side peer independent of the Go IPC codec;
- real executable plus generated daemon server for process/sign/revise;
- real upstream 4.99.5 SMTP receive and transport delivery;
- Debian 13 and Ubuntu 26.04 official source/package rows;
- SMTP and local submission, duplicate/folded headers, binary body,
  inbound SMTPUTF8/EAI paths, outbound SMTPUTF8-envelope rejection, forged
  Authentication-Results, Bcc-style delivery,
  daemon unavailable/timeout/overflow/malformed result and evidence expiry;
- SMTP local-scan timeout temporary rejection versus non-SMTP message drop and
  non-zero Exim exit;
- `max_rcpt=1` yielding one `$pipe_addresses` argv and deliberate rejection of
  a transport configuration that can batch multiple recipients;
- real filter output disconnect proving deferral rather than success.

Fuzz targets, each run for at least ten seconds after its last change:

1. IPC request/response framing;
2. Exim observed-message LF/CRLF reconstruction;
3. strict daemon response and action admission;
4. evidence record parsing/integrity;
5. transport-filter message rewrite;
6. config and Exim command-argument parsing.

Generated and documentation checks:

- OpenAPI source, server, test client, Milter client and Exim client remain
  reproducible and current;
- workspace/module/vendor metadata includes the new module;
- C fixtures retain license/provenance and matrix version metadata;
- compatibility report and operator/build docs match the tested versions;
- dependency guards prove no Exim/Milter/service imports in `lib/` and no
  Milter imports in the Exim module.

Final unchanged-snapshot gates:

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
git diff --check
```

The real Exim compatibility target is also mandatory and may use pinned
container/package caches with documented network prerequisites. A blocked
network fetch is not a successful matrix result.

## Acceptance Criteria

- Exim integration is an independent adapter family with no Milter dependency.
- A real source-linked C `local_scan()` module, not a production stub, drives
  generated daemon processing through versioned bounded IPC.
- Inbound observed message, envelope, recipients and session facts are
  byte-accounted and accurately labeled.
- Header mutation is limited to the reviewed RFC 8601 behavior and exact Exim
  APIs.
- The outbound helper rewrites the entire LF message only after complete daemon
  response and action validation.
- Sign and revise use the generated daemon client and no parallel REST DTO.
- Revision supplies distinct immutable incoming and outgoing envelopes and
  never substitutes one for the other.
- Inbound SMTPUTF8 and RFC 6532 bytes are preserved without invented
  normalization; outbound non-ASCII envelope paths fail before authority use.
- Multi-recipient transport batches fail closed until per-message Bcc
  disclosure authority exists.
- Default inbound failures tempfail; C-to-Go failures never fail open; the
  reached-service-only inbound fail-open policy is explicit, evidence-safe and
  observable; outbound failures always defer.
- Partial filter output is indeterminate and non-zero, never accepted or
  retried internally.
- Config, capabilities, evidence state, socket, timeouts, resources,
  concurrency and lifecycle fail closed.
- Observability is bounded, low-cardinality and secret-safe.
- Current upstream Exim, the frozen Debian 13 architecture baseline, any newer
  authenticated Debian security row, and Ubuntu 26.04 pass with real
  source/package evidence.
- Independent review has no open findings, complete guardrails pass on one
  unchanged snapshot and exactly one project-formatted commit follows.

## Completion Evidence

The implementation candidate contains the source-linked module, Go
service/filter, protected evidence and configuration, packaging validators,
operator docs, five authenticated source fixtures, and the strict 43-case
real-matrix runner. Final unchanged-candidate matrix, fuzz/race, guardrail,
candidate-manifest, and independent-review identities remain to be recorded;
no pending field is presented as a pass.

### Later M17 qualification addendum — 2026-07-31

The preceding completion text and review matrix preserve the milestone state at
the time they were written. The later unchanged Linux qualification supersedes
their pending matrix fields:

- all five authenticated rows passed all 43 cases;
- the fail-closed privacy verifier passed;
- the matrix run ID is
  `0487837fbec882979f6cf290e2d1ccb36d37a07558f03e64f77fa0cc5a7cca6b`;
- the candidate-bound `run-v1.txt` SHA-256 is retained in the imported
  full-profile evidence rather than embedded in this candidate document,
  avoiding a self-referential snapshot digest;
- the qualified rows are upstream Exim 4.99.5, Debian
  4.98.2-1+deb13u3/u4, and Ubuntu 4.99.1-1ubuntu1.3/u1.4.

The durable conformance model is intentionally not a portable Exim runner.
Portable reports record the Linux case as `not_applicable`. A full report must
receive an explicit absolute evidence root, rerun the strict matrix verifier,
and import only a bounded content-free summary bound to the current manifest,
base revision, candidate snapshot, and verifier digest. Missing, stale,
malformed, privacy-failing, or candidate-mismatched evidence fails closed.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Separate Exim adapter; no Milter/lib drift | Separate `cmd/dkim2-exim` module and generated daemon client boundary | done | Final review remains candidate-bound |
| ABI | Real source-linked module on every required baseline | Five authenticated upstream, Debian and Ubuntu source fixtures and build IDs | partial | Final 43-case matrix pending |
| Fidelity | Exim-observed bytes and LF conversion are exact and labeled | Byte-class, header-order and SMTP capture measurements implemented | partial | Final matrix pending |
| Envelopes | Incoming evidence and outgoing authority remain distinct | Authenticated receive evidence and outgoing return-path projections implemented | partial | Final matrix pending |
| Actions | Exact daemon mapping and hook-specific mutations | Process/sign/revise action-plan checks implemented | partial | Final matrix pending |
| Failure | Tempfail/defer defaults and partial output are closed | SMTP/local/daemon/evidence/filter-output fault cases implemented | partial | Final matrix pending |
| Security | Capabilities, evidence, resources and telemetry are safe | Protected capabilities, bounded IPC/HTTP, redacted evidence and privacy scans implemented | partial | Full final gates pending |
| Tests | Hermetic, real-Exim, fuzz, race and abuse proof exists | Unit, verifier, fuzz/race and five-row runners exist | partial | Unchanged-candidate executions pending |
| Generated | OpenAPI clients and workspace/vendor output are fresh | No Exim DTO duplication; generated freshness remains a final gate | partial | Final gate pending |
| Effort | Prompt timing is complete and compared to estimate | Exact retained prompt timing is ledger-owned | partial | Final closeout comparison pending |

## Decisions And Open Questions

- Settled: Exim is a separate adapter family and imports no Milter code.
- Settled: the smallest real product is a source-linked, version-probed C
  `local_scan()` module plus a separately testable Go service/filter helper.
- Settled: the C/Go boundary is bounded versioned AF_UNIX IPC, not cgo or a Go
  shared library.
- Settled: official distribution inbound support requires source-package
  rebuild; a universal drop-in local-scan binary is not claimed.
- Settled: `spool_wireformat=true` is unsupported initially; the public
  local-scan ABI cannot detect it per message, so the paired
  `dkim2_spool_format=unix_lf` option and deployment validator enforce the
  invariant without inventing an expansion variable.
- Settled: Exim-observed representations receive explicit OpenAPI fidelity
  values and are never called raw wire input.
- Settled: peer/HELO are adapter fidelity facts, not new daemon policy state.
- Settled: receive-time evidence is immutable protected state referenced by
  opaque `$local_scan_data`; revision never reconstructs it from outgoing data.
- Settled: transport batches are single-recipient until exact Bcc disclosure
  evidence exists.
- Settled: only inbound pre-mutation availability failures may use explicit
  fail-open, and only inside a reached Go service after forged-claim,
  fidelity, warning and evidence proof; C-to-Go failures and outbound
  sign/revise never fail open.
- Settled: current upstream 4.99.5, Debian 13 architecture baseline
  `4.98.2-1+deb13u3` and Ubuntu 26.04 security
  `4.99.1-1ubuntu1.3` are the first required matrix.
- Open: none that blocks implementation. Any real-Exim API conflict updates
  this durable contract before implementation broadens or validation weakens.

## Completion Conditions

Independent review must find no unresolved draft/RFC mismatch, Exim API
assumption, fidelity overclaim, envelope conflation, Bcc disclosure, action
confusion, mutation/output indeterminacy, fail-open expansion, IPC/parser
allocation defect, protected-state weakness, raw diagnostic leak, lifecycle
race, generated drift or module-boundary violation.

Completion requires:

- every finding fixed at its root with a stable reproducer where practical;
- real current-upstream and required distribution evidence;
- two independent approvals of one unchanged candidate;
- exactly one project-formatted commit containing only durable paths;
- a clean worktree/index after commit; and
- the ignored prompt pack and execution ledger remaining under `temp/`.
