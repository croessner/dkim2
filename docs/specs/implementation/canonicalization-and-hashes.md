# Canonicalization And Hashes

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

Status: completed.

This spec defines Milestone M3, the DKIM2 canonicalization and hash foundation
for the reference library. It covers header hash input, body hash input,
signature input canonicalization, SHA-256 hash calculation, golden tests, and
byte-level debug helpers. This work builds on the completed M1 raw message
model and M2 DKIM2 tag parsers and touches only the library protocol core.

## Source Documents

This spec is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`, especially Sections 3.1, 3.2, 3.3, 3.4,
  3.5, 3.6, 5.2, 5.3, 5.4, 5.6, 6.1, 6.2, 9, 10, 11.1, 11.2,
  11.4, 11.5, 12.1, 12.2, 12.3, 12.5, 13, 14, 15, 16, and 18
- `docs/specs/spec-and-prompt-template.md`
- `docs/specs/implementation/raw-message-model.md`
- `docs/specs/implementation/dkim2-tag-parsers.md`
- `lib/internal/rawmsg/doc.go`
- `lib/internal/tagvalue/doc.go`
- `lib/internal/instance/doc.go`
- `lib/internal/signature/doc.go`
- `lib/internal/canonical/doc.go`
- `Makefile`
- `.gitignore`
- `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05, especially
  Sections 3.1, 4, 6.1, 6.2, 9.6, 11.6, and 11.7
- RFC 5322 Internet Message Format semantics for header fields, header
  continuation, field names, field values, and CRLF line endings
- RFC 4648 base64 behavior as already constrained by M2 for stored hash values

If this spec conflicts with a source document, stop and reconcile the durable
artifact before implementation continues.

`draft-ietf-dkim-dkim2-spec-04` is the binding implementation baseline for M3.
If a later DKIM2 draft changes canonicalization, hash, or signature-input
semantics, update durable documentation and golden vectors before changing
protocol behavior.

## Original Gap

The repository currently has completed foundations for M1 and M2:

- `lib/internal/rawmsg` owns byte-preserving RFC 5322 message parsing,
  immutable header/body views, lowercase header names, unfolded header values,
  CRLF policy, and body line indexes.
- `lib/internal/tagvalue` owns shared DKIM2 tag-list parsing and strict
  base64string parsing.
- `lib/internal/instance` parses `Message-Instance` fields, hash sets, recipe
  base64 containers, and contiguous `m=` sequences.
- `lib/internal/signature` parses `DKIM2-Signature` fields, envelope-path
  containers, signature sets, flags, nonces, contiguous `i=` sequences, and
  the unreferenced-instance special case.

`lib/internal/canonical` is still a package stub. There is no implementation
contract for DKIM2 canonical header bytes, canonical body bytes, SHA-256 hash
calculation, signature input construction, null-signature handling, golden
fixtures, or safe debug output. M4 and M5 cannot safely verify signatures or
message hashes until M3 defines exactly which bytes are hashed or signed.

The risk is protocol-critical: if M3 relies on map iteration order, raw header
serialization from a friendly parser, lossy whitespace handling, accidental
MIME decoding, or ad hoc signature-field rewriting, later verification can
produce plausible but draft-incompatible results.

## Goal

Implement the M3 canonicalization contract in `lib/internal/canonical` so later
milestones can consume deterministic bytes and hashes:

- Produce canonical body hash input from M1 body bytes according to
  `draft-ietf-dkim-dkim2-spec-04` Section 6.1.
- Produce canonical header-field hash input from M1 header fields according to
  Section 6.2, including excluded header names, lowercase names, unfolding,
  WSP compression and deletion, sort order, and duplicate-header reverse
  occurrence order.
- Calculate SHA-256 hashes for body and header inputs according to Section 3.1.
- Produce canonical signature input over `Message-Instance` and
  `DKIM2-Signature` fields according to Section 9.6, including ordering by
  `m=` and `i=` and an incomplete target `DKIM2-Signature` field whose
  signature value strings are null.
- Provide verification-oriented helpers required by Sections 11.6 and 11.7 so
  callers can compare signature input and message hash values without
  reimplementing canonicalization.
- Provide byte-level debug helpers that expose deterministic synthetic
  fixtures, offsets, lengths, and hex/base64 digests without exposing raw
  message bodies, raw recipients, nonces, private keys, or full raw DKIM2
  fields by default.

M3 must not implement cryptographic signature verification, DNS key lookup,
recipe application, public facade APIs, daemon behavior, Milter behavior,
OpenAPI behavior, policy decisions, or concrete observability exporters.

## Delivery Shape

The implementation should be split into focused, reviewable slices executed in
order. Expected prompt count is five implementation prompts plus one final
closeout prompt.

1. Canonical package contract and errors:
   Define M3 domain types, options, default limits, typed secret-safe errors,
   debug metadata shapes, package documentation, and helper APIs that consume
   existing M1/M2 types without widening package boundaries.
2. Body hash input and SHA-256 hashes:
   Implement Section 6.1 body canonicalization and SHA-256 hash helpers,
   including empty body, trailing empty-line removal, missing terminal CRLF,
   MIME-agnostic byte preservation, and immutable returned bytes.
3. Header hash input:
   Implement Section 6.2 header canonicalization, excluded header filtering,
   lowercase field names, unfolding, WSP compression, trailing WSP deletion,
   colon WSP deletion, deterministic sorting, duplicate-header reverse order,
   and SHA-256 header hash helpers.
4. Signature input canonicalization:
   Implement Section 9.6 input by parsing `Message-Instance` and
   `DKIM2-Signature` fields from one authoritative immutable `HeaderBlock`,
   including `m=` ascending order, `i=` ascending
   order, incomplete target signature construction, null signature values in
   every selected `s=` set, WSP deletion, and sequence-bound verification input
   selection.
5. Golden fixtures, debug helpers, and fuzz smoke:
   Add draft-versioned golden tests for body input, header input, header
   hashes, signature input, and SHA-256 values; add bounded byte-level debug
   helpers and fuzz smoke for canonicalization inputs.
6. Final proof and closeout:
   Reconcile the full spec against implementation evidence, update measured
   effort, run final gates, and verify no production code names reference
   prompt labels or transient planning milestones.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 5 to 9 agent-days |
| Highest-risk area | exact draft canonicalization bytes and signature input ordering |
| Expected prompt count | 5 implementation prompts plus 1 final closeout prompt |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: no network calls, no OpenAPI generation, no daemon wiring, no
  datasource provider, no DNS lookup, no concrete observability exporter, and
  no Milter adapter behavior.
- Medium risk: M3 needs careful API design so `lib/internal/canonical`
  consumes M1/M2 immutable views and does not duplicate raw parsing,
  tag-value parsing, or sequence validation.
- Medium risk: byte-level debug helpers are useful for golden tests but can
  become data-leak paths if they expose raw bodies, raw header values, decoded
  envelope paths, nonces, signatures, or recipients in default diagnostics.
- Highest risk: Section 6.2 and Section 9.6 have similar but different
  whitespace rules. Header hash input compresses WSP in field values to a
  single SP; signature input deletes all WSP. Tests must prove these paths do
  not share an over-broad helper that applies the wrong rule.

Measured effort is filled during implementation closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-canonical-contract-and-errors.md` | 2026-07-03T11:18:54+02:00 | 2026-07-03T11:24:58+02:00 | 6m04s | Not separately tracked | Done; focused canonical contract tests and final prompt gates passed. |
| `02-body-hash-input-and-sha256.md` | 2026-07-03T11:48:59+02:00 | 2026-07-03T11:53:44+02:00 | 4m45s | Not separately tracked | Done; body canonicalization, SHA-256 helpers, focused tests, and final prompt gates passed. |
| `03-header-hash-input.md` | 2026-07-03T11:54:45+02:00 | 2026-07-03T11:58:50+02:00 | 4m05s | Not separately tracked | Done; header hash input behavior, focused tests, and final prompt gates passed. |
| `04-signature-input-canonicalization.md` | 2026-07-03T11:59:49+02:00 | 2026-07-03T12:08:57+02:00 | 9m08s | Not separately tracked | Done; signature input selection, null signature rendering, focused tests, and final prompt gates passed. |
| `05-golden-debug-and-fuzz.md` | 2026-07-03T12:09:57+02:00 | 2026-07-03T12:18:03+02:00 | 8m06s | Not separately tracked | Done; golden fixtures, bounded debug metadata assertions, canonical fuzz targets, and final prompt gates passed. |
| `06-final-proof-closeout.md` | 2026-07-03T12:19:16+02:00 | 2026-07-03T12:23:47+02:00 | 4m31s | Not separately tracked | Done; final reconciliation, proof gates, durable completion evidence, and prompt timing ledger updated. |

Total measured productive wall-clock for the six-prompt M3 pack is 36m39s.
Prompts 01 through 05 account for 32m08s, and the final proof closeout accounts
for 4m31s. This is far below the planning estimate of 5 to 9 agent-days
because the completed scope remained inside the existing library-only
M1/M2/M3 package boundaries, used standard-library primitives, and avoided
cryptographic verification, DNS lookup, recipe reconstruction, daemon, Milter,
OpenAPI, datasource, CLI, and concrete observability surfaces.

Separate blocked or waiting episode not included in the productive total:
the first Prompt 02 agent `019f274c-77cd-7472-8e2d-e6bbad472eff` was closed
after no workspace progress and produced no files. It is recorded here only as
discarded waiting/context overhead, not M3 implementation effort.

The required measurement is wall-clock time from the start of prompt execution
to the final closeout response for that prompt. Active engineering time may be
recorded as an additional estimate, but it does not replace wall-clock time.

## Scope

In scope:

- `lib/internal/canonical` domain types, package documentation, canonical byte
  builders, SHA-256 hash helpers, structured errors, debug metadata, tests,
  fuzz smoke, and testdata.
- Consumption of existing `rawmsg.Message`, `rawmsg.HeaderField`,
  `instance.MessageInstance`, `signature.Signature`, and `tagvalue`
  immutable accessors.
- Draft-versioned golden fixtures under `lib/internal/canonical/testdata/`
  or another narrow library testdata location if implementation evidence shows
  a better package-local shape.
- Unit tests and malformed input tests for M3.
- Final Makefile-driven validation evidence.

Out of scope:

- Public `lib` facade APIs, unless a later implementation prompt updates this
  spec with a concrete facade need.
- Raw RFC 5322 parsing changes in `lib/internal/rawmsg`.
- DKIM2 tag parser changes in `lib/internal/tagvalue`,
  `lib/internal/instance`, or `lib/internal/signature`, unless an M3 test
  exposes a root-cause defect in those packages and this spec is updated first.
- Recipe JSON parsing, recipe application, recipe generation, or previous
  instance reconstruction.
- Cryptographic RSA or Ed25519 signing or verification.
- DNS key record parsing or DNS lookup behavior.
- Current SMTP envelope matching, timestamp policy, chain-of-custody policy,
  replay detection, local policy evaluation, or action planning.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl` changes.
- OpenAPI contracts or generated artifacts.
- Concrete logging, tracing, metrics, Prometheus labels, OpenTelemetry
  exporters, or debug modules outside library-safe metadata.
- Commits.

## Protocol, Runtime Or Domain Semantics

M3 is bound to `draft-ietf-dkim-dkim2-spec-04`. The package must implement
draft semantics as deterministic byte transformations and hash helpers. It must
not infer MIME, Unicode, IDNA, local-part, or SMTP-envelope semantics.

### Hash Algorithms

- Section 3.1 makes SHA-256 mandatory for body and header hashes. M3 implements
  `sha256` as the known baseline hash algorithm and returns raw 32-byte digest
  bytes plus padded RFC 4648 base64 text where needed for fixture comparison.
- Unknown hash algorithms parsed by M2 remain non-success data for later
  verification. M3 does not add experimental algorithms unless a later spec
  update changes the draft baseline.
- Hash functions consume canonical byte inputs. They must not hash raw message
  bytes, parsed convenience strings, decoded MIME content, or debug-rendered
  text unless that exact byte stream is the canonical input under this spec.

### Body Hash Input

Section 6.1 treats the message body as octets and gives MIME no special
treatment. M3 body canonicalization must:

- Consume M1 `rawmsg.Body.Bytes()` without MIME decoding, charset conversion,
  quoted-printable decoding, base64 decoding, Unicode normalization, or line
  ending rewriting beyond the explicit Section 6.1 terminal-empty-line rule.
- Ignore all empty lines at the end of the message body. An empty line is a
  zero-length line after removing its line terminator.
- Convert any run of zero or more CRLF line endings at the end of the body to
  exactly one CRLF.
- Treat an empty body as canonical body input `\r\n`.
- Treat a body without trailing CRLF as that body followed by exactly `\r\n`,
  unless the body has trailing empty lines that reduce to the same single CRLF.
- Make no other changes to body bytes.
- Return immutable canonical bytes and bounded metadata such as input length,
  output length, removed trailing empty-line count, and terminal-CRLF action.

Ambiguity note: M1 strict parsing requires CRLF network-normal input. M3 must
not add a compatibility path for bare LF or bare CR body bytes. If a later M1
compatibility mode exists, M3 must consume parser-owned normalized bytes only
when the caller explicitly selected that parser policy.

### Header Hash Input

Section 6.2 header hash canonicalization must apply the draft steps in order.
M3 must implement them as one authoritative transformation path:

1. Exclude these header fields case-insensitively before hashing:
   `Received`, `Return-Path`, `Delivered-To`, `Authentication-Results`, any header field name
   starting with `X-`, `DKIM-Signature`, any header field name starting with
   `ARC-`, `Message-Instance`, and `DKIM2-Signature`.
2. Convert included header field names to lowercase ASCII. M1 already stores
   `NameLower()`, and M3 must use that view rather than revalidating names.
3. Unfold continuation lines according to RFC 5322 by treating CRLF followed
   by WSP inside continued field values as though the CRLF were absent. The
   CRLF ending the header field value must remain part of the canonical field.
4. Convert every sequence of one or more WSP characters in the unfolded field
   value to a single SP. This includes WSP before and after a line folding
   boundary after unfolding.
5. Delete all WSP characters at the end of each unfolded header field value.
6. Delete WSP before and after the colon separator. The colon remains.
7. Sort included header fields alphabetically by lowercase header field name.
8. For duplicate included header field names, place duplicates in reverse
   occurrence order: the last occurrence in the RFC 5322 header block comes
   first, then the earlier matching occurrences moving upward.
9. Concatenate the canonical field bytes and calculate the requested hash.

Canonical header field bytes must have the shape:

```text
<lowercase-name>:<canonical-value>\r\n
```

Where `<canonical-value>` has no WSP surrounding the colon, no trailing WSP
before the CRLF, and internal WSP runs compressed to one SP. Empty values are
allowed and produce `<lowercase-name>:\r\n`.

Sorting must be deterministic and must not rely on map iteration order. The
recommended implementation shape is to collect included fields into a slice
with `(nameLower, originalIndex, canonicalBytes)` and sort by `nameLower`
ascending, then by `originalIndex` descending for equal names.

M3 must not use `net/mail`, MIME parsers, or header-specific semantic parsers
as canonicalization truth. Header values remain bytes.

### Signature Input Canonicalization

Section 9.6 defines a separate canonicalization path for the bytes fed to the
signature algorithm. It is not the same as Section 6.2 header hashing.

M3 signature input canonicalization must:

- Include only relevant `Message-Instance` and `DKIM2-Signature` header
  fields for the signing or verification state being constructed.
- Convert relevant header field names to lowercase ASCII.
- Unfold continued header field values according to RFC 5322 while retaining
  the terminating CRLF for each header field.
- Delete all WSP characters. This includes WSP before and after the colon,
  WSP anywhere within the unfolded value, and trailing WSP before CRLF. The
  colon and CRLF are retained.
- Order complete `Message-Instance` fields by ascending `m=` value.
- Order complete `DKIM2-Signature` fields by ascending `i=` value.
- Append an incomplete target `DKIM2-Signature` field last. The incomplete
  field has all tags that are present for that signature state, but every
  signature value component inside `s=` is the null string.
- Apply the same unfolding, trailing CRLF, and WSP-deletion rule to the
  incomplete target field as to complete fields.
- Concatenate the canonical field bytes and feed them to the signature
  algorithm in later milestones.

For signing, the incomplete target field is the signature field being created.
For verification under Section 11.6, the incomplete target field is derived
from the `DKIM2-Signature` field being verified by replacing its selected
signature value string or strings with null strings so the bytes correspond to
what was signed. The canonicalization helper must not mutate the original
`rawmsg.Message`, `signature.Signature`, or parser-owned field bytes.

M3 must support multi-algorithm `s=` values by nulling signature value strings
inside the incomplete target field. The draft requires verifiers to check every
signature they can and report failures appropriately, but actual cryptographic
verification and mixed pass/fail result modeling remain M4/M5 scope.

Relevant-field selection for verification must be explicit:

- To verify a DKIM2-Signature with sequence `i=N`, include
  `Message-Instance` fields whose `m=` values are covered by the target state
  and complete `DKIM2-Signature` fields with `i=` values before `N`.
- Ignore any `Message-Instance` or `DKIM2-Signature` fields added after the
  target state, as required by Section 10.
- Because recipe application is deferred, M3 only builds canonical signature
  input from protocol fields present in the supplied immutable `HeaderBlock`.
  Callers cannot supply independently trusted parsed slices. Previous-instance
  reconstruction remains M8.

If implementation evidence shows a different precise selection API is needed
for M4, update this spec before widening behavior.

### Hash Validation Helpers

Section 11.7 requires verifiers to repeat signer hash calculations and compare
values. M3 should expose library-internal helpers that:

- Compute current SHA-256 header and body hashes from `rawmsg.Message`.
- Compare computed digest bytes to M2 `instance.HashSet` values for known
  `sha256` hash sets.
- Return typed mismatch results without embedding raw header bytes, raw body
  bytes, raw base64 values, or full `Message-Instance` fields in errors.
- Preserve unknown hash algorithms as non-success data for later verification
  result modeling.

M3 comparison helpers are optional if implementation evidence shows they belong
more cleanly in M5 service coordination. If deferred, M3 must still provide the
canonical input and digest primitives needed to implement Section 11.7 without
duplicating canonicalization.

### Debug Byte Helpers

M3 should expose package-local or test-oriented debug helpers that make golden
failures understandable without leaking sensitive data:

- Allowed debug facts:
  canonicalization kind, draft version, algorithm name, input length, output
  length, field count, excluded header count by allowlisted reason, body
  trailing-empty-line count, SHA-256 digest bytes only in hex or base64 for
  synthetic fixtures, and stable byte offsets for synthetic testdata.
- Forbidden debug facts by default:
  raw RFC 5322 messages, raw body content, raw header values, full
  `Message-Instance` fields, full `DKIM2-Signature` fields, decoded `mf=` or
  `rt=` paths, recipient lists, sender or recipient local parts, raw nonces,
  raw signature values, private keys, tokens, passwords, protected config
  values, and unbounded error strings.
- Debug helpers used by tests may return canonical byte slices for synthetic
  fixtures. Production error strings, default logs, future REST output, and
  future CLI output must not include those bytes.

## Package Boundaries

Intended ownership:

- `lib/internal/canonical`:
  Owns DKIM2 body hash input, header hash input, signature input
  canonicalization, SHA-256 digest helpers, typed canonicalization errors,
  immutable canonical byte results, golden fixture helpers, and bounded debug
  metadata. It is the only package that implements Section 6.1, Section 6.2,
  and Section 9.6 byte transformations.
- `lib/internal/rawmsg`:
  Remains the source of truth for byte-preserving RFC 5322 message
  representation. M3 consumes `Message`, `HeaderBlock`, `HeaderField`, and
  `Body` accessors and must not alter raw parsing or CRLF policy.
- `lib/internal/tagvalue`:
  Remains the owner of generic DKIM2 tag-list scanning and base64string
  parsing. M3 may consume immutable base64 containers but must not implement
  parallel tag scanning.
- `lib/internal/instance`:
  Remains the owner of `Message-Instance` parsing, hash-set parsing, recipe
  base64 containers, and `m=` sequence validation. M3 invokes that parser and
  validation over fields selected from the authoritative `HeaderBlock`; it
  does not redefine `h=` syntax or trust a caller-supplied parsed slice.
- `lib/internal/signature`:
  Remains the owner of `DKIM2-Signature` parsing, signature-set parsing,
  envelope containers, flags, nonces, and `i=` sequence validation. M3 invokes
  that parser and validation over fields selected from the authoritative
  `HeaderBlock`; it does not redefine `s=` syntax except for a narrow
  null-signature rendering helper needed by Section 9.6.
- `lib/internal/recipe`:
  Does not change in M3. Previous-state reconstruction remains deferred.
- `lib/internal/keyresolver`, `lib/internal/datasource`,
  `lib/internal/policy`, `lib/internal/service`, and
  `lib/internal/observability`:
  Do not change in M3.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl`:
  No M3 code changes.

Generated REST DTOs must stay at HTTP boundaries. Core DKIM2 packages must not
import generated OpenAPI types, Cobra, Viper, Fx, Prometheus, OTLP exporters,
Milter packages, SQL drivers, LDAP drivers, Valkey clients, or CLI frameworks.

## Security And Privacy

Default behavior is restrictive:

- Canonicalization fails closed on unsupported algorithms, unsafe options,
  malformed parser-owned state, resource-limit violations, or ambiguous input
  selection.
- Canonicalization helpers must not silently skip parser errors, sequence
  validation errors, missing target fields, duplicate target identifiers, or
  unsupported line-ending policy.
- Unknown hash or signature algorithms are ignored for success, not treated as
  pass.
- Section 6.2 excluded headers are omitted only from the header hash input.
  They remain visible to the raw message model and future policy layers where
  appropriate.
- Section 9.6 signature input must sign only DKIM2 protocol fields. It must not
  accidentally include regular message header fields or body bytes.
- Returned canonical byte slices must be immutable copies or otherwise safe
  from caller mutation.
- Errors and test helpers must not include raw message bodies, full raw header
  values, full raw DKIM2 fields, decoded envelope paths, recipient lists,
  sender local parts, nonce values, signature values, private keys, tokens,
  passwords, protected config values, or unbounded strings.
- Golden fixtures must be synthetic and must not contain live messages,
  production recipients, real nonces, real signatures, production domains,
  private keys, or secret-bearing headers.
- Byte-oriented paths must not assume valid UTF-8 and must not corrupt
  EAI-capable input that the current draft leaves undefined.

Recommended initial resource limits:

| Limit | Initial default |
| --- | ---: |
| Maximum canonical body input bytes | 32 MiB |
| Maximum canonical header input bytes | 2 MiB |
| Maximum canonical signature input bytes | 2 MiB |
| Maximum canonicalized field bytes | 128 KiB |
| Maximum canonicalized field count | 4,000 |
| Maximum excluded-header debug counters | small allowlist only |

If implementation evidence shows these defaults are not practical, update this
spec before changing behavior.

## Observability

M3 should not add concrete logging, metrics, tracing, Prometheus labels,
OpenTelemetry exporters, or debug modules. `canonical` may expose structured
errors and bounded metadata that future observers can safely classify.

Allowed future observation facts from M3 state are low-cardinality or bucketed:

- Canonicalization kind: `body_hash_input`, `header_hash_input`, or
  `signature_input`.
- Draft version.
- Hash algorithm allowlist name.
- Result class.
- Error code.
- Error reason class.
- Included field count bucket.
- Excluded field count bucket.
- Input size bucket.
- Output size bucket.
- Body trailing-empty-line count bucket.

Forbidden observation values include:

- Raw RFC 5322 messages.
- Raw body content.
- Raw header values.
- Full canonical header input.
- Full canonical body input.
- Full canonical signature input.
- Raw `Message-Instance` fields.
- Raw `DKIM2-Signature` fields.
- Raw `mf=` or `rt=` decoded paths.
- Raw sender or recipient local parts.
- Full recipient lists.
- Raw nonce values.
- Raw signature values.
- Private keys, tokens, passwords, and protected configuration values.
- Raw or unbounded error strings.

Prometheus labels, when added by later milestones, must remain on a strict
low-cardinality allowlist and must not include identity values, raw hashes,
raw errors, or message-derived strings.

## Required Tests

Unit tests:

- Body canonicalization treats an empty body as `\r\n`.
- Body canonicalization appends one CRLF when the body lacks a terminal CRLF.
- Body canonicalization converts any trailing run of empty CRLF lines to one
  CRLF.
- Body canonicalization preserves all non-trailing body bytes exactly,
  including MIME-looking content and non-UTF-8 bytes.
- Body SHA-256 returns deterministic 32-byte digest bytes and padded base64
  text for synthetic fixtures.
- Header hash canonicalization excludes `Received`, `Return-Path`,
  `Delivered-To`, `Authentication-Results`, `X-*`, `DKIM-Signature`, `ARC-*`,
  `Message-Instance`, and `DKIM2-Signature` case-insensitively.
- Header hash canonicalization lowercases field names without changing field
  values except for required WSP handling.
- Header hash canonicalization unfolds continuation lines while retaining the
  field-ending CRLF.
- Header hash canonicalization compresses WSP runs in values to a single SP.
- Header hash canonicalization deletes trailing WSP before CRLF.
- Header hash canonicalization deletes WSP before and after the colon while
  retaining the colon.
- Header hash canonicalization sorts names alphabetically and orders duplicate
  names from the last raw header occurrence upward.
- Header hash canonicalization handles empty values as `<name>:\r\n`.
- Header SHA-256 returns deterministic digest bytes and padded base64 text for
  synthetic fixtures.
- Signature input canonicalization includes only `Message-Instance` and
  `DKIM2-Signature` fields relevant to the target state.
- Signature input canonicalization orders `Message-Instance` fields by
  ascending `m=` and complete `DKIM2-Signature` fields by ascending `i=`.
- Signature input canonicalization appends the incomplete target
  `DKIM2-Signature` field last.
- Signature input canonicalization renders null signature value strings inside
  `s=` while preserving selector and algorithm components.
- Signature input canonicalization deletes all WSP, unlike header hash
  canonicalization which compresses value WSP.
- Signature input canonicalization keeps colon separators and CRLF endings.
- Signature input canonicalization does not mutate the original raw message,
  authoritative header block, freshly parsed protocol objects, or returned
  byte slices.
- Hash comparison helpers, if implemented in M3, detect matching and
  mismatching `sha256` header/body hash values without leaking raw hash input.
- Error strings and test failure helpers do not include raw body content,
  full raw header values, raw DKIM2 fields, decoded envelope paths, recipient
  lists, nonces, signatures, or secret-bearing material.
- Accessor immutability: mutating returned canonical byte slices cannot mutate
  stored canonical results or parsed protocol state.

Golden tests:

- Draft-versioned fixture for body canonicalization with empty body, terminal
  CRLF, multiple trailing empty lines, and no terminal CRLF.
- Draft-versioned fixture for header hash input with excluded headers, folded
  fields, WSP compression, duplicate headers, and deterministic sort order.
- Draft-versioned fixture for signature input with at least two
  `Message-Instance` fields, at least two `DKIM2-Signature` fields, and
  multi-algorithm `s=` null signature values.
- Golden files must identify `draft-ietf-dkim-dkim2-spec-04` in file content
  or fixture metadata.

Fuzz tests:

- Fuzz body canonicalization with small byte inputs that have already passed
  M1 strict parsing where practical.
- Fuzz header hash canonicalization with synthetic `rawmsg.Message` inputs.
- Fuzz signature input canonicalization with synthetic M1/M2 parser-owned
  fields.
- Assert no panics, no unbounded memory growth, deterministic error classes,
  no caller input mutation, and no raw input leakage in error strings.

Integration or E2E tests:

- None required for M3. The proof is library-only unit, golden, and fuzz-smoke
  coverage. Cryptographic verification begins in M4 and vertical verification
  begins in M5.

Generated and documentation checks:

- No OpenAPI generated artifacts are touched.
- Package documentation for `lib/internal/canonical` must describe the DKIM2
  canonicalization ownership contract, draft baseline, Section 6.1 body input,
  Section 6.2 header input, Section 9.6 signature input, and secret-safe debug
  policy.
- All changed or added hand-written named functions and receiver methods must
  have concise English doc comments.

Final gate:

- `make guardrails`
- `git diff --check`
- `git status --short`

If `make guardrails` cannot run because a tool such as `golangci-lint` is not
installed, run the largest equivalent subset through Makefile targets and
document the exact blocker.

## Acceptance Criteria

- `lib/internal/canonical` is the single source of truth for DKIM2
  canonicalization and hash byte inputs.
- Section 6.1 body hash input is implemented and golden-tested.
- Section 6.2 header hash input is implemented and golden-tested, including
  every excluded header class, lowercase names, unfolding, WSP compression,
  trailing WSP deletion, colon WSP deletion, alphabetical sort, and
  duplicate-header reverse order.
- Section 9.6 signature input is implemented and golden-tested, including
  `Message-Instance` ascending `m=` order, `DKIM2-Signature` ascending `i=`
  order, incomplete target signature field, and null signature value strings.
- SHA-256 helper output is deterministic, immutable, and test-covered.
- M3 consumes M1/M2 parser-owned immutable views and does not duplicate raw
  RFC 5322 parsing, tag-list parsing, base64 parsing, or sequence validation.
- Canonicalization behavior is strict by default and fails closed on malformed
  or ambiguous state.
- Debug helpers and errors are bounded and secret-safe.
- No daemon, Milter, OpenAPI, CLI, datasource, concrete observability exporter,
  Valkey, SQL, LDAP, or service-only dependency leaks into `lib`.
- Unit, malformed input, golden, and fuzz-smoke tests cover the M3 behavior
  named in `docs/ARCHITECTURE.md`.
- `make guardrails` passes, or skipped portions are explicitly justified with
  narrower passing commands.
- Prompt timings are recorded in the measured effort table during closeout.

## Completion Evidence

- Focused tests:
  `cd lib && GOCACHE=/private/tmp/dkim2-gocache go test ./internal/rawmsg/... ./internal/tagvalue/... ./internal/instance/... ./internal/signature/... ./internal/canonical/...`
  passed.
- Draft-04 remediation tests:
  target `DKIM2-Signature` tag spelling/case and the terminating semicolon are
  preserved while only `s=` signature bytes are nulled, and `Delivered-To` is
  excluded with a dedicated low-cardinality metadata counter. Focused package
  tests, `FuzzSignatureInput`, and `FuzzHeaderHashInput` passed on 2026-07-10.
- Golden tests:
  included in the focused and final test runs through
  `lib/internal/canonical/golden_test.go`; fixtures under
  `lib/internal/canonical/testdata/golden/` name
  `draft-ietf-dkim-dkim2-spec-04`.
- Fuzz-smoke:
  `cd lib && GOCACHE=/private/tmp/dkim2-gocache go test ./internal/canonical/... -run '^$' -fuzz=Fuzz -fuzztime=10s`
  was rejected by Go because it matched multiple fuzz targets:
  `FuzzBodyHashInput`, `FuzzHeaderHashInput`, and `FuzzSignatureInput`.
  The three required canonical fuzz targets were then run individually and
  passed:
  `FuzzBodyHashInput`, `FuzzHeaderHashInput`, and `FuzzSignatureInput`, each
  with `-fuzztime=10s`.
- Generated checks:
  no OpenAPI contracts or generated artifacts were changed; `make guardrails`
  included the `check-openapi` target.
- Guardrails:
  `GOCACHE=/private/tmp/dkim2-gocache make test`,
  `GOCACHE=/private/tmp/dkim2-gocache make vet`,
  `GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache make lint`,
  `GOCACHE=/private/tmp/dkim2-gocache make race`, and
  `GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache make guardrails`
  passed. The root guardrail now also runs `govulncheck`; all workspace modules
  reported no known vulnerabilities during the 2026-07-10 draft-04 closeout.
- `git diff --check`: passed.
- `git status --short`:
  dirty M1/M2/M3 implementation worktree with uncommitted docs, prompt
  artifacts under ignored `temp/`, and library-core package changes; no
  commits or staging were performed.
- Skipped checks:
  none. The aggregate canonical fuzz command was not skipped; it was rejected
  by Go due to multiple matching targets, and the equivalent target-specific
  fuzz-smoke commands passed.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Work stays inside `lib/internal/canonical`, package-local tests, package-local testdata, and this spec | Implementation changed canonical package code/tests/testdata, package docs, this spec, and the ignored local prompt timing ledger only during final closeout | done | No command modules, OpenAPI contracts, generated artifacts, datasource, DNS lookup, cryptographic verification, recipe, policy, Milter, or concrete observability code changed for M3 closeout. |
| Behavior | Body, header, and signature canonicalization match draft-04 Sections 4, 6.1, 6.2, and 9.6 | Body input, header input, Delivered-To exclusion, signature input, deterministic ordering, SHA-256 digest containers, and null signature rendering are implemented and test-covered | done | Section 6.2 WSP compression and Section 9.6 WSP deletion remain separate helpers with focused tests. |
| Tests | Unit, malformed input, golden, immutability, and fuzz-smoke coverage exist | Unit, limit, immutability, secret-safe error, golden, and three target-specific canonical fuzz-smoke runs passed | done | Golden fixtures name `draft-ietf-dkim-dkim2-spec-04`; aggregate fuzz was split because Go matched multiple targets. |
| Security | Fail-closed and secret-safe behavior is preserved | Unsupported algorithms, unsafe options, size limits, missing targets, duplicate raw targets, and malformed authoritative fields fail with typed bounded errors; signature-input callers cannot inject foreign parsed protocol objects | done | Error tests and fuzz assertions cover raw body, raw header, DKIM2 field, decoded path, nonce, signature, and secret marker leakage. |
| Boundaries | Module and generated-code boundaries hold | `lib/internal/canonical` consumes M1/M2 accessors and uses standard-library helpers only | done | No service-only dependencies or generated REST DTOs leaked into `lib`; OpenAPI files were untouched and `check-openapi` ran through `make guardrails`. |
| Observability | Only bounded metadata exists; no concrete exporters or high-cardinality labels | Canonical result metadata carries kind, draft, safe algorithm names, counts, lengths, excluded-header counters, and body terminal action only | done | No logs, metrics, traces, exporters, debug modules, or Prometheus labels were added. |
| Effort | Prompt timings are measured and recorded | Six-prompt productive wall-clock total is 36m39s versus the 5 to 9 agent-day planning estimate | done | Separate discarded Prompt 02 wait episode is recorded but excluded from productive M3 effort because it produced no files. |

## Decisions And Open Questions

- Settled: `lib/internal/canonical` is the single owner for DKIM2
  canonicalization byte transformations and SHA-256 hash helpers.
- Settled: M3 consumes M1 `rawmsg` immutable accessors and invokes the M2
  parsers over the supplied authoritative `HeaderBlock`; it accepts no
  independently trusted parsed protocol slices and implements no second raw
  message parser or tag parser.
- Settled: Section 6.2 header hash canonicalization and Section 9.6 signature
  input canonicalization must use distinct whitespace rules.
- Settled: Header hash input excludes `Received`, `Return-Path`,
  `Delivered-To`, `Authentication-Results`, `X-*`, `DKIM-Signature`, `ARC-*`,
  `Message-Instance`, and `DKIM2-Signature`.
- Settled: Duplicate included header names in header hash input are ordered
  from the last RFC 5322 header occurrence upward.
- Settled: Body hash input is MIME-agnostic and follows the DKIM1 simple-style
  terminal-empty-line rule described by DKIM2 Section 6.1.
- Settled: Signature input signs only DKIM2 protocol fields; message content is
  covered indirectly through `Message-Instance` hashes.
- Settled: Null signature values are rendered only in the incomplete target
  `DKIM2-Signature` field used for signing or verification input.
- Settled: Hash comparison helpers are deferred to later verification/service
  coordination; M3 provides the canonical input and SHA-256 digest primitives
  needed to implement Section 11.7 without duplicating canonicalization.
- Settled: The aggregate canonical fuzz command can match multiple Go fuzz
  targets; final proof should run the body, header, and signature fuzz targets
  individually when that happens.
- Open: The exact public facade shape for M3 canonicalization remains deferred
  until M5 service coordination needs it.
- Open: Previous-instance signature input after recipe application remains
  deferred to M8/M5 coordination; M3 only provides current-state primitives and
  explicit selection hooks.
- Settled: Draft-04 Section 9.6 requires every signature value in the target
  field's `s=` tag to be replaced by the null string. Per-algorithm nulling is
  not permitted by the active baseline.
