# Raw Message Model

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

Status: completed.

This spec defines Milestone M1, the raw RFC 5322 message model for the DKIM2
reference library. It covers byte-preserving parsing, header and body views,
explicit CRLF policy, immutable message representation, parser unit tests, and
malformed input tests. This work touches only the library protocol core and
does not implement DKIM2 tag parsing, canonicalization, signing, daemon,
Milter, OpenAPI, datasource, or observability exporter behavior.

## Source Documents

This spec is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`, especially Sections 2, 3.1, 3.2, 3.3, 3.4, 3.5,
  3.6, 5.1, 5.2, 6.1, 12.1, 12.4, 12.5, 13.1, 13.3, 13.5, 14, 15, 16,
  17, and 19
- `docs/specs/spec-and-prompt-template.md`
- `lib/doc.go`
- `lib/internal/rawmsg/doc.go`
- `Makefile`
- `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05, as the active DKIM2
  architecture baseline
- `draft-chuang-dkim2-dns-04`, dated 2026-03-18, as the related DNS baseline
  even though M1 does not implement DNS behavior
- RFC 5322 Internet Message Format semantics for header fields, header
  continuation, header/body separation, and CRLF line endings

If this spec conflicts with a source document, stop and reconcile the durable
artifact before implementation continues.

## Original Gap

The repository currently has only the package stubs:

- `lib/doc.go`
- `lib/internal/rawmsg/doc.go`

There is no raw message parser, no controlled header/body model, no line ending
policy, no immutable representation, no structured parser diagnostics, and no
unit coverage for valid or malformed RFC 5322 message inputs. Later milestones
need this foundation before they can safely parse `Message-Instance`,
`DKIM2-Signature`, canonicalize headers and body bytes, generate recipes, or
build vector-driven verification.

The risk is architectural: if later code parses email through a friendly object
model or a reserializing library, it can silently change header order, folding,
line endings, or body bytes. That would corrupt DKIM2 hashes and make later
recipe and signature behavior untrustworthy.

## Goal

Implement a controlled raw RFC 5322 message representation in
`lib/internal/rawmsg` that:

- Parses raw message bytes into an immutable `Message`.
- Preserves header field occurrence order and original field bytes.
- Stores the field name as raw bytes and a canonical lowercase ASCII name.
- Stores raw and unfolded field values without MIME encoded-word decoding.
- Splits headers and body at the first RFC 5322 header/body delimiter when an
  optional body is present, and accepts a CRLF-terminated header-only message.
- Preserves body bytes and builds line indexes needed by later recipe work.
- Accepts only strict CRLF line endings; reserved normalization policies fail
  validation until separately specified.
- Fails closed on malformed input under the default strict policy.
- Reports structured error codes without including raw message bodies, raw
  header values, or other secret-bearing content in errors or test logs.

The model is intended for protocol work, not user-facing email rendering. It
must not depend on `net/mail` for parser truth, canonicalization, signing,
recipe handling, or verification.

## Delivery Shape

The implementation should be split into focused, reviewable slices executed in
order:

1. Domain contract and immutable types:
   Define `Message`, `HeaderBlock`, `HeaderField`, `Body`, line index types,
   parser options, structured error codes, package documentation, and narrow
   access methods that preserve immutability.
2. Header parser and strict CRLF policy:
   Parse header blocks, detect the header/body delimiter, enforce default
   strict CRLF handling, preserve original header bytes, unfold continuation
   lines, lowercase field names, and reject malformed header syntax.
3. Body model and line indexing:
   Preserve body bytes, index body lines without changing bytes, handle empty
   body and terminal CRLF cases, enforce body line and size limits, and expose
   safe accessors for later recipe and canonicalization work.
4. Negative tests, fuzz seeds, and proof:
   Add table-driven malformed input coverage, byte-preservation assertions,
   policy tests for line endings, immutability tests, fuzz seed corpus where
   practical, and final guardrail evidence.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | medium |
| Estimated wall-clock effort | 3 to 5 agent-days |
| Highest-risk area | byte-preserving RFC 5322 parsing and CRLF policy |
| Expected prompt count | 4 implementation prompts plus one final closeout prompt |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: no external network calls, no OpenAPI generation, no daemon wiring,
  no datasource provider, and no cryptographic dependency.
- Medium risk: exact RFC 5322 edge cases, header folding, field-name validation,
  empty body handling, body line indexing, and avoiding accidental byte
  mutation through returned slices.
- Highest risk: accepting malformed line endings or silently normalizing input
  in the default protocol path, because that would weaken later
  canonicalization and signature checks.

Measured effort is filled during implementation closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-domain-contract-and-immutable-types.md` | 2026-07-03T09:22:17+02:00 | 2026-07-03T09:29:15+02:00 | 6m58s | Not separately tracked | Done; focused rawmsg tests, `make test`, `make guardrails`, and `git diff --check` passed. |
| `02-header-parser-and-crlf-policy.md` | 2026-07-03T09:30:26+02:00 | 2026-07-03T09:35:16+02:00 | 4m50s | Not separately tracked | Done; focused parser/header run, rawmsg tests, `make test`, `make guardrails`, and `git diff --check` passed. |
| `03-body-model-and-line-indexing.md` | 2026-07-03T09:36:21+02:00 | 2026-07-03T09:40:10+02:00 | 3m49s | Not separately tracked | Done; focused body/limit/immutable run, rawmsg tests, `make test`, `make guardrails`, and `git diff --check` passed. |
| `04-negative-tests-fuzz-and-proof.md` | 2026-07-03T09:41:09+02:00 | 2026-07-03T09:46:33+02:00 | 5m24s | Not separately tracked | Done; rawmsg tests, fuzz-smoke, `make test`, `make guardrails`, and `git diff --check` passed. |
| `05-final-proof-docs-closeout.md` | 2026-07-03T09:47:57+02:00 | 2026-07-03T09:51:00+02:00 | 3m03s | Not separately tracked | Done; final focused rawmsg, fuzz-smoke, `make test`, `make vet`, `make lint`, `make race`, `make guardrails`, and `git diff --check` passed. |

Total measured wall-clock for the five-prompt M1 pack is 24m04s. This is far
below the planning estimate of 3 to 5 agent-days because the implementation
scope remained tightly bounded to `lib/internal/rawmsg`, used only standard
library code, and did not require adapter, OpenAPI, datasource, or
canonicalization work.

The required measurement is wall-clock time from the start of prompt execution
to the final closeout response for that prompt. Active engineering time may be
recorded as an additional estimate, but it does not replace wall-clock time.

## Scope

In scope:

- `lib/internal/rawmsg` domain types, parser, options, structured errors, and
  package documentation.
- Unit tests under `lib/internal/rawmsg`.
- Testdata or fuzz seeds needed for raw message parsing, if useful and small.
- Internal helpers needed to preserve bytes, detect malformed input, and build
  line indexes.
- Makefile-driven validation evidence.

Out of scope:

- Public `lib` facade APIs beyond what is required to keep package docs
  accurate.
- `Message-Instance` parsing.
- `DKIM2-Signature` parsing.
- Header, body, or signature canonicalization.
- Message hash calculation.
- Recipe parsing, application, generation, or minimization.
- DNS key record parsing or resolver behavior.
- Signing, verification, policy evaluation, replay detection, or result
  modeling.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl` code.
- OpenAPI contracts or generated artifacts.
- Concrete logging, tracing, metrics exporters, labels, or debug modules.
- Use of `net/mail` as the protocol parser.
- Commits.

## Protocol, Runtime Or Domain Semantics

M1 is a prerequisite for DKIM2 semantics, not a complete DKIM2 verifier. The
following rules bind the raw message model:

- RFC 5322 source:
  The input is an Internet Message Format message made of header fields,
  optional continuation lines, and an optional CRLF-delimited body. A
  header-only message ends with the final header field CRLF. CRLF is the
  normative line ending for protocol input.
- DKIM2 draft baseline:
  `draft-ietf-dkim-dkim2-spec-04` is the active behavior baseline for later
  DKIM2 work. M1 must preserve the bytes and header order that later
  `Message-Instance`, `DKIM2-Signature`, canonicalization, hash, and recipe
  code will consume.
- Architecture source:
  `docs/ARCHITECTURE.md` requires the core to sign and verify a controlled RFC
  5322 representation, not a friendly mail object reconstructed by a generic
  parser. It also requires header occurrence order, raw and canonical field
  names, raw and unfolded values, body bytes, CRLF decisions, and body line
  indexes to be preserved.
- Local security policy:
  Ambiguous message-fidelity state fails closed by default. Compatibility
  behavior must be explicit, typed, tested, and unavailable by accident.

Parser semantics:

- The default parser mode is strict CRLF transport mode for RFC 5322 input.
- Strict mode accepts CRLF-delimited input and rejects bare LF, bare CR, and
  mixed line endings before constructing a `Message`.
- Any compatibility mode that accepts LF and normalizes to CRLF must be an
  explicit parser option, must not be the default, and must record that
  normalization occurred through structured metadata. M1 does not implement
  such a mode; all reserved compatibility options fail validation.
- The parser splits a message with a body at the first `\r\n\r\n` delimiter.
  RFC 5322 Section 3.5 also permits `(fields / obs-fields)` without the optional
  `[CRLF body]`; M1 therefore accepts a syntactically valid header-only message
  ending in CRLF without inventing a compatibility mode.
- RFC 5322 Sections 2.1.1 and 2.3 limit physical lines to 998 characters, and
  RFC 6532 Section 3.4 defines that ceiling as 998 octets for UTF-8 messages.
  Strict M1 defaults enforce 998 content octets for physical header and body
  lines. A 999-octet line fails with a typed resource-limit error. Wider
  receiver compatibility is not implemented because it would require an
  explicit option and metadata that distinguishes nonconformant input.
- Header fields keep occurrence order and zero-based indexes.
- Field names are byte-oriented ASCII tokens. Non-ASCII, empty, space-bearing,
  colon-bearing, or control-character-bearing names are malformed.
- Header continuation lines are associated with the previous field. A
  continuation line before any field is malformed.
- Original header field bytes include the terminating line ending bytes exactly
  as represented after the selected input policy.
- Raw field values preserve bytes after the first colon and before the field's
  terminating line ending, including leading field-value whitespace.
- Header field values preserve RFC 5322 obsolete receiver syntax, including
  ASCII NUL and control octets, because conformant receivers must recognize
  obsolete forms. Octets at or above `0x80` must form valid RFC 6532 UTF-8;
  malformed UTF-8 fails closed, while valid UTF-8 is preserved byte-for-byte.
- Unfolded field values remove continuation CRLF while retaining the following
  WSP according to RFC 5322 folding rules, without MIME encoded-word decoding,
  Unicode normalization, IDNA mapping, local-part normalization, or semantic
  header parsing.
- Body bytes are preserved exactly after the header/body delimiter under the
  selected policy. Apart from CRLF framing and line limits, arbitrary body
  octets remain opaque to the raw parser.
- Body line indexing must not rewrite body bytes and must define behavior for
  empty bodies, final lines without terminal CRLF, and terminal empty lines.
- The message object is immutable once parsing succeeds. Accessors that expose
  bytes must return copies or otherwise prevent caller mutation from affecting
  stored protocol state.
- Rebuilding the message from the model must reproduce the parser-owned raw
  bytes for valid strict input. M1 never normalizes input, and its metadata
  therefore always records that normalization did not occur.
- Constructors validate their complete owned invariants: field views match
  original field bytes, header fields concatenate to the header block, body
  line-ending declarations match body bytes, full message bytes match either
  header-only or header-delimiter-body framing, and metadata counts match the
  stored components.
- Errors use typed codes and bounded context such as offset, line number,
  column, reason class, and policy name. Error strings must not include raw
  message body content, full raw header values, recipient lists, private keys,
  tokens, or protected config values.

Ambiguities and interpretations:

- DKIM2 draft EAI behavior is still incomplete. M1 preserves EAI-capable bytes
  without normalization and does not add Unicode semantics.
- This spec does not define canonicalization whitespace rules beyond the
  minimum unfolding needed to provide a safe header field view. Canonicalization
  remains owned by `lib/internal/canonical`.
- This spec does not define Milter reconstruction fidelity. The Milter adapter
  may later report fidelity metadata, but `rawmsg` remains the raw RFC 5322
  source of truth.

## Package Boundaries

Intended ownership:

- `lib/`:
  Owns the standalone DKIM2 library module. M1 may keep the public package
  empty except for documentation unless later implementation evidence requires
  an exported facade.
- `lib/internal/rawmsg`:
  Owns the raw RFC 5322 parser, immutable message representation, header block,
  header fields, body bytes, line indexing, parser options, and parser error
  types.
- `lib/internal/canonical`:
  Does not change in M1. Later consumes `rawmsg` without owning parser or
  message-fidelity rules.
- `lib/internal/instance` and `lib/internal/signature`:
  Do not change in M1. Later consume header fields from `rawmsg`.
- `lib/internal/recipe`:
  Does not change in M1. Later consumes body line indexes and message
  snapshots from `rawmsg`.
- `cmd/dkim2d`:
  No M1 code changes. Later adapts OpenAPI raw-message input into library
  domain requests.
- `cmd/dkim2-milter`:
  No M1 code changes. Later sends raw RFC 5322 input or explicit fidelity
  failure to the daemon/library boundary.
- `cmd/dkim2ctl`:
  No M1 code changes. Later uses generated OpenAPI client workflows and vector
  fixtures.

Generated REST DTOs must stay at HTTP boundaries. Core DKIM2 packages must not
import generated OpenAPI types, Cobra, Viper, Fx, Prometheus, OTLP exporters,
Milter packages, SQL drivers, LDAP drivers, or CLI frameworks.

## Security And Privacy

Default behavior is restrictive:

- Malformed message syntax fails before a `Message` is returned.
- Bare LF, bare CR, and mixed line endings fail in strict mode.
- A body requires the header/body delimiter. A header-only message is regular
  RFC 5322 syntax and requires the final header field CRLF; unterminated header
  input fails closed.
- Reserved line-ending normalization options fail validation rather than
  silently doing nothing.
- Oversized messages, oversized header blocks, excessive header count,
  excessive field length, excessive physical header line length, and excessive
  body line length or count fail with typed resource-limit errors.
- Parser options must have safe defaults and must not silently disable limits.
- Error values and test logs must not include raw message bodies, full raw
  header values, recipient lists, sender local parts, private keys, tokens,
  passwords, protected config values, or unbounded error strings.
- Test fixtures must be synthetic and must not contain live messages,
  production recipients, or secret-bearing headers.
- Byte-oriented paths must not assume valid UTF-8 and must not corrupt
  EAI-capable input. Header octets above `0x7f` must be valid UTF-8, while body
  octets remain opaque.

Recommended initial resource limits:

| Limit | Initial default |
| --- | ---: |
| Maximum raw message size | 32 MiB |
| Maximum header block size | 1 MiB |
| Maximum header count | 2,000 |
| Maximum single header field size, including continuations | 64 KiB |
| Maximum physical header line size, excluding CRLF | 998 octets |
| Maximum indexed body line count | 65,536 |
| Maximum body line length recorded for indexing | 998 octets |

If implementation evidence shows these defaults are not practical, update this
spec before changing behavior.

## Observability

M1 should not add concrete logging, metrics, tracing, Prometheus labels, or
OpenTelemetry exporters. `rawmsg` may expose structured parser errors and
bounded parser metadata that future observers can safely classify.

Allowed future observation facts from M1 state are low-cardinality or bucketed:

- Parse result class.
- Error class.
- Line ending policy name.
- Whether explicit normalization occurred.
- Message size bucket.
- Header count bucket.
- Body line count bucket.

Forbidden observation values include:

- Raw RFC 5322 messages.
- Raw body content.
- Raw header values.
- Full recipient lists.
- Raw sender or recipient local parts.
- Raw `Message-ID` values.
- Raw `DKIM2-Signature` fields.
- Raw `Message-Instance` fields.
- Tokens, passwords, private keys, and protected configuration values.
- Raw or unbounded error strings.

Prometheus labels, when added by later milestones, must remain on a strict
low-cardinality allowlist and must not include identity values, raw hashes, raw
errors, or message-derived strings.

## Required Tests

Unit tests:

- Strict CRLF happy path with multiple headers and body bytes.
- Header occurrence order preservation.
- Duplicate header names preserving order and indexes.
- Raw field name, lowercase ASCII name, raw value, unfolded value, and original
  field bytes.
- Folded header fields with space and tab continuation.
- Empty body after `\r\n\r\n`.
- Header-only message ending at the final field CRLF.
- Body with multiple lines, terminal CRLF, and no extra synthetic bytes.
- Body line indexes for start offset, end offset, and line ending width.
- Rebuild or raw-bytes accessor reproduces strict input bytes.
- Accessor immutability: mutating a returned byte slice cannot mutate the
  stored `Message`.
- Byte preservation for non-ASCII header values and body bytes without UTF-8
  assumptions in the body.
- Byte preservation for valid UTF-8 header values and RFC 5322 obsolete ASCII
  control octets, including NUL.
- Parser option defaults are restrictive.
- Reserved compatibility options fail validation until their behavior is
  separately specified and implemented.
- Exact 998-octet physical header and body lines are accepted and preserved;
  999-octet lines fail under the strict defaults.
- Exactly 65,536 indexed body lines are accepted and preserved; the parser
  returns a typed `max_body_lines` resource-limit error before appending line
  65,537.
- Wider physical line limits fail option validation because M1 has no explicit
  long-line compatibility mode or metadata.
- Header field, header block, body line, body, and message constructors reject
  inconsistent byte views, line-ending declarations, and metadata counts.

Malformed input tests:

- Bare LF in strict mode.
- Bare CR in strict mode.
- Mixed line endings in strict mode.
- Unterminated header-only input and body input without a delimiter.
- Header continuation before any field.
- Header line without colon.
- Empty header field name.
- Header field name containing whitespace.
- Header field name containing non-ASCII or control bytes.
- Header field value containing invalid RFC 6532 UTF-8 octets.
- Header field exceeding configured field limit.
- Physical header line exceeding configured line limit.
- Header block exceeding configured header limit.
- Message exceeding configured message limit.
- Body line exceeding configured indexing limit.
- Error strings do not contain raw body content or full raw header values.

Fuzz tests:

- Fuzz the raw parser with small byte inputs and safe parser limits.
- Assert no panics, no unbounded memory growth, deterministic error classes,
  and no mutation of caller-owned input after parsing.

Integration or E2E tests:

- None required for M1. The proof is library-only unit and fuzz-smoke coverage.
  Integration begins when later milestones expose public or daemon boundaries.

Generated and documentation checks:

- No OpenAPI generated artifacts are touched.
- Package documentation for `lib/internal/rawmsg` must describe the raw
  message ownership contract and strict default policy.
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

- `lib/internal/rawmsg` owns a byte-preserving raw RFC 5322 parser and
  immutable message representation.
- Default parsing is strict about CRLF and fails closed on ambiguous
  message-fidelity state.
- Header order, raw names, lowercase ASCII names, raw values, unfolded values,
  original field bytes, body bytes, and body line indexes are test-covered.
- Parser errors are structured, bounded, and secret-safe.
- Resource limits exist with restrictive defaults and test coverage.
- Raw-message and recipe owners share the hard 65,536 indexed-body-line cap,
  and the parser checks it before growing the line index.
- Strict physical header and body line limits enforce the RFC 6532 998-octet
  ceiling, and wider values are rejected during option validation.
- All constructed domain views prove byte consistency instead of trusting
  caller-supplied split representations.
- No daemon, Milter, OpenAPI, CLI, datasource, concrete observability exporter,
  or service-only dependency leaks into `lib`.
- The implementation does not use `net/mail` as parser truth.
- Unit and malformed input tests cover the M1 behavior named in
  `docs/ARCHITECTURE.md`.
- `make guardrails` passes, or skipped portions are explicitly justified with
  narrower passing commands.
- Prompt timings are recorded in the measured effort table during closeout.

## Completion Evidence

- Focused tests: `cd lib && go test ./internal/rawmsg/...` passed.
- Fuzz-smoke: `cd lib && go test ./internal/rawmsg/... -run '^$' -fuzz=Fuzz
  -fuzztime=10s` passed with 49 baseline entries and approximately 1.8M
  executions.
- Final checks: `make test`, `make vet`, `make lint`, `make race`, and
  `make guardrails` passed.
- Generated checks: no OpenAPI or generated artifacts were changed; the
  `make guardrails` `check-openapi` step passed.
- `git diff --check`: passed.
- `git status --short`: showed M1 rawmsg/doc changes in the dirty worktree and
  no out-of-scope command, OpenAPI, datasource, DNS, signing, verification,
  canonicalization, recipe, or concrete observability changes.
- Skipped checks: none.

The 2026-07-10 conformance follow-up made header-only messages regular strict
RFC 5322 input, enforced the RFC 6532 998-octet physical-line ceiling, rejected
invalid UTF-8 header octets while retaining obsolete ASCII receiver syntax, and
hardened all raw-message constructors against split-brain byte views. `go test
./lib/internal/rawmsg`, `go test -race ./lib/internal/rawmsg`, and `git diff
--check` passed. A read-only cross-package probe found that pre-commit M2 test
helpers construct inconsistent unfolded field values; those consumers require a
parser-faithful fixture update in their own milestone and were not changed by
this M1 follow-up.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Work stays inside `lib/internal/rawmsg`, tests, and package docs | Implementation changed rawmsg code/tests, rawmsg package docs, this spec, and the ignored prompt timing ledger only | done | No command modules, OpenAPI contracts, generated artifacts, datasource, DNS, signing, verification, canonicalization, recipe, or concrete observability code changed. |
| Behavior | Raw RFC 5322 bytes, headers, body, CRLF policy, and line indexes are implemented | Parser preserves raw message/header/body bytes, accepts header-only syntax, validates RFC 6532 UTF-8 headers, and owns all composed byte invariants | done | Strict CRLF is required; a delimiter is required only when the optional body is present. |
| Tests | Parser unit tests, malformed input tests, immutability tests, and fuzz-smoke coverage exist | Unit coverage includes header-only messages, duplicate headers, folding, valid and invalid UTF-8, obsolete ASCII controls, body offsets, strict 998/999 boundaries, split-brain constructors, malformed inputs, immutability, secret-safe errors, and fuzz-smoke | done | Focused tests prove RFC framing, line limits, and constructor consistency. |
| Security | Malformed and ambiguous input fails closed; diagnostics are secret-safe | Bare LF, bare CR, mixed endings, unterminated headers, invalid UTF-8, unavailable normalization, inconsistent constructed views, malformed headers, and resource-limit violations return typed bounded errors | done | Error tests assert raw header/body content is not emitted. |
| Boundaries | Library remains free of daemon, Milter, OpenAPI, Cobra, Viper, Fx, Prometheus, OTLP, CLI, LDAP, SQL dependencies | `lib/internal/rawmsg` imports only standard library packages and does not use `net/mail` as parser truth | done | `go list -deps ./internal/rawmsg` showed only standard library dependencies plus the rawmsg package. |
| Observability | Only bounded parser metadata exists; no concrete exporters or high-cardinality labels | Parser metadata records bounded byte counts, header count, line-ending policy, and normalization flag only | done | No logs, metrics, traces, exporters, or label dimensions were added. |
| Effort | Prompt timings are measured and compared to the 3 to 5 agent-day estimate | Five-prompt measured wall-clock total is 24m04s versus the 3 to 5 agent-day estimate | done | The estimate variance is explained by the narrow standard-library-only M1 scope and lack of integration/generation work. |

## Decisions And Open Questions

- Settled: `lib/internal/rawmsg` is the single source of truth for controlled
  raw RFC 5322 message representation.
- Settled: strict CRLF parsing is the default policy.
- Settled: M1 accepts RFC 5322 header-only syntax; the header/body delimiter is
  required only when an optional body is present.
- Settled: strict physical header and body lines are limited to 998 octets, and
  wider option values are rejected because no explicit compatibility mode or
  metadata exists.
- Settled: raw-message and recipe indexing share a hard maximum of 65,536 body
  lines; this local resource ceiling preserves accepted bytes and is reported
  as a limit rather than malformed RFC 5322 syntax.
- Settled: valid UTF-8 header values and obsolete ASCII controls are preserved;
  invalid high-octet UTF-8 fails closed and arbitrary body octets remain opaque.
- Settled: raw-message constructors validate component, line-index, full-byte,
  and metadata consistency.
- Settled: compatibility normalization, if implemented, must be explicit,
  typed, tested, and visible through parser metadata.
- Settled: `net/mail` must not be parser truth for protocol paths.
- Settled: M1 does not expose public facade APIs unless implementation evidence
  proves a narrow need.
- Settled: M1 does not touch OpenAPI, daemon, Milter, datasource, policy,
  signature, instance, recipe, canonicalization, DNS, or concrete
  observability packages.
- Open: The exact public facade shape for parsed raw messages remains deferred
  until the service layer needs it.
- Open: Any future line-ending normalization or nonconformant long-line receiver
  mode requires an explicit option, fidelity metadata, and separately specified
  tests. M1 rejects those behaviors.
- Open: Exact body line index API names are implementation details, but the
  invariant is durable: indexes must describe parser-owned bytes without
  rewriting them.
