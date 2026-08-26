# DKIM2 Tag Parsers

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

Status: completed.

This spec defines Milestone M2, the DKIM2 tag parser foundation for the
reference library. It covers `Message-Instance` parsing,
`DKIM2-Signature` parsing, shared strict tag-value handling, padded base64
behavior, structured errors, duplicate and unknown tag handling, sequence-gap
validation, and parser-focused tests. This work builds on the completed M1 raw
message model and touches only the library protocol core.

## Source Documents

This spec is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`, especially Sections 3.1, 3.2, 3.3, 3.4,
  3.5, 3.6, 5.4, 5.6, 6.2, 9, 10, 11.1, 11.4, 11.5, 12.1, 12.3,
  12.5, 13, 14, 15, 16, and 18
- `docs/specs/spec-and-prompt-template.md`
- `docs/specs/implementation/raw-message-model.md`
- `lib/internal/rawmsg/doc.go`
- `lib/internal/instance/doc.go`
- `lib/internal/signature/doc.go`
- `Makefile`
- `.gitignore`
- `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05, especially
  Sections 2.8, 2.12, 2.14, 7, 8, 9.6, 10, 11.2, and 11.4
- `draft-chuang-dkim2-dns-04`, dated 2026-03-18, especially
  Section 3.2 for the shared DKIM2 tag-value syntax used by DNS records

If this spec conflicts with a source document, stop and reconcile the durable
artifact before implementation continues.

## Original Gap

The repository currently has a completed raw RFC 5322 message model in
`lib/internal/rawmsg`, but `lib/internal/instance` and
`lib/internal/signature` are still package stubs:

- `lib/internal/instance/doc.go`
- `lib/internal/signature/doc.go`

There is no parser for `Message-Instance` header fields, no parser for
`DKIM2-Signature` header fields, no shared tag-value scanner, no strict
padded-base64 helper, no DKIM2 tag-specific structured error model, and no
unit coverage for duplicate tags, unknown extension tags, required tags,
invalid base64, very large sequence values, or sequence gaps.

Later milestones need parsed DKIM2 protocol fields before canonicalization,
hash calculation, signing, verification, DNS key lookup, policy decisions, or
Milter action planning can be implemented safely. If M2 duplicates tag parsing
rules across packages or exposes raw message-derived values in diagnostics,
later code will either drift from the draft or leak sensitive mail data.

## Goal

Implement the M2 parser contract in the library core:

- Parse `Message-Instance` header fields from M1 `rawmsg.HeaderField` values.
- Parse `DKIM2-Signature` header fields from M1 `rawmsg.HeaderField` values.
- Use one shared strict tag-value parser for DKIM2 header tag lists.
- Treat DKIM2 header tag identifiers case-insensitively and tag values
  case-sensitively unless a tag-specific rule explicitly says otherwise.
- Reject duplicate tag names, including duplicate extension tag names, within
  one field.
- Ignore unknown extension tags for semantic results while still validating
  their syntax and duplicate status.
- Enforce required tags and tag-specific empty-value rules.
- Enforce RFC 4648-style padded base64 syntax with zero pad bits, ignoring FWS
  where the draft allows base64string FWS.
- Return structured, bounded, secret-safe errors.
- Validate `Message-Instance` and `DKIM2-Signature` contiguous numbering from
  origin value `1`.
- Provide parser-level extraction from `rawmsg.Message` without adding public
  facade APIs, service dependencies, OpenAPI DTOs, Milter types, or concrete
  observability exporters.

M2 is a parser and validation milestone. It does not calculate message hashes,
canonicalize signature input, verify cryptographic signatures, resolve DNS
keys, evaluate policy, parse recipe JSON semantics, or match the current SMTP
envelope beyond the parser-level data needed by later milestones.

## Delivery Shape

The implementation should be split into focused, reviewable slices executed in
order. Expected prompt count is five implementation prompts plus one final
closeout prompt.

1. Shared tag-value scanner and error model:
   Add a small `lib/internal/tagvalue` package, or an equivalently cohesive
   internal helper package if implementation evidence shows a better name. It
   owns DKIM2 tag-list tokenization, FWS trimming, duplicate detection,
   extension-tag syntax validation, bounded limits, and secret-safe structured
   errors.
2. Strict base64 helper:
   Add the shared base64string parser used by `Message-Instance`,
   `DKIM2-Signature`, and later DNS/recipe work. It strips allowed FWS,
   requires correct padding when padding is needed, rejects non-zero pad bits,
   preserves a canonical no-FWS encoded form, and exposes decoded bytes through
   immutable accessors.
3. `Message-Instance` parser:
   Implement `lib/internal/instance` domain types and parser methods for
   `m=`, `h=`, optional `r=`, hash sets, unknown hash names, extension tags,
   sequence-number validation, and package documentation.
4. `DKIM2-Signature` parser:
   Implement `lib/internal/signature` domain types and parser methods for
   required `i=`, `m=`, `t=`, `d=`, and `s=`, the mutually exclusive
   envelope forms `nd=` or `mf=` plus `rt=`, optional `n=`, optional `f=`,
   extension tags, algorithm signature sets, flags, nonce limits, and package
   documentation.
5. Raw-message extraction and sequence validators:
   Add package-level helpers that find relevant header occurrences in
   `rawmsg.Message`, preserve occurrence order, parse all DKIM2 fields,
   validate contiguous `m=` and `i=` sequences from `1`, and report the
   draft-required special case where a `Message-Instance` has a higher `m=`
   value than any `DKIM2-Signature` `m=` reference.
6. Negative tests, fuzz smoke, docs, and proof:
   Add duplicate/unknown tag tests, base64 malformed tests, parser limit tests,
   sequence-gap tests, secret-safe error tests, focused fuzz seeds where
   practical, final guardrail evidence, and measured effort updates.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | medium |
| Estimated wall-clock effort | 3 to 5 agent-days |
| Highest-risk area | draft tag grammar, padded base64, and sequence-gap semantics |
| Expected prompt count | 5 implementation prompts plus 1 final closeout prompt |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: no network calls, no OpenAPI generation, no daemon wiring, no
  datasource provider, no concrete observability exporter, and no cryptographic
  verification.
- Medium risk: draft text has both header-field-specific tag ABNF and a shared
  tag-list syntax from the DNS draft; implementation must document the chosen
  interpretation and keep tests easy to update when the draft changes.
- Medium risk: base64string allows FWS but also requires padding and zero pad
  bits, so tests must distinguish accepted folding whitespace from malformed
  alphabet, missing padding, over-padding, and non-zero pad bits.
- Highest risk: leaking decoded `mf=`, `rt=`, `n=`, raw hash values, raw
  signature values, or raw header values through errors, logs, test failures,
  REST output, CLI output, or future telemetry.

Measured effort was filled during implementation closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-shared-tag-value-scanner-and-errors.md` | 2026-07-03T10:05:10+02:00 | 2026-07-03T10:10:05+02:00 | 4m55s | Not separately tracked | Done; `cd lib && go test ./internal/tagvalue/...`, `make test`, `make guardrails`, and `git diff --check` passed. |
| `02-strict-base64-helper.md` | 2026-07-03T10:11:11+02:00 | 2026-07-03T10:16:16+02:00 | 5m05s | Not separately tracked | Done; `cd lib && go test ./internal/tagvalue/...`, `make test`, `make guardrails`, and `git diff --check` passed. |
| `03-message-instance-parser.md` | 2026-07-03T10:17:18+02:00 | 2026-07-03T10:27:17+02:00 | 9m59s | Not separately tracked | Done; `go test ./internal/tagvalue/... ./internal/instance/...`, `make test`, `make guardrails`, and `git diff --check` passed using `/private/tmp` caches. |
| `04-dkim2-signature-parser.md` | 2026-07-03T10:28:29+02:00 | 2026-07-03T10:38:34+02:00 | 10m05s | Not separately tracked | Done; `go test ./internal/tagvalue/... ./internal/signature/...`, `go test ./...`, `make test`, `make guardrails`, and `git diff --check` passed using `/private/tmp` caches. |
| `05-raw-message-extraction-and-sequences.md` | 2026-07-03T10:39:45+02:00 | 2026-07-03T10:45:56+02:00 | 6m11s | Not separately tracked | Done; `go test ./internal/rawmsg/... ./internal/tagvalue/... ./internal/instance/... ./internal/signature/...`, `make test`, `make guardrails`, and `git diff --check` passed using `/private/tmp` caches. |
| `06-negative-tests-fuzz-docs-closeout.md` | 2026-07-03T10:46:45+02:00 | 2026-07-03T10:54:47+02:00 | 8m02s | Not separately tracked | Done; final focused parser tests, tagvalue/instance/signature fuzz-smoke, `make test`, `make vet`, `make lint`, `make race`, `make guardrails`, and `git diff --check` passed using `/private/tmp` caches. |

Total measured wall-clock for the six-prompt M2 pack is 44m17s. This is far
below the planning estimate of 3 to 5 agent-days because the implementation
scope remained limited to internal parser packages, used existing M1 rawmsg
accessors and standard-library parsing helpers, and did not require
canonicalization, cryptography, DNS, daemon, Milter, OpenAPI, datasource, or
observability work.

The later draft-04 parser migration is not added to the original prompt timing
ledger because its execution start was not recorded under that ledger. Its
reproducer, focused tests, fuzz-smoke, downstream library test, and scope are
recorded under Completion Evidence and the Review Matrix.

The required measurement is wall-clock time from the start of prompt execution
to the final closeout response for that prompt. Active engineering time may be
recorded as an additional estimate, but it does not replace wall-clock time.

## Scope

In scope:

- Shared strict DKIM2 tag-value parser behavior for header fields.
- Shared padded base64string parser behavior needed by M2.
- `lib/internal/instance` parser types, errors, helpers, tests, fuzz seeds,
  and package docs.
- `lib/internal/signature` parser types, errors, helpers, tests, fuzz seeds,
  and package docs.
- Parser extraction helpers that consume `rawmsg.Message` and
  `rawmsg.HeaderField` without mutating M1-owned message state.
- Structured parser and validation errors that are suitable for later mapping
  to `PERMERROR`, `FAIL`, `TEMPERROR`, or local policy findings.
- Unit tests and malformed input tests for M2.
- Final Makefile-driven validation evidence.
- The narrow `lib/internal/canonical` signature-input scanner call and its
  draft-versioned fixtures, solely so canonical target rendering enforces the
  same header terminator contract.

Out of scope:

- Public `lib` facade APIs, unless a later implementation prompt updates this
  spec with a concrete facade need.
- Raw RFC 5322 parsing changes in `lib/internal/rawmsg`.
- Header hash, body hash, or DKIM2-Signature canonicalization behavior beyond
  selecting the shared strict header scanner and updating affected fixtures.
- Message hash calculation or hash comparison.
- Cryptographic signing or verification.
- DNS key record parsing or DNS lookup behavior.
- Recipe JSON parsing, recipe application, recipe generation, or recipe
  expansion limits beyond syntactic `r=` base64 validation.
- SMTP envelope matching against current delivery state beyond parsed `mf=`
  and `rt=` values needed by later verification.
- Timestamp age policy beyond syntactic unsigned decimal parsing.
- Local policy evaluation and action planning.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl` changes.
- OpenAPI contracts or generated artifacts.
- Concrete logging, tracing, metrics, Prometheus labels, exporters, or debug
  modules.
- Commits.

## Protocol, Runtime Or Domain Semantics

M2 is bound to `draft-ietf-dkim-dkim2-spec-04`, with
`draft-chuang-dkim2-dns-04` used only for the shared DKIM2 tag-value list
syntax that the DNS record format copies from DKIM2.

### Shared Tag-Value Semantics

- DKIM2 header fields are parsed from M1-owned `rawmsg.HeaderField` values.
  Parser code consumes field values from `rawmsg` accessors and must not mutate
  caller-owned or parser-owned byte slices.
- Header field names are matched case-insensitively through M1's lowercase
  header name view. A `Message-Instance` parser must reject non
  `Message-Instance` fields. A `DKIM2-Signature` parser must reject non
  `DKIM2-Signature` fields.
- A shared tag-value scanner owns DKIM2 tag-list mechanics. `instance` and
  `signature` packages must not implement parallel semicolon splitting,
  duplicate detection, FWS trimming, base64 FWS stripping, or tag-name
  validation.
- For DKIM2 header fields, tag identifiers before `=` are case-insensitive.
  The implementation canonicalizes tag identifiers to lowercase for matching
  and duplicate detection. Generic DNS-compatible tag lists retain
  case-sensitive tag identifiers as required by DNS draft-04 Section 3.2.
- Tag values after `=` are case-sensitive unless a tag-specific draft rule
  explicitly says otherwise.
- WSP and FWS around tag names, `=`, tag values, commas, and colons is handled
  only where the relevant ABNF permits it.
- Semicolons terminate header-field tags. Unencoded semicolons inside a tag
  value are invalid, empty tag specifications are invalid, and every
  `Message-Instance` or `DKIM2-Signature` tag including the final tag must have
  the semicolon required by the draft-04 `mi-tag-list` and `sig-tag-list`
  ABNF. The shared scanner must expose this as an explicit strict header mode:
  DKIM2 DNS draft-04 Section 3.2 permits an optional final semicolon, so the
  reusable tag-list core must remain capable of parsing that DNS grammar
  without weakening the two header parsers.
- Tags with duplicate names make the entire field invalid. This applies to
  required tags, optional tags, and extension tags after case-insensitive
  canonicalization.
- Unknown extension tags are syntactically validated and then ignored by
  semantic results. They must not produce success data, but they still
  participate in duplicate detection and resource limits. Their values must
  satisfy the printable non-semicolon `tag-value` ABNF; control bytes fail
  closed.
- Empty values are distinct from omitted tags. Omitted required tags are
  missing-tag errors. Empty required values are invalid unless the tag-specific
  ABNF explicitly permits an empty value.

### Base64string Semantics

- M2 base64 parsing follows the DKIM2 draft base64string rule and RFC 4648
  encoding behavior.
- FWS inside base64string values is ignored before decoding. Because M1 has
  already unfolded header continuations, M2 must at minimum strip space and tab
  bytes where base64string FWS is allowed. If a later raw-message mode exposes
  folded bytes differently, the base64 helper must continue to treat only
  draft-allowed FWS as ignorable.
- Decoding uses the standard base64 alphabet. URL-safe alphabet variants,
  non-base64 bytes, missing padding when padding is required, excess padding,
  interior `=` characters, and non-zero pad bits are invalid.
- Encoded values preserve two views:
  the original parser-owned tag value bytes without exposing mutable storage,
  and a canonical no-FWS base64 representation suitable for later comparison.
- Decoded bytes are exposed only through immutable accessors.
- Base64 parser errors must not include the raw encoded value or decoded bytes.
- M2 validates base64 syntax and padding. Algorithm-specific byte lengths are
  enforced only where the parser has a durable rule: `sha256` message hash
  values decode to 32 bytes. Variable RSA signature lengths and public-key
  compatibility checks are deferred to later cryptographic and DNS milestones.

### Message-Instance Semantics

- `Message-Instance` fields contain `m=` and `h=` as required tags and
  optional `r=`.
- `m=` is the Message-Instance revision number. Origin uses value `1`.
  Additional instances increment by one. M2 rejects zero, negative syntax,
  non-decimal syntax, and values that overflow the chosen unsigned integer
  representation.
- Parsed `Message-Instance` collections must validate that instance numbers are
  contiguous from `1` with no gaps. Gaps make verification impossible and are
  reported as structured parser or validation errors.
- `h=` contains one or more hash sets separated by commas. Each hash set
  contains hash name, header hash, and body hash separated by colons.
- `sha256` is the known baseline hash name. Unknown hash names are represented
  but cannot create verification success in later milestones. Header and body
  components for unknown algorithms still parse as strict base64string values.
- `sha256` header and body hashes must decode from valid padded base64string
  values to 32 bytes.
- Duplicate hash algorithm names within one `h=` value are invalid for M2.
  This prevents ambiguous selection and keeps later hash comparison fail-closed.
- `r=` is parsed as syntactically valid base64string and stores decoded bytes
  plus canonical encoded form. M2 does not parse the decoded JSON recipe
  object; recipe semantics remain owned by `lib/internal/recipe`.
- Message-Instance extension tags are ignored after syntactic validation and
  duplicate detection.

### DKIM2-Signature Semantics

- `DKIM2-Signature` fields contain required `i=`, `m=`, `t=`, `d=`, and `s=`
  tags. They contain exactly one envelope form: either `nd=`, or both `mf=`
  and `rt=`. Optional tags are `n=` and `f=`.
- `i=` is the DKIM2-Signature sequence number. Origin uses value `1`.
  Additional signatures increment by one. M2 rejects zero, negative syntax,
  non-decimal syntax, and values that overflow the chosen unsigned integer
  representation.
- Parsed `DKIM2-Signature` collections must validate that signature sequence
  numbers are contiguous from `1` with no gaps. Gaps make the message unsigned
  and are reported as structured parser or validation errors.
- `m=` references the highest numbered `Message-Instance` header field covered
  by this signature. It uses the same unsigned decimal parsing rules as
  Message-Instance `m=`.
- A parsed DKIM2 field set must report the draft special case where any
  `Message-Instance` `m=` value is higher than every `DKIM2-Signature` `m=`
  reference.
- `t=` is an unsigned decimal timestamp in seconds since
  `1970-01-01T00:00:00Z`. M2 parses it without truncating to 31 or 32 bits and
  must handle values up to at least `10^12`. Age and future-time policy are
  deferred to verification/policy milestones.
- `mf=` is a padded base64string for the RFC 5321 reverse-path, including angle
  brackets and excluding mail parameters. M2 decodes it and validates the
  imported RFC 5321 `Reverse-path` grammar, including null reverse-path,
  mailbox local-part/domain syntax, quoted local-parts, address literals, and
  obsolete source routes that receivers must accept. Current-envelope matching
  remains deferred.
- `rt=` is one or more padded base64string forward-path values separated by
  commas. M2 decodes and validates each imported RFC 5321 `Forward-path`,
  rejects the null path, and applies a configurable recipient-count limit.
  Current-envelope matching and Bcc privacy policy are deferred.
- Draft-04 imports RFC 5321 paths, not RFC 6531 extended mailbox syntax.
  Therefore M2 preserves accepted path bytes without normalization but rejects
  non-ASCII SMTPUTF8 local-parts and U-label domains. A later SMTPUTF8 policy
  requires a draft/versioned contract change rather than implicit acceptance.
- `nd=` is a canonical ASCII DNS name for the domain that must appear in the
  next signature's `d=` value. When `nd=` is present, `mf=` and `rt=` are
  forbidden. When `nd=` is absent, both `mf=` and `rt=` are required. Sequence
  validation of `nd=` against the next signature belongs to verification, but
  the parser must preserve the canonical domain and fail closed on invalid or
  mutually incompatible tag combinations.
- `d=` is the signing domain used for key lookup. M2 validates ASCII DNS-label
  syntax, rejects empty labels, leading or trailing dot, label length over 63,
  total length over 253, and control or whitespace bytes. IDNA, Unicode, and
  EAI semantics remain deferred because the DKIM2 EAI section is TBA.
- `s=` contains one or more signature sets separated by commas. Each set
  contains selector, signature algorithm name, and message signature separated
  by colons.
- Known signature algorithm names are `rsa-sha256` and `ed25519-sha256`.
  Unknown algorithm names are represented but cannot create verification
  success in later milestones.
- For `ed25519-sha256`, M2 may enforce the stable 64-byte Ed25519 signature
  length after base64 decoding. RSA signature lengths and key matching remain
  deferred to M4 and DNS milestones.
- Duplicate signature algorithms or duplicate selectors inside one `s=` value
  are invalid when they would make later selection ambiguous. If implementation
  evidence shows legitimate same-algorithm multi-selector behavior is needed,
  update this spec before accepting it.
- `n=` is optional, simple printable ASCII excluding semicolon, and must not
  exceed 64 characters. Unknown semantics are preserved only as bounded parser
  data; it must not become a correlation key in default logs or metrics.
- `f=` contains comma-separated flags. Known flags are `donotmodify`,
  `donotexplode`, `feedback`, `feedhere`, and `exploded`. Unknown flags are
  ignored for semantic decisions. Duplicate known flags are invalid to avoid
  ambiguous policy inputs.
- `DKIM2-Signature` extension tags are ignored after syntactic validation and
  duplicate detection.

### Raw Message Extraction Semantics

- Extraction helpers consume `rawmsg.Message` and return parsed field
  collections in RFC 5322 occurrence order.
- Message-Instance and DKIM2-Signature parser results retain the original
  header occurrence index from M1 so later canonicalization can place fields in
  draft-required order without relying on map iteration.
- M2 does not remove, add, rewrite, or fold header fields.
- M2 does not depend on `net/mail` for protocol parsing.
- M2 must not introduce Unicode normalization, IDNA mapping, local-part
  normalization, relaxed domain matching, or SMTP address rewriting.

## Package Boundaries

Intended ownership:

- `lib/internal/tagvalue`:
  Owns shared DKIM2 tag-list tokenization, tag-name canonicalization, FWS
  handling, duplicate detection, base64string parsing, bounded limits, and
  generic structured tag errors. If implementation evidence favors a different
  package name, it must remain under `lib/internal/` and must be the single
  owner of shared tag parsing behavior.
- `lib/internal/instance`:
  Owns `Message-Instance` domain types, tag-specific validation, hash-set
  parsing, recipe base64 container parsing, instance collection extraction, and
  contiguous `m=` sequence validation.
- `lib/internal/signature`:
  Owns `DKIM2-Signature` domain types, tag-specific validation, envelope-path
  container parsing, signature-set parsing, flag parsing, nonce validation,
  signature collection extraction, and contiguous `i=` sequence validation.
- `lib/internal/rawmsg`:
  Remains the source of truth for byte-preserving RFC 5322 message
  representation. M2 consumes its accessors and must not alter its parser
  contract except through a separate spec update.
- `lib/internal/canonical`:
  Does not change in M2. Later consumes M2 parser results and M1 raw message
  state for canonicalization.
- `lib/internal/recipe`:
  Does not change in M2. Later owns decoded `r=` JSON recipe semantics.
- `lib/internal/keyresolver`, `lib/internal/datasource`,
  `lib/internal/policy`, `lib/internal/service`, and
  `lib/internal/observability`:
  Do not change in M2.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl`:
  No M2 code changes.

Generated REST DTOs must stay at HTTP boundaries. Core DKIM2 packages must not
import generated OpenAPI types, Cobra, Viper, Fx, Prometheus, OTLP exporters,
Milter packages, SQL drivers, LDAP drivers, Valkey clients, or CLI frameworks.

## Security And Privacy

Default behavior is restrictive:

- Ambiguous tag syntax fails before a parsed DKIM2 protocol object is returned.
- Missing required tags fail closed.
- Duplicate tags fail closed.
- Invalid base64, missing required padding, non-zero pad bits, invalid
  extension tag syntax, invalid numeric syntax, sequence gaps, and parser limit
  violations fail closed.
- Unknown extension tags are ignored only after they pass generic syntax,
  duplicate, and limit checks.
- Sequence numbers and timestamps must not overflow into wrapped or truncated
  values.
- Parser options and limits must have restrictive defaults and must not
  silently disable size or count limits.
- Error values and test logs must not include raw header values, full raw
  `Message-Instance` fields, full raw `DKIM2-Signature` fields, decoded
  `mf=` or `rt=` paths, recipient lists, sender local parts, nonce values,
  hash bytes, signature bytes, private keys, tokens, passwords, protected
  config values, or unbounded error strings.
- Synthetic tests must not contain live messages, production recipients,
  real nonces, real signatures, production domains, private keys, or
  secret-bearing headers.
- Byte-oriented paths must not normalize accepted bytes. Because draft-04
  imports RFC 5321 rather than RFC 6531, non-ASCII EAI/SMTPUTF8 path forms fail
  closed until a versioned contract explicitly enables them.

Recommended initial resource limits:

| Limit | Initial default |
| --- | ---: |
| Maximum unfolded DKIM2 header field value bytes | 64 KiB |
| Maximum tags per DKIM2 header field | 64 |
| Maximum tag name bytes | 64 |
| Maximum single tag value bytes before base64 FWS stripping | 64 KiB |
| Maximum decoded base64 value bytes for parser-owned containers | 1 MiB |
| Maximum hash sets per `Message-Instance` | 16 |
| Maximum signature sets per `DKIM2-Signature` | 16 |
| Maximum `rt=` recipients per `DKIM2-Signature` | 2000 |
| Maximum flags per `DKIM2-Signature` | 32 |
| Maximum nonce bytes | 64 |

If implementation evidence shows these defaults are not practical, update this
spec before changing behavior.

## Observability

M2 should not add concrete logging, metrics, tracing, Prometheus labels,
OpenTelemetry exporters, or debug modules. Parser packages may expose
structured errors and bounded metadata that future observers can safely
classify.

Allowed future observation facts from M2 state are low-cardinality or bucketed:

- Parse result class.
- Header kind: `message_instance` or `dkim2_signature`.
- Error code.
- Error reason class.
- Known tag name when it is one of the DKIM2-defined small allowlists.
- Unknown extension tag count bucket.
- Hash set count bucket.
- Signature set count bucket.
- Recipient count bucket.
- Field size bucket.

Forbidden observation values include:

- Raw RFC 5322 messages.
- Raw header values.
- Raw `Message-Instance` fields.
- Raw `DKIM2-Signature` fields.
- Raw `mf=` or `rt=` decoded paths.
- Raw sender or recipient local parts.
- Full recipient lists.
- Raw nonce values.
- Raw hash values.
- Raw signature values.
- Raw selector values unless a future explicit debug module uses a
  deployment-local keyed hash.
- Tokens, passwords, private keys, and protected configuration values.
- Raw or unbounded error strings.

Prometheus labels, when added by later milestones, must remain on a strict
low-cardinality allowlist and must not include identity values, raw hashes,
raw errors, or message-derived strings.

## Required Tests

Unit tests:

- Shared tag scanner accepts semicolon-separated tags with and without a final
  trailing semicolon in generic DNS-compatible mode, while strict header mode
  rejects a missing final terminator.
- Shared tag scanner rejects empty interior tag specs, missing `=`, invalid
  tag names, unencoded semicolons in values, duplicate known tags, duplicate
  extension tags, and fields over configured limits.
- Shared tag scanner uses exact case-sensitive names and unfolds valid CRLF WSP
  for DNS-compatible `Scan`, while strict header `ScanTerminated` consumes
  already-unfolded values and canonicalizes identifiers case-insensitively.
  Both preserve case-sensitive values.
- Unknown extension tags are ignored by semantic parsers but still validated
  and duplicate-checked.
- Empty tag values are distinct from omitted tags.
- Base64 helper accepts padded RFC 4648 values, strips allowed FWS, exposes a
  canonical no-FWS encoded form, and returns immutable decoded bytes.
- Base64 helper rejects URL alphabet, non-base64 bytes, missing required
  padding, excess padding, interior `=`, non-zero pad bits, and values over
  decoded-size limits.
- `Message-Instance` parser accepts required `m=` and `h=` plus optional `r=`.
- `Message-Instance` parser rejects missing `m=`, missing `h=`, duplicate
  tags, zero `m=`, overflowing `m=`, malformed hash sets, duplicate hash names,
  invalid sha256 hash lengths, invalid hash base64, and invalid `r=` base64.
- `Message-Instance` parser preserves unknown hash names as non-success
  parser data and ignores unknown extension tags.
- `DKIM2-Signature` parser accepts required `i=`, `m=`, `t=`, `d=`, and `s=`,
  exactly one valid envelope form (`nd=` or `mf=` plus `rt=`), and optional
  `n=` and `f=`.
- `DKIM2-Signature` parser rejects missing required tags, duplicate tags,
  zero or overflowing `i=`, zero or overflowing `m=`, malformed `t=`,
  malformed `mf=`, malformed `rt=`, malformed `nd=`, incompatible or missing
  envelope forms, invalid domain syntax, malformed
  signature sets, invalid base64 signatures, nonce values over 64 bytes, nonce
  semicolons, duplicate known flags, and values over configured limits.
- `DKIM2-Signature` parser preserves unknown algorithms and unknown flags as
  non-success parser data where the draft requires ignoring them.
- Raw-message extraction finds all `Message-Instance` and `DKIM2-Signature`
  occurrences in M1 header order and preserves M1 header occurrence indexes.
- Sequence validators reject missing origin sequence, duplicate sequence
  numbers across fields, gaps in `m=` values, gaps in `i=` values, and
  `Message-Instance` `m=` values higher than any signature `m=` reference.
- Error strings and test failure helpers do not include raw DKIM2 field values,
  decoded envelope paths, recipient lists, nonces, hashes, signatures, or
  secret-bearing material.
- Accessor immutability: mutating returned byte slices cannot mutate parsed
  `Message-Instance`, `DKIM2-Signature`, base64, hash, signature, or envelope
  path state.

Fuzz tests:

- Fuzz the shared tag-value scanner with small byte inputs and safe parser
  limits.
- Fuzz `Message-Instance` parsing with synthetic values and safe limits.
- Fuzz `DKIM2-Signature` parsing with synthetic values and safe limits.
- Every fuzz target parses the same bounded input twice and asserts identical
  success or typed error code/class outcomes, in addition to immutability and
  secret-leak checks.
- Assert no panics, no unbounded memory growth, deterministic error classes,
  no caller input mutation, and no raw input leakage in error strings.

Integration or E2E tests:

- None required for M2. The proof is library-only unit and fuzz-smoke
  coverage. Integration begins when later milestones expose public,
  canonicalization, cryptographic, daemon, or Milter boundaries.

Generated and documentation checks:

- No OpenAPI generated artifacts are touched.
- Package documentation for `lib/internal/instance` must describe the
  `Message-Instance` parser contract, draft baseline, sequence invariants,
  recipe deferral, and secret-safe diagnostics.
- Package documentation for `lib/internal/signature` must describe the
  `DKIM2-Signature` parser contract, draft baseline, sequence invariants,
  envelope-path container parsing, signature deferral, and secret-safe
  diagnostics.
- Package documentation for any shared tag-value helper package must describe
  ownership of DKIM2 tag-list syntax and base64string behavior.
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

- M2 adds one shared internal owner for DKIM2 tag-list parsing and padded
  base64string behavior.
- Generic tag-list parsing remains compatible with DKIM2 DNS draft-04 Section
  3.2, while `Message-Instance`, `DKIM2-Signature`, and canonical target
  rendering require every header tag's semicolon terminator.
- `lib/internal/instance` parses and validates `Message-Instance` fields,
  including required tags, hash sets, optional recipe base64, unknown
  extensions, duplicate tags, and contiguous `m=` sequence checks.
- `lib/internal/signature` parses and validates `DKIM2-Signature` fields,
  including required tags, optional nonce and flags including `feedhere`,
  exactly one `nd=` or `mf=` plus `rt=` envelope form, immutable canonical
  next-domain state, signature sets, unknown extensions, duplicate tags, and
  contiguous `i=` sequence checks.
- Parser behavior is strict by default and fails closed on ambiguous syntax,
  malformed base64, missing required tags, duplicate tags, numeric overflow,
  and sequence gaps.
- Unknown extension tags are ignored only after syntax, duplicate, and limit
  checks.
- Parser errors are structured, bounded, and secret-safe.
- M1 `rawmsg` remains the raw RFC 5322 source of truth and is consumed through
  immutable accessors.
- No daemon, Milter, OpenAPI, CLI, datasource, concrete observability exporter,
  Valkey, SQL, LDAP, or service-only dependency leaks into `lib`.
- Unit and malformed input tests cover the M2 behavior named in
  `docs/ARCHITECTURE.md`.
- Fuzz-smoke coverage exists for shared tag-value parsing and the two DKIM2
  header parsers where practical.
- `make guardrails` passes, or skipped portions are explicitly justified with
  narrower passing commands.
- Prompt timings are recorded in the measured effort table during closeout.

## Completion Evidence

- Draft-04 parser migration focused tests: `cd lib && go test
  ./internal/tagvalue/... ./internal/instance/... ./internal/signature/...
  ./internal/canonical/...` passed. The strict-header regressions first failed
  against the prior optional-terminator and fixed-envelope parser, then passed
  after the shared scanner/API and parser corrections.
- Draft-04 parser migration fuzz-smoke: `FuzzScanTagList`,
  `FuzzParseMessageInstance`, and `FuzzParseDKIM2Signature` each passed for 5s
  with updated terminating-tag, `nd=`, `feedhere`, and malformed-form seeds.
- Draft-04 downstream library check: `cd lib && go test ./...` passed,
  including canonical and verify consumers.
- Focused tests: `cd lib && GOCACHE=/private/tmp/dkim2-gocache go test ./internal/tagvalue/... ./internal/instance/... ./internal/signature/...` passed.
- Fuzz-smoke:
  `cd lib && GOCACHE=/private/tmp/dkim2-gocache go test ./internal/tagvalue/... -run '^$' -fuzz=Fuzz -fuzztime=10s`,
  `cd lib && GOCACHE=/private/tmp/dkim2-gocache go test ./internal/instance/... -run '^$' -fuzz=Fuzz -fuzztime=10s`, and
  `cd lib && GOCACHE=/private/tmp/dkim2-gocache go test ./internal/signature/... -run '^$' -fuzz=Fuzz -fuzztime=10s` passed.
- Generated checks: no OpenAPI or generated artifacts changed; `make guardrails` included `check-openapi`.
- Guardrails: `GOCACHE=/private/tmp/dkim2-gocache make test`, `GOCACHE=/private/tmp/dkim2-gocache make vet`, `GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache make lint`, `GOCACHE=/private/tmp/dkim2-gocache make race`, and `GOCACHE=/private/tmp/dkim2-gocache GOLANGCI_LINT_CACHE=/private/tmp/dkim2-golangci-cache make guardrails` passed.
- `git diff --check`: passed.
- `git status --short`: dirty M1/M2 implementation worktree with new M2 parser, test, fuzz, testdata, docs, and prompt-pack artifacts; no commits created.
- Skipped checks: none.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Work stays inside M2 parser packages, tests, docs, shared internal parser helpers, and the narrow canonical strict-scanner consumer | Changes are limited to `lib/internal/tagvalue`, `lib/internal/instance`, `lib/internal/signature`, M2 docs/testdata, and the canonical signature-input scanner call plus affected fixtures | done | No command modules, OpenAPI contracts, generated artifacts, datasource, DNS lookup, signing, verification behavior, recipe semantics, policy, or concrete observability code changed for the migration. |
| Behavior | Message-Instance and DKIM2-Signature parser semantics match draft-04 and architecture M2 | Shared tag parsing, header terminators, strict base64string parsing, required tags, mutually exclusive envelope forms, `feedhere`, unknown extension handling, duplicate rejection, parser limits, sequence validation, and the unreferenced-instance special case are implemented and covered | done | Recipe JSON, cryptography, DNS, current-envelope matching, canonicalization algorithms, and policy remain deferred as specified. |
| Tests | Unit, malformed input, immutability, and fuzz-smoke coverage exist | Unit suites cover malformed inputs, limits, duplicates, unknowns, immutability, sequence gaps, and secret-safe diagnostics; one fuzz target plus synthetic seed corpus exists for each M2 parser package | done | Final focused tests, all fuzz-smoke commands, and Makefile gates passed. |
| Security | Fail-closed and secret-safe behavior is preserved | Ambiguous syntax, invalid base64, missing tags, duplicate tags, numeric overflow, sequence gaps, and limit violations fail closed with typed bounded errors | done | Error-string tests and fuzz-smoke marker assertions cover raw field, decoded path, nonce, hash, signature, and secret marker leakage. |
| Boundaries | Module and generated-code boundaries hold | Parser code remains inside the standalone `lib` module and uses `rawmsg` accessors plus standard-library helpers | done | No service-only dependencies, OpenAPI DTOs, generated files, Milter, datasource, DNS, policy, or observability exporter imports were added. |
| Observability | Only bounded parser metadata exists; no concrete exporters or high-cardinality labels | M2 exposes typed parser errors and bounded metadata only | done | No logs, metrics, traces, exporters, debug modules, or Prometheus labels were introduced. |
| Effort | Prompt timings are measured and compared to the 3 to 5 agent-day estimate | Six-prompt wall-clock total is 44m17s versus the 3 to 5 agent-day planning estimate | done | The measured effort is lower because the slice stayed library-only and avoided later milestone surfaces. |

## Decisions And Open Questions

- Settled: M1 `lib/internal/rawmsg` is a prerequisite and remains the single
  source of truth for raw RFC 5322 header occurrence order and byte-preserving
  field values.
- Settled: M2 parser packages consume M1 accessors and do not rewrite header
  fields.
- Settled: Shared tag-list mechanics and base64string parsing must live in one
  internal abstraction to avoid duplicate protocol rules.
- Settled: DKIM2 header tag identifiers are matched case-insensitively, while
  tag values remain case-sensitive unless a tag-specific draft rule says
  otherwise.
- Settled: Duplicate extension tags invalidate the field even though unknown
  extension tags are otherwise ignored.
- Settled: Generic `tagvalue.Scan` accepts the optional final semicolon required
  by DKIM2 DNS draft-04 Section 3.2 and treats names case-sensitively. Strict
  `ScanTerminated` requires the final semicolon and case-insensitive names
  mandated for every Message-Instance and DKIM2-Signature tag by header
  draft-04 Sections 7 and 8; both header parsers and canonical target rendering
  use the strict API.
- Settled: Unknown extension values use printable non-semicolon tag-value
  syntax, and unknown hash algorithms retain strict base64string components.
- Settled: `mf=` and `rt=` validate the ASCII RFC 5321 path grammar imported by
  draft-04. SMTPUTF8/EAI syntax is not silently accepted because RFC 6531 is
  not imported by the current draft.
- Settled: A DKIM2-Signature has exactly one envelope form: canonical `nd=`, or
  both `mf=` and `rt=`. Parser-level `nd=` to the next signature's `d=` chain
  validation remains deferred.
- Settled: `feedhere` is a parser-known draft-04 flag.
- Settled: M2 validates syntactic base64, padding, zero pad bits, and stable
  parser-level decoded containers, but defers most cryptographic length and
  key-compatibility checks to later milestones.
- Settled: Recipe JSON semantics are deferred to `lib/internal/recipe`.
- Settled: Current SMTP envelope matching is deferred to verification and
  Milter/service milestones.
- Open: Whether same-algorithm multi-selector `s=` sets should be accepted for
  algorithmic dexterity remains conservative in M2. The initial parser rejects
  ambiguous duplicates unless a later spec update documents a legitimate
  selection model.
- Open: The final public facade shape for parsed DKIM2 fields remains deferred
  until the service layer needs it.
