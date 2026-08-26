# DKIM2 Recipe Generation

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

Status: implemented; final exact-snapshot review and commit closeout in progress.

This specification defines deterministic, bounded generation of DKIM2 JSON
recipes that reconstruct a previous message state from a current message state.
It is the durable contract for the recipe-generation milestone and deliberately
stops before Message-Instance construction, base64 encoding, signing, or public
service integration.

## Source Documents

This specification is governed by:

- `AGENTS.md`.
- `POLICY.md`.
- `docs/ARCHITECTURE.md`.
- `docs/specs/spec-and-prompt-template.md`.
- `docs/specs/implementation/raw-message-model.md`.
- `docs/specs/implementation/canonicalization-and-hashes.md`.
- `docs/specs/implementation/recipe-application.md`.
- [draft-ietf-dkim-dkim2-spec-04](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-04), especially Sections 4, 5, 5.1, 5.2, 6, 6.1, 6.2, 7.2, and 9.1.
- RFC 5322 for header-field and line framing constraints.
- RFC 8259 for UTF-8 JSON strings and escaping.
- `Makefile`.

The implementation baseline is exactly `draft-ietf-dkim-dkim2-spec-04`.
Generated vectors and interpretation tests must name that version. A later
draft is not an implicit behavior update. If any source above conflicts with
this document, implementation stops until the durable documents and versioned
evidence agree.

## Original Gap And Resolution

`lib/internal/recipe` originally owned the strict draft-04 recipe parser, closed
immutable recipe model, bounded recipe application, body-unavailable state,
and reconstruction usage accounting, but did not generate recipes or serialize
the closed model to deterministic decoded JSON.

The completed implementation now provides the inverse recipe component needed
to describe a Reviser change under draft-04 Section 5: apply a recipe to the
current state to recover the previous state. Recipe owns deterministic
matching, representability decisions, output limits, compact decoded JSON, and
generated parse/apply/semantic proof. Originator/Reviser role orchestration and
the Section 9.1 hash gate remain M10 ownership; signing, service, and adapter
packages do not carry parallel generation rules.

## Goal

Add a cohesive generator and serializer under `lib/internal/recipe` that:

- accepts a previous/before target state and a current/after source state;
- emits a conservative inverse recipe from current to previous;
- returns a closed no-recipe result when no recipe-semantic relevant change
  exists;
- emits correct, deterministic, non-minimal `h` and `b` plans within the same
  limits enforced by the M8 parser and applier;
- treats header relevance through a narrow injected implementation owned by
  `lib/internal/canonical`, without copying signed-header exclusions;
- distinguishes representable output from an explicitly authorized `b:null`;
- requires an explicit copy-only or bounded-literal disclosure policy;
- proves generated JSON by parsing and applying it before returning success;
- remains immutable, concurrent-safe, fail-closed, and protected-message-safe.

Correctness means recipe-semantic reconstruction, not a claim that raw header
bytes or original cross-header-name placement are reproduced. Header names are
case-insensitive and occurrences are compared in draft bottom-up order by exact
unfolded field-value bytes. Body content, line terminators, and final framing
are exact. Every reconstructed known dimension must also produce the same
Section 6 canonical input and hash as the previous state.

## Delivery Shape

The ignored local prompt pack split implementation into these reviewable
slices:

1. Add generation-specific limits, usage, typed errors, immutable result
   types, and the injected header-relevance seam.
2. Add deterministic header planning and focused duplicate/case/folding tests.
3. Add deterministic body planning, framing rules, and explicit unavailable
   policy tests.
4. Add the bounded compact JSON writer and byte-exact draft-04 golden vectors.
5. Add internal serialize/parse/apply reconstruction proof and canonical
   integration evidence.
6. Add exact-limit, abuse, property, fuzz, race, privacy, and dependency tests.
7. Close documentation, run complete guardrails, obtain two independent
   approvals of one unchanged snapshot, and create the milestone's one commit.

The prompt pack remains under ignored `temp/recipe-generation-prompts/` and is
never staged or committed.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 4 to 10 hours |
| Highest-risk area | inverse recipe semantics, body representability, deterministic bounded output |
| Expected prompt count | 7 |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: package placement and reuse of the closed M8 recipe model.
- Medium risk: immutable result design, compact JSON escaping, and exact limit
  accounting.
- Highest risk: duplicate occurrence matching, terminal body framing,
  unrepresentable binary literals, cross-header-name limitations, and proving
  that generated output remains accepted by the same parser and applier.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| 01 | 2026-07-13T10:38:31+02:00 | 2026-07-13T11:05:55+02:00 | 27m24s | not separately tracked | Contracts, relevance, limits, and errors |
| 02 | 2026-07-13T11:06:34+02:00 | 2026-07-13T12:03:40+02:00 | 57m06s | not separately tracked | Header generation and adversarial bounds |
| 03 | 2026-07-13T12:04:13+02:00 | 2026-07-13T12:31:29+02:00 | 27m16s | not separately tracked | Body generation and framing |
| 04 | 2026-07-13T12:32:01+02:00 | 2026-07-13T13:01:09+02:00 | 29m08s | not separately tracked | Bounded compact JSON and goldens |
| 05 | 2026-07-13T13:01:36+02:00 | 2026-07-13T13:31:04+02:00 | 29m28s | not separately tracked | Strict self-validation and canonical proof |
| 06 | 2026-07-13T13:31:44+02:00 | 2026-07-13T14:05:44+02:00 | 34m00s | not separately tracked | Abuse, fuzz, race, privacy, and dependency proof |
| 07 | 2026-07-13T14:06:03+02:00 | 2026-07-13T14:16:42+02:00 | 10m39s | not separately tracked | Durable content freeze after documentation alignment and final gates; exact approval and commit evidence remain out of band |

Wall-clock duration for Prompts 01 through 06 is measured from each execution
start to its final closeout response. Prompt 07 is measured through the durable
content freeze so later exact-hash approvals and the commit do not require a
self-modifying tracked document; the ignored timing ledger retains the final
closeout span. Missing timestamps are recorded as unavailable, never
reconstructed from guesses.

## Scope

In scope:

- Recipe generation in `lib/internal/recipe` from immutable M8 states.
- A narrow header-relevance contract implemented by canonical ownership.
- Deterministic conservative header and body matching.
- Explicit representation of unchanged, generated, and body-unavailable
  outcomes.
- Deterministic serialization of decoded compact recipe JSON.
- Generation-specific limits, usage, typed errors, and immutable output.
- Internal generated-output parse/apply proof.
- Unit, integration, golden, property, fuzz, race, abuse, privacy, and package
  direction tests.
- Durable architecture and recipe package documentation needed by this work.

Out of scope:

- Message-Instance `r=` base64 encoding or field formatting.
- Deciding from Section 9.1 hashes whether a new Message-Instance is required.
- Incrementing `m=`, selecting hash algorithms, or constructing hash sets.
- DKIM2-Signature construction, private-key access, or cryptographic signing.
- Service, daemon, OpenAPI, CLI, Milter, Exim, datasource, replay-store, or
  observability integration.
- A minimal or globally optimal recipe, LCS, edit-distance, or compression
  optimization.
- MIME interpretation, encoded-word decoding, Unicode normalization, address
  rewriting, or EAI policy.
- Historical signature or policy evaluation.
- Transport rewriting from reconstructed internal state.

## Normative Draft-04 Interpretation

### Direction And Ownership

Generation is always inverse:

```text
previous/before/target <- apply(recipe, current/after/source)
```

API names, tests, and comments must use `previous` and `current` consistently.
A plan generated in the opposite direction is a protocol defect.

The generator describes one system's change as required by Section 9.1. It
does not decide whether the canonical hashes require a new Message-Instance;
that orchestration belongs to signing and revision work. A caller may therefore
generate directly for testing even when the later M10 hash gate would decide
not to create a new instance.

### Closed Success Outcomes

Generation returns one of two top-level success states:

- `unchanged`: no decoded JSON and no recipe object are present;
- `recipe`: one initialized immutable recipe and its decoded compact JSON are
  present.

There is no successful empty-object recipe. Draft-04 requires at least `h` or
`b`, so `{}` is invalid. If all relevant header groups and the body are
recipe-semantically unchanged, or only excluded headers changed, the result is
`unchanged`. This is compatible with the subset of Section 9.1 cases whose
hashes are also unchanged. Recipe-semantic whitespace or framing changes can
still be hash-neutral; the actual hash gate remains solely M10 ownership.

An unchanged dimension is omitted from a generated recipe. `h` is present only
when at least one relevant header name changed. `b` is present only when body
content or framing changed.

### Header Relevance

Draft-04 Section 5.1 says recipes should not be emitted for unsigned header
fields. Local restrictive policy tightens that `SHOULD NOT` into never
generating an excluded name. The generator must not maintain a second list. It
receives a narrow immutable signed-header relevance classifier whose production
implementation is owned by `lib/internal/canonical`.

The classifier covers the Section 4 exclusions plus the additional Section 6.2
exclusions, notably `Message-Instance` and `DKIM2-Signature`, as well as
`Delivered-To`, `X-*`, and all other draft-04 classes. The generator supplies
only validated canonical lowercase ASCII names and never exposes them through
errors or telemetry. The contract has explicit validation and fallible
classification; nil, typed-nil, zero, invalid, erroring, out-of-domain, or
nondeterministic classifiers fail closed. Each distinct sorted name is
classified for planning and reclassified before return; disagreement is an
opaque invariant error.

`lib/internal/recipe` owns the narrow consumer interface; it does not import
`lib/internal/canonical`. The canonical package exposes an immutable type whose
method set satisfies that interface without importing recipe. A cross-package
test proves that production wiring and the full exclusion table remain aligned.

### Header Change Semantics

Header names are grouped case-insensitively by canonical lowercase ASCII name.
Within one name, occurrences are numbered bottom-up as required by Section
5.1. Two occurrences match when their exact unfolded field-value bytes match.
Raw field-name case and physical folding are intentionally ignored; whitespace
remaining after unfolding is not compressed or normalized.

This rule is deliberately stronger than merely comparing a Section 6 header
hash. A hash-neutral raw presentation change does not by itself need a recipe,
but a whitespace change that remains after unfolding is a recipe-semantic
change. If another dimension causes a new Message-Instance, every changed
relevant group must have a recipe.

For each changed relevant name:

- absent `h[name]` would mean retain every current occurrence and is therefore
  forbidden;
- an empty step array means the previous state had no occurrences;
- a non-empty plan emits the previous occurrences in bottom-up order;
- every `c` range is positive, inclusive, ascending, and strictly after the
  preceding copy range;
- every `d` string is the exact previous unfolded field value, without CR or
  LF; the applier supplies the field name, colon, and CRLF.

The draft does not encode original placement between different header names.
Application therefore reconstructs deterministic canonical-name groups, as M8
already specifies. Success proves the exact bottom-up unfolded values within
each relevant name and Section 6 canonical equivalence. It does not claim raw
cross-name byte order and must never be used as a transport rewrite.

### Body Change Semantics

Body occurrences are logical lines ordered top-down, starting at one. Exact
matching includes line content and whether the line ends in CRLF. A copied
terminal unterminated line preserves its missing terminator. A `d` string
always gains CRLF during application.

Consequences:

- absent `b` means the body is recipe-semantically unchanged;
- `b:[]` reconstructs a delimited-empty previous body;
- `b:null` means the previous body cannot be recreated under an explicit
  caller-authorized unavailable policy;
- a copied unterminated source line may appear only as the final emitted item;
- an unmatched unterminated previous line cannot be represented by `d`;
- a `d` literal must be valid UTF-8 and must not contain CR or LF;
- other control octets are permitted when valid UTF-8 and RFC 8259-escaped;
- no MIME, character-set, line-ending, or Unicode normalization is allowed.

Binary or otherwise invalid-UTF-8 lines remain representable when an exact
monotone copy exists. If an unmatched target line is invalid UTF-8, or an
unmatched terminal target line lacks CRLF, body reconstruction is
unrepresentable.

### Explicit Body-Unavailable Policy

`b:null` is never an automatic recovery from cancellation, resource limits,
allocation failure, serialization failure, internal proof failure, or a
generic diff failure. Those conditions return a typed error and no partial
result.

The generation request carries a closed body-unavailable policy:

- reject unavailable, the secure default;
- allow unavailable when exact reconstruction is impossible under the draft
  representation or the selected copy-only disclosure policy.

Only the second policy may convert proven literal/framing unrepresentability or
a copy-only literal requirement to `b:null`. The result records a closed
non-sensitive reason code. It never
contains the rejected bytes. Header reconstruction has no null form: an
unrepresentable changed relevant header always fails closed, even when body
unavailability is allowed.

The request separately selects `copy-only` or `allow-literals`. Copy-only is
the secure zero value. Only the explicit `allow-literals` action authorizes
embedding previous content in outbound recipe JSON. Copy-only rejects a header
plan that requires `d`. A body plan that
requires `d` fails unless body unavailability is also explicitly allowed, in
which case it yields `b:null`. Allow-literals remains capped by the configured
literal-byte limit. Neither policy guesses whether content is secret.

An unmatched unfolded header value that is invalid UTF-8, contains CR/LF, or
cannot form one RFC 5322 field line within the existing raw-message limit is
unrepresentable unless a compatible source occurrence can be copied.

Initialized raw-message states already guarantee valid UTF-8 and CR/LF-free
unfolded values. M9 keeps that claim as rawmsg boundary evidence and does not
fabricate impossible states. A folded, valid header whose unfolded value cannot
fit one generated field line remains a reachable copy-or-fail case.

## Deterministic Conservative Algorithm

The required algorithm is non-minimal and linear or bounded near-linear. It
must not use LCS, edit distance, recursive backtracking, pairwise all-to-all
comparison, or any other unbounded quadratic strategy.

### Shared Matching Rule

For each ordered current source sequence, build an exact-key index from value
to ascending occurrence numbers. Map iteration is never used for output. For
each previous target item in output order:

1. Look up the exact key.
2. Select the earliest candidate strictly after the last selected copy range.
3. Consume candidates through a monotone per-key cursor.
4. Emit a copy item when the candidate is valid for framing.
5. Otherwise emit a data item, or apply the explicit unrepresentability rule.

A valid candidate is always copied before considering a literal. This greedy
rule is deterministic but does not claim globally minimal disclosure; an
all-literal shortcut is forbidden.

Header keys are exact unfolded value bytes within one canonical name. Body
keys include exact line bytes and terminator state. Exact byte-string keys are
permitted internally; they are protected message data and never leave the
operation.

Adjacent selected source occurrence numbers coalesce into one `c` range.
Adjacent target literals coalesce into one `d` step. A copy range and a data
step never reorder across each other. This fixes a single reproducible output
without claiming minimality.

### Header Planning

The generator forms the sorted union of canonical lowercase names from
previous and current states. It validates and classifies each name, skips
excluded names, and compares bottom-up exact unfolded sequences. Before return
it reclassifies the same ordered names and fails if any result differs.
Unchanged sequences are omitted.

Changed names are processed in ascending bytewise ASCII order. Matching uses
the shared earliest-monotone rule. The JSON object key is the canonical
lowercase name. Copy steps preserve a compatible current occurrence; data
steps reconstruct the previous unfolded value through M8 semantics. Empty
previous groups produce an empty array.

Header traversal uses a read-only `rawmsg` field view so validation can inspect
lengths and physical lines without hidden deep clones. The planner charges the
single owned unfolded-value copy before retaining it. Name sorting uses a
deterministic merge-sort bound that includes worst-case byte comparisons for
long common prefixes, scratch storage, and moves. Phase-specific checked work
bounds also cover every complete header-name scan performed by string-map
hashing, canonical validation, relevance classification, and group lookup.

### Body Planning

The generator first compares exact raw body bytes and framing. If equal, `b` is
omitted. Otherwise it plans logical lines top-down with the shared
earliest-monotone rule.

An exact terminal unterminated source line is copyable only when it is also the
last target item and no later output follows. Unmatched representable target
lines become data strings with their CRLF removed. Empty content followed by
CRLF is a valid empty data string and must remain distinct from an empty body.
Unrepresentable target lines follow the explicit body-unavailable policy.

Framing asymmetry is versioned evidence: previous header-only with current
delimited-empty is not representable by any `b` plan and may become `b:null`
only under explicit policy. Current header-only with previous delimited-empty
is representable as `b:[]`. The implementation must not collapse these states.

| Previous target | Current source | Body result |
| --- | --- | --- |
| Same content and framing | Same content and framing | omit `b` |
| Delimited empty | Header-only | `b:[]` |
| Header-only | Delimited empty | error, or `b:null` with explicit allow-unavailable |
| Changed body/framing | Any known body | bounded `c`/`d`, or explicit unavailable under the two policies |

### Complexity And Adversarial Duplicates

Every source item is indexed once, every target item is visited once, and every
candidate cursor moves only forward. Repeated identical headers or body lines
therefore do not create quadratic work. The implementation uses checked
integer arithmetic for counts, byte totals, occurrence numbers, and writer
preflight. Hash-only matching is insufficient unless exact bytes are compared
before acceptance; collisions must never change correctness.

## Deterministic Decoded JSON

M9 serializes the closed recipe model to decoded JSON only. M10 and
`lib/internal/instance` retain ownership of padded base64, the `r=` tag,
Message-Instance folding, and full field formatting.

The byte representation is fixed:

- compact JSON with no insignificant whitespace or trailing newline;
- root member order `h`, then `b`;
- header keys in ascending bytewise canonical lowercase ASCII order;
- step order exactly plan order;
- one-property step objects with key `c` or `d`;
- copy integers in canonical base-10 without leading zeroes;
- `b:null` only for the explicit unavailable result;
- no map-order dependence.

String escaping is a package-owned RFC 8259 policy:

- reject invalid UTF-8 before sizing or writing; never replace it with U+FFFD;
- escape quotation mark and reverse solidus as `\"` and `\\`;
- use `\b`, `\t`, and `\f` for those control scalars;
- CR and LF are rejected in data literals rather than serialized;
- encode other U+0000 through U+001F scalars as lowercase `\u00xx`;
- emit every other valid UTF-8 scalar directly, including `<`, `>`, `&`, and
  U+2028/U+2029;
- perform no Unicode normalization and no HTML escaping.

The serializer uses either an exact checked preflight followed by one bounded
write or a bounded writer that checks every append. It must not call
`encoding/json` into an unbounded buffer and inspect size afterward. Every
delimiter, key, escaped scalar, digit, and literal contributes incrementally to
output and work usage. Output exceeding the M8 decoded-recipe limit returns a
typed limit error with no bytes.

## Domain Model And API Shape

The implementation uses cohesive immutable receiver types. Exact names may be
refined during the first prompt, but the behavior must remain equivalent to:

```go
type HeaderRelevance interface {
    Validate() error
    IsRelevantHeader(nameLower string) (bool, error)
}

type BodyUnavailablePolicy uint8
type LiteralDisclosurePolicy uint8

const (
    CopyOnly LiteralDisclosurePolicy = iota
    AllowLiterals
)

const (
    RejectUnavailableBody BodyUnavailablePolicy = iota
    AllowUnavailableBody
)

type GenerationRequest struct {
    Previous              State
    Current               State
    BodyUnavailablePolicy BodyUnavailablePolicy
    LiteralPolicy         LiteralDisclosurePolicy
}

type Generator struct { /* immutable validated value */ }

func NewGenerator(limits GenerationLimits, relevance HeaderRelevance) (Generator, error)
func (g Generator) Generate(request GenerationRequest) (Generation, GenerationUsage, error)
```

Both input states must be initialized and must contain known bodies. A prior
`b:null` state cannot be used as a generation target or source. A nil or
typed-nil relevance dependency, zero-value generator, invalid closed enum,
invalid limits, or uninitialized state fails closed.

`Generation` is a closed immutable value with methods that distinguish
unchanged from recipe success. Recipe objects and decoded JSON returned by
accessors are copies or immutable views whose backing storage cannot be
mutated by callers. A recipe result also exposes a closed body outcome of
unchanged, generated, or explicitly unavailable and, for unavailable only, a
closed reason. The unchanged result has neither recipe nor JSON.

Generation does not accept or emit raw RFC 5322 messages as byte slices; it
consumes the already validated M8 state/raw-message model. It does not expose
parser internals or maps. The same initialized `Generator` may be reused safely
by concurrent callers and holds no per-operation mutable state.

## Internal Proof Before Success

A recipe result is not returned merely because planning and serialization
succeeded. The generator must perform this bounded self-check on the exact
generated bytes:

1. Parse the bytes with the existing strict M8 parser under the same limits.
2. Construct the returned `Generation.Recipe` from that exact parsed model,
   never from a separate pre-serialization plan.
3. Apply the parsed recipe to the current state with the existing M8 applier.
4. For every relevant header name, compare bottom-up exact unfolded values
   with the previous state.
5. For a known generated or unchanged body, compare exact body bytes, line
   terminators, and final framing with the previous state.
6. For an unavailable body, prove the reconstructed state reports body
   unavailable and do not claim body equality.
7. Through cross-package integration tests, prove the reconstructed known
   dimensions yield the same Section 6 canonical input and hashes.

This stronger recipe-semantic proof implies canonical equivalence for known
dimensions while explicitly tolerating only the draft's missing cross-name
header placement information. Any internal parse, apply, or comparison failure
is an invariant error with zero result and zero output bytes. Generated output
must never require relaxed parser or applier limits.

## Package Boundaries

`lib/internal/recipe` owns:

- generation request, result, body policy, and usage types;
- deterministic header and body planning;
- representability classification;
- compact decoded-JSON serialization;
- generated-output parse/apply proof;
- recipe-generation error mapping and resource accounting.

`lib/internal/rawmsg` remains the only owner of:

- validated RFC 5322 header bytes and unfolded values;
- logical body lines and terminator state;
- header, body, line, and framing limits.

`lib/internal/canonical` remains the only owner of:

- Section 4 plus Section 6.2 signed-header relevance classification;
- Section 6 canonical input and hash semantics;
- the immutable production implementation of the recipe-owned relevance
  interface.

`lib/internal/instance` remains the only owner of:

- padded base64 encoding and decoding for `r=`;
- Message-Instance tag ordering, folding, numbering, and formatting.

M10 signing/revision orchestration will own canonical hash comparison, the
decision to add an instance, `m=` progression, hash-set construction, and
signature creation. No `cmd/` module, OpenAPI DTO, service type, crypto key, or
observability runtime enters `lib/internal/recipe`.

Package-direction tests must continue to reject production recipe imports of
instance, canonical, verify, service, command, OpenAPI, Cobra, Viper, Fx,
Prometheus, or OTLP packages. Integration tests may import recipe and canonical
from an external test package.

## Limits And Usage

Generation uses a dedicated immutable `GenerationLimits` value rather than
overloading M8 parse/apply counters with misleading meanings:

```go
type GenerationLimits struct {
    RecipeLimits          Limits
    MaxInputBytes         int
    MaxInputItems         int
    MaxCandidateEntries   int
    MaxCandidateKeyBytes  int
    MaxComparisons        int
    MaxGenerationWorkUnits int
}
```

`RecipeLimits` is normalized and validated by M8 and bounds generated names,
steps, ranges, copies, strings, literal bytes, JSON bytes, reconstructed items,
and internal parse/apply proof. Generation adds only counters whose meaning M8
does not already express.

For `DefaultLimits()`, the zero-value generation fields resolve to these exact
defaults and hard maxima:

| Field | Default and hard maximum | Derivation |
| --- | ---: | --- |
| `MaxInputBytes` | 67,108,864 | `2 * MaxStateBytes` |
| `MaxInputItems` | 135,072 | `2 * (MaxHeaderFields + MaxBodyLines)` |
| `MaxCandidateEntries` | 67,536 | `MaxHeaderFields + MaxBodyLines` for current source |
| `MaxCandidateKeyBytes` | 33,554,432 | one `MaxStateBytes` source index |
| `MaxComparisons` | 135,072 | target lookups plus monotone candidate advances |
| `MaxGenerationWorkUnits` | 268,435,456 | finite aggregate ceiling for scans, plans, output, and proof |

`DefaultGenerationLimits()` returns `DefaultLimits()` plus that table.
Normalization first resolves `RecipeLimits`, then derives zero values for the
first five generation fields using the table formulas and checked arithmetic.
Zero `MaxGenerationWorkUnits` resolves to 268,435,456. Derivation never uses
attacker-provided unvalidated values. Negative values, values above the table's
hard maxima, multiplication/addition overflow, or incoherent combinations are
invalid options. Nonzero values may narrow but never widen a derived bound.

Coherence requires `MaxInputBytes <= 2*MaxStateBytes`,
`MaxInputItems <= 2*(MaxHeaderFields+MaxBodyLines)`,
`MaxCandidateEntries <= MaxHeaderFields+MaxBodyLines`,
`MaxCandidateKeyBytes <= MaxStateBytes`, and
`MaxComparisons <= MaxInputItems`. The aggregate work limit is independently
bounded by its hard maximum and must be at least the checked sum
`MaxInputBytes + MaxCandidateKeyBytes + MaxComparisons +
2*MaxDecodedRecipeBytes + 2*MaxOperationWorkUnits`; otherwise construction
fails. Literal disclosure uses `RecipeLimits.MaxTotalLiteralBytes`, so
allow-literals is always capped.

`GenerationUsage` is immutable and uses semantic counters such as input bytes
and items examined, candidates retained, comparisons, generated steps and
literals, JSON bytes, proof work, and aggregate work. Usage is returned on
success and typed failure so tests and callers can explain bounded behavior
without receiving protected content. Counter accessors contain numbers only.

Every input byte/item scan, exact comparison, retained key byte, candidate
entry, plan append, JSON sizing operation, JSON append, parse proof, apply
proof, and semantic reconstruction proof is charged before the action or
allocation. Parser and applier each retain their full operation cap; semantic
proof work is charged separately to the aggregate generation limit. All
arithmetic is checked. Hitting a limit fails before exceeding it and returns
no partial plan, recipe, or JSON.
Recipe-wide step, copy-range, copied-item, data-string, and literal-byte totals
belong to one operation-owned planning budget shared by header and body
planning; dimension planners never reset those totals.

## Error Contract

Generation extends the existing recipe error family with the smallest closed
set of codes needed for:

- invalid generator, request, policy, state, or limits;
- relevant-header unrepresentability;
- body unrepresentability under the default policy;
- generation limit or checked-arithmetic failure;
- deterministic serialization failure;
- generated-output parse/apply invariant failure;
- reconstruction mismatch.

Existing error classes are reused where their public semantics fit. Body
unavailability allowed by policy is a success outcome, not an error. Errors
remain compatible with `errors.Is`/`errors.As`, contain bounded static English
messages, and never contain header names, values, body bytes, JSON, source
indexes, hashes, message identifiers, recipients, or exception text from a
content-bearing callback.

No failure returns a usable `Generation`, `Recipe`, plan, state, or JSON byte
slice. Internal invariant failures are fail-closed production errors, not
panics. Test-only diagnostics may identify vector names but must not dump toxic
fixture content.

## Security And Privacy

- The secure default rejects unrepresentable body state; `b:null` requires an
  explicit request policy.
- Relevant header reconstruction never degrades to omission or null.
- Limits, cancellation if later introduced, allocation errors, and invariant
  failures never degrade to `b:null`.
- The algorithm is monotone and bounded against repeated-item and candidate
  bombs.
- Invalid UTF-8 is rejected before JSON serialization and never replaced.
- The generated decoded JSON is protected message data because it can contain
  header values and body lines.
- Base64 is not confidentiality. Returned recipes and JSON are content-bearing
  protocol output, never diagnostics. Each `d` literal re-embeds removed
  previous header or body content in the outbound `r=` payload. Copy-only
  callers fail rather than embed a required header literal; body null still
  requires its separate opt-in.
- Source and target states, exact-match keys, generated plans, JSON, hashes,
  header names, values, body content, recipients, and message identifiers must
  not appear in logs, traces, metrics, REST/CLI output, errors, panic strings,
  benchmark names, or ordinary test failures.
- Accessors clone protected byte slices. Caller mutation cannot alter a result
  or future serialization.
- There is no package-level mutable state, shared scratch buffer, or cached
  message-derived key.
- Concurrent generator reuse must pass race tests.
- No lossy normalization, replacement character, fallback parser, or relaxed
  line limit is accepted as a fix.

## Observability

This milestone adds no production logs, metrics, spans, exporters, or debug
switches. If a later integration records generation behavior, it may expose
only closed result/error classes and bounded numeric usage. Raw header names,
values, body data, decoded JSON, source indexes, and raw errors are forbidden
as attributes or labels. Metrics labels remain on the central low-cardinality
allowlist.

## Required Tests

### Unit Tests

- Constructor, zero-value, nil dependency, invalid state, invalid policy, and
  immutable accessor tests.
- Closed unchanged result for identical states and changes limited to every
  Section 4 or Section 6.2 excluded class.
- Header add, delete, replace, duplicate, case-only name, physical folding,
  unfolded whitespace, empty value, and mixed copy/data vectors.
- Bottom-up numbering, earliest monotone selection, adjacent copy coalescing,
  adjacent data coalescing, sorted header keys, and deterministic repetition.
- Copy-first, copy-only, bounded allow-literals, and non-minimal-disclosure
  vectors; toxic literals appear only in successful returned output when
  required and never in errors or ordinary test failure text.
- Empty previous header group encoded as an empty array; unchanged relevant
  groups omitted.
- Rawmsg boundary tests prove initialized states cannot contain invalid-UTF8 or
  CR/LF-bearing unfolded values; the reachable valid-folded but overlong value
  without a copy fails closed without content disclosure.
- Body insertion, deletion, replacement, duplicate lines, empty body, one
  empty CRLF line, trailing empty lines, and final unterminated line vectors.
- Both framing asymmetries: header-only target from delimited-empty source is
  unavailable-only; delimited-empty target from header-only source uses `b:[]`.
- Copyable binary body data succeeds through `c`; unmatched invalid UTF-8 and
  unmatched unterminated data fail by default and yield `b:null` only with the
  explicit policy.
- Prove `b:null` is not used for limit, arithmetic, writer, parse, apply, or
  invariant failures.
- Exact compact JSON goldens for root ordering, sorted header keys, step order,
  integers, quotes, reverse solidus, allowed controls, direct UTF-8, and no HTML
  escaping.
- A legal RFC 5322 field name containing JSON-sensitive quote and backslash
  bytes is escaped as an `h` object key and survives strict parse/apply.
- Invalid UTF-8 rejection before preflight/write and no U+FFFD replacement.
- Exact and one-over tests for every generation and inherited M8 limit,
  including output bytes, names, steps, ranges, copies, literals, candidates,
  comparisons, retained bytes, scanned input, and proof work.
- Repeated identical header/body bombs, adversarial interleaving, many unique
  keys, very long lines, maximum field/line counts, and checked-overflow tests.
- Failure atomicity, cloned input/output, initialized-state invariants, and
  repeated/concurrent generator reuse.
- Error-code/class and toxic-marker privacy tests.

### Integration And Property Tests

- `Generate -> JSON -> Parse -> Apply` reconstructs exact relevant bottom-up
  unfolded header sequences and exact known body bytes/framing.
- Canonical integration proves reconstructed known dimensions have the same
  Section 6 canonical inputs and hashes as previous.
- Cross-name header ordering is explicitly tested as canonical-equivalent
  internal state and never asserted as a raw transport rewrite.
- Canonical's production relevance implementation excludes the complete
  draft-04 Section 4 and Section 6.2 sets without a duplicate recipe table;
  nil, typed-nil, zero, invalid, erroring, and nondeterministic test
  implementations fail closed without content-bearing errors.
- Generated plan and JSON remain accepted under the exact same parser/applier
  limits used for generation.
- Repeated generation of the same states yields byte-identical JSON across
  runs, map allocation perturbation, and concurrent execution.

### Versioned Golden And Fuzz Evidence

Retain draft-04 fixtures under the recipe package testdata. Each fixture names
the draft version and includes previous/current input, literal-disclosure
policy, body-unavailable policy, expected closed outcome, exact JSON when
present, reconstructed semantic state, and expected canonical evidence without
embedding real operational data.

Stable fuzz targets must cover at least:

- deterministic generation and serialization from bounded raw-message pairs;
- `Generate -> Parse -> Apply` reconstruction invariants;
- header duplicate/case/folding and body terminator/framing combinations;
- invalid UTF-8 and explicit unavailable-policy behavior;
- repeated-item candidate distributions and limit edges.

Fuzz assertions include no panic, no partial output on error, output within
limits, accepted parser/applier round-trip on success, byte-identical repeated
serialization, exact semantic reconstruction for known dimensions, and no
toxic marker in errors. Retained seeds cover every normative interpretation.
Race tests exercise shared generator reuse and immutable result access.

### Documentation And Dependency Checks

- Recipe package documentation describes inverse direction, deterministic
  non-minimal output, explicit unavailable policy, and decoded-JSON ownership.
- Architecture remains aligned with the canonical relevance seam and M10
  boundary.
- Dependency tests prove recipe production code does not import canonical,
  instance, verify, service, command, OpenAPI, or runtime-only packages.
- `temp/` remains ignored and unstaged.

### Validation Commands

Focused commands are expected to include:

```sh
go test ./lib/internal/recipe/... ./lib/internal/rawmsg/... ./lib/internal/canonical/...
go test -race ./lib/internal/recipe/... ./lib/internal/canonical/...
go test ./lib/internal/recipe -run '^$' -fuzz '^FuzzGenerateRecipe$' -fuzztime=10s
go test ./lib/internal/recipe -run '^$' -fuzz '^FuzzGeneratedRecipeRoundTrip$' -fuzztime=10s
git diff --check
make guardrails
```

Prompt implementation must prefer repository `make` targets when an equivalent
target exists. The final required gate is `make guardrails`.

## Acceptance Criteria

- The inverse direction is explicit and executable: applying generated output
  to current reconstructs previous recipe semantics.
- All-unchanged and excluded-only changes return the closed unchanged outcome,
  never `{}`.
- Every changed relevant header name has a valid recipe or generation fails;
  there is no header-null or silent omission.
- Canonical-owned Section 4 plus Section 6.2 relevance is injected through one
  validated fallible interface and no unsigned-header table is duplicated.
- Header matching uses exact unfolded values; body matching preserves exact
  bytes, terminators, and framing.
- Earliest monotone matching, coalescing, sorting, compact escaping, and fixed
  member order produce byte-identical output.
- Invalid UTF-8 is never replaced or normalized.
- `b:null` occurs only for proven body representation/disclosure impossibility
  under the explicit allow policy.
- Every scan, comparison, retained key, plan item, output byte, and proof step
  is bounded and charged with checked arithmetic.
- Generated bytes fit the same M8 limits and pass internal strict parse/apply
  proof before success.
- Results and accessors are immutable and concurrent-safe.
- Tests cover round-trip, canonical equivalence, exact output, exact/one-over
  limits, abuse, fuzz, race, privacy, and dependency direction.
- No M10 signing, Message-Instance formatting, base64, or service behavior is
  introduced.
- `make guardrails` passes on the exact final implementation snapshot.
- Two independent reviewers approve that unchanged snapshot: one for live
  draft/RFC/mail conformance and one for architecture/security/test quality.
- Exactly one project-conformant commit records the complete milestone after
  both approvals; no intermediate milestone commit is created.
- `temp/` is ignored and never staged.

## Completion Evidence

- Focused tests: recipe, rawmsg, canonical, and complete library tests passed on
  the durable content-freeze candidate.
- Generated golden checks: retained serializer and reachable generation
  fixtures for draft-04 pass strict inventory, policy, reconstruction, and
  canonical-evidence validation.
- Fuzz smoke: `FuzzGenerateRecipe` and `FuzzGeneratedRecipeRoundTrip` each
  passed retained-seed validation and a final run of at least 10 seconds.
- Race tests: shared generator reuse, immutable result access, recipe, and full
  repository race targets passed.
- Guardrails: `make test`, `make vet`, `make lint`, and `make race` passed. The
  network-capable `make guardrails` passed formatting, vet, lint, tests, race,
  OpenAPI checks, and every module's vulnerability scan with no vulnerabilities
  found.
- Exact approved snapshot hash: pending root freeze after closeout gates; the
  hash is reported out of band to avoid a self-referential document hash.
- Independent draft/RFC approval: every implementation slice through abuse and
  privacy proof is approved; final exact-snapshot approval is pending freeze.
- Independent architecture/security approval: every implementation slice
  through abuse and privacy proof is approved; final exact-snapshot approval is
  pending freeze.
- Worktree proof: tracked and untracked durable changes are unstaged,
  `git diff --check` and `git diff --cached --check` pass, the cached name list
  is empty, and the timing ledger and prompt pack remain ignored.
- Final milestone commit: pending both exact-snapshot approvals; no intermediate
  commit exists.
- Measured effort: the seven retained spans through durable content freeze total
  3h35m01s. Active engineering time was not separately tracked.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Recipe generation and decoded JSON only | Implemented without command, service, signing, or Message-Instance formatting behavior | done | M10 deferments remain explicit |
| Draft-04 | Sections 4, 5, 6, 7.2, and 9.1 interpretations pinned | Versioned fixtures and live primary-text review | done; final hash review pending | No later-draft behavior inferred |
| Direction | Current source reconstructs previous target | Executable strict parse/apply/semantic self-proof | done | Opposite direction fails retained evidence |
| Determinism | Earliest monotone, coalesced, sorted, fixed JSON | Byte-exact goldens, repeated generation, fuzz, and race proof | done | Non-minimal by design |
| Representability | Header fail-closed; body null only explicit | Closed policy and reason types with framing/literal tests | done | No limit/error fallback |
| Boundaries | Recipe owns JSON; instance/M10 own base64 and signing | Recursive dependency guard and external canonical integration | done | Canonical relevance is injected |
| Security | Bounded, immutable, secret-safe, no lossy normalization | Exact/one-over, overflow, bomb, privacy, and toxic-marker evidence | done | Errors are bounded and secret-safe; no logging, metrics, tracing, CLI, or REST sinks exist |
| Tests | Round-trip, limits, abuse, fuzz, race, privacy | Stable named targets, retained normative seeds, and final full reruns | done | Same parser/applier limits |
| Effort | Prompt timings retained | Seven exact spans through durable content freeze | done | No inferred timestamps or active-time claim |
| Closeout | Guardrails, two approvals, exactly one commit | Documentation and final gates done; freeze/reviews/commit remain | in progress | Exact unchanged snapshot required |

## Decisions And Open Questions

- Settled: the draft baseline is exactly `draft-ietf-dkim-dkim2-spec-04`.
- Settled: generation is inverse from current/after source to previous/before
  target.
- Settled: output is deterministic, conservative, and non-minimal.
- Settled: header equality is exact unfolded value equality by name; body
  equality includes framing; cross-name raw placement is not claimed.
- Settled: canonical owns relevance; recipe keeps no exclusion list.
- Settled: unchanged has no recipe; body null is explicit, never a fallback.
- Settled: M9 owns decoded JSON; instance and M10 own base64 and formatting.
- Settled: generated bytes pass the same M8 parse/apply limits before return.
- Settled: guardrails and two approvals precede the one milestone commit.
- Open: no protocol or architecture question blocks final closeout.

## Explicit Deferments

- Section 9.1 canonical hash gating and the decision to create a new instance.
- Message-Instance generation, padded base64, `r=` placement, and folding.
- `m=` progression, hash-set selection, and originator versus Reviser workflow.
- DKIM2-Signature construction, signing input, key handles, and crypto.
- Public library/service APIs and all command-module adapters.
- Minimal/global diff optimization and recipe compression.
- External interoperability claims beyond retained draft-04 vectors.

Any deferred behavior requires its own durable specification or an explicit
reviewed amendment before implementation.
