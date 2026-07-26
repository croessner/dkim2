# DKIM2 Recipe Application

## Status

- Increment: strict recipe parsing, bounded previous-message reconstruction,
  and previous-instance hash validation.
- Protocol baseline: `draft-ietf-dkim-dkim2-spec-04`, especially Sections 2,
  5, 6, 7.2, 9.1, 10.2, and 11.7.
- Architecture owners: `lib/internal/recipe` for recipe syntax and
  reconstruction, `lib/internal/rawmsg` for RFC 5322 bytes, and
  `lib/internal/canonical` for hash input and SHA-256.
- Status: implementation completed with focused, fuzz, race, and repository
  proof; unchanged-snapshot approvals are recorded in the final handoff and the
  single increment commit remains pending for the root maintainer.
- Commit: the single increment commit containing this document and the
  completed implementation.

## Purpose

This increment makes the optional `r=` value of a parsed Message-Instance
useful without weakening any existing parser, raw-message, canonicalization,
or verification invariant. It strictly parses the decoded RFC 8259 JSON
object, applies header and body recipes to the current controlled message
state, and validates the reconstructed previous state against the previous
Message-Instance hash set.

Recipe application is an inverse operation. A recipe carried by Message-
Instance `m=n` describes how to reconstruct `m=n-1` from the state represented
by `m=n`. It is not a generic JSON transformation language and it never edits
the caller's message in place.

The implementation is deliberately conservative. Malformed, duplicate,
ambiguous, out-of-range, or over-limit recipe input fails closed. A body-null
recipe is a truthful declaration that the previous body is unavailable; it is
not a malformed recipe and it does not fabricate empty body bytes. Header-null
recipes and the earlier `z` step do not exist in draft-04 and are rejected.

## Normative Sources And Precedence

The binding sources are, in order:

1. `draft-ietf-dkim-dkim2-spec-04`, Sections 2 and 5, for RFC 8259 use, unknown
   JSON-field handling, the recipe-v1 schema, header occurrence numbering,
   body line numbering, copy and data steps, and null-body meaning.
2. `draft-ietf-dkim-dkim2-spec-04`, Sections 6, 7.2, 9.1, 10.2, and 11.7, for
   the relation between a Message-Instance recipe and its previous state,
   base64 ownership, meticulous validation, and hash checking.
3. RFC 8259 for JSON text syntax, Unicode escapes, duplicate-member
   interoperability concerns, and UTF-8 interchange.
4. RFC 5322 for header field-name and field-body syntax and logical folded
   header fields.
5. RFC 6376 only where draft-04 explicitly inherits simple body
   canonicalization behavior.
6. `POLICY.md` and `docs/ARCHITECTURE.md` for immutable raw-message ownership,
   fail-closed ambiguity handling, bounded resource use, typed errors, package
   boundaries, and secret-safe diagnostics.

Later draft revisions must update this durable document and draft-versioned
tests before protocol behavior changes.

### Recorded Draft-04 Interpretations

The following interpretations are explicit, testable, and versioned to
draft-04:

- The JSON schema is normative alongside the surrounding prose. Unknown
  members are ignored only where the schema permits them. Top-level members
  other than `h` and `b` are ignored. A recipe step still has exactly one
  recognized key and `additionalProperties: false`, so an unknown step key or
  an extra member in a `c` or `d` step is invalid rather than an extension.
- Every JSON object is scanned for duplicate member names before semantic
  decoding or unknown-member removal. RFC 8259 calls duplicate behavior
  unpredictable; repository policy resolves it by rejecting duplicates,
  including duplicate unknown top-level members. This prevents parser choice
  or member ordering from changing authenticated behavior.
- Header-name keys are additionally unique under ASCII case-insensitive
  comparison, as draft-04 explicitly requires. `Subject` and `subject` in the
  same `h` object are therefore invalid even though their JSON spellings differ.
- Only `b:null` is a valid null recipe. Draft-04 removed header-null recipes.
  `h:null`, a null per-header recipe, a null step, and a null literal are
  malformed.
- Draft-04 removed the earlier `z` body step. Any `z` member is an unknown
  step key and fails the closed step schema.
- An absent `h` means the header state is unchanged. Within a present `h`, an
  absent header-name key retains every current occurrence of that name, while
  an empty recipe array removes every occurrence of the named field.
- An absent `b` means the body state is unchanged. An empty `b` array produces
  an empty reconstructed body. This differs from `b:null`, which means the
  previous body cannot be reconstructed.
- A recipe with neither `h` nor `b` is invalid even if it contains recognized
  extension members; the schema requires at least one of `h` or `b`.
- A `c` range is inclusive, uses positive one-based indexes, and must have
  `start <= end`. Draft wording that says “start to end” plus schema bounds is
  implemented as a non-empty forward range. Starts of later `c` steps must be
  strictly greater than the end of every preceding `c` step in that same
  per-header or body recipe, even when `d` steps intervene.
- A header `c` step copies the complete original bytes of each selected
  logical header occurrence, including its original field-name casing,
  folding, and terminal CRLF. Logical numbering ignores physical continuation
  lines and runs bottom-up independently for each case-insensitive name.
- Header recipe output is accumulated in bottom-up emission order. The final
  physical top-down order for a name is its reverse, so later emitted fields
  appear above earlier emitted fields as draft-04 requires. A `d` array is
  processed from its first string to its last under that same rule.
- A header `d` string becomes the recipe key spelling, a colon, the decoded
  string's UTF-8 bytes, and CRLF. No space is inserted. Empty string therefore
  produces `Name:\r\n`. CR or LF in a decoded string is invalid.
- Body lines are numbered top-down. A `c` step preserves the selected line
  bytes and its existing CRLF termination. Because rawmsg permits an
  unterminated line only at the end, copying an unterminated source line is
  valid only when it is the final reconstructed output line; otherwise
  application fails closed. A `d` line always ends in CRLF. This byte-fidelity
  interpretation is locked by draft-versioned tests because draft-04 does not
  state the copied unterminated-line case explicitly.
- JSON strings are RFC 8259 Unicode strings. Valid UTF-8 and valid escaped
  Unicode are decoded to their UTF-8 octets. Invalid UTF-8, unpaired UTF-16
  surrogates, decoder replacement, and CR/LF in data strings are rejected.
  RFC 8259 noncharacters remain valid. No MIME, EAI, Unicode
  normalization, or IDNA semantics are invented.
- JSON object member order has no protocol meaning. Draft-04 defines header
  reconstruction separately per case-insensitive name, and Section 6.2 sorts
  names before hashing; it does not define original placement between
  different names. The implementation produces a deterministic hash-equivalent
  header representation: case-insensitive name groups are ordered by canonical
  lowercase ASCII name, with the required top-down occurrence order inside
  each group. It never claims to recover the original cross-name byte order.
- A Message-Instance `r=` value is already strictly base64-decoded by
  `lib/internal/instance`. `lib/internal/recipe` accepts only the cloned decoded
  JSON bytes. It does not parse tag lists or base64 again.
- For `m>1`, absent `r=` violates the Section 9.1 carriage requirement and
  prevents reconstruction. It is not inferred to be an identity transition.
- A recipe on `m=1` may describe a pre-DKIM2 state, as draft-04 permits, but
  no Message-Instance `m=0` exists whose hashes can authenticate it. The parser
  and applier accept it for explicit callers; normal previous-instance hash
  validation stops at `m=1` and makes no authenticated claim about prehistory.
- Null or unavailable historical body state is separate from malformed input,
  mismatch, and the existing current four-state verification truth. This
  increment does not rewrite a current `PASS` into another state merely because
  an older signer truthfully declared `b:null`. Public full-history policy and
  historical signature truth remain outside this increment.

## Scope

### In Scope

- A strict, duplicate-aware RFC 8259 parser for decoded recipe JSON.
- The exact draft-04 recipe-v1 object shape for `h`, `b`, `c`, and `d`.
- Ignoring bounded unknown top-level members without retaining their values.
- Case-insensitive header-key collision rejection.
- Immutable recipe, step, limit, result, and typed-error values.
- Header recipe application with bottom-up occurrence numbering.
- Body recipe application with top-down line numbering.
- Explicit known and unavailable body reconstruction states.
- Deterministic, hash-equivalent cross-name header ordering.
- Identity behavior for an absent dimension inside a present recipe.
- Previous Message-Instance SHA-256 header/body hash validation coordinated by
  verify through the existing canonicalizer.
- Iterative bounded reconstruction from a current state toward earlier
  Message-Instance numbers for internal verification coordination.
- Draft-versioned examples, golden tests, negative tests, property tests,
  fuzzing, abuse tests, immutability tests, privacy tests, and race tests.

### Out Of Scope

- Recipe generation, minimization, normalization, or serialization; these
  belong to the next increment.
- Header-null recipes, `z` steps, or compatibility with recipe schemas from
  draft-00 through draft-02.
- Recovering or claiming original ordering between different header names.
- Inventing MIME, encoded-word, charset, Unicode normalization, EAI, or IDNA
  behavior.
- Verifying historical DKIM2 signatures, authenticating historical flags, or
  completing public chain-of-custody policy facts.
- Replacing the current public verifier's four-state result or current-scope
  claim with a full-history result.
- DSN construction or propagation, signing/revising, replay storage,
  datasource providers, daemon/OpenAPI, CLI, Milter, Exim, or observability
  exporter work.
- Logging raw recipes, JSON strings, header values, body lines, reconstructed
  messages, hashes, signatures, domains, selectors, or recipient data.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 3 to 8 focused agent-hours |
| Highest-risk area | Draft-04 recipe ambiguity, bounded reconstruction, and authenticated historical-content integration |
| Expected prompt count | 7 |
| Required final gate | `make guardrails` plus four named 10-second fuzz targets |

Measured evidence is preserved without reconstructing missing start times. The
ignored ledger at `temp/recipe-application-prompts/index.md` is the detailed
timing source; this durable rollup records only evidence suitable for the
project history.

| Prompt | Started At | Completed At | Wall-Clock Duration | Notes |
| --- | --- | --- | --- | --- |
| 01 | 2026-07-11T16:52:11+02:00 | 2026-07-11T17:11:27+02:00 | 19m16s | Exact retained span |
| 02 | 2026-07-11T17:16:32+02:00 | 2026-07-11T17:51:31+02:00 | 34m59s | Exact retained span |
| 03 | unavailable | 2026-07-11T18:13:44+02:00 | unavailable | Exact final approval time retained; start was not retained |
| 04 | unavailable | 2026-07-11T18:38:38+02:00 | unavailable | Exact final approval time retained; start was not retained |
| 05 | unavailable | 2026-07-11T19:21:29+02:00 | 41m50s retained handoff duration | Start was not retained; duration is contemporaneous best-available evidence, not a reconstructed timestamp pair |
| 06 | 2026-07-13T08:59:34+02:00 | 2026-07-13T09:33:21+02:00 | 33m47s | Exact final unchanged-hash approval closes the span |
| 07 | 2026-07-13T09:36:17+02:00 | 2026-07-13T09:52:19+02:00 | 16m02s measured closeout span | Formal capture began after initial hash/read-first bootstrap; the earlier interval is not inferred |

An exact M8 total cannot be calculated because Prompt 03 and Prompt 04 starts
were not retained and Prompt 05 has no retained start. The available evidence
therefore cannot prove or refute the original 3-to-8-hour estimate. This is a
measurement limitation only; implementation, tests, guardrails, and review
evidence are complete.

## Package And Dependency Boundaries

`lib/internal/recipe` owns:

- Recipe limits and their validation.
- Duplicate-aware JSON structural scanning and semantic decoding.
- Immutable `Recipe`, header recipe, body recipe, and closed step types.
- Schema validation, header-name collision validation, range ordering, and
  literal validation.
- Application to a controlled current state and deterministic reconstruction.
- Known/unavailable dimension state and bounded reconstruction metadata.
- Recipe-specific typed errors and stable error codes.

`lib/internal/rawmsg` remains the sole owner of:

- Valid RFC 5322 header field construction.
- Header occurrence bytes and logical field boundaries.
- Body bytes and line indexing.
- Strict CRLF policy and controlled immutable message construction.

Recipe code must use exported rawmsg constructors or a narrow new rawmsg
builder that validates the same invariants. It must not populate rawmsg
unexported fields, fork the RFC 5322 parser, or weaken its line limits.

`lib/internal/canonical` remains the sole owner of:

- Section 6.1 body hash canonicalization.
- Section 6.2 header hash canonicalization and ignored-header rules.
- Hash algorithm selection and SHA-256 digest construction.

Recipe code never reimplements header exclusions, name sorting, WSP handling,
terminal-empty-line handling, or SHA-256. Verify-owned previous-instance
validation calls the canonical package over a known reconstructed dimension.

`lib/internal/instance` continues to own Message-Instance tag parsing,
strict padded base64string validation, hash-set parsing, and immutable decoded
`r=` storage. It gains no JSON schema knowledge. It owns one
`SHA256HashSet()` selection method used by both current and historical
verification. The parser already rejects duplicate algorithm names, so this
method returns exactly one known SHA-256 set, `unsupported` for unknown-only
sets, or `missing` when no SHA-256 set exists without any unknown set.

`lib/internal/verify` exclusively owns Message-Instance adjacency, authenticated
descent, shared hash-set selection consumption, canonical hash comparison,
context cancellation, and history-transition results. Recipe never imports
instance, canonical, or verify. `lib/internal/service` and the public root
facade keep their current result mapping in this increment.

No command module, root public API, OpenAPI type, Milter type, datasource type,
configuration framework, telemetry exporter, or additional external
dependency enters `lib/internal/recipe`.

## Domain Model And Conceptual API

These additive internal names and ownership seams are fixed:

```text
recipe.NewParser(recipe.Limits) -> recipe.Parser or error
recipe.Parser.Parse(decodedJSON []byte)
  -> (recipe.Recipe, recipe.Usage, error)

recipe.Recipe:
  HasHeaderRecipe() -> bool
  HeaderNames() -> cloned deterministic metadata only
  BodyMode() -> recipe.BodyModeAbsent | Steps | Unavailable

recipe.NewState(rawmsg.Message) -> recipe.State or error
recipe.State:
  Headers() -> cloned known rawmsg.HeaderBlock
  BodyState() -> recipe.BodyAvailabilityKnown | Unavailable
  Body() -> cloned rawmsg.Body only when known
  Materialize() -> rawmsg.Message only when body is known

recipe.NewApplier(recipe.Limits) -> recipe.Applier or error
recipe.Applier.Apply(current recipe.State, plan recipe.Recipe)
  -> (recipe.State, recipe.Usage, error)

verify.NewHistoryCoordinator(recipe.Parser, recipe.Applier,
  canonical.Canonicalizer, verify.HistoryLimits)
  -> verify.HistoryCoordinator or error
verify.HistoryCoordinator.Walk(ctx context.Context,
  current verify.Result, instances instance.Collection,
  initial recipe.State)
  -> verify.HistoryWalk or error
verify.HistoryCoordinator.ValidatePrevious(
  reconstructed recipe.State,
  current MessageInstance,
  previous MessageInstance,
) -> verify.HistoryTransition or verify.Error
```

`recipe.Limits` contains the per-parse/per-apply fields assigned to it in the
Limits And Work Accounting table. `verify.HistoryLimits` contains only the
cumulative walk fields assigned there. `recipe.StepKind`, `recipe.BodyMode`, and
`recipe.BodyAvailability` are closed enums. `recipe.Recipe` owns cloned header
plans and ordered steps; no exported constructor permits caller-authored
partially valid steps. `recipe.State` always has an initialized HeaderBlock,
which may contain zero reconstructed fields, plus either a valid Body or the
unavailable marker.

Rawmsg adds narrow reconstructed-state constructors that validate indexed
fields/body bytes under `ParserOptions`, accept a valid zero-field header
block, and materialize the RFC 5322 header/body separator when required. The
reconstructed HeaderBlock carries an unexported initialized marker, so an
empty-but-valid block is distinguishable from the invalid Go zero value;
rawmsg and canonical constructors reject an uninitialized block. The existing
parser's acceptance policy does not silently widen.

`verify.HistoryTransition` has adjacent `FromInstance` and `ToInstance` numbers;
`RecipeMode` (`applied` only in M8); `HeaderState` (`matched`, `mismatch`,
`unsupported`); `BodyState` (`matched`, `mismatch`, `unavailable`,
`unsupported`); and a reconstructed `recipe.State` only
when application succeeded. A hash mismatch is a populated immutable
transition result, not a Go error. Malformed recipe, unavailable copy source,
invalid adjacency, limit exhaustion, or internal incoherence is a typed error
and returns a zero transition. Unknown-only hashes produce `unsupported`
dimension results; they are not errors and never count as a match.

Here `FromInstance` and `ToInstance` are Message-Instance `m=` numbers, never
DKIM2-Signature `i=` sequence numbers. The exact shared selection API is:

```text
instance.MessageInstance.SHA256HashSet()
  -> (instance.HashSet, instance.HashSelectionStatus)

HashSelectionStatusSelected | Missing | Unsupported
```

`Selected` requires one valid known 32-byte SHA-256 header/body tuple and a
nonzero HashSet. `Missing` and `Unsupported` require a zero HashSet.

The exact walk vocabulary is:

```text
HistoryCoverageComplete | Partial | Unreconstructable | Failed | Unsupported
HistoryStopOriginReached | RecipeMissing | RecipeInvalid | ApplicationInvalid
HistoryStopSourceUnavailable | LimitExceeded | HashMismatch | HashUnsupported
HistoryStopHashMissing | InternalContract

HistoryWalk:
  Coverage() -> HistoryCoverage
  StopReason() -> HistoryStopReason
  TargetInstance() -> uint64
  ReachedInstance() -> uint64
  Transitions() -> cloned bounded []HistoryTransition
  Usage() -> bounded HistoryUsage
```

The Go zero value of HistoryWalk is invalid and means not evaluated; every
initialized walk has positive target/reached instance numbers, a known
coverage/stop pair, coherent contiguous retained transitions, and bounded
usage. The integrated `verify.Result` retains one unexported HistoryWalk and
offers only an internal cloning accessor `(HistoryWalk, bool)`.

The zero value of every domain object is invalid. Constructors validate and
clone caller-owned bytes and slices. Accessors return values or deep copies.
No accessor exposes raw decoded JSON after parsing.

`recipe.Usage` is initialized and immutable with decoded, emitted, item, and
work-unit accessors. Parse/apply success returns a valid Recipe/State, valid
Usage, and nil error. Failure returns a zero Recipe/State, valid Usage charging
all work performed before rejection, and a typed error. Usage contains no raw
input. This is the sole accounting source; verify never recomputes it.

### Recipe Forms

A valid top-level recipe has at least one recognized dimension:

```json
{"h":{"Subject":[{"c":[1,1]}]}}
{"b":[{"c":[1,3]},{"d":["restored line"]}]}
{"h":{"X-Example":[]},"b":null}
```

The third example is schema-valid even though draft-04 says recipes SHOULD NOT
be specified for unsigned header classes. Application treats it mechanically;
the canonical owner later ignores unsigned classes. An implementation may emit
a bounded non-fatal metadata counter, but it must not invent a protocol failure
for violation of that SHOULD.

### Closed Step Representation

A step is exactly one of:

- Copy: positive inclusive `[start,end]`.
- Data: one or more immutable decoded UTF-8 strings.

No generic `map[string]any`, `json.RawMessage`, interface-typed payload, or
unknown enum survives parsing. The parser may use internal transient tokens,
but the resulting model is a closed sum type whose invariants cannot express a
mixed, empty, or unknown step.

### Reconstruction State

Headers are always known because draft-04 has no header-null form. Body is one
of:

- `known`: immutable rawmsg body bytes and index exist.
- `unavailable`: a body-null transition was encountered; no bytes exist and no
  body hash may be computed or compared.

An absent body recipe retains unavailable. Another `b:null` retains
unavailable. A body
recipe containing `c` cannot run without known source lines and returns a typed
unavailable-source result. A body recipe composed solely of `d` steps can
re-establish a known earlier body because it does not depend on unavailable
source bytes. This distinction is determined structurally before application.

Materialization into a full rawmsg.Message is allowed only when both dimensions
are known. Header-only hash validation uses the known HeaderBlock directly and
does not fabricate a message or body.

## JSON Parsing Contract

### Input Boundary

- Input is cloned decoded JSON bytes obtained from `MessageInstance.Recipe()`.
- The byte limit is checked before tokenization.
- Empty input, non-whitespace data before or after the single root value,
  multiple JSON values,
  non-object top level, invalid UTF-8, invalid escape syntax, unpaired
  surrogates, and excessive nesting fail closed.
- Leading and trailing RFC 8259 whitespace around the single root object is
  accepted and charged to decoded-byte and work budgets.
- JSON numbers are accepted only in `c` positions and parsed as exact
  mathematical positive integers. Lexemes such as `1`, `1.0`, and `1e0` are
  accepted when exact decimal/exponent evaluation yields the same bounded
  integer. Fractional results, negative values including negative zero,
  invalid leading-zero forms, non-JSON numbers, or machine-overflowing values
  are rejected. Binary floating-point conversion is forbidden.
- Booleans are not valid anywhere in the recognized schema.

The implementation uses the standard library where it preserves these rules,
with a small token-level scanner for duplicate-member detection and strict
string validation. It must not unmarshal directly into maps and thereby lose
duplicates before validation. It must not add a third-party JSON dependency
unless a later architecture decision proves that necessary.

### Duplicate And Unknown Members

- Duplicate exact member names in any object fail with `duplicate_member`.
- Two header recipe names that compare equal under ASCII case folding fail with
  `header_name_collision`.
- Unknown top-level members are syntax-checked, bounded, skipped recursively,
  and never retained or exposed.
- Unknown top-level values remain subject to the global byte, token, member,
  string, and nesting limits so an ignored extension cannot be an abuse bypass.
- The `h` object has no extension-member namespace: every member name is a
  header field name and its value must be a recipe-step array.
- Step objects accept only `c` or `d` and exactly one member.

### Header Names And Literal Strings

Header recipe member names must satisfy RFC 5322 `field-name`: one or more
printable ASCII bytes excluding colon. Non-ASCII, space, control, DEL, colon,
empty, and over-limit names fail. ASCII lowercase is used only for matching and
collision detection; the original JSON spelling is retained for `d` emission.

Data strings:

- Must be valid RFC 8259 strings whose decoded form is valid UTF-8.
- Must not contain U+000D or U+000A, whether literal or escaped.
- May be empty.
- Must fit per-string and aggregate decoded-byte limits.
- Are never interpreted as MIME, JSON again, a field name, or a format string.

## Header Application Semantics

### Source Index

Application builds a bounded index of source header occurrences by canonical
lowercase name. Each list retains physical top-down order and complete
`OriginalBytes`. Index construction checks source header count and bytes even
when the rawmsg parser already checked them, because injected zero or
incoherent state is a contract error.

For one name with physical occurrences:

```text
top:    Subject: oldest-visible       occurrence 3
        Subject: middle               occurrence 2
bottom: Subject: newest-visible       occurrence 1
```

The bottom-up recipe view is the reverse of the physical list.

### Copy Steps

- Validate the range against the source occurrence count before copying.
- Copy each selected occurrence from `start` through `end` in increasing
  bottom-up number.
- Preserve the selected occurrence's complete original bytes.
- Do not unfold, refold, lowercase, MIME-decode, or rewrite it.
- The same occurrence may not be selected by two ranges because strict range
  ordering makes overlap impossible.

### Data Steps

- Emit each string in array order into the bottom-up output sequence.
- Construct a new logical header as `<recipe-key>:<value>\r\n`.
- Validate it through rawmsg header constructors.
- Empty values and UTF-8 octets are preserved exactly as described above.
- Output line and field size limits apply before allocation and again at the
  rawmsg constructor boundary.

### Unmentioned And Removed Names

If `h` is absent, return the cloned source HeaderBlock unchanged. If `h` is
present:

- A source name absent from `h` retains all its occurrences.
- A recipe name absent from the source may use only `d` steps or an empty
  array. A `c` range is out of bounds.
- An empty array produces no occurrences for that name.
- A recipe that reproduces the same fields is permitted; generation policy is
  outside this increment.

After all per-name recipes are applied, each group's bottom-up output is
reversed into physical top-down order. Every source name, whether mentioned or
unmentioned, forms exactly one case-folded group. Groups are then ordered by
canonical lowercase ASCII name; names cannot tie after collision validation.
Copied fields retain exact original bytes and casing. Data fields use the exact
recipe-key spelling and `<name>:<UTF-8-value>\r\n`. A removed group contributes
nothing; a recipe may therefore produce a valid initialized zero-field header
state. This deterministic representation is sufficient for draft-04 header
hash validation and subsequent per-name recipe application. Tests must state
that cross-name original order is unrecoverable from the recipe.

Before constructing a data field, require
`len(name)+1+len(value) <= MaxHeaderLineBytes` and the complete field including
CRLF to fit `MaxHeaderFieldBytes`. M8 never invents folding to make an
over-limit field fit.

## Body Application Semantics

### Source Lines

Source lines come only from `rawmsg.Body.Lines()`. Numbering is one-based and
top-down. The bytes of a line exclude its terminal CRLF; line-ending width is
consulted only to locate the bytes safely.

An empty body has zero source lines. A body consisting of `\r\n` has one empty
source line. A terminal unterminated line is one source line and retains its
missing terminator only when copied as the final reconstructed output line.

### Copy And Data Steps

- A body `c` range validates against the source line count, then appends each
  selected line's bytes with its original termination in ascending line order.
  An unterminated copied line is rejected unless it is the final emitted line.
- A body `d` step appends each decoded string's UTF-8 bytes followed by CRLF in
  array order.
- Empty `d` strings append CRLF.
- Step order is preserved, so later body output appears below earlier output.
- An empty step array produces zero body bytes.
- Body bytes are never MIME-decoded, transfer-decoded, dot-unstuffed, charset-
  converted, or otherwise normalized.

The output is validated through rawmsg body construction and indexing. Limits
are checked incrementally before append; the implementation must not construct
an over-limit temporary buffer and reject it afterward.

### Null Body

`b:null` returns a successful reconstruction result with body state
`unavailable`. It returns no body bytes, no empty placeholder, and no hash
comparison result. It may coexist with a header recipe, whose output remains
known and independently validatable.

## Previous-Instance Hash Validation

### Transition Contract

For a transition from current Message-Instance `n` to previous instance
`n-1`:

The integrated history coordinator MUST be invoked only after aggregate
current verification is `PASS`, including the current DKIM2 signature and the
current `m=N` header/body hashes. A non-PASS result performs zero recipe parse,
application, allocation, or history work and retains no HistoryWalk. No recipe
fact can influence the current authentication decision that gates it.

1. Require `n > 1` and exact adjacency between the supplied parsed instances.
2. Start from the controlled reconstruction state representing `n`.
3. Require instance `n` to carry `r=`, then parse and apply it. Missing `r=` is
   a typed malformed-history error; no identity transition is inferred.
4. Select the previous instance's hash state exclusively through
   `instance.MessageInstance.SHA256HashSet()`. Both current and historical
   verification use this method. Unknown-only algorithms produce
   `unsupported`; absence without unknown algorithms produces `missing` and is
   a typed malformed-history error. Duplicate names were already rejected by
   the parser. Mixed known/unknown lists compare the single SHA-256 set and
   ignore unknown sets for this increment.
5. Calculate the reconstructed header hash with
   `canonical.Canonicalizer.HeaderHash` and compare it in constant time with
   the previous `sha256` header hash.
6. If the body is known, calculate and compare its body hash through
   `canonical.Canonicalizer.BodyHash`. If unavailable, record body
   `unavailable` and perform no comparison.
7. Return immutable typed facts plus the reconstructed state for the next
   backward transition.

A header mismatch or known-body mismatch is an authenticated-content result,
not a JSON parser error. Impossible adjacency, malformed recipe/state, missing
SHA-256, unavailable copy input, or over-limit reconstruction is a fail-closed
typed verify/history error with no transition. Unknown-only SHA-256 is an
unsupported transition result. Body-unavailable is neither match nor mismatch.

### Closed Result And Precedence Matrix

Single-transition evaluation follows this total precedence:

1. Invalid options/state, non-adjacency, missing `r=`, malformed recipe,
   application failure, unavailable copy source, or limit overflow returns a
   typed error and a zero transition; no hash result is minted.
2. Missing SHA-256 returns a typed missing-hash error and zero transition.
3. Unknown-only hash sets return a populated transition with every known
   dimension `unsupported`; an unavailable body remains `unavailable`.
4. With SHA-256, each known dimension is independently `matched` or
   `mismatch`; unavailable body remains `unavailable` and is not hashed.
5. The reconstructed state is retained in the transition for matched,
   mismatch, unavailable, and unsupported outcomes because application
   succeeded, but the iterative walk stops after any mismatch or unsupported
   header. It may continue header-only after body unavailable.

The internal walk fold is deterministic:

| Observed history | Internal walk coverage | Stop reason |
| --- | --- | --- |
| Current target is `m=1` | `complete` with zero transitions | `origin_reached` |
| Every hop to `m=1` has header/body matched | `complete` | `origin_reached` |
| Every hop has header matched and at least one body unavailable | `partial` | `origin_reached` |
| First hop missing `r=` | `unreconstructable` | `recipe_missing` |
| First-hop parse/application/source/limit/internal failure | `unreconstructable` | matching `recipe_invalid`, `application_invalid`, `source_unavailable`, `limit_exceeded`, or `internal_contract` |
| The same failure after one or more matched hops | `partial` | the same matching closed stop reason |
| Any supported header or body mismatch | `failed` | `hash_mismatch` |
| Missing SHA-256 before any matched transition | `unreconstructable` | `hash_missing` |
| Missing SHA-256 after one or more matched transitions | `partial` | `hash_missing` |
| Unknown-only hashes before any matched dimension | `unsupported` | `unsupported_hash` |
| Unknown-only hashes after an earlier matched transition | `partial` | `unsupported_hash` |
| Context cancellation at any point | no walk result; return `ctx.Err()` | none |

`failed` has precedence over `partial` and `unsupported`. A supported mismatch
in one dimension therefore remains `failed` even when the body is unavailable
or another dimension is unsupported. `b:null` on the first hop with a matching
header is `partial`, never `complete` or `unreconstructable`. Later null and
all-data body recovery follow the same per-hop rules. Retention narrowing may
omit transition details but never changes this authoritative internal fold.

`ValidatePrevious` begins after recipe application and owns only adjacency and
hash validation; it never parses/applies a recipe and therefore has no recipe
Usage to return. It uses the disjoint transition/error contract above.
`HistoryCoordinator.Walk` directly calls Parser and Applier, then consumes
ValidatePrevious's typed hash/adjacency errors. It has a
different, also disjoint contract: authenticated history problems—missing or
malformed recipe, application/source failure, missing/unsupported hash,
mismatch, or resource exhaustion—are sealed into one initialized HistoryWalk
with nil Go error according to the table. An impossible internal contract
defect seals `internal_contract` during an integrated post-PASS walk so it
cannot rewrite current truth. Direct caller contract misuse—zero/incoherent
Result, Collection, or State—returns a zero HistoryWalk with typed
`history_invalid_state` or `history_internal_contract`; it cannot synthesize
positive target/reached numbers. Direct invocation with non-PASS current
Result is contract misuse and follows the same zero-walk typed-error lane.
Context cancellation/deadline likewise
returns a zero HistoryWalk with `ctx.Err()`. These direct errors and an
initialized walk are mutually exclusive. Constructors reject invalid
configuration before verification begins.

After current PASS, verify attaches the initialized walk to its Result even
when coverage is failed, partial, unsupported, or unreconstructable. Those
states never change current state, target, checks, reason, signature facts, or
custody facts and never cause `Verify` to return a Go error. Service and root
intentionally do not map or expose the walk in M8. Non-PASS performs zero
history work. Tests snapshot every current field before/after malformed,
mismatch, limit, missing, and unsupported history and prove semantic identity.
If the integrated verifier ever receives a direct typed Walk contract error
despite its validated inputs, it preserves the current result and attaches a
coherent `NewInternalContractHistoryWalk(targetInstance)` with coverage
`unreconstructable`, stop `internal_contract`, target/reached equal to the
known positive current target, zero transitions, and bounded zero usage. It
does not return that internal error through the public verification call.

### Iterative Reconstruction

An internal coordinator may walk from the highest current instance down toward
`m=1`. It must:

- Validate contiguous instance numbering before applying any recipe.
- Apply at most one transition per positive decrement.
- Enforce cumulative transition, decoded-byte, emitted-byte, header, line, and
  work-budget limits across the entire walk, not merely per recipe.
- Stop immediately on malformed recipe, mismatch, limit failure, cancellation,
  or incoherent state.
- Preserve already proven bounded facts only in the immutable internal walk
  result; it must not return a public chain verdict in M8.
- Treat `b:null` as partial historical content and continue header validation.
- Continue body reconstruction only when the source is known or the next body
  recipe is source-independent (`d` only or empty).

This increment exposes this coordination only internally and through tests.
The existing service and public verifier continue to report current scope and
historical signatures/content as `not_evaluated`. M8's `HistoryWalk` is an
internal verified-content seam with no facade accessor; this compatibility rule
is locked by current-result golden tests. A later durable specification must
define public history and authenticated historical-policy projection before
those fields change.

## Limits And Work Accounting

Default limits are restrictive and constructor-validated. Zero values select
defaults; negative values, values above hard maxima, arithmetic overflow, and
incoherent combinations are invalid options.

| Owner and field | Default/hard max | Purpose |
| --- | ---: | --- |
| recipe `MaxDecodedRecipeBytes` | 49,152 | Largest payload representable by existing 64-KiB encoded tag value |
| recipe `MaxJSONDepth` | 16 | Bound ignored extension traversal |
| recipe `MaxJSONMembers` | 2,048 | Bound duplicate tracking and extensions |
| recipe `MaxJSONTokens` | 8,192 | Bound total parsing work |
| recipe `MaxHeaderNames` | 256 | Bound recipe and source/output distinct case-folded groups |
| recipe `MaxHeaderNameBytes` | 998 | Bound one field name |
| recipe `MaxTotalHeaderNameBytes` | 16,384 | Bound retained names |
| recipe `MaxStepsPerHeader` | 256 | Bound one header-name step array |
| recipe `MaxBodySteps` | 2,048 | Bound the body step array |
| recipe `MaxTotalSteps` | 4,096 | Bound combined recipe work |
| recipe `MaxCopyRanges` | 2,048 | Bound range metadata |
| recipe `MaxCopiedItemsPerRange` | 2,000 | Bound one range expansion |
| recipe `MaxTotalCopiedItems` | 8,192 | Bound per-apply copy expansion |
| recipe `MaxDataStrings` | 4,096 | Bound literal item count |
| recipe `MaxDataStringBytes` | 16,384 | Bound one decoded retained string before dimension coherence |
| recipe `MaxTotalLiteralBytes` | 32,768 | Bound retained immutable literals |
| recipe `MaxHeaderFields` | 2,000 | Align with rawmsg defaults |
| recipe `MaxHeaderFieldBytes` | 65,536 | Align with rawmsg defaults |
| recipe `MaxHeaderLineBytes` | 998 | Align with rawmsg physical-line policy |
| recipe `MaxHeaderBytes` | 1 MiB | Align with rawmsg defaults |
| recipe `MaxBodyLines` | 65,536 | Align with the rawmsg hard index cap and bound copy loops |
| recipe `MaxBodyLineBytes` | 998 | Align with rawmsg physical-line policy |
| recipe `MaxStateBytes` | 32 MiB | Align with rawmsg message default |
| recipe `MaxOperationWorkUnits` | 4,194,304 | Bound one parse or apply operation |
| history `MaxTransitions` | 128 | Bound backward chain work |
| history `MaxCumulativeDecodedBytes` | 6 MiB | Bound multi-hop JSON input |
| history `MaxCumulativeEmittedBytes` | 64 MiB | Bound multi-hop reconstruction output |
| history `MaxCumulativeItems` | 524,288 | Bound multi-hop fields, lines, ranges, steps, and literals |
| history `MaxCumulativeWorkUnits` | 16,777,216 | Bound total parser/application work |
| history `MaxRetainedTransitions` | 128 | Bound immutable internal walk facts |

Hard maxima equal the defaults in this increment except where a narrower
caller may lower a value. Constructors additionally require
`MaxDataStringBytes <= MaxTotalLiteralBytes <= MaxDecodedRecipeBytes`,
per-header steps not above total steps, per-range copies not above total
copies, and every reconstructed rawmsg limit not above its authoritative
rawmsg ceiling. Raising hard maxima requires a durable security review and
coordinated rawmsg/service limits; merely configuring a larger value is not an
unsafe escape hatch. Exact/one-over tests may use coherent narrower limits to
make every independent field reachable.

Instance parsing sets `MaxBase64DecodedBytes` to no more than
`MaxDecodedRecipeBytes`; recipe receives only decoded bytes and never owns the
encoded count. `MaxDataStringBytes` does not allow a 64-KiB unfolded header
line: header data must also satisfy `name + colon + value <= 998`; the larger
string ceiling is useful only for bounded body parsing before its 998-byte line
coherence check.

Every append and multiplication uses checked arithmetic. Range expansion is
charged before iteration. One work unit is charged for each decoded byte
scanned, JSON token, JSON member, recipe step, copied source item, emitted item,
and emitted byte; overlapping categories intentionally accumulate. Sorting a
header-name group charges one unit per comparison. Cumulative items add every
parsed step/range/literal and every examined/emitted header field/body line.
Unknown top-level members consume byte, token, member, depth, item, and work
budgets. Parser and applier return an internal immutable `recipe.Usage` with
decoded, emitted, item, and work counters. Each operation enforces recipe
limits first. Walk checked-adds Parser Usage exactly once and immediately
enforces every history limit before it may call Apply. It then checked-adds
Applier Usage exactly once and immediately enforces every history limit before
hash validation or transition retention. Failed parser/applier Usage is still
charged once before the stop result is sealed. This ordering makes cumulative
limits execution bounds, not after-the-fact retention checks.
Limit errors identify only a stable limit name and bounded counts.

## Error Model And Diagnostics

`lib/internal/recipe` uses one typed error with closed code, class, bounded
location, and bounded details. Its stable parse/application codes are:

```text
invalid_options
invalid_state
limit_exceeded
invalid_json
duplicate_member
invalid_top_level
missing_recipe_dimension
invalid_header_name
header_name_collision
invalid_header_recipe
invalid_body_recipe
invalid_step
invalid_copy_range
copy_range_order
copy_range_out_of_bounds
invalid_literal
source_unavailable
```

`lib/internal/verify` separately owns these history-coordinator codes:

```text
history_invalid_options
history_invalid_state
history_instance_not_adjacent
history_missing_recipe
history_missing_sha256
history_limit_exceeded
history_internal_contract
```

Header/body mismatches and unknown-only hashes are closed transition result
states, not errors. Context cancellation is returned unchanged as `ctx.Err()`.

Locations may contain only bounded structural coordinates such as JSON byte
offset, instance number, step index, member index, header-name ordinal, or body
line number. Details may contain a stable limit name, expected/actual count,
and closed dimension or step kind. They must not contain:

- Raw or decoded recipe JSON.
- JSON member names originating from the message.
- Header names or values.
- Body lines or reconstructed bytes.
- Hash or base64 values.
- Message-Instance field contents.
- Domains, selectors, addresses, recipients, message IDs, signatures, keys, or
  provider errors.

`Error()` is deterministic, short, bounded, and safe to expose to internal
mapping. `Unwrap()` may retain a safe standard-library cause for debugging but
must not make toxic input appear in the formatted error. Error classification
uses codes or `errors.Is`/typed helpers, never string matching.

Cancellation during an iterative validation walk is caller control flow and is
returned as the context error without a partial protocol result. Pure parse and
single-application methods do not accept context because their work is tightly
bounded and in-memory.

## Security And Privacy Invariants

- Parsing is duplicate-aware before semantic projection.
- Unknown top-level extensions cannot bypass limits.
- Recipe output is immutable and no caller storage is retained.
- Copy ranges are bounds-checked before indexing.
- All arithmetic is overflow-checked before allocation.
- Output is built incrementally under hard byte and item budgets.
- Body-null never becomes empty-body success.
- Missing recipes never become unauthenticated proof; hash comparison remains
  authoritative.
- Hash validation reuses canonical and compares fixed-size digests in constant
  time.
- Rawmsg remains the only RFC 5322 validity authority.
- Invalid input never causes a panic, partial mutable output, fallback parse,
  best-effort reconstruction, or relaxed hash comparison.
- No recipe or message content enters logs, traces, metrics, REST, CLI, error
  text, test failure messages, or examples intended for operators.
- Metrics or future observation events may use only closed low-cardinality
  values such as error code, dimension, step kind, and result class.

## Required Tests

### Parser And Schema Tests

- Accept header-only, body-only, combined, empty-step-array, empty per-header
  array, and body-null recipes.
- Accept bounded unknown top-level members and prove they are not retained.
- Reject no recognized dimension, non-object top level, trailing JSON, invalid
  UTF-8, unpaired surrogates, invalid escapes, excessive depth, and over-limit
  ignored members.
- Reject exact duplicate members at every object level before unknown removal.
- Reject case-colliding header keys.
- Reject `h:null`, empty `h` object, null per-header recipe, null step, `z`,
  unknown/extra step keys, mixed `c` and `d`, missing step key, and malformed
  array shapes.
- Accept exact integral decimal/exponent forms and reject zero, negative,
  fractional-result, overflow, reversed, overlapping, or non-ascending ranges.
- Reject empty `d` arrays, CR/LF literals including escaped forms, invalid
  field names, and over-limit decoded strings.
- Prove parsed recipes and all accessors are deeply immutable.

### Header Application Tests

- Prove bottom-up numbering for duplicate folded fields.
- Prove copy preserves exact field bytes, casing, folding, and CRLF.
- Prove later emitted fields appear above earlier emitted fields.
- Prove `d` array order under bottom-up emission.
- Prove absent names retain all occurrences and empty recipes remove all.
- Prove recipe names absent from source can add data but cannot copy.
- Prove case-insensitive lookup with recipe-key spelling used for new fields.
- Prove deterministic canonical-name group order and explicitly avoid a claim
  of original cross-name order.
- Prove ignored header classes remain mechanically reconstructable while the
  canonicalizer alone excludes them.
- Prove rawmsg header count, field length, line length, header bytes, and total
  output limits fail before excessive allocation.

### Body Application Tests

- Prove top-down one-based numbering and inclusive copy ranges.
- Prove inserted and empty data lines receive CRLF, copied lines preserve
  termination, and an unterminated copy is allowed only as final output.
- Prove terminal unterminated source-line behavior.
- Distinguish empty `b` array, `b:null`, absent `b`, empty source body, and one
  empty source line.
- Prove byte preservation for copied non-UTF-8 body bytes.
- Prove literal UTF-8 escape equivalence without Unicode normalization.
- Prove body line, literal item, emitted byte, and message byte limits.
- Prove source-unavailable behavior for copy-dependent and source-independent
  later recipes.

### Hash And Transition Tests

- Validate a reconstructed previous header and body against known SHA-256
  hashes calculated by the existing canonicalizer.
- Detect header mismatch and known-body mismatch separately.
- Report unavailable-body without calculating or comparing a body hash.
- Prove absent `r=` above `m=1` prevents reconstruction and is never inferred
  as an identity transition.
- Reject non-adjacent, reversed, zero, duplicate, or missing instances.
- Return typed missing-SHA-256 error and closed unknown-only unsupported
  transition state; neither is success.
- Reconstruct multiple transitions toward `m=1` under cumulative limits.
- Prove a body-null transition preserves later header validation, absence
  preserves unavailability, copy requires source, and all-data can recover it.
- Prove normal descent ignores `m=1` recipe bytes entirely, so even malformed
  irrelevant prehistory cannot poison authenticated coverage; explicit parser
  callers may still parse a supplied recipe independently.
- Prove verify calls canonical ownership while recipe has no canonical import
  or duplicate hash implementation, using cross-package golden tests.

### Fuzz, Abuse, Privacy, And Race Tests

- Fuzz decoded recipe parsing with bounded input and assert no panic,
  deterministic code, and immutable output.
- Fuzz application using valid small source messages and structurally varied
  recipes; assert either a valid rawmsg-owned result or a typed error.
- Seed duplicate members, case collisions, huge numbers, deep ignored values,
  copy bombs, data bombs, CR/LF injection, invalid UTF-8, null variants, `z`,
  and terminal unterminated lines.
- Property-test deterministic output across repeated runs and map-allocation
  perturbations.
- Run concurrent parse/apply on shared immutable inputs and prove no mutation or
  race.
- Inject toxic markers into every string-bearing input and assert they do not
  appear in errors, test diagnostics from production types, or metadata.
- Run representative parser and application fuzz targets for the repository's
  documented bounded smoke duration before final review.

## Implementation Sequence

1. Add closed limits, error codes, immutable recipe/step types, and structural
   tests.
2. Add duplicate-aware strict JSON scanning and schema decoding, with negative
   and fuzz tests.
3. Add header indexing/application through rawmsg-owned constructors and its
   byte-order golden tests.
4. Add body application, null/unavailable state, and terminal-line tests.
5. Add previous-instance validation through canonical ownership and bounded
   iterative reconstruction.
6. Add abuse, privacy, immutability, property, race, and bounded fuzz coverage.
7. Update package documentation and complete unchanged-snapshot conformance,
   architecture, security, and review proof.

Each implementation slice must receive live draft-conformance oversight and an
independent review before the next slice. No review may approve a diff that
changes after its recorded snapshot.

### Expected Implementation Inventory

The implementation adds cohesive files under
`lib/internal/recipe` for `limits`, `errors`, `types`, `parser`, `state`,
`apply_header`, and `apply_body`, with matching unit/fuzz/abuse tests. Rawmsg
changes are limited to reconstructed header/body/message constructors and
tests. Instance adds the shared SHA-256 selector and tests. Verify keeps the
cohesive history types and coordinator implementation together in
`lib/internal/verify/history.go`, with focused history tests; service/root
changes are limited to compatibility tests proving their public
`not_evaluated` contract is unchanged. File names may split only for cohesion;
ownership may not move.

The ignored prompt pack is fixed at seven slices:

1. contracts, limits, errors, state, and rawmsg seams;
2. strict duplicate-aware JSON parsing;
3. header application;
4. body application and availability;
5. instance hash selection and verify-owned authenticated history;
6. abuse, fuzz, privacy, immutability, and race proof;
7. documentation and exact-snapshot closeout.

Architecture estimates M8 at 3 to 8 focused agent-hours. The timing ledger in
`temp/recipe-application-prompts/index.md` records retained exact timestamps and
durations and explicitly marks unavailable data without inference.

### Exact Proof Commands

Focused proof uses Make targets where present plus these module-local commands:

```text
go test ./lib/internal/recipe/... ./lib/internal/rawmsg/... ./lib/internal/instance/... ./lib/internal/canonical/... ./lib/internal/verify/... ./lib/internal/service/... ./lib/...
go test -race ./lib/internal/recipe/... ./lib/internal/verify/... ./lib/internal/service/... ./lib/...
go test ./lib/internal/recipe -run '^$' -fuzz '^FuzzParseRecipe$' -fuzztime=10s
go test ./lib/internal/recipe -run '^$' -fuzz '^FuzzApplyHeader$' -fuzztime=10s
go test ./lib/internal/recipe -run '^$' -fuzz '^FuzzApplyBody$' -fuzztime=10s
go test ./lib/internal/verify -run '^$' -fuzz '^FuzzHistoryWalk$' -fuzztime=10s
make test
make vet
make lint
make race
make guardrails
git diff --check
git diff --cached --check
git status --short
```

Fuzz target names are part of the implementation contract. If a target is
intentionally split, the prompt closeout records the equivalent exact commands
and reviewer approval.

### Completion Evidence

- Focused package graph: the exact command above passed for recipe, rawmsg,
  instance, canonical, verify, service, and the complete library module.
- Draft-versioned vector: `TestGoldenRecipeApplicationDraft04` loaded
  `recipe-application-draft-ietf-dkim-dkim2-spec-04.json` and passed both known
  and unavailable body cases.
- Closed vocabularies and adapters: recipe and history error-code matrices,
  history enum contracts, service seams, public adapters, public policy
  vocabularies, and public verification vocabularies passed their exhaustive
  tests.
- Current-truth compatibility: integrated history ran only after current PASS;
  public scope, four-state truth, historical signatures, and historical policy
  evidence remained unchanged and not evaluated.
- Fuzz smoke: `FuzzParseRecipe`, `FuzzApplyHeader`, `FuzzApplyBody`, and
  `FuzzHistoryWalk` each passed for 10 seconds after the last production-code
  fix.
- Repository gates: `make test`, `make vet`, `make lint`, and `make race`
  passed. The first sandboxed `make guardrails` reached `govulncheck` and failed
  closed because `vuln.go.dev` DNS was unavailable; the approved network-capable
  rerun passed every module with no vulnerabilities found.
- Worktree proof: `git diff --check` and `git diff --cached --check` passed, the
  cached name list was empty, and `git check-ignore -v temp/recipe-application-prompts/index.md`
  confirmed the timing ledger remained ignored.
- Skipped checks: none. No OpenAPI generation was required because no REST
  contract or generated artifact changed; the existing OpenAPI presence check
  passed inside guardrails.

### Review Snapshot And Commit Evidence

| Evidence | Required value | Status |
| --- | --- | --- |
| Durable spec and prompt-pack normative approval | Initial approval plus final finding fixes and re-review | done; exact unchanged-snapshot approval is retained in the final handoff |
| Prompt 01 through 07 approvals | Watcher plus independent reviewer per slice | done; missing historical timing does not replace recorded approvals |
| Final durable-tree SHA-256 | Exact hash over the established diff-plus-untracked stream | done; reported out of band in the final handoff to avoid a self-referential document hash |
| Normative/mail/security final approval | Exact unchanged hash | done; retained in the final handoff |
| Architecture/DRY/API final approval | Exact unchanged hash | done; retained in the final handoff |
| Focused tests and fuzz smoke | Exact commands and results | done; focused package graph and all four named 10-second fuzz targets passed |
| `make guardrails` | Full repository gate including vulnerability checks | done; the sandboxed vulnerability fetch failed closed, then the approved network-capable rerun passed with no vulnerabilities found |
| Cached diff and ignored temp proof | Empty cached diff; prompt pack ignored | done; final closeout proof records both states |
| Structured milestone commit | Commit ID and project-format message | pending |

## Acceptance Matrix

| Area | Requirement | Proof | Status |
| --- | --- | --- | --- |
| Baseline | Behavior is explicitly draft-04, including no header-null and no `z` | Versioned golden fixture, parser negatives, interpretation-to-test mapping | done |
| JSON | Strict RFC 8259, duplicates rejected, bounded unknown top-level members ignored | Parser unit, fuzz, and abuse tests | done |
| Header semantics | Bottom-up per-name copy/data and deterministic hash-equivalent reconstruction | Byte-level unit/property tests and draft-04 golden fixture | done |
| Body semantics | Top-down copy/data, exact copied termination, CRLF data emission, and truthful null-body state | Body unit/edge tests and draft-04 golden fixture | done |
| Ownership | Rawmsg owns RFC 5322 bytes; canonical owns hashing; instance owns base64 | Dependency-direction, cross-package, and verifier integration tests | done |
| Hash validation | Previous known dimensions are checked against the previous instance | Transition, mismatch, and multi-hop tests | done |
| Limits | Per-recipe and cumulative work cannot expand without bound | Every hard maximum exact/one-over, bomb, arithmetic, and verifier-bound tests | done |
| Privacy | No toxic input enters errors or diagnostics | Recipe/history toxic-marker tests | done |
| Immutability | No caller storage is retained or exposed | Mutation, concurrent reuse, and race tests | done |
| Review | Two independent exact-snapshot approvals, including normative audit | Final handoff records both approvals against one unchanged hash | done |
| Guardrails | Formatting, vet, lint, tests, race, OpenAPI checks, and vulnerability policy pass | `make guardrails` plus four bounded fuzz commands | done |

## Definition Of Done

- The durable spec and ignored prompt pack are reviewed before implementation.
- Every implemented function and method, including unexported named helpers,
  has a concise English doc comment.
- No recipe rule is duplicated outside `lib/internal/recipe`, and no rawmsg or
  canonical rule is forked inside it.
- Draft-04 null, unknown-member, ordering, range, and CRLF semantics are covered
  by positive and negative tests.
- Resource, overflow, privacy, immutability, fuzz, property, and race tests are
  green.
- Existing current verification behavior and public result truth remain
  unchanged unless a separately reviewed durable amendment explicitly expands
  scope.
- `make guardrails` passes, or any unavailable external gate has an exact,
  narrow, maintainer-approved exception that does not claim success.
- Independent draft/mail and architecture/security reviewers approve the exact
  unchanged final snapshot.
- `temp/` remains ignored and unstaged.
- The increment is committed once with the project-approved structured commit
  format.

## Deferred And Open Items

- Draft-04 does not define cross-header-name placement. The deterministic
  canonical-name grouping in this increment is hash-equivalent and reversible
  for future per-name recipes, but it is not original raw byte order.
- Draft-04 does not explicitly state whether a copied terminal unterminated
  body line retains the missing terminator. This increment preserves it only
  when it remains the final output line and otherwise fails closed; versioned
  tests lock that interpretation.
- EAI behavior remains TBA in draft-04. JSON literals use RFC 8259 UTF-8 only;
  no additional mail-address or header normalization is inferred.
- Public historical verification state, historical signature verification,
  authenticated historical flag projection, and policy compliance remain for a
  later durable specification.
- Recipe generation and deterministic serialization are completed by
  `docs/specs/implementation/recipe-generation.md`; they consume the closed
  model defined here rather than creating a parallel schema.

### Interpretation-To-Test Mapping

Every durable draft-04 interpretation above is bound to retained executable
evidence. Test names are stable evidence identifiers; the final gate executes
their packages in addition to the focused commands.

| Interpretation | Retained evidence |
| --- | --- |
| Unknown root members are bounded and ignored; step objects stay closed | `TestParserAcceptsDraftRecipeForms`, `TestParserRejectsSchemaAndSyntaxFailures`, `TestParserStringUsageCountsRecognizedAndIgnoredOnce` |
| Duplicate members are rejected before semantic projection | `TestParserRejectsDuplicateAndCollidingMembers`, `TestParserAdditionalDraftAndRFC8259Vectors` |
| Header recipe keys are ASCII-case-insensitively unique | `TestParserRejectsDuplicateAndCollidingMembers` |
| Only `b:null` is a valid null form | `TestParserAcceptsDraftRecipeForms`, `TestParserRejectsSchemaAndSyntaxFailures`, `TestApplyBodyDistinguishesAbsentNullAndEmpty` |
| Draft-04 has no `z` step | `TestParserRejectsSchemaAndSyntaxFailures`, `FuzzParseRecipe` seeds |
| Absent and empty header members have distinct retain/remove behavior | `TestApplyHeadersPreservesAbsentDimensionIdentity`, `TestApplyHeadersRemovesRetainsAndMatchesCaseInsensitively`, `TestApplyHeadersCanProduceInitializedEmptyBlock` |
| Absent, empty, and null body members are distinct | `TestApplyBodyDistinguishesAbsentNullAndEmpty`, `TestApplyBodyDistinguishesEmptySourceAndEmptyLine` |
| At least one recognized dimension is required | `TestParserRejectsSchemaAndSyntaxFailures` |
| Copy ranges are positive, inclusive, forward, and strictly ordered | `TestParserAcceptsExactMathematicalIntegers`, `TestParserRejectsInvalidMathematicalIntegersAndRanges` |
| Header copies preserve complete logical-field bytes and bottom-up numbering | `TestApplyHeadersReconstructsBottomUpGroups` |
| Header step and multi-data emission order reverses into the required physical order | `TestApplyHeadersReversesEveryEmission`, `TestGoldenRecipeApplicationDraft04` |
| Header data uses exact key spelling, colon, UTF-8 value, and CRLF | `TestApplyHeadersHandlesMissingSourceGroup`, `TestApplyHeadersRemovesRetainsAndMatchesCaseInsensitively` |
| Body copy/data steps use top-down numbering, preserve step/data order, and terminate data with CRLF | `TestApplyBodyCopiesTopDownAndMixesData`, `TestGoldenRecipeApplicationDraft04` |
| Body copies preserve source termination only in a valid final position | `TestApplyBodyPreservesCopiedTermination`, `FuzzApplyBody` terminal-line seeds |
| Strings are strict RFC 8259 Unicode without CR/LF or invented normalization | `TestParserAdditionalDraftAndRFC8259Vectors`, `TestApplyBodyLiteralUTF8PreservesCodePoints` |
| Cross-name header order is deterministic hash-equivalent grouping, not recovered original placement | `TestApplyHeadersReconstructsBottomUpGroups`, `TestGoldenRecipeApplicationDraft04` |
| Instance owns padded base64 while recipe owns decoded JSON | `TestParseRejectsInvalidRecipeBase64`, `TestVerifierInstanceParserUsesRecipeDecodedByteLimit`, `TestRecipeProductionDependencyDirection` |
| Missing `r=` above `m=1` is not an identity transition | `TestHistoryWalkSealsAuthenticatedFailures`, `TestVerifierIntegratesHistoryOnlyAfterAggregatePass` |
| An `m=1` recipe is irrelevant to authenticated descent | `TestHistoryWalkOriginAndCumulativeLimit` |
| Unavailable historical body never rewrites current truth or authenticates policy/signatures | `TestHistoryWalkRecordsUnavailableBodyAsPartial`, `TestHistoryResultAttachmentDoesNotChangeCurrentFacts`, `TestHistoriedCorePassRemainsCurrentOnlyAcrossServiceAndFacade` |
