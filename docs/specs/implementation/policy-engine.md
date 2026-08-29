# DKIM2 Policy Engine

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-06 authority is the migration disposition
> and current durable architecture.

## Status

- Increment: local policy evaluation after current DKIM2 verification and DNS
  key resolution.
- Protocol baseline: `draft-ietf-dkim-dkim2-spec-04` plus
  `draft-chuang-dkim2-dns-04`.
- Architecture owners: `lib/internal/policy` for decisions and action planning,
  `lib/internal/verify` for parsed flag candidates, and
  `lib/internal/service` for authenticated verified-fact sealing.
- Status: implemented and final-proof complete under the documented M7-only
  maintainer exception for the external vulnerability database check;
  unchanged-snapshot review and milestone commit pending.
- Commit: the single increment commit containing the completed implementation
  and this document.

## Purpose

This increment adds a deterministic local policy engine over already verified,
bounded DKIM2 facts. It keeps the four-state verification result unchanged and
produces a separate local verdict, findings, feedback intent, and action plan.
The engine supports explicit strict, permissive, and testing modes without
turning deployment policy into cryptographic truth.

The initial public verifier still has `scope=current` and reports historical
content and historical signatures as `not_evaluated`. Consequently, this
increment can evaluate the current four-state result and authenticated flags on
the current passing signature, but it cannot claim that historical
`donotmodify` or `donotexplode` requests were honored. The policy package
defines the authenticated historical-fact contract needed by recipe and full
chain verification later; synthetic package tests exercise that contract now.

## Normative Sources And Precedence

The binding sources are, in order:

1. `draft-ietf-dkim-dkim2-spec-04`, especially Sections 8.10, 10.4, 11.1,
   and 11.8, for flag meaning, output states, and local-policy separation.
2. `draft-chuang-dkim2-dns-04`, Section 3.4.1, for the DNS `t=y` testing
   declaration.
3. RFC 5321 for the distinction between permanent rejection and temporary SMTP
   failure.
4. RFC 8601 only for vocabulary compatibility; Authentication-Results output
   itself is outside this increment.
5. `POLICY.md` and `docs/ARCHITECTURE.md`, especially Sections 5.10, 5.11,
   6.4, and 10, for package ownership, fail-closed defaults, result separation,
   and action planning.

Repository security policy resolves undefined, contradictory, unauthenticated,
or over-limit input fail closed. Later draft changes require a durable spec and
test-vector update before behavior changes.

### Recorded Draft Interpretations

The following interpretations are explicit and draft-versioned:

- DKIM2 verification has exactly four states: `PASS`, `FAIL`, `PERMERROR`, and
  `TEMPERROR`. A policy verdict never replaces, rewrites, upgrades, or
  downgrades that state.
- The draft says a verifier that observes a later modification despite
  `donotmodify`, or a later `exploded` report despite `donotexplode`, SHOULD
  reject. These are authenticated policy violations layered over protocol
  verification, not new cryptographic output states.
- "Later hop" means a strictly greater `i=` sequence. A single signature that
  contains both `donotexplode` and `exploded` does not by itself prove that a
  later hop violated the request.
- A `donotmodify` request prohibits a later body change that alters the body
  hash and removal or alteration of existing header fields. Header additions
  are permitted by Section 8.10; they are not automatically classified as a
  violation. A later receiver may record a bounded concern about an impactful
  addition, but this increment does not infer impact from header names or
  values.
- A `donotexplode` request is violated only by an authenticated `exploded`
  report on a later hop. Absence of `exploded` is not proof that no explosion
  occurred. Replay or copy-count inference belongs to the replay-store
  increment.
- `feedback` requests feedback. Its absence explicitly means feedback is not
  requested. `feedhere` asks that requested feedback be relayed through that
  hop; it does not independently create consent or a feedback request.
- The feedback transport, payload, recipient, and external routing protocol are
  undefined by draft-04 and remain out of scope. The engine emits bounded
  intent only.
- A `feedhere` hop is eligible only when an authenticated `feedback` request
  exists at the same or a lower sequence number. A same-hop
  `feedback,feedhere` pair is therefore eligible, but a later feedback request
  does not retroactively activate an earlier `feedhere`. If several eligible
  authenticated relay hops exist, the nearest return relay is the highest
  eligible sequence number. This is a local deterministic interpretation of
  underspecified routing, is covered by draft-versioned tests, and must be
  revisited when the draft defines feedback delivery.
- DNS `t=y` and the local policy mode named `testing` are different concepts.
  DNS `t=y` is signed-key metadata and never selects or mutates deployment
  configuration. The local testing mode is an explicit operator choice.
- DNS-04 requires messages from a signer declaring `t=y` not to be treated
  differently from unsigned mail, including when the signature fails. The
  policy result therefore expresses `continue`/no DKIM2 authentication weight
  for every coherent effective testing declaration, including `PASS`, rather
  than inventing an accept. Other local mail controls remain in charge.
- The active DNS draft describes `t=y` as a domain declaration although it is
  published per selector. For a multi-algorithm target, the declaration is
  effective only when every non-ignored, outcome-driving signature set with a
  coherently resolved key declares testing. Missing, ambiguous, temporary,
  provider-contract, or mixed declaration state does not activate the
  exception. This conservative rule avoids one selector weakening another.
- `TEMPERROR` is the only verification class eligible for an SMTP temporary
  failure. `FAIL`, `PERMERROR`, and policy violations never map to tempfail.
  Explicit testing or DNS testing treatment may return `continue`, but never a
  false `PASS`.

## Scope

### In Scope

- Closed strict, permissive, and testing policy modes.
- A closed, immutable policy verdict and reason vocabulary.
- Exhaustive mapping from the existing four-state verification result.
- Authenticated, sequence-aware flag facts minted only by the verification
  service after successful cryptographic coverage.
- Current-scope `not_evaluated` historical compliance.
- Synthetic full-history fact evaluation for later-hop `donotmodify` and
  `donotexplode` behavior.
- Bounded feedback and `feedhere` routing intent.
- Bounded `exploded` reporting without replay inference.
- DNS `t=y` treatment distinct from local testing mode.
- A small immutable action plan with exactly one disposition action.
- Public root-package policy types and an evaluator that accepts only a
  library-created `VerifyResult`, not caller-authored protocol facts.
- Unit, table, property, fuzz, abuse, immutability, privacy, and race tests.
- English package documentation and synthetic examples.

### Out Of Scope

- Historical recipe parsing/application or reconstruction.
- Historical signature verification or a claim that historical requests were
  honored under `scope=current`.
- Signing, revising, or deciding whether a future outbound transformation is
  permitted.
- Replay detection, copy counting, recipient correlation, Valkey, or any replay
  datastore.
- Sending feedback, choosing an email address or URL, formatting feedback, or
  revealing a downstream route.
- Authentication-Results formatting or header mutation.
- Quarantine, body replacement, header add/change/delete actions, or MTA-
  specific mutation commands.
- Daemon, OpenAPI, CLI, Milter, Exim, datasource, configuration-file, or
  concrete observability work.
- DNS `t=s` enforcement while the active DNS and signature drafts conflict on
  the meaning of `i=`.
- Reputation, spam scoring, DMARC, DKIM1, or unsigned-message acceptance
  policy.

## Package And API Boundaries

`lib/internal/policy` owns:

- Policy modes, policy-facing protocol classes, compliance states, findings,
  verdicts, feedback intent, action-plan validation, and the pure evaluator.
- The immutable authenticated-hop fact shape consumed by the evaluator.
- Closed mapping matrices and deterministic precedence among policy findings.
- Policy limits and input-coherence validation.

`lib/internal/verify` owns:

- Deriving one bounded target-flag candidate from the already parsed target
  `signature.Signature`; it performs no second parse.
- Carrying that candidate immutably in `verify.Result` alongside the
  authoritative target and complete hard-bounded signature-set results.
- Exposing a cloned/value candidate accessor to the internal service. The
  candidate is parsed evidence, not yet authenticated policy evidence.

`lib/internal/service` owns:

- The single exhaustive mapping from its authoritative four verification
  states into the policy-facing protocol class.
- Validating the verify-owned candidate against the authoritative target and
  upgrading it to an authenticated flag fact only when aggregate current
  verification maps to `PASS`.
- Preserving `scope=current` and both historical states as `not_evaluated`.
- Building an unexported, sealed policy projection during verification from
  the authoritative target, authenticated parser/verification state, and the
  complete bounded signature-set results before any public fact-retention
  narrowing.
- Applying public check/signature retention only after authoritative mapping;
  retention caps narrow presentation and never rewrite verification state or
  the complete sealed policy evidence.

The root `dkim2` package owns:

- Stable public `PolicyMode`, `PolicyVerdict`, `PolicyReason`,
  `PolicyFinding`, `FeedbackIntent`, `Action`, `ActionPlan`, and
  `PolicyDecision` value types.
- Restrictive policy options and an evaluator entry point that receives an
  existing library-created `VerifyResult`.
- Constructing and calling the internal evaluator over the sealed projection,
  then converting the internal decision into public immutable values without
  duplicating policy rules.
- Deep-copy adapters between internal and public immutable values.
- An unexported sealed policy projection embedded in `VerifyResult` by the
  facade adapter. Copying a `VerifyResult` preserves this projection, but no
  public constructor or accessor exposes or permits caller-authored provenance.

Conceptually, the public entry point is:

```text
EvaluatePolicy(result VerifyResult, options ...PolicyOption) -> PolicyDecision or Go error
```

The public API does not accept arbitrary parsed signatures, raw flags, raw messages, raw
recipients, selector/domain strings, or caller-asserted "authenticated" facts.
The zero or internally incoherent `VerifyResult`, invalid option, unknown enum,
or impossible result/fact combination returns a typed Go error and no decision.

`lib/internal/policy` must not import the root package, command modules,
OpenAPI generated types, Milter types, DNS transports, datasource providers,
or concrete telemetry. `lib/internal/service` may depend on `policy`; `policy`
must not depend on `service`, preventing a cycle. The small policy-facing
protocol class is not a second verification model: only the service maps the
authoritative state into it, exhaustively, and tests lock one-to-one coherence.
Policy evaluation does not reparse the message or reconstruct provenance from
the narrowed public `SignatureSets()` slice. A missing, zero, or incoherent
sealed projection is a typed no-decision contract error.

The implementation seam is frozen as follows:

1. The core verifier builds `verify.TargetFlagCandidate` directly from the
   selected parsed target signature. It contains target sequence plus exactly
   five booleans: donotmodify, donotexplode, feedback, feedhere, and exploded.
   Its fields are unexported and it exposes only value accessors. It contains no
   raw flag strings, unknown flags, or signature object.
2. `verify.Result` gains an unexported candidate field. Production
   `Verifier.Verify` attaches it through an unexported helper after selecting
   the already parsed target. `TargetFlagCandidate()` returns
   `(verify.TargetFlagCandidate, bool)` as the bounded value accessor. The
   helper accepts the candidate only when its sequence equals `Result.Target()`.
3. `policy.Projection` is an internal-package value with unexported fields,
   cloning accessors, and no caller-facing constructor. It has exactly two
   closed forms: `target_selected` and `target_unavailable`.
4. The verification service constructs that projection from the core result.
   It validates the candidate but authenticates/upgrades it only after the
   exhaustive aggregate mapping yields `PASS`. Non-PASS candidates are
   discarded. Independently, the service maps the complete pre-retention
   signature-set list into sealed DNS testing facts before applying public
   check/signature retention.
5. `service.Result` owns the projection and exposes it only through an
   internal cross-package cloning accessor used by the root facade adapter.
6. The root adapter embeds the clone in the unexported
   `VerifyResult.policyProjection` field while independently applying any
   configured public check/signature fact retention.
7. `EvaluatePolicy` passes only that embedded projection to the internal
   evaluator. It never invokes a parser and never derives policy facts from
   public accessors.

Because `policy` and `service` are Go `internal` packages, external library
consumers cannot import the projection type or call the internal service seam.
Zero-value and manually copied public structs cannot forge a valid projection.

Neither `lib/internal/service`, the root adapter, nor `EvaluatePolicy` calls
`signature.Parse`, scans `f=`, or imports tag-value parsing to recover flags.
The single parse remains in the existing verify extraction path.

The projection-form invariants are exact:

- `target_selected` requires a positive authoritative target sequence and a
  verify-owned candidate with that same sequence. On aggregate PASS the
  service may upgrade its flags; on non-PASS it retains no authenticated hop.
- `target_unavailable` requires public target sequence zero, no candidate, no
  authenticated hops, no signature-set/key-policy facts, verification state
  `PERMERROR`, and one of these pre-target reasons:
  `limit_exceeded`, `malformed_message`, `malformed_protocol`,
  `missing_protocol`, `sequence_invalid`, or `internal_contract`.
- `target_unavailable` is valid policy input. It is DNS-testing-ineligible and
  maps through the base `PERMERROR` policy row. It is not an invalid-input
  error merely because no target or candidate exists.
- Candidate-on-zero, target-unavailable with facts, target-selected without a
  candidate, and candidate/target mismatch are contract errors with no
  decision.

Service pre-extraction/error mapping and the existing root public preflight
limit result must seal the explicit `target_unavailable` form. The root
preflight constructor is trusted module code but cannot add facts; normal
selected-target projections still flow only from verify through service.

### Expected Implementation Files

The implementation is expected to touch only these production areas:

- `lib/internal/verify/result.go` and `lib/internal/verify/verifier.go` for the
  target-flag candidate result seam.
- `lib/internal/policy/` for contracts, errors, evaluator, compliance,
  feedback, DNS testing, action planning, and package documentation.
- `lib/internal/service/result.go`, `lib/internal/service/mapping.go`, and a
  focused service policy-projection file for authentication, complete
  pre-retention key facts, and sealed projection ownership.
- `lib/verify_result.go` and `lib/adapters.go` for the unexported facade
  projection field and cloning adapter.
- Focused root-package policy API/options files for public values and
  `EvaluatePolicy`.

Tests live beside those owners. Public synthetic examples may be added under
`lib/`. No command module, OpenAPI contract/generated file, recipe, replay,
datasource, Milter, Exim, or concrete observability file is expected to change.

## Input Model And Trust Boundary

### Verification Facts

The evaluator receives a sealed value containing:

- The exact four-state protocol class.
- The closed target form and authoritative `i=` sequence: positive for
  `target_selected`, zero only for `target_unavailable`.
- The verification scope.
- Historical content and historical signature coverage states.
- The complete bounded pre-retention signature-set outcomes and key metadata
  needed to determine effective DNS testing state. This sealed collection is
  independent of any caller-selected public signature-fact retention limit.
- Zero or more authenticated hop facts.

The evaluator never parses RFC 5322 bytes, DKIM2 fields, recipes, DNS records,
or cryptographic keys. A caller cannot set the authenticated marker through a
public constructor.

### Authenticated Hop Facts

One hop fact contains only:

- A positive `i=` sequence number.
- Whether `donotmodify`, `donotexplode`, `feedback`, `feedhere`, and
  `exploded` were present in that authenticated signature.
- A closed transition state. Sequence 1 uses `origin`; every later sequence
  describes the transition from the message state covered by the immediately
  preceding authenticated signature to the state covered by this signature:
  `origin`, `unchanged`, `body_changed`, `headers_removed_or_changed`,
  `body_and_headers_changed`, `header_addition_only`, `indeterminate`, or
  `not_evaluated`.

It contains no domain, selector, nonce, envelope path, recipient, header name,
header value, body bytes, hash bytes, signature bytes, DNS owner, or raw error.
Unknown flags are discarded by the parser and never become policy facts.

Facts must be strictly increasing by sequence, unique, within limits, and
consistent with the authoritative target and declared history coverage. A
history that claims complete coverage contains exactly one fact for every
sequence from 1 through the target, ends at that target, uses `origin` only at
sequence 1, and gives every later hop one compatible adjacent transition.
A complete-coverage claim with a gap, duplicate, wrong terminal sequence,
missing adjacent transition, or misplaced `origin` is an internal-contract
error. Deliberately partial authenticated coverage is represented as
`indeterminate` or `not_evaluated`; it never becomes complete by inference.
A complete history cannot contain `not_evaluated`; current-only history cannot
contain an earlier hop or claim compliance. `indeterminate` is not equivalent
to `unchanged` and cannot prove that a request was honored.

### Current Verification Projection

For the existing public verifier:

- `scope` remains `current`.
- Historical content and signatures remain `not_evaluated`.
- If and only if the top-level result is `PASS`, the service may mint one fact
  for the current signature's authenticated flags.
- The sealed authoritative target sequence equals `VerifyResult.Target()` and
  the single current fact, when present, must use that same sequence.
- That current fact can express a feedback request, `feedhere`, `exploded`, or
  future-facing `donot*` request, but cannot prove a later-hop violation.
- For `FAIL`, `PERMERROR`, or `TEMPERROR`, parsed `f=` values are not trusted
  and no authenticated flag fact is minted.
- The policy decision records historical compliance as `not_evaluated`; it
  never reports `honored` merely because no violation was observable.

This prevents unauthenticated `donot*` or `exploded` injection from becoming a
policy denial-of-service primitive.

## Closed Policy Vocabulary

### Modes

- `strict`: secure default; enforce DKIM2 failure and proven flag violations.
- `permissive`: accept permanent DKIM2 failure for rollout compatibility while
  preserving findings; temporary inability still tempfails.
- `testing`: observe DKIM2 outcomes without a DKIM2 terminal accept/reject;
  return `continue` so other local controls decide.

Unknown or empty modes are invalid. Constructors default to `strict`; there is
no implicit environment or DNS-selected mode.

### Verdicts And Disposition Actions

The closed policy verdicts are:

- `accept`: DKIM2 policy authorizes normal continuation.
- `reject`: permanent DKIM2 or enforced policy rejection.
- `tempfail`: temporary SMTP deferral caused only by `TEMPERROR`.
- `continue`: DKIM2 makes no terminal decision; other local policy continues.

The action plan contains exactly one matching disposition action. `accept`,
`reject`, and `tempfail` are terminal DKIM2 dispositions; `continue` is the
explicit non-terminal disposition and is not `accept`, `PASS`, or temporary
deferral. Adapters later translate dispositions into their own protocol
operations; this increment does not produce SMTP text or codes.

### Compliance States

Each `donotmodify` and `donotexplode` check has one closed state:

- `not_requested`
- `honored`
- `violated`
- `indeterminate`
- `not_evaluated`

The closed internal model reserves `honored` and `violated` for complete
authenticated history with the positive evidence required by the specific
request; indeterminate reconstruction cannot yield either. The current
verifier does not yet mint `unchanged`, `header_addition_only`, or prohibited
modification transitions from reconstructed history. Consequently its current
`donotmodify` projection can emit only `not_requested`, `indeterminate`, or
`not_evaluated`; `honored` and `violated` remain internal future states and are
excluded from the public wire contract. A later authenticated `exploded`
report can currently prove `donotexplode` violated, but absence of that report
cannot prove it honored because no positive single-recipient evidence exists.
Current-only verification yields `not_evaluated` when a request is visible and
`not_requested` only for the current signature itself; the aggregate
historical check remains `not_evaluated` because earlier unauthenticated
requests may exist.

### Findings And Reasons

`PolicyReason` is a closed string enum with exactly these tokens:

```text
invalid_input
limit_exceeded
internal_contract
protocol_pass
protocol_fail
protocol_permerror
protocol_temperror
permissive_override
testing_mode_observe
dns_testing_effective
dns_testing_mixed
dns_testing_ineligible
donotmodify_honored
donotmodify_violated
donotmodify_indeterminate
donotmodify_not_evaluated
donotexplode_violated
donotexplode_indeterminate
donotexplode_not_evaluated
feedback_requested
feedback_relay_selected
feedhere_inert
exploded_reported
```

`FindingSeverity` is a closed string enum with exactly these tokens:

```text
info
warning
permanent
temporary
```

Empty or unknown reason/severity values are invalid. The exhaustive mapping is:

| Input or derived fact | Policy reason | Severity | Emission |
| --- | --- | --- | --- |
| Invalid option, zero public result, or invalid sealed input | `invalid_input` | `permanent` | Typed error, no finding or decision |
| Hop, finding, or action limit exceeded | `limit_exceeded` | `permanent` | Typed error, no finding or decision |
| Impossible enum/state/provenance/action coherence | `internal_contract` | `permanent` | Typed error, no finding or decision |
| Verification `PASS` | `protocol_pass` | `info` | One protocol finding |
| Verification `FAIL` | `protocol_fail` | `permanent` | One protocol finding |
| Verification `PERMERROR` | `protocol_permerror` | `permanent` | One protocol finding |
| Verification `TEMPERROR` | `protocol_temperror` | `temporary` | One protocol finding |
| Permissive mode accepts `FAIL` or `PERMERROR` | `permissive_override` | `warning` | One mode finding |
| Local testing mode returns `continue` | `testing_mode_observe` | `warning` | One mode finding |
| Coherent all-set DNS testing makes `PASS`, eligible `FAIL`, or eligible `PERMERROR` non-terminal | `dns_testing_effective` | `warning` | One DNS finding |
| At least one set declares DNS testing but another relevant set does not | `dns_testing_mixed` | `warning` | One DNS finding |
| Testing metadata exists on a top-level state/reason excluded by the eligibility matrix | `dns_testing_ineligible` | `warning` | One DNS finding |
| Complete nonviolating modification evidence | `donotmodify_honored` | `info` | Internal future model; current verifier emits no such finding |
| Proven later prohibited modification | `donotmodify_violated` | `permanent` | Internal future model; current verifier emits no such finding |
| Indeterminate modification transition | `donotmodify_indeterminate` | `warning` | One modification finding at request sequence |
| Modification request with incomplete/current-only history | `donotmodify_not_evaluated` | `warning` | One modification finding at request sequence |
| Proven later exploded report | `donotexplode_violated` | `permanent` | One explosion-request finding at request sequence |
| Complete history without positive single-recipient evidence | `donotexplode_indeterminate` | `warning` | One explosion-request finding at request sequence |
| Explosion request with incomplete/current-only history | `donotexplode_not_evaluated` | `warning` | One explosion-request finding at request sequence |
| Authenticated feedback request | `feedback_requested` | `info` | One feedback finding at request sequence |
| Highest eligible feedback relay | `feedback_relay_selected` | `info` | One relay finding at selected sequence |
| Authenticated feedhere with no earlier/same-hop feedback | `feedhere_inert` | `info` | One inert-relay finding at sequence |
| Authenticated exploded report | `exploded_reported` | `info` | One report finding at sequence |

No request, no DNS testing declaration, and no optional report emit no finding.
Findings contain only reason, severity, optional sequence number, and bounded
booleans. They contain no human-authored messages or protocol input.

Finding order is exact: protocol, mode, DNS testing, `donotmodify`,
`donotexplode`, feedback request, feedback relay/inert relay, then exploded
report. Within one class, sequence is ascending; fixed enum order breaks a
same-sequence tie. Errors return before findings and therefore are not part of
this ordering.

### Primary Decision Reason

Every successful evaluation has exactly one primary reason. The precedence is:

1. `dns_testing_effective` when DNS testing makes `PASS`, eligible `FAIL`, or
   eligible `PERMERROR` non-terminal, regardless of local mode.
2. In strict mode with protocol `PASS`, `donotmodify_violated` in the internal
   future model, then currently reachable `donotexplode_violated`, when a
   proven violation changes accept to reject. Both findings remain present
   when both are violated after authenticated transition minting is
   implemented.
3. `testing_mode_observe` for every local-testing-mode decision not covered by
   step 1.
4. `permissive_override` when permissive mode accepts `FAIL` or `PERMERROR`.
5. Otherwise the matching protocol reason: `protocol_pass`, `protocol_fail`,
   `protocol_permerror`, or `protocol_temperror`.

`dns_testing_mixed`, `dns_testing_ineligible`, honored,
indeterminate, not-evaluated, feedback, inert relay, and exploded-report
reasons are never primary. Invalid input, limit, and internal contract return
no decision; their error reason is therefore not a primary decision reason.

## Policy Matrices

### Base Four-State Matrix

This matrix applies when effective DNS testing is false and no proven enforced
flag violation overrides a passing result:

| Verification state | Strict | Permissive | Testing |
| --- | --- | --- | --- |
| `PASS` | `accept` | `accept` | `continue` |
| `FAIL` | `reject` | `accept` | `continue` |
| `PERMERROR` | `reject` | `accept` | `continue` |
| `TEMPERROR` | `tempfail` | `tempfail` | `continue` |

The output retains the original verification state in every cell. Permissive
acceptance does not describe the message as cryptographically valid. Testing
mode does not accept the message; it withholds a DKIM2 terminal decision.

### Proven Flag-Violation Matrix

This matrix is evaluated only over complete authenticated historical facts:

| Base state | Condition | Strict | Permissive | Testing |
| --- | --- | --- | --- | --- |
| `PASS` | proven `donotmodify` violation | `reject` | `accept` with finding | `continue` with finding |
| `PASS` | proven `donotexplode` violation | `reject` | `accept` with finding | `continue` with finding |
| `PASS` | both proven | `reject` with both findings | `accept` with both findings | `continue` with both findings |
| non-`PASS` | any flag fact | base four-state result; unverified facts ignored | base four-state result | base four-state result |

An indeterminate or not-evaluated check never becomes a violation and never
becomes proof of honor. It adds a bounded finding but leaves the base matrix in
control.

### DNS Testing Eligibility And Matrix

Effective DNS testing is computed from the sealed complete pre-retention set
facts, never from the optionally narrowed public `SignatureSets()` accessor.
Eligibility requires at least one supported non-ignored set and requires every
supported set relevant to the top-level outcome to carry coherent
`TestingDeclared=true` metadata from a unique parsed DNS record. One false,
missing, mixed, or ineligible declaration makes the aggregate ineligible.

The exact eligible status/reason pairs are:

| Top-level state | Top-level reason | Required supported set status/reason | Effective testing |
| --- | --- | --- | --- |
| `PASS` | `none` | every set `pass/none` with testing declared | true; policy continues without DKIM2 authentication weight |
| `FAIL` | `signature_mismatch` | every outcome-driving set is `fail/signature_mismatch` or `pass/none`, all with testing declared | true |
| `FAIL` | `hash_mismatch` | every supported set is `pass/none`, all with testing declared | true |
| `PERMERROR` | `invalid_key` | every outcome-driving permanent set is `permerror/invalid_key`, all supported sets declare testing | true |
| `PERMERROR` | `revoked_key` | every outcome-driving permanent set is `permerror/revoked_key`, all supported sets declare testing | true |
| `PERMERROR` | `unsupported_key_type` | every outcome-driving permanent set is `permerror/unsupported_key_type`, all supported sets declare testing | true |
| `PERMERROR` | `key_algorithm_mismatch` | every outcome-driving permanent set is `permerror/key_algorithm_mismatch`, all supported sets declare testing | true |
| `PERMERROR` | `timestamp_invalid` | every supported set is `pass/none`, all with testing declared | true |
| `PERMERROR` | `envelope_mismatch` | every supported set is `pass/none`, all with testing declared | true |
| `PERMERROR` | `domain_alignment_mismatch` | every supported set is `pass/none`, all with testing declared | true |
| `PERMERROR` | `next_domain_mismatch` | every supported set is `pass/none`, all with testing declared | true |
| `PERMERROR` | `out_of_band_required` | every supported set is `pass/none`, all with testing declared | true |

Mixed eligible permanent reasons may be effective only when the top-level
primary reason is the deterministic existing aggregate of those same four
closed key reasons and every supported set declares testing. Post-key permanent
rows are eligible only when every supported set passed and declares testing;
they do not permit a failed, missing, ambiguous, or provider-error set.

The following are always ineligible and use the base matrix:

- `TEMPERROR`: provider-temporary set facts cannot coherently carry DNS key
  metadata, so effective testing is impossible.
- Missing or ambiguous key, provider permanent, provider contract, internal
  contract, limit, malformed/missing protocol, or sequence reasons.
- Unsupported/ignored algorithms as the only sets, zero supported sets, mixed
  testing declarations, narrowed-result reconstruction, or metadata attached
  to a status/reason pair that the M6 result contract forbids.

When effective testing is true, all local modes use this matrix:

| Verification state | Policy treatment | Reason |
| --- | --- | --- |
| `PASS` | `continue` | Preserve verification success but assign no DKIM2 authentication policy weight. |
| eligible `FAIL` | `continue` | Treat failed testing signature like unsigned mail. |
| eligible `PERMERROR` | `continue` | Do not enforce an eligible testing-key failure. |

For effective testing `PASS`, parsed current flags remain present only inside
the sealed verifier projection for provenance auditing. Policy suppresses all
hop-derived do-not compliance findings, feedback/feedhere intent, and exploded
reports because a testing signer cannot receive operational authentication
weight. Compliance and feedback history remain `not_evaluated`. Historical
projections cannot carry DNS signature facts under the current sealed contract,
so no synthetic historical DNS exception is inferred.

Effective testing never changes `VerifyResult.State()`. A zero, unknown, or
forbidden status/reason/metadata combination is a typed contract error, not a
testing exception.

### Decision Precedence

Evaluation order is fixed:

1. Reject invalid configuration or incoherent sealed input with a typed Go
   error and no decision.
2. Copy the original verification state into the decision.
3. Determine conservative effective DNS testing state from bounded key facts.
4. Apply the DNS testing matrix when eligible; otherwise apply the base matrix.
5. Evaluate authenticated historical flag compliance.
6. In strict mode, proven flag violations override only a `PASS` base verdict
   to `reject`. They never convert `TEMPERROR` to reject or tempfail a permanent
   state.
7. Derive feedback intent and informational exploded state.
8. Produce deterministic findings and exactly one disposition action.

## Flag Semantics

### `donotmodify`

For each authenticated request at sequence `r`, inspect only authenticated
transitions attributable to hops with sequence greater than `r`:

- `body_changed`, `headers_removed_or_changed`, or
  `body_and_headers_changed` proves a violation.
- `unchanged` and `header_addition_only` do not prove a violation.
- `indeterminate` makes the aggregate request indeterminate unless another
  later transition already proves a violation.
- Incomplete or current-only history yields `not_evaluated`.

Multiple requests are retained only as bounded findings; one proven violation
is enough for the aggregate state. The engine never inspects added header
content to guess whether it changes display or reply behavior.

### `donotexplode` And `exploded`

For each authenticated request at sequence `r`, a fact with `exploded=true`
violates the request only when its sequence is greater than `r`. An
`exploded` report before or on the requesting hop does not. Incomplete history
yields `not_evaluated`. Even complete signature history with no later report
yields `indeterminate`, not `honored`, because absence of the advisory report
is not positive evidence that only one recipient copy existed. A future
authenticated single-recipient evidence source requires its own durable
contract before `donotexplode` may be reported honored.

Every authenticated `exploded` flag may produce one bounded informational
finding. It does not infer the number or identity of recipients and does not
perform replay detection.

### `feedback` And `feedhere`

Feedback intent contains:

- `requested`: true when at least one authenticated `feedback` flag exists.
- `relay_required`: true only when at least one authenticated `feedhere` is
  eligible for an authenticated `feedback` request at the same or a lower
  sequence.
- `relay_sequence`: the highest eligible authenticated `feedhere` sequence
  when relay is required.
- `history_state`: complete, indeterminate, or not evaluated.

`feedhere` without an authenticated feedback request at the same or a lower
sequence is inert and may produce a bounded informational finding. A
same-signature request and relay pair is eligible. A feedback request on a
later signature does not retroactively activate an earlier relay. Current-only
PASS may expose a request on the current signature but marks history
`not_evaluated`; it cannot claim that no earlier relay exists. No routing
identity or feedback destination is retained.

## Configuration And Limits

The pure evaluator is constructed with an immutable config. Defaults are:

| Setting | Default | Hard maximum |
| --- | --- | --- |
| Mode | `strict` | closed enum |
| Maximum authenticated hop facts | 128 | 128 |
| Maximum findings | 128 | 128 |
| Maximum actions | 1 | 1 |

Options may narrow limits but never widen hard maxima. Zero, negative,
unknown, contradictory, or over-hard-limit configuration fails construction.
No package-level mutable policy, environment lookup, global mode, global
clock, or random ordering is allowed.

Over-limit sealed facts are internal-contract errors, not truncated success.
The public adapter returns a typed, bounded Go error and no partial decision.
The evaluator allocates proportionally only within the configured bounds.

Derived finding limits are checked before constructing a decision. After input
coherence validation, the evaluator deterministically pre-counts every finding
that the closed ordering rules would emit, using overflow-safe arithmetic over
already bounded facts. If that exact count exceeds `MaxFindings`, evaluation
returns the typed `limit_exceeded` no-decision error with only the limit name,
configured limit, and bounded count. It does not truncate, drop lower-priority
findings, partially aggregate requests, or return an action. A narrowed
`MaxFindings` option therefore either accommodates the complete decision or
fails closed.

## Immutability And Error Contract

- Constructors validate and clone caller-owned slices.
- Accessors return values or independent copies.
- Evaluation does not mutate `VerifyResult`, facts, options, or prior
  decisions.
- Repeated and concurrent evaluation of the same input is deterministic and
  race-free.
- Unknown internal enums, impossible state/reason pairs, duplicate or
  unordered sequences, contradictory coverage, metadata on an ineligible key
  result, and an action/verdict mismatch fail closed.
- Caller cancellation does not enter the pure evaluator because it performs no
  I/O. A future context-bearing service must return caller control-flow errors
  outside policy results.
- Error strings contain only stable error code, class, bounded counts, and
  limit name. They never contain raw inputs or `%v`-formatted nested errors.

## Security And Privacy

The policy engine treats parsed but unverified flags as attacker-controlled.
They cannot cause rejection, acceptance, feedback, or routing intent. Only the
service can mint authenticated facts, and only after the relevant signature
and message state have cryptographic coverage.

The following must never appear in policy facts, findings, decisions, action
plans, errors, examples, logs, traces, metric labels, REST/CLI output, or test
failure text:

- raw RFC 5322 headers or body;
- raw recipients, MAIL FROM, local parts, or complete addresses;
- domains, selectors, DNS owners, nonces, hashes, signatures, or public/private
  key material;
- raw DNS records, provider identifiers, datastore keys, raw errors, or
  protected configuration values;
- feedback destinations or downstream topology.

Sequence numbers and bounded enum values are permitted. Tests use toxic marker
values to prove that no forbidden input reaches formatting channels.

An explicit permissive or testing mode is a compatibility choice, not the
default. Effective config must eventually make such a choice operator-visible,
but daemon config and observability are later increments.

## Observability

This increment adds no logger, exporter, Prometheus registry, span provider, or
global telemetry. A future observer may record only:

- policy mode;
- original verification state;
- policy verdict and bounded primary reason;
- compliance states;
- feedback requested/relay-required booleans;
- bounded finding count and whether DNS testing treatment was effective.

Allowed metrics labels are closed low-cardinality enums only. Sequence numbers,
domains, selectors, recipients, feedback routes, request IDs, raw errors, and
all message-derived strings are forbidden labels.

## Public Documentation

Package documentation and synthetic examples must explain:

- verification state and policy verdict are separate;
- strict is the default and permissive/testing require explicit selection;
- `continue` means no DKIM2 terminal decision, not accept;
- current-only verification cannot establish historical flag compliance;
- only authenticated facts influence policy;
- `donotmodify`, `donotexplode`, `exploded`, `feedback`, and `feedhere`
  semantics and limitations;
- DNS `t=y` differs from local testing mode and cannot rewrite verification;
- no feedback is sent and no route identity is exposed.

Examples use library-created synthetic results and print only state, verdict,
reason, compliance enums, booleans, and counts.

## Required Tests

### Mode And Result Mapping

- Exhaustive 4-by-3 base matrix.
- DNS testing matrix covering PASS, signature/hash FAIL, each of the four
  eligible permanent key reasons, all five post-key permanent reasons, mixed eligible key reasons, mixed
  declarations, missing/ambiguous key, zero sets, ignored algorithm sets,
  provider-contract cases, and proof that TEMPERROR is never eligible.
- The DNS eligibility test must evaluate the sealed complete pre-retention set
  projection while the public signature-fact limit is narrowed, proving that
  the public slice is neither reparsed nor used as policy evidence.
- Exact proof that verification state remains byte-for-byte/value-for-value
  unchanged after evaluation.
- Unknown/zero mode, verdict, action, reason, and protocol-class negatives.
- Exactly one disposition action matching every verdict.
- Exhaustive `PolicyReason.Known()` and `FindingSeverity.Known()` tests prove
  exactly the frozen tokens and reject empty/future values.
- Table tests assert the exact reason/severity row for every protocol, mode,
  DNS, compliance, feedback, inert-relay, and exploded fact.
- Primary-reason tests cover protocol plus effective DNS testing, protocol PASS
  plus each violation, both violations together, permissive override, testing
  observation, and DNS testing plus local testing mode; they assert the frozen
  precedence while retaining every non-primary finding. A non-PASS projection
  carrying authenticated flag violations is an impossible contract negative,
  not a precedence case.

### Authenticated Fact Boundary

- Core verify-result tests prove the target candidate is derived from the
  already parsed selected signature, carries the exact target sequence and
  five booleans, ignores unknown flags, owns no raw strings, and is immutable.
- Core PASS and non-PASS results both may carry a parsed candidate; service
  tests prove only aggregate PASS upgrades it to authenticated policy evidence.
- Candidate/result target mismatch, selected-target missing candidate, unknown
  candidate state, and candidate on a zero target fail the service projection
  contract.
- Valid `target_unavailable` has zero target/candidate/facts, maps base
  PERMERROR, and remains DNS-testing-ineligible rather than becoming an input
  error.
- Public malformed-message, malformed/missing-protocol, sequence-invalid, and
  preflight-limit PERMERROR results evaluate under all three modes with the
  exact base-matrix verdict and primary reason.
- Target-unavailable carrying a hop, key fact, non-PERMERROR state, disallowed
  reason, or nonzero target is a no-decision contract negative.
- Package/dependency review proves service and facade code do not call the
  signature/tag-value parser; a toxic raw `f=` marker appears only in
  parser/verify fixtures and never in the sealed projection.
- Current PASS mints only the current authenticated flags.
- Current FAIL/PERMERROR/TEMPERROR mint no flag facts even when raw headers
  contain toxic or policy-relevant flag spellings.
- A forged public value cannot construct authenticated hop facts.
- Current scope always reports aggregate historical compliance
  `not_evaluated`, never `honored`.
- Duplicate, descending, zero, over-limit, contradictory, and incomplete facts
  fail closed.
- Complete-history exact `i=1..target` coverage, origin placement, adjacent
  transitions, final target match, plus gap and terminal-mismatch negatives.
- Partial/gapped coverage explicitly marked indeterminate never reports either
  request honored.

### Flag Evaluation

- `donotmodify` followed by body change, header removal/change, both, unchanged,
  header-addition-only, indeterminate, and incomplete history.
- Request at several sequences, violation before request, violation on same
  sequence, and violation strictly later.
- `donotexplode` with earlier, same-hop, and later `exploded` reports.
- Complete history with no later `exploded` remains indeterminate and never
  emits an honored finding without future positive single-recipient evidence.
- Absence of `exploded` does not create replay or recipient-count facts.
- Multiple violations produce deterministic bounded findings without duplicate
  disposition actions.
- Strict, permissive, and testing handling of proven violations.

### Feedback

- Feedback absent, present once, present multiple times, feedhere without
  feedback, one relay, and several relays.
- Same-hop `feedback,feedhere` eligibility.
- Earlier feedback activates later feedhere; later feedback does not
  retroactively activate earlier feedhere.
- Highest eligible authenticated relay sequence selection while higher
  ineligible relay facts are ignored.
- Current-only history remains not evaluated.
- No domain, selector, recipient, nonce, or raw route appears in intent or
  formatting.

### Immutability, Privacy, Fuzz, And Abuse

- Deep-copy tests for every slice-bearing public and internal type.
- Concurrent evaluation and caller mutation under `go test -race`.
- Exact and one-over hop/finding/action limits.
- Finding pre-count exact-limit success and one-below-required narrowed-limit
  no-decision failure, proving no truncation, partial findings, or action.
- Toxic-marker tests across `%v`, `%#v`, errors, examples, and decision
  accessors.
- Fuzz sealed policy facts with valid seeds for all modes, states, flags,
  transitions, DNS testing combinations, and limits.
- Fuzz properties: no panic, deterministic closed output, no input mutation,
  no raw-input leak, exactly one disposition action for a decision, and no
  false `honored` from incomplete history.

### Public Integration

- Public evaluation of library-created RSA and Ed25519 PASS results.
- Public FAIL, PERMERROR, TEMPERROR, DNS testing, and current-scope flags.
- Static provider results carry no invented DNS testing metadata.
- DNS provider metadata affects only eligible policy treatment.
- No duplicate parser, crypto verifier, DNS resolver, or four-state mapper.
- No command, OpenAPI, generated, Milter, datasource, replay, recipe, signing,
  or concrete exporter change.

## Implementation Slices

The ignored prompt pack must decompose implementation into sequential reviewed
slices:

1. Internal policy contracts, limits, config, errors, and closed base matrix.
2. Verify-owned parsed target-flag candidate, authenticated hop-fact model,
   complete pre-retention key facts, and exhaustive service projection sealing.
3. `donotmodify`, `donotexplode`, and `exploded` compliance evaluation.
4. Feedback/feedhere intent plus exact DNS `t=y` eligibility/reason treatment.
5. Action planner, public immutable facade projection, no-reparse bridge, and
   current-verifier integration.
6. Negative, abuse, fuzz, privacy, immutability, and race coverage.
7. Documentation, examples, final evidence, independent review, and closeout.

Every slice receives live draft/RFC oversight and mandatory independent review.
Findings are fixed at their root and re-reviewed before the next slice. Slices
are not committed separately. One project-format commit is created only after
the final unchanged diff and all required gates converge.

## Required Gates

Use focused tests and root Make targets. Before the increment commit:

```text
go test ./lib/internal/policy/...
go test ./lib/internal/service/...
go test ./lib/...
go test -race ./lib/...
go vet ./lib/...
make test
make vet
make lint
make race
make guardrails
git diff --check
git diff --cached --name-only
```

Enumerate and run every new fuzz target separately for a bounded smoke period.
The external vulnerability scan must not be reported successful unless it
actually completes; a blocked scan requires the repository's documented
maintainer-exception process.

## Review Requirements

Independent normative/mail and security/architecture reviewers inspect the
full diff and surrounding ownership boundaries. Review must cover:

- Draft-04 flag meaning, later-hop ordering, SHOULD-level rejection, feedback
  ambiguity, and four-state preservation.
- DNS-04 `t=y` treatment and its strict separation from local testing mode.
- Proof that unauthenticated flags cannot influence decisions.
- Current-scope `not_evaluated` fidelity and no false historical success.
- Exhaustive mode/state/violation/testing matrices and precedence.
- One-way package graph, single mapping owners, immutable public values, and
  bounded allocations.
- No raw message, identity, key, route, or provider leakage.
- Test quality, generated/cmd scope, documentation, and final evidence.

Post-review changes invalidate approval. The final diff hash is rechecked and
re-approved before staging. Ignored `temp/` artifacts are never staged.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | medium |
| Estimated wall-clock effort | 2 to 4 hours |
| Highest-risk area | authenticated flag provenance, DNS testing semantics, and policy/result separation |
| Expected prompt count | 7 sequential prompts |
| Required final gate | `make guardrails` |

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| Prompt 01 | 2026-07-11T13:08:14+02:00 | 2026-07-11T13:22:28+02:00 | 14m14s | not separately tracked | Contracts and base matrix approved. |
| Prompt 02 | 2026-07-11T13:23:38+02:00 | 2026-07-11T13:55:15+02:00 | 31m37s | not separately tracked | Authenticated projection and service seam approved. |
| Prompt 03 | 2026-07-11T13:56:23+02:00 | 2026-07-11T14:07:14+02:00 | 10m51s | not separately tracked | Do-not compliance approved. |
| Prompt 04 | 2026-07-11T14:08:34+02:00 | 2026-07-11T14:27:46+02:00 | 19m12s | not separately tracked | Feedback and DNS testing approved. |
| Prompt 05 | 2026-07-11T14:28:03+02:00 | 2026-07-11T14:53:54+02:00 | 25m51s | not separately tracked | Public facade, actions, and retention root fix approved. |
| Prompt 06 | 2026-07-11T14:56:04+02:00 | 2026-07-11T15:22:12+02:00 | 26m08s | not separately tracked | Abuse, fuzz, privacy, race, and permanent-precedence hardening approved. |
| Prompt 07 | 2026-07-11T15:23:06+02:00 | 2026-07-11T15:50:46+02:00 | 27m40s | not separately tracked | Documentation, DNS-04 literal correction, final proof, and exception-scoped handoff completed. |

Measured prompt wall-clock totals are 2h35m33s. The overall elapsed interval
from Prompt 01 start through Prompt 07 content freeze is 2h42m32s, including
6m59s between prompts. Active engineering and reviewer-waiting time were not
tracked separately. The result is within the original 2-to-4-hour planning
estimate. The estimate held because the increment remained library-only and
reused the existing parser, verifier, service, and DNS provider boundaries;
the highest-risk work was the final literal DNS-04 `t=y` reconciliation.

## Completion Evidence

- Focused policy, verify, service, and root tests passed with
  `go test ./lib/internal/policy/... ./lib/internal/verify/... ./lib/internal/service/... ./lib/...`.
- Service/public integration tests passed, including real RSA and Ed25519,
  target-unavailable, authenticated flags, all-set DNS testing, post-key
  permanent failures, and presentation-retention independence.
- Final fuzz proof passed separately after the last behavior change:
  `FuzzSealedPolicyEvaluation` ran for 10 seconds with 143,600 executions, and
  `FuzzEvaluatePolicySealedResults` ran for 10 seconds with 74,877 executions.
- `go test -race ./lib/...` and `make race` passed for every library package and
  command module.
- `go vet ./lib/...`, `make test`, `make vet`, and clean-cache `make lint`
  passed; golangci-lint reported zero issues in all modules.
- `make guardrails` passed formatting, vet, lint, tests, race tests, and OpenAPI
  presence checks, then stopped only when `govulncheck` could not resolve
  `vuln.go.dev` inside the sandbox. The required escalated `make govulncheck`
  attempt was rejected by the platform because its usage limit was exhausted
  until 17:42. No successful M7 vulnerability scan is claimed.
- The maintainer granted a narrow exception for this local M7 milestone commit
  only. There are no dependency or `go.mod` changes, and the preceding M6
  closeout completed a clean vulnerability scan. Publishing `main` or any `v*`
  tag still requires a fresh successful `govulncheck`; this exception does not
  waive repository publication policy.
- Normative/mail and security/architecture content reviews have no unresolved
  finding. Their final approvals are bound to the reproduced full snapshot hash
  recorded in the handoff; no post-approval tracked edit is required.
- Recursive package/import guards and final scope inspection found no command,
  OpenAPI, generated, Milter, datasource, recipe, replay, signing, or concrete
  exporter change.
- `git diff --check` passed. `temp/` is ignored, the cached diff is empty, and
  the final handoff remains intentionally unstaged.
- Commit: ready for the containing milestone commit under the M7-only
  vulnerability-scan exception; root stages and commits without content change.

### Completion Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Policy engine and durable M7 spec only | Library policy, provenance seams, tests, docs, and no later runtime scope | done | Command/OpenAPI/generated diff is empty. |
| Behavior | Draft-04 and DNS-04 policy semantics with immutable four-state verification | Closed modes/actions, later-hop flags, literal testing-signer continue treatment, exact post-key rows | done | Verification state is never rewritten. |
| Tests | Unit, matrix, integration, abuse, fuzz, race, vet, lint | All local suites and two final 10-second fuzz targets passed | done | Final fuzz evidence follows the last behavior change. |
| Security | Authenticated, fail closed, bounded, immutable, secret-safe | Provenance, hard limits, allocation cap, mutation/race, toxic formatting, and package graph pass | partial | External vulnerability database scan is excepted only for this local commit; no scan success claimed. |
| Boundaries | Single owners and one-way library graph | Verify candidate, service sealing, policy evaluator/action, root facade remain distinct | done | Public retention never narrows sealed evidence. |
| Review | Live normative oversight plus independent security/architecture review | No unresolved content finding; exact-hash approvals recorded in final handoff | done | Any content change invalidates approval. |
| Time | Exact prompt timing and estimate comparison | 2h35m33s prompt total; 2h42m32s elapsed; within 2-to-4-hour estimate | done | Active/waiting time not separately tracked. |

## Acceptance

- The original four-state verification result remains authoritative and
  unchanged.
- Strict, permissive, and testing behavior matches the closed matrices.
- Strict is the default; invalid configuration and incoherent input fail
  closed.
- Only authenticated facts can affect policy, feedback, or exploded findings.
- Current-only verification reports historical compliance as not evaluated.
- Later-hop `donotmodify` and `donotexplode` semantics match draft-04 without
  treating header additions or same-hop flags as automatic violations.
- Feedback/feedhere output is bounded intent only and leaks no route identity.
- DNS `t=y` is applied conservatively according to DNS-04 and never selects
  local testing mode or rewrites protocol state.
- Action plans contain exactly one closed disposition action and no adapter-
  specific mutation.
- Types are immutable, deterministic, bounded, race-free, and secret-safe.
- Unit, integration, negative, abuse, fuzz, race, and documentation tests pass.
- No later-scope recipe, replay, signing, datasource, daemon, OpenAPI, CLI,
  Milter, Exim, or exporter behavior is added.
- Independent reviews have no unresolved finding.
- All non-excepted guardrail subgates converge, the M7-only vulnerability-scan
  exception remains explicit, ignored prompt artifacts remain unstaged, and
  one structured project-format commit records the increment.

## Decisions And Open Questions

- Settled: policy verdicts never rewrite verification states.
- Settled: strict is the secure default; permissive and testing are explicit.
- Settled: current-only history is not evaluated, not honored.
- Settled: only authenticated flag facts influence policy.
- Settled: same-hop request/report pairs are not later-hop violations.
- Settled: header additions alone do not violate `donotmodify`.
- Settled: `feedhere` without an earlier or same-hop feedback request is inert;
  the highest eligible authenticated feedhere sequence is the local
  nearest-relay interpretation, and later feedback is not retroactive.
- Settled: `exploded` is a report, not replay proof.
- Settled: DNS `t=y` and local testing mode are independent.
- Open: recipe/full-chain work must define how authenticated transition facts
  are minted from reconstructed historical states.
- Open: the working group may define feedback transport and routing, replacing
  the local nearest-relay interpretation.
- Open: the working group should clarify selector-level disagreement for a
  DNS declaration described as domain-wide.
- Open: DNS `t=s` remains metadata until the drafts reconcile it with numeric
  signature `i=`.
