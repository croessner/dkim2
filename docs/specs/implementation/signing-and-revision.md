# DKIM2 Signing And Revision

Status: implemented; independently reviewed.

This specification defines the public-library signing and revision boundary for
Originators, unchanged Forwarders, and Revisers. It covers deterministic
`Message-Instance` and `DKIM2-Signature` generation, exact hash gating,
chain-of-custody continuity, opaque private-key callbacks, and atomic immutable
message output. It deliberately stops before datasource-backed profile lookup,
service integration, and mail-server adapters.

## Source Documents

This specification is governed by:

- `AGENTS.md`.
- `POLICY.md`.
- `docs/ARCHITECTURE.md`.
- `docs/specs/spec-and-prompt-template.md`.
- `docs/specs/implementation/raw-message-model.md`.
- `docs/specs/implementation/dkim2-tag-parsers.md`.
- `docs/specs/implementation/canonicalization-and-hashes.md`.
- `docs/specs/implementation/static-key-signature-verification.md`.
- `docs/specs/implementation/mvp-core-verification.md`.
- `docs/specs/implementation/policy-engine.md`.
- `docs/specs/implementation/recipe-application.md`.
- `docs/specs/implementation/recipe-generation.md`.
- [draft-ietf-dkim-dkim2-spec-04](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-04), especially role Sections 2.1 through 2.6 and Sections 3, 6, 7, 8, 9, 13, 14, and 16.
- [draft-chuang-dkim2-dns-04](https://datatracker.ietf.org/doc/html/draft-chuang-dkim2-dns-04) only for selector-to-public-key-record compatibility.
- RFC 4648 for canonical padded Base64.
- RFC 5321 for SMTP reverse-path and forward-path syntax.
- RFC 5322 for message and header-field framing.
- RFC 8017 for RSA PKCS #1 v1.5.
- RFC 8032 for PureEdDSA Ed25519.
- `Makefile`.

The implementation baseline is exactly `draft-ietf-dkim-dkim2-spec-04`.
Versioned vectors and interpretation tests must name that version. A later
draft is not an implicit behavior update. If any governing source conflicts
with this document, implementation stops until durable documentation and
versioned evidence agree.

Draft-04 Sections 14 and 16 are currently `TBA`. The EAI and security defaults
in this document are therefore explicit restrictive local policy, not
normative text attributed to those empty draft sections.

## Original Gap

The library currently parses immutable raw messages, parses and validates
DKIM2 fields, computes Section 6 hashes and Section 9.6 verification input,
verifies current signatures, evaluates local policy, applies recipes, and
generates deterministic inverse recipe JSON. It does not yet:

- decide the Section 9.1 hash gate;
- construct or render a `Message-Instance` or `DKIM2-Signature` field;
- progress `m=` and `i=` values for a new signing operation;
- sign with RSA-SHA256 or Ed25519-SHA256 through an opaque private-key handle;
- append a signature while proving ordinary or `nd=` chain continuity;
- issue a sealed, exact-input capability suitable for revision signing;
- insert generated fields into an immutable RFC 5322 message; or
- expose signing through the same root `lib/` facade as verification.

The existing verifier also lacks one draft-04 Section 9.4 rule: for each
ordinary signature after `i=1`, the new `mf=` domain must relaxed-match at
least one `rt=` domain from the immediately preceding ordinary signature.
Signing must not copy that omission into a second chain implementation.

## Goal

Implement one cohesive, fail-closed signing flow that:

- creates `m=1` and `i=1` for an Originator;
- lets an unchanged Forwarder add only `i=highest+1`, referencing the unchanged
  highest `m=`;
- requires a Reviser whose current SHA-256 header or body hash differs to add
  exactly one `m=highest+1` with the M9 inverse recipe;
- adds no `Message-Instance` when both current SHA-256 hashes equal the highest
  recorded hash tuple;
- adds exactly one ordinary or terminal-`nd=` `DKIM2-Signature` per operation;
- validates all old and new custody transitions with one shared state machine;
- can create, continue, or complete a terminal `nd=` transition only through
  explicit, exact, closed out-of-band authorization and a mandatory acceptance
  restriction;
- generates one or both baseline algorithms with distinct selectors;
- keeps private keys behind context-aware opaque callbacks;
- returns complete immutable RFC 5322 bytes only after every check, callback,
  self-verification, and insertion proof succeeds; and
- never accepts a bare public PASS result as revision authority.

Correctness is byte-oriented. Raw RFC 5322 bytes and SMTP envelope bytes are
separate evidence. Existing protocol fields are preserved byte-for-byte.
Message content is never inferred from MIME, address, or Unicode models.

## Delivery Shape

Implementation should be split into focused, independently reviewable slices:

1. Add rendering contracts, limits, immutable output, and typed errors.
2. Add the shared ordinary/`nd=` custody state machine and repair verification.
3. Add sealed full-revision verification plus OOB, policy, and disclosure
   authorization capabilities.
4. Add exact hash gating, progression, M9 recipe integration, and ordinary/
   terminal-`nd=` field plans.
5. Add opaque key handles, deterministic multi-algorithm signing, and
   cryptographic self-verification.
6. Add raw-message insertion, public facade integration, and atomic proof.
7. Add draft-versioned vectors, negative/abuse/fuzz/race/privacy tests, docs,
   complete guardrails, and independent exact-snapshot review.

No prompt pack is part of this specification-preparation change. Any later
prompt pack belongs under ignored `temp/` and must never be staged.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 4 to 8 hours |
| Highest-risk area | custody authorization, exact-input capability binding, atomic multi-key signing |
| Expected prompt count | 7 to 9 |
| Required final gate | `make guardrails` |

Risk notes:

- Low risk: SHA-256 calculation and padded Base64 through existing owners.
- Medium risk: deterministic rendering, raw insertion, immutable facade types,
  and callback error classification.
- Highest risk: closing the ordinary-chain verifier gap, terminal `nd=` trust,
  policy restrictions, exact recipe direction, and preventing partial or
  unauthorized external-forward output.

Measured specification-preparation effort:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| Durable signing and revision specification | 2026-07-13T14:22:22+02:00 | 2026-07-13T15:12:17+02:00 | 49m55s | not separately tracked | Official draft text, current repository contracts, and two independent review passes completed; no implementation or prompt pack |
| Implementation prompt 01 | 2026-07-13T15:48:08+02:00 | 2026-07-13T17:03:30+02:00 | 1h15m22s | not separately tracked | Rendering contracts, limits, immutable outputs, and typed errors |
| Implementation prompt 02 | 2026-07-13T17:04:40+02:00 | 2026-07-13T18:02:35+02:00 | 57m55s | not separately tracked | Shared custody validation and verification repairs |
| Implementation prompt 03 | 2026-07-13T18:03:18+02:00; resumed start unavailable | 2026-07-23T10:51:46+02:00 | unavailable; resumed start was not retained and is not inferred | not separately tracked | Sealed revision verification and exact-input capability work |
| Implementation prompt 04 | 2026-07-23T10:53:35+02:00 | 2026-07-23T12:43:44+02:00 | 1h50m09s | not separately tracked | Route, policy, authorization, and publication capabilities |
| Implementation prompt 05 | 2026-07-23T13:12:12+02:00 | 2026-07-23T13:39:39+02:00 | 27m27s | not separately tracked | Hash gate, progression, recipe integration, and deterministic plan construction |
| Implementation prompt 06 | 2026-07-23T13:41:15+02:00 | 2026-07-23T14:58:32+02:00 | 1h17m17s | not separately tracked | Opaque signing, Section 9.6 inputs, self-verification, and multi-algorithm behavior |
| Implementation prompt 07 | unavailable; exact execution start was not retained | 2026-07-23T16:08:35+02:00 | unavailable; the exact start was not retained and is not inferred | not separately tracked | Raw insertion, root facade integration, and immutable result proof |
| Implementation prompt 08 | 2026-07-23T16:09:39+02:00 | 2026-07-23T17:01:30+02:00 | 51m51s | not separately tracked | Next-domain authorization and restricted release |
| Implementation prompt 09 | 2026-07-23T17:04:45+02:00 | 2026-07-23T17:59:48+02:00 | 55m03s | not separately tracked | Draft-versioned vectors, fuzzing, privacy coverage, documentation, and closeout |

The seven implementation prompts with complete timing total 7h35m04s, already
near the original estimate's upper bound. A complete implementation total
cannot be compared with the 4-to-8-hour estimate because prompts 03 and 07 lack
exact retained start times; neither missing duration is inferred. Review
turnaround is included in wall-clock timings where measurable. No external
blocked time was recorded.

## Scope

In scope:

- Root-library Originator and verified revision/forwarding facades.
- A sealed `VerifiedRevisionInput` bound to exact inbound message and envelope.
- Full relevant cryptographic and custody verification needed to issue it.
- A shared authoritative ordinary/`nd=` chain checker used by verification and
  signing.
- The draft-04 Section 9.4 adjacent ordinary-chain verification fix.
- Section 9.1 SHA-256 hash gating and one-instance-per-operation policy.
- M9 inverse recipe generation and padded `r=` encoding.
- Deterministic instance/signature models, rendering, folding, and insertion.
- RSA-SHA256 and Ed25519-SHA256 signing through opaque handles.
- One- and two-algorithm `s=` sets with distinct selectors.
- Creation, continuation, and completion of terminal `nd=` transitions through
  exact OOB authorization.
- Explicit terminal-`nd=`, policy, and recipient-disclosure authorizations and
  mandatory result restrictions.
- Strict limits, immutable copies, typed bounded errors, and atomic output.
- Unit, integration, versioned-vector, fuzz, abuse, privacy, and race evidence.

Out of scope:

- Datasource lookup or concrete private-key storage.
- Flat-file, LDAP, SQL, KMS, HSM, PKCS #11, or cloud-key providers.
- More than one newly emitted signature field per operation.
- Algorithms other than RSA-SHA256 and Ed25519-SHA256.
- Hash algorithms other than SHA-256.
- SMTPUTF8/EAI envelope signing.
- Daemon, OpenAPI, CLI, Milter, Exim, replay-store, or concrete observability
  integration.
- Transport rewriting, SMTP dot-stuffing, MIME transformations, queue policy,
  recipient routing, or actual network transmission.
- DSN construction or propagation.
- Recipe minimization or compression.

## Protocol, Runtime Or Domain Semantics

### Roles And Inputs

The public facade has three closed entry paths:

1. Originator signing accepts immutable raw RFC 5322 bytes, the exact outgoing
   SMTP envelope, one sealed `RouteCopyPlan`, a validated signing profile, and
   optional bounded signing metadata. It rejects every pre-existing
   `Message-Instance` or `DKIM2-Signature` field.
2. Forwarding/revision signing accepts a sealed `VerifiedRevisionInput`, the
   exact current/revised RFC 5322 bytes, the outgoing SMTP envelope, one sealed
   `RouteCopyPlan`, a validated profile, and any required closed
   authorizations. The role is derived from the hash gate, not trusted from a
   caller-provided label.
3. Next-domain signing accepts a sealed `VerifiedRevisionInput`, the exact
   current/revised bytes, the exact intended SMTP envelope or sealed receiver
   transaction identity, a closed route scope, a validated profile, one
   canonical next domain, one sealed `RouteCopyPlan`, a sealed
   published-next-domain capability, and exact OOB authorization. It emits one
   highest `nd=` signature without `mf=`/`rt=` and returns only a
   `requires_out_of_band_acceptance` result. The resulting
   message may still be sent over SMTP, but only on the bound route whose
   receiver has the prior OOB arrangements needed to accept the otherwise
   unverifiable envelope hop.

Hash equality derives `hash_unchanged_forwarder`; inequality derives
`reviser`. The first name deliberately makes no raw-message-identity claim.
There is no caller option that forces or suppresses a required new instance.
All three paths require one non-reusable copy ticket issued by a finalized
sealed parent fanout plan; there is no unsealed single-copy shortcut.
Originator `exploded` is derived from the parent total exactly like every later
hop.

All byte slices are cloned on entry and access. A zero request, zero
capability, mismatched capability, malformed message, missing required
transport binding, or unsafe option fails before any private-key callback.

### Sealed Revision Verification

`VerifiedRevisionInput` is an opaque root-package value with no public
constructor and no raw-message accessor. A dedicated `VerifyForRevision`
operation evaluates cloned exact inbound RFC 5322 bytes and cloned exact
inbound reverse/forward paths. It returns a separate closed
`RevisionVerification` outcome and, only for the two clean states below, the
sealed capability. It does not wrap, reuse, or reinterpret `VerifyResult`.

Caller/API/context errors return zero outcome, zero capability, and a Go error.
Protocol/provider verification outcomes return the closed outcome, either a
legal capability or zero capability, and nil Go error. Any inconsistent pair
is an internal contract failure. A bare `VerifyResult`, PASS enum, boolean,
caller digest, or externally constructed struct is not a substitute.

The capability is bound to:

- the exact inbound raw bytes;
- the exact inbound envelope bytes and recipient order;
- the active draft version;
- parsed `Message-Instance` and `DKIM2-Signature` sequences;
- successful verification of every existing signature set that is required
  for the custody chain;
- successful current/highest SHA-256 header and body hash checks;
- complete ordinary/`nd=` custody facts;
- every existing signature timestamp passing the existing deterministic
  14-day maximum-age and future-tolerance policy, not only the highest target;
- authenticated `donotmodify`, `donotexplode`, and `exploded` facts; and
- whether the only unresolved condition is a cryptographically clean terminal
  `nd=` requiring out-of-band authorization.

Issuance does not claim that every historical message body was reconstructed;
that can be impossible after explicit `b:null`. Before that point, every
existing `r=` is strictly parsed and applied in sequence and every available
historical hash is proved; malformed recipes, failed application, wrong
history hashes, or undeclared unavailable body state prevents sealing. After
`b:null`, unavailable older body proof is represented explicitly rather than
invented. The capability still proves every existing signature over protocol
fields, the current/highest message hashes, sequence/reference integrity, and
the complete custody structure relevant to appending a hop.

Within every existing signature field, every known supported signature set
must pass. Unknown sets in a mixed field are ignored as draft extensions, but
a field with no supported set is unsupported-only and prevents capability
issuance. All-hop verification is subject to hard/narrowable total field, set,
lookup, canonical-work, and provider-call budgets.

The normal capability state is `verified`. A second closed state,
`terminal_next_domain_authorization_required`, may be issued only when every
cryptographic and structural check passes and the sole non-PASS condition is
the current highest `nd=`. No capability is issued for any other FAIL,
PERMERROR, TEMPERROR, ambiguity, unsupported-only signature set, or provider
contract failure.

When consumed, the coordinator compares the capability's protected binding to
the exact pre-revision state and rejects mismatch in constant time where a
digest is used. The capability privately retains cloned exact previous raw
bytes, envelope, bounded verified facts, and an internal seal. That seal uses a
versioned, domain-separated transcript with explicit presence markers and
length/count prefixes for every byte string, path, field, and fact; ambiguous
concatenation is forbidden. Current content may legitimately differ during a
revision. Only every inherited protocol field must match the sealed inbound
field bytes, order, occurrence, case, and folding exactly. Addition, deletion,
reordering, refolding, or replacement of an inherited protocol field is
tampering and fails closed.

Capabilities are not timeless. Consumption rechecks every inherited signature
timestamp against the single captured operation clock using the existing
14-day/future-tolerance policy. A capability issued just before expiry cannot
authorize signing after expiry.

### Exact Section 9.1 Hash Gate

The gate uses `lib/internal/canonical` and exactly SHA-256:

- An Originator with no protocol fields always creates `m=1` with the current
  header and body hashes and no `r=`.
- For a verified existing message, the highest instance must contain exactly
  one usable parser-known SHA-256 tuple. Missing, duplicate, malformed, or
  unsupported-only current hash state fails closed.
- The coordinator computes current/revised header and body hashes from the
  authoritative current raw message.
- If both 32-byte digests exactly equal the highest recorded tuple, no new
  `Message-Instance` is added. This local policy makes the draft's SHOULD NOT
  deterministic.
- If either digest differs, exactly one new instance is mandatory. Its number
  is `highest m + 1`; overflow fails closed.
- A single operation never creates more than one instance even though the
  draft permits a system to do so.

Only the canonical digest comparison decides. Recipe-plan equality, raw byte
equality, MIME interpretation, caller intent, or an excluded-header change
cannot override it.

### Recipe Semantics For A Changed Instance

When the gate requires `m+1`, the coordinator invokes the M9 generator in the
only valid direction:

```text
verified previous state <- apply(recipe, current revised state)
```

The generated decoded JSON must pass M9's parse/apply/semantic and canonical
proof before use. It is encoded with canonical padded Base64 and placed in
`r=`. A whole null recipe and a null header recipe do not exist. Relevant
header unrepresentability fails closed. `b:null` is allowed only through M9's
explicit body-unavailable policy and must remain visible in the result facts.
Limit, cancellation, ambiguity, proof failure, or internal error can never be
converted into `b:null`.

An `m>1` generated by this library always carries `r=`. Hash inequality with a
generation result claiming unchanged is an invariant failure. Hash equality
does not generate or carry a recipe.

### Sequence Continuity

For an Originator, the new values are exactly `m=1`, `i=1`, and the signature
references `m=1`.

For an existing message:

- all `m=` values must be the unbroken sequence 1 through highest;
- all `i=` values must be the unbroken sequence 1 through highest;
- every old signature reference must remain valid;
- unchanged forwarding uses `i=highest+1` and references the existing highest
  `m=`;
- revision uses `i=highest+1` and references the newly created `m=highest+1`;
  and
- integer overflow, zero, gaps, duplicates, or ambiguous raw selection fails
  closed. Historical signatures may reference the instance current at their
  own hop under the settled M4 validity/nondecreasing-order rules; only the
  newly emitted highest signature must reference the highest current/new
  instance.

The baseline emits exactly one new signature field. It never renumbers,
rewrites, removes, or normalizes an existing protocol field.

### Shared Chain-Of-Custody State Machine

`lib/internal/signature` owns one chain checker used by both verification and
signing. There is no verifier-only and signer-only copy.

For every signature in ascending `i=` order:

- exactly one envelope form exists: either `nd=`, or both `mf=` and `rt=`;
- a direct signature's `d=` relaxed-matches its own non-null `mf=` domain by
  exact match or repeated removal of leftmost `mf=` labels;
- the null reverse-path `<>` has no `d=` alignment requirement;
- after an ordinary predecessor, a new ordinary signature's `mf=` domain must
  relaxed-match at least one `rt=` domain from the immediately preceding
  signature; local parts are ignored only for this Section 9.4 domain link;
- after an ordinary predecessor, a new `nd=` signature's `d=` must exactly
  equal one canonical domain from the immediately preceding signed `rt=` set.
  Section 9.3 says the key is associated with a domain in that recipient entry
  but does not define relaxed matching for this transition; exact equality is
  the restrictive local draft-04 interpretation. No labels are stripped from
  either value, and any relaxation requires a reviewed amendment and vectors;
- after an `nd=` predecessor, the next signature's canonical `d=` must exactly
  equal the predecessor's canonical `nd=`;
- an `nd=` run may contain more `nd=` signatures but must terminate in an
  ordinary `mf=`/`rt=` signature unless the highest field is the explicitly
  recognized terminal out-of-band case; and
- the current highest ordinary signature's recorded `mf=` must exactly equal
  the actual reverse-path, and every actual forward-path must occur exactly in
  its signed `rt=` set. Signed extras and order differences are allowed by the
  draft; local parts remain case-sensitive and ASCII domain letters compare
  case-insensitively.

For a new ordinary signature after an ordinary predecessor, the same adjacent
rule is checked against the proposed outgoing `mf=` before signing. When an
ordinary envelope cannot establish that link, the caller must use the closed
next-domain entry; the ordinary entry fails closed.

### Terminal `nd=` Authorization

A cryptographically clean terminal `nd=` capability is not PASS and is not a
generic override. To append the terminating ordinary signature:

- the selected profile `d=` must exactly equal the inherited canonical `nd=`;
- an injected context-aware out-of-band authorizer receives a closed query
  bound to the exact capability, inherited domain, proposed profile domain,
  and operation purpose;
- it returns exactly the closed result `authorized` or `denied` with nil
  error, never a boolean or unclassified string; unavailability is represented
  only by a zero result plus a typed temporary or permanent error; and
- authorization is single-operation evidence and is not retained as a general
  domain trust rule.

The completion signature must use ordinary `mf=`/`rt=` and terminates the
`nd=` run.

The closed next-domain entry performs the inverse transition and may also
continue a draft-04 `nd=` run. It may emit
exactly one highest signature with `nd=` and no `mf=`/`rt=` only when:

- an ordinary predecessor authorizes the profile only when proposed `d=`
  exactly equals one predecessor `rt=` domain under the restrictive shared
  state-machine rule; or an `nd=` predecessor authorizes it only when proposed
  `d=` exactly equals the inherited `nd=`;
- the proposed `nd=` is a validated canonical ASCII DNS name distinct from an
  empty value and has a sealed authoritative published-key capability;
- the exact OOB authorization query binds the verified capability, predecessor
  facts, profile `d=`, proposed `nd=`, published-next-domain capability, exact
  intended envelope/recipient or receiver transaction identity, route scope,
  and the closed purpose `send_terminal_next_domain`; an `nd=` predecessor also
  requires a distinct bound `receive_terminal_next_domain` authorization; and
- all ordinary policy, hash-gate, recipe, key, and atomic-output checks pass.

Its immutable output restriction is exactly
`requires_out_of_band_acceptance`; no unrestricted result is available. This
does not prohibit SMTP delivery: it records the draft-04 requirement that the
receiver use OOB trust/arrangements for acceptance. A later ordinary operation
can consume the resulting
cryptographically clean terminal capability only with exact OOB authorization
and a profile `d=` equal to that `nd=`. This pair of closed operations supports
new imaginary-hop entry, continuation, and exit while still emitting one field
per operation.

The expected verification state immediately after terminal creation or
continuation is the cryptographically clean
`terminal_next_domain_authorization_required`, never ordinary PASS. Only a
later authorized `nd=` to ordinary transition can restore ordinary current-hop
PASS.

The OOB-restricted result privately retains a versioned binding to the
authorized envelope/receiver, copy ticket, and route scope. It has no generic
raw-message accessor; release requires the same sealed authorization or
receiver-transaction capability and atomically consumes the release phase of
that ticket lineage. The DKIM2 field itself cannot
cryptographically bind omitted `mf=`/`rt=` values, so once released the
protocol still relies on the documented OOB receiver arrangement and must not
claim replay prevention outside that arrangement.

### Authenticated Policy Restrictions

Authenticated `donotmodify` and `donotexplode` requests are not silently
converted into permission to forward externally.

- `donotmodify` is evaluated independently of the Section 9.1 hash gate. The
  coordinator compares the verified previous body state and every previous
  header occurrence against the proposed current state. The body hash must be
  unchanged, and every previous header field must remain byte-for-byte present
  in the same relative occurrence order. New fields may be added, but no old
  field, including an unsigned/excluded field, may be removed, rewritten,
  refolded, or reordered. Inherited protocol fields already have the stricter
  exact-preservation rule.
- Any such body or existing-header change under authenticated `donotmodify`
  denies external forwarding even when Section 6 hashes remain equal. A closed
  local-policy authorization may allow signing only with a `local_only`
  forwarding restriction.
- If an authenticated `donotexplode` request applies, producing or authorizing
  multiple copies/recipients for external forwarding is denied. A closed
  local-policy authorization can only yield the same `local_only` restriction.
- The immutable signing result has the strongest effective restriction in its
  closed type. `local_only` and `requires_out_of_band_acceptance` can never be
  converted, asserted, formatted, or unwrapped as unrestricted output.
- Existing authenticated `exploded` state is preserved. The new signature
  adds the `exploded` flag when this operation signs a disclosed multi-recipient
  group or otherwise declares multiple copies.

Authorization consumes a sealed policy result tied to the exact verified
capability and intended route scope. A boolean, mode string, caller-provided
flag, or bare prior `PolicyDecision` cannot waive these restrictions.

### Signing Metadata, Flags, And Multiplicity

`SigningMetadata` is immutable and closed. It contains an optional nonce with
an explicit presence bit and requested baseline flags. Multiplicity is not an
ordinary metadata integer or caller assertion.

Signing occurs only after final fanout planning. A two-level sealed model is
required:

- one finalized parent `RouteFanoutPlan` fixes total distinct multiplicity,
  every intended output message, and each output's disclosure class; after
  sealing it cannot add or omit a copy; and
- the routing authority issues exactly one non-reusable `RouteCopyPlan` ticket
  per output message. The ticket binds its parent, exact reverse/forward paths,
  disclosure-safe `rt=` set, receiver/route scope, copy identity, and the
  parent's total multiplicity.

Before parent allocation or ticket issuance, the library computes for each
output entry a versioned, domain-separated, length/presence/count-prefixed
digest of that copy's exact pre-sign raw bytes and binds it to a closed purpose
(`origin`, `revision`, or `next_domain`). Revision additionally binds the exact
sealed `VerifiedRevisionInput`. The parent entry and its ticket carry that binding;
cross-message, cross-purpose, or cross-capability replay fails closed.

Parent planning is bounded before allocation: at most 128 output copies/tickets,
256 KiB of total canonical parent/ticket descriptor bytes, and 4,096 planning
work units, plus 64 MiB of total unique pre-sign source bytes hashed. Repeated
copies to the same recipient still count separately. Identical copies are
charged once only when they explicitly reference the same immutable source
object; equal contents in separate caller buffers are separate sources and are
charged/hashed separately.

Planning work is charged exactly once per output entry, immutable source
object, reverse path, forward path, disclosure-class declaration, and route
binding. Byte hashing is governed by the separate 64 MiB source budget and
descriptor serialization by the 256 KiB budget; neither is hidden inside an
arbitrary work estimate. Options may narrow only. Every exact-limit succeeds
and one-over fails before the authority is called, allocates, or seals anything.

Each signing operation consumes exactly one copy ticket, never the parent
directly. Bcc-safe fanout therefore uses separate tickets and separately signed
messages without exposing another copy's recipients. Duplicate, extra, stale,
or reused tickets and cross-parent/cross-copy mixing fail closed
where presented to the library. Unknown or underreported total multiplicity fails
closed; a separately authorized local-only parent can produce only
`local_only` results.

`lib/internal/routeplan` is the invariant-owning leaf. An injected
context-aware `RouteFanoutAuthority` is the only issuer/sealer of parent plans,
unique bound copy tickets, and replacement tickets; callers cannot construct,
self-seal, clone, or choose opaque ticket identity. The root package exposes an
immutable bridge without duplicating route invariants.

Each authority method has a method-specific closed success result (`issued`,
`reserved`, `released`, `burned`, `consumed`, or `replacement_issued`) or
`denied`, always with nil error. `released` is the sole state permitting retry
with the same ticket. `burned` irrevocably forbids that ticket's reuse and
permits only explicit same-lineage replacement or final restricted-release
consumption; `consumed` is terminal. Zero result plus the active context error
is control flow; zero result
plus a typed temporary/permanent provider error uses the shared classifier.
Every other pair, typed nil, wrong method status, mismatched binding, alias,
over-budget descriptor, or reused identity is a contract failure. Authority
queries/results and all formatting are redacted. Context is checked before and
after each call. Route-authority calls have a separate hard/narrowable budget
of four per signing/release attempt and do not consume the general four
OOB/policy/feedback-relay/disclosure authorization-callback budget. The
general maximum remains four because a terminal next-domain target has no
ordinary recipient disclosure stage: the maximal `nd` continuation uses
receive-OOB, send-OOB, policy, and feedback-relay, while `nd` completion uses
receive-OOB, policy, feedback-relay, and disclosure.

After zero-callback local preflight, ticket reservation is an atomic authority
operation. Exactly one concurrent caller can move a fresh ticket to reserved;
all others fail closed. Crossing the first external/provider boundary burns the
ticket whether the operation succeeds, is canceled, or later fails, so callback
side effects can never be retried with the same ticket. A retry requires the
authority to issue one replacement bound to the same parent/copy after marking
the burned predecessor; at most one ticket lineage can produce a successful
result. Failures before atomic reservation consume nothing.
Cancellation detected after reservation but before the first external call
atomically releases that reservation because no external side effect occurred.

Independent one-message signing calls cannot atomically prove that every
declared parent ticket was eventually used after earlier bytes were released.
Omitted-ticket completion is therefore an explicit router/adapter orchestration
obligation, not a library success claim. The trusted finalized parent still
prevents multiplicity underreporting in every produced signature, and the
authority prevents duplicate or extra ticket issuance.

Creating an extra copy outside the sealed parent is not authorized by any
result. The library cannot technically prevent an adapter from duplicating or
misrouting returned bytes; adapter contracts and later integration tests must
enforce the retained ticket/parent restriction.

Callers may request only `donotmodify`, `donotexplode`, and `feedback` directly.
`exploded` is derived from the parent total carried by each ticket and emitted
identically on every copy whenever distinct output multiplicity is greater
than one; callers cannot suppress or forge it. `feedhere` is eligible
only when a fully verified prior signature authenticated `feedback` and the
sealed privacy-routing policy authorizes feedback relay through this exact hop.
Unknown flags, caller-requested `exploded`, causally unsupported `feedhere`, or
metadata/ticket/parent disagreement fails before provider callbacks.
When present, generated flags use the fixed order `donotmodify`,
`donotexplode`, `feedback`, `feedhere`, then `exploded`.

Any fully verified prior authenticated `donotmodify` or `donotexplode` flag is
effective, not only a flag on the highest signature. The sealed policy
authorization binds the exact capability, sealed parent and copy ticket,
derived multiplicity, modification facts, intended route scope, and resulting
`unrestricted` or `local_only` restriction.

### Recipient Disclosure And Bcc Privacy

The library cannot infer whether an SMTP recipient was obtained from `To`,
`Cc`, `Bcc`, an alias, or routing policy. The safe public default therefore
permits one outgoing `rt=` value per message copy.

A multi-recipient `rt=` set requires a context-aware recipient-disclosure
authorizer to return closed `authorized` or `denied` for that exact recipient
set and operation. The interface does not return a boolean. Authorization is
checked before key callbacks and is bound to the request and exact copy
ticket. Without it, multiple recipients fail closed. Recipient paths
never appear in errors, observations, or test-failure output.

Duplicate outgoing paths are rejected rather than silently merged. Input order
is preserved in `rt=`; deterministic output means identical validated inputs
produce identical bytes, not that recipient identity is reordered or exposed.

Every OOB, policy, feedback-relay, and disclosure authorizer uses the same exact
return matrix: a declared closed `authorized`/`denied` result with nil error; zero
result with the active context error; or zero result with a typed temporary or
permanent provider error classified by the shared provider classifier. A
declared `unavailable` result does not exist. Typed-nil providers/errors,
zero-plus-nil, result-plus-error, unknown status, wrong
purpose, stale/reused capability, or binding mismatch is a contract failure.

Disclosure queries carry exact cloned paths only across the explicit trusted
authorizer boundary, or carry an opaque route handle when the authority already
owns those paths. They do not expose paths through formatting, generic result
accessors, errors, or observations.

### Published-Key Preconditions

Draft-04 Sections 8.7 and 8.8 require generated `d=` and `nd=` domains to be
names under which DKIM2 key records are published. Syntax or a profile's own
assertion is insufficient.

Before any private-key callback, every generated `s=` credential is checked
through the injected provider-neutral `PublicKeyProvider` using its exact
canonical `(selector, d, algorithm)` tuple. The authoritative found result must
contain public material exactly equal to the credential's immutable public key.
Missing, revoked, invalid, ambiguous, unsupported, algorithm-mismatched,
temporary, permanent, typed-nil, or inconsistent result/error states fail
under the existing closed provider classification. This lookup proves current
publication and catches a private profile that would create an unverifiable
signature; M11 private signing-profile lookup remains a separate concern.

For a newly emitted `nd=`, an explicit publication-issuance operation accepts
one candidate future credential and issues a sealed
`PublishedNextDomainCapability` only after a fresh authoritative lookup proves
the concrete future
`(selector, nd domain, baseline algorithm, public key)` credential. Its public
key evidence is immutable and provider-validated even though the field carries
only the domain. The exact capability is bound into the OOB authorization and
restricted result. A domain-only boolean, DNS-name syntax check, stale profile
claim, or unclassified lookup error cannot authorize `nd=` generation.

The publication capability is operation-scoped, single-use, and has a bounded
freshness interval tied to the exact provider observation. Signing consumes and
revalidates exactly the supplied capability immediately before authorization/
key callbacks. It never silently remints or substitutes it. Expiry, reuse,
missing/revoked/mismatched current publication, or observation drift fails
closed; the caller must explicitly run publication issuance again. OOB
authorization binds the exact supplied capability. It is not a cacheable
assertion that a domain will remain published.

### Algorithms, Profiles, And Opaque Handles

The minimum provider-neutral profile, credential, handle, and signer-service
contracts have one invariant-owning definition in the internal signing/domain
leaf. The root package provides immutable constructors and bridges without a
parallel model. Later datasource providers depend downward on these leaf
contracts; they do not return root facade types. A profile contains:

- one canonical ASCII signing domain;
- one or two credentials;
- exactly one credential per enabled baseline algorithm;
- a distinct canonical selector for every credential;
- matching immutable public verification material; and
- one opaque `PrivateKeyHandle` value per credential.

The credential order supplied by a caller is not output order. The canonical
order is RSA-SHA256 followed by Ed25519-SHA256. Duplicate algorithms,
duplicate selectors, selector/algorithm/key mismatch, zero handles, unknown
algorithms, RSA exponent other than 65537, RSA below 1024 bits, or malformed
Ed25519 public material fails during preflight. RSA above the 8192-bit hard
maximum also fails before provider callbacks.

The signer implementation supports both RSA-SHA256 and Ed25519-SHA256 as the
main draft-04 recommends. A validated profile and one operation may emit one
of them or both together; disabling one in a particular profile does not remove
the implementation's support for it. The DNS-04 draft constrains compatible
key-record lookup/material and does not override the main draft's signer
algorithm requirement.

`lib/internal/cryptodkim2` is the single lower leaf owner of RSA/Ed25519
public-key structure, algorithm matching, RSA exponent/key-size policy,
signature-length rules, and cryptographic verification/self-verification.
DNS decoding reuses only its structural predicates and cloning helpers; it
does not apply verifier or signing policy. Verify and signing reuse the
policy-bearing validation without retaining a copy. As part of this approved
draft-04 conformance repair, ordinary verification as well as signing rejects
an RSA public exponent other than 65537; versioned negative vectors cover the
shared rule.

The handle and callback service are deliberately separate. A handle is an
opaque, immutable, comparable reference with no signing method, key getter,
path getter, or provider metadata. The one context-aware service is
conceptually:

```go
type PrivateKeySigner interface {
    SignDigest(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error)
}
```

The request contains only a closed algorithm identifier and an immutable
32-byte SHA-256 digest. It contains no raw message, envelope, recipe, selector,
domain, private key, key path, provider record, or open-ended `any`. The result
contains only immutable signature bytes and a closed status. The interface has
no private-key getter and does not accept `crypto.Signer` or raw key bytes.

The legal signer return matrix is exact:

- `signed` plus non-empty bounded signature bytes and nil error is success;
- zero result plus the active caller-context error is control-flow
  cancellation;
- zero result plus a typed temporary or permanent provider error is classified
  through the same shared provider classifier used by public-key and
  authorization providers; and
- every other pair, including typed-nil services/errors, declared status plus
  error, zero result plus nil, unknown status, or oversized bytes, is a
  provider-contract failure. The minimal result does not echo an algorithm;
  profile/algorithm/handle coherence is established during preflight.

The service and handles must support concurrent use. All `%v`, `%+v`, `%#v`,
`String`, and Go-syntax formatting of handles, profiles, capabilities, queries,
authorizations, and provider results is explicitly redacted and must not reveal
opaque identity or protected fields.

All pure local parsing, hash gating, recipe proof, inherited-field/chain,
profile/metadata/fanout, transport, sequence, canonical-plan, and exact
field/header/message size checks complete before any provider, authorizer, or
private-key call. Public-key/publication and any required full verification
calls then complete, followed by the OOB, policy, feedback-relay, and
disclosure authorizers in the exact order below, followed by private-key
callbacks in canonical algorithm order. Cancellation is Go control flow only.
Typed temporary/permanent callback failures remain classified; raw causes and
provider strings never cross the boundary.

The coordinator checks the caller context immediately before and after every
provider, authorizer, and private-signing call and honors its deadline. It does
not launch helper goroutines to pretend context-ignoring injected code can be
forcibly canceled. After zero-callback local preflight, deterministic external
order is: atomically reserve the copy ticket; revalidate existing hops in
ascending `i=` order and, within a field, known sets in RSA then Ed25519 order;
validate generated-profile publication in RSA then Ed25519 order; revalidate
the exact supplied next-domain publication capability when applicable; call
`receive_terminal_next_domain` OOB authorization before
`send_terminal_next_domain`; then general policy authorization; then
feedback-relay authorization; then disclosure authorization; then RSA private
signing; then Ed25519 private signing. Feedback-relay is applicable only when
a fully verified prior signature authenticated `feedback`; a caller's newly
requested same-hop `feedback` does not make it applicable. Explicit
feedback-relay denial omits `feedhere` and continues, while callback,
control-flow, or contract failure fails the operation. Inapplicable stages are
skipped and never replaced by dummy calls. Returned provider/signature slices
are cloned before validation and again before retention so aliases cannot
mutate proof or output.

For RSA-SHA256, Section 9.6 bytes are hashed once with SHA-256 and the native
32-byte digest is signed using RSA PKCS #1 v1.5 without truncation or further
conversion. For Ed25519-SHA256, the same 32-byte digest is signed as the
message using PureEdDSA Ed25519; it is not Ed25519ph. Every callback result is
self-verified against the credential's public material before publication.
Failure of any set discards the entire result. Callback side effects cannot be
rolled back, but no partial message or signature set is returned.

### Section 9.6 Input

The signing coordinator does not construct a fake complete signature with a
placeholder signature value. `lib/internal/signature` builds a validated
unsigned target model whose every `s=` signature component has an empty value.
`lib/internal/canonical` accepts that model through a signing-specific seam and
owns the Section 9.6 byte construction.

The canonical input contains, in this exact order:

1. all covered `Message-Instance` fields in ascending `m=` order;
2. all complete prior `DKIM2-Signature` fields in ascending `i=` order; and
3. the incomplete new target last, with every selector and algorithm present
   and every signature value the empty string.

For each field, canonicalization lowercases the field name, unfolds it, deletes
all WSP, and retains the colon and terminal CRLF. The incomplete field receives
the identical treatment. Final padded Base64 signatures replace only the
logical empty `s=` values. Physical FWS may be deterministically reflowed
because non-empty Base64 values require different folding. Every other logical
tag name, tag value, ordering decision, and envelope form remains identical to
the unsigned target.

The final proof reparses the complete field, empties all `s=` values
simultaneously in the structured model, rebuilds Section 9.6 input, and
requires those canonical bytes to equal the exact pre-sign input. The normal
complete-field parser remains strict, and the unsigned model is never emitted.

Multi-algorithm `s=` sets use different algorithms and different selectors.
Unknown algorithms are not generated. Duplicate algorithm or selector sets,
empty final values, mismatched handle results, or output that no longer parses
to the unsigned plan is an invariant failure.

### Deterministic Field Formatting And Folding

The draft permits arbitrary tag order and FWS. This implementation adopts one
local deterministic representation:

- `Message-Instance` tag order is `m`, `h`, then optional `r`.
- Ordinary `DKIM2-Signature` tag order is `i`, `m`, `t`, `mf`, `rt`, `d`,
  `s`, optional `n`, then optional `f`.
- Terminal next-domain signature tag order is `i`, `m`, `t`, `nd`, `d`, `s`,
  optional `n`, then optional `f`; it never contains `mf=` or `rt=`.
- Hash sets contain SHA-256 only.
- Signature sets use canonical algorithm order.
- Decimal integers have no sign or leading zeroes.
- Canonical domains, selectors, algorithm names, tags, and known flags are
  lowercase ASCII.
- Every tag terminates with `;`, every field terminates with CRLF, and no bare
  CR or LF is emitted.

Standard RFC 4648 Base64 is used with canonical zero pad bits and mandatory
trailing `=` padding for `h=`, `r=`, `mf=`, every `rt=` value, and every `s=`
value. Encoding never uses the raw or URL alphabet.

Rendering uses deterministic `CRLF HTAB` folding only at grammar-permitted FWS
positions. Each tag starts on its own continuation line after the first tag.
Comma-list members start at a deterministic continuation boundary. Long
Base64 atoms are split into fixed 64-character chunks separated by
`CRLF HTAB`; decoders ignore that FWS. Tokens, domains, selectors, numbers,
and decoded SMTP path bytes are never split or normalized; only their encoded
Base64 representation may fold. No physical line may exceed 998 octets,
excluding the terminating CRLF as RFC 5322 specifies. The formatter fails if a
legal fold cannot satisfy the hard limit. Byte-exact goldens freeze this local
policy.

Timestamp seconds come from exactly one call to an injected clock per
operation and are rendered as an unsigned decimal integer. A negative,
non-representable, or policy-out-of-range time fails before provider/key
callbacks. The same captured instant drives every all-hop age/future check and
the new `t=` so tests cannot observe clock drift. A supplied nonce is optional,
immutable, at most 64 printable ASCII characters excluding semicolon, and its
presence bit distinguishes absent from a present empty value. It is not
generated implicitly. Known flags use one fixed documented order; unknown
flags are never generated.

### Raw Message Insertion And Transport Form

`lib/internal/rawmsg` owns validated insertion. The coordinator never splices
unvalidated byte offsets itself.

- Every request carries a closed transport-form declaration whose only
  signable value is `final_network_form_pre_dot_stuffing`. It is an explicit
  caller contract that content-transfer and local line-ending conversions are
  complete and SMTP dot-stuffing has not yet occurred.
- Raw RFC 5322 bytes cannot distinguish legitimate body lines beginning with
  two dots from already dot-stuffed wire bytes and cannot predict future
  transport rewriting. The library therefore performs no dot-prefix heuristic
  and makes no impossible byte-only claim. A zero or wrong transport-form
  declaration fails before callbacks; detectable bare CR/LF still fails.
- Existing header fields and any body are copied byte-for-byte. `rawmsg`
  distinguishes a normal message with a header/body separator from a validated
  header-only input. For a normal message, new fields are inserted immediately
  before the existing separator. For header-only input, they are appended after
  the last complete field without inventing a separator or body. In both forms
  generated order is optional new `Message-Instance`, then the new
  `DKIM2-Signature`, each with its own terminal CRLF.
- Empty/header-only framing, an existing separator, and body presence are
  explicit immutable states. Output preserves the input form except for the
  inserted fields; it never silently converts header-only evidence into an
  empty-body message.
- The completed message is reparsed, old protocol field bytes are compared
  again, sequences/references and chain are revalidated, current hashes are
  checked, the new signature sets are verified, and output limits are checked
  before success.

The result internally owns immutable complete RFC 5322 bytes plus bounded
facts: derived role, signature envelope form, new `m=` if any, new `i=`,
algorithms, recipe/body-unavailable state, authorization classes, and the exact
restriction. Its public API is a closed sum:

- `UnrestrictedSignedMessage` alone has a generic byte-copy accessor.
- `LocalOnlySignedMessage` has no generic byte accessor. Release proves that
  the requested destination is the exact same copy ticket's sealed
  in-control route scope, then atomically consumes that ticket lineage's
  release phase. External, changed, cross-ticket, stale, replayed, or unknown
  routes fail closed without bytes.
- `OutOfBandAcceptanceSignedMessage` has no generic byte accessor and uses the
  exact OOB release contract above.

No interface assertion, common embedded byte method, marshal/text method,
format method, zero value, restriction enum rewrite, or helper can downgrade a
restricted result. All variants omit partial fields, unsigned targets, digests,
signature input, callback results, and mutable internal message state.

### EAI And SMTPUTF8

Draft-04 Section 14 is `TBA`, while Sections 8.5 and 8.6 import RFC 5321 paths.
This baseline accepts only the current parser's ASCII bracketed reverse-path
and forward-path grammar. Any non-ASCII envelope path fails closed before
Base64 encoding; there is no Unicode normalization, IDNA conversion, lossy
replacement, or local-part case folding.

Arbitrary valid RFC 5322 message octets remain byte-preserved. SMTPUTF8/EAI
envelope signing is deferred until normative semantics and parser policy are
durably specified and versioned.

## Package Boundaries

### `lib/`

The root package owns the public immutable facade and bridge:

- signer construction and options;
- Originator and revision request constructors;
- `VerifiedRevisionInput` issuance/consumption;
- constructors/adapters for internal provider-neutral profile, handle,
  signer-service, and closed callback contracts without duplicating their
  invariants;
- closed OOB, policy, and recipient-disclosure authorization interfaces;
- closed unrestricted/local-only/OOB signed-message result variants and their
  route-bound release capabilities; and
- mapping internal typed errors to bounded public errors.

Public APIs must not expose `lib/internal` types, generated DTOs, mutable
slices, raw private keys, `crypto.Signer`, or `any`.

### `lib/internal/signing`

A new cohesive coordinator owns operation ordering, exact gate decisions,
progression, authorizations, preflight, callback sequencing, atomic assembly,
and final proof. It also owns the single internal profile/credential/opaque
handle/signer-service contracts consumed by provider leaves. It does not parse
tags, implement canonicalization, serialize
recipes, format fields, mutate raw bytes directly, resolve datasource records,
or construct exporters.

### Existing Owners

- `lib/internal/instance` owns instance construction, hash/recipe invariants,
  and deterministic `Message-Instance` rendering.
- `lib/internal/signature` owns unsigned/complete signature construction,
  deterministic rendering, sequence/reference rules, and the one shared
  ordinary/`nd=` custody state machine.
- `lib/internal/canonical` owns Section 6 hashes and the Section 9.6
  signing-input seam over a structured unsigned target.
- `lib/internal/recipe` owns deterministic decoded inverse JSON and its proof.
- `lib/internal/rawmsg` owns parser truth and validated field insertion.
- `lib/internal/cryptodkim2` is the shared leaf for key validation and
  signature verification/self-verification used by verify and signing.
- `lib/internal/routeplan` owns fanout authority contracts, parent/copy
  invariants, atomic ticket state, and replacement lineage; it does not claim
  cross-operation delivery completion.
- `lib/internal/verify` verifies all facts needed to issue a sealed revision
  capability and reuses signature-owned custody logic.
- `lib/internal/policy` derives sealed signing restrictions from authenticated
  flags; it does not sign or mutate messages.

M11 provider implementations are leaf dependencies on internal datasource and
signing contracts. They do not import the root facade, and protocol/coordinator
packages do not import concrete providers.

Import direction must remain acyclic. In particular, instance/signature/recipe/
canonical/rawmsg do not import the coordinator or root package. The standalone
library gains no Cobra, Viper, Fx, OpenAPI, Prometheus, OTLP, Milter, LDAP, SQL,
Valkey, KMS, or CLI dependency.

### Command Modules

- `cmd/dkim2d`: no work in this increment.
- `cmd/dkim2-milter`: no work in this increment.
- `cmd/dkim2ctl`: no work in this increment.

Generated REST DTOs remain at HTTP boundaries and are not changed.

## Limits And Usage

Signing reuses existing hard maxima and adds only explicit narrowing options.
Defaults must cover at least:

| Resource | Default/Hard Policy |
| --- | --- |
| Raw input/output message | existing 32 MiB hard maximum |
| Raw header block | existing 1 MiB hard maximum after insertion |
| Existing Message-Instance fields | 128 hard maximum |
| Existing signature fields/hops | 128 hard maximum |
| Total DKIM2 protocol fields | 256 hard maximum |
| Existing instance hash sets | existing 16 maximum |
| Signature sets | 16 per field, 256 total per full-chain operation; generation maximum 2 |
| Public-key lookups | 256 total per full-chain operation |
| Total canonical work | 64 MiB across one full-chain operation |
| Authorization callbacks | 4 total; every purpose counted |
| Private signing callbacks | generation maximum 2 |
| Generated outgoing recipients | 128 hard maximum; disclosure default 1 |
| Parent output copies/tickets | 128 hard maximum |
| Parent/ticket descriptor bytes | 256 KiB total hard maximum |
| Fanout planning work units | 4,096 hard maximum |
| Unique pre-sign source bytes hashed | 64 MiB total hard maximum |
| Route-authority calls | 4 per signing/release attempt |
| Total decoded outgoing envelope paths | 32 KiB signing-subset maximum |
| Nonce | draft maximum 64 ASCII characters |
| Signature input | existing 2 MiB maximum |
| Generated decoded recipe JSON | 45 KiB signing-subset maximum |
| Generated protocol field | existing 64 KiB maximum including folding |
| RSA verification/signing policy | 1024 through 8192 bits; exponent exactly 65537 |
| Private callback signature bytes | 1024 maximum |
| Ed25519 public/signature | exactly 32/64 bytes |
| New instance fields | 0 or 1 |
| New signature fields | exactly 1 |
| Physical field line | 998 octets excluding CRLF |
| Recipe generation/application | existing M8/M9 limits and usage accounting |

Options may narrow but never widen hard maxima. Counts and byte budgets are
checked before allocation where possible and again on final output. Arithmetic
uses checked addition. Overflows, excessive folding, excessive callback
output, or a result larger than the configured output limit fail closed.

The signing subset is intentionally narrower than some component limits. M9
can generate 49,152 decoded JSON bytes, but that becomes 65,536 Base64 bytes
before folding and cannot fit the 64 KiB field limit. Signing therefore caps
decoded recipe JSON at 45 KiB and still computes exact padded-Base64, FWS,
other-tag, field-name, and CRLF size before callbacks. Likewise, a count limit
of 128 generated recipients is not evidence that their encoded `rt=` value fits: the
32 KiB decoded-envelope budget and exact fully rendered signature-field budget
must both pass.

Preflight computes coherent exact sizes for the instance field, unsigned and
worst-case complete signature field (RSA length from the modulus, Ed25519 fixed
length), final header block, and final message. Exact-limit succeeds and
one-over fails before callbacks. Sequence validation is O(n) over bounded
collections. After origin and duplicate checks, a valid contiguous sequence
has `highest == count`; values greater than the bounded possible sequence and
`MaxUint64` are rejected before iteration. Code never loops from 1 to an
attacker-supplied high value.

## Error Contract

Errors are typed and bounded. They identify only a closed phase, class, safe
algorithm enum, sequence/instance number, count, or limit name. Expected codes
include invalid request/options, capability mismatch, malformed input,
protocol tampering, sequence/reference failure, hash-state ambiguity, chain
failure, authorization denied/unavailable, policy restriction, disclosure
denied, unsupported algorithm, key mismatch, callback temporary/permanent,
cryptographic self-check failure, limit exceeded, and internal
invariant failure.

Caller context cancellation and public API misuse return no result and a Go
error. Protocol, authorization, provider, and signing failures return no
partial message. Classification never parses error text. Unknown callback
errors are provider-contract failures, not temporary by assumption.

## Security And Privacy

- Ambiguous message, hash, sequence, custody, authorization, key, or policy
  state fails closed.
- No private key bytes enter library requests, results, errors, logs, traces,
  metrics, REST/CLI output, fixtures, or durable documents.
- No raw message/body, header value, recipe JSON, canonical input, digest,
  signature bytes, selector, domain, nonce, envelope path, recipient, key path,
  provider record, or capability binding enters diagnostics.
- A private signer invocation receives only the opaque handle argument plus a
  request containing the closed algorithm and 32-byte digest.
- All input/output/accessor slices are cloned; returned results share no
  caller-owned or provider-owned mutable storage.
- No package-level mutable state, global clock, global key registry, or global
  authorization cache is introduced.
- Authorization is operation-bound, context-aware, closed, and non-boolean.
- Multi-recipient disclosure is denied by default.
- Authenticated modification/explosion restrictions cannot be silently lost at
  the signing boundary.
- Preflight happens before secret-key use. All generated signatures are
  self-verified and the final message is reparsed before return.
- Tests use generated or synthetic keys and identities only. Failure messages
  use secret markers to prove redaction.

## Observability

This increment emits no observation events and adds no logger, exporter,
metric registry, span provider, debug output, or global telemetry state.
Concrete and library-safe signing observations are deferred to M15 so their
cardinality and redaction contract is reviewed once rather than inferred from
protocol results. Result facts are domain output, not telemetry. Domains,
selectors, key/handle identifiers, message/envelope data, nonces, signatures,
digests, raw errors, capabilities, and route bindings remain forbidden from
incidental diagnostics.

## Required Tests

### Unit Tests

- Originator creates exactly `m=1` and `i=1`; pre-existing protocol fields are
  rejected.
- Equal SHA-256 tuples add no instance; header/body mismatch each add exactly
  one instance with correct current hashes.
- Changed state produces the inverse M9 recipe; wrong direction, no-recipe,
  header-unrepresentable, unauthorized `b:null`, and proof failures fail.
- `m=`/`i=` gaps, duplicates, overflow, ambiguous selection, bad references,
  and old-field byte changes fail before callbacks.
- A positive multi-revision chain retains historical references such as
  `i=1` to `m=1`, `i=2` to `m=2`, and a new `i=3` to `m=3`; inherited
  references are not incorrectly forced to the final highest instance.
- The shared chain state machine covers ordinary-to-ordinary adjacency,
  ordinary-to-`nd`, `nd` runs, exact `nd`-to-`d`, termination, null reverse
  path, relaxed label direction, and terminal authorization.
- Existing verification gains the adjacent ordinary-chain rejection and uses
  the same checker as signing.
- A bare PASS/`VerifyResult`, wrong message, wrong envelope, changed order, or
  forged/zero capability cannot authorize revision.
- `VerifyForRevision` checks every hop's known sets, rejects unsupported-only
  fields, ignores unknown sets only beside passing known sets, enforces every
  timestamp, and strictly proves recipe history until explicit `b:null`.
- A capability issued just before the 14-day boundary and consumed after it is
  rejected; older-hop expired/future timestamps, one-call clock drift,
  negative time, and non-representable time are covered.
- Terminal `nd=` capability issuance requires all cryptographic facts clean;
  exact OOB authorization and exact profile-domain binding are mandatory.
- Creating a new terminal `nd=` requires an ordinary predecessor, profile `d=`
  exact equality with a predecessor `rt=` domain, exact proposed-next-domain
  OOB authorization, no signature envelope tags, and a mandatory OOB
  acceptance result. Parent/child domain near-misses fail in both directions.
- `nd=` to `nd=` generation requires exact inherited `nd=` to profile `d=`,
  separate receive/send purposes, refreshed published-next-domain evidence,
  and the same exact route binding. Terminal creation/continuation yields the
  clean OOB-required state; authorized `nd=` to ordinary completion yields PASS.
- Generated `d=` publication tests cover missing, revoked, ambiguous,
  algorithm/key mismatch, public-key mismatch, and temporary failure.
  Published-next-domain tests cover expiry, reuse, revocation/removal,
  explicit fresh reissuance after rejection, provider-observation drift,
  selector/key mismatch, and
  intended-envelope/receiver/route replay.
- `donotmodify`, `donotexplode`, `exploded`, local-only restriction, and
  external denial matrices are closed and exhaustive.
- API-shape tests prove only unrestricted output has a generic byte accessor.
  Local-only release succeeds once on the same ticket's sealed in-control
  route; external/wrong/cross-ticket/stale/replayed routes, concurrent double
  release, enum/type downgrade, interface assertion, formatting, and marshaling
  yield no bytes. OOB-restricted output has the symmetric route-bound proof.
- `donotmodify` rejects body change and removal/rewrite/refolding/reordering of
  any prior header occurrence, including excluded headers and hash-equal
  mutations; only additions remain eligible without a local-only override.
- One recipient works by default; two require exact group-disclosure
  authorization; duplicates and secret-bearing diagnostics are rejected.
- Sealed fanout tests cover a positive Bcc-safe separate-copy plan with
  per-copy envelope verification, multiplicity underreport, extra-ticket
  rejection, parent/ticket replay, concurrent double-consume,
  burn-and-explicit-replacement, cross-parent/cross-copy mixing, attempted
  post-result extra copy, stale route, unknown fanout, metadata/ticket
  disagreement, local-only fanout, identical parent-derived `exploded`,
  inherited `donotexplode`, and causally valid/invalid `feedhere`.
- Fanout-bound tests cover 128 copies exact and 129 one-over, descriptor/work
  exact and one-over, 64 MiB unique source bytes exact and one-over, explicit
  shared-source dedup versus equal independent buffers, a huge same-recipient
  copy count, zero allocation/issuance/authority calls on local limit failure,
  exact raw-message digest binding, cross-message/
  purpose/revision-capability replay, every legal/illegal authority result-error
  pair, redaction, context, aliasing, and route-authority call budgets.
- Omitted-ticket completion is tested at the later router/adapter orchestration
  boundary and is not asserted as atomic library behavior.
- Deterministic tag order, folding, 64-character Base64 chunks, CRLF framing,
  padded output, and 998-octet enforcement have byte-exact tests.
- RSA-SHA256 uses PKCS #1 v1.5 over the one SHA-256 digest and exponent 65537.
- RSA profile bounds pass at exactly 8192 bits and fail at 8193/one-over before any
  provider/private callback; ordinary verification shares the exponent rule.
- DNS decoding accepts structurally valid RSA records independently of the
  verifier/signing exponent and size policy. Ordinary verification rejects
  exponent 3, 1023-bit, and 8193-bit DNS key material after lookup but before
  signature crypto; exact 8192-bit verification remains covered.
- Ed25519-SHA256 uses PureEdDSA over the same digest and not Ed25519ph.
- Two-algorithm output has canonical order and distinct selectors; duplicates,
  mismatch, partial failure, malformed output, and self-check failure are
  atomic no-result failures.
- Every accessor and request/result boundary is immutable.
- `%v`, `%+v`, `%#v`, `String`, and Go-syntax formatting for every opaque
  handle/capability/query/result is redacted; typed-nil and every illegal
  signer/authorizer result-error pair is rejected.
- Non-ASCII envelopes, bare CR/LF, post-sign mutation, zero/wrong transport
  metadata, and final-message proof failures fail closed. A legitimate
  pre-transport body line beginning with two dots is accepted and preserved.
- Normal and header-only insertion preserve their distinct framing and all
  inherited bytes; the structured unsigned target is never emitted.
- Local one-over field/header/message/recipe/envelope sizes, invalid flags,
  fanout mismatch, malformed chain/transport/profile/plan, and `MaxUint64`
  sequences assert zero provider, authorizer, and private-key calls.

### Integration And Versioned Vectors

- Root-facade Originator, hash-unchanged Forwarder, Reviser, terminal-`nd=`
  creation/continuation/completion, and dual-algorithm flows verify through the
  public verifier with their expected PASS or OOB-required state.
- Draft-04 byte-exact golden vectors cover unsigned target, Section 9.6 bytes,
  rendered fields, final message, RSA, Ed25519, dual signatures, and recipe
  revision.
- Negative vectors cover every custody transition, old-field tampering,
  missing authorization, policy restrictions, recipient disclosure, malformed
  Base64/folding, and algorithm/key mismatch.
- Existing draft-04 verification vectors are updated only where the approved
  Section 9.4 adjacent-chain fix makes an invalid chain correctly fail.
- Property tests prove `parse(render(model))` equivalence and final-message
  verification for generated valid models.

### Abuse, Fuzz, Race, And Privacy

- Fuzz request construction, hash gating, instance rendering, signature
  rendering, custody transitions, unsigned target construction, final
  insertion, and public facade entry points.
- Seed fuzzers with gaps, maximum integers, long foldable Base64, malformed
  paths, duplicate recipients/selectors/algorithms, `nd` chains, and secret
  markers.
- Abuse tests cover 32 MiB input, recipient/signature/field limits, recipe
  expansion, checked arithmetic, hostile callback sizes, cancellation before
  and between callbacks, deadlines, result alias mutation, deterministic call
  order, and context-ignoring fakes without helper-goroutine leaks.
- `go test -race` exercises concurrent reuse of immutable signer, profile,
  capability, requests, authorizers, and concurrency-safe fake handles.
- Privacy tests assert that errors, observations, formatted test failures, and
  result facts contain none of the seeded message, envelope, identity, key,
  signature, nonce, recipe, or capability markers.

### Documentation And Dependency Checks

- All new/changed hand-written named functions and receiver methods have
  concise English doc comments.
- Package docs describe exact ownership and secret boundaries.
- Import/dependency tests keep `lib/` standalone and package direction acyclic.
- No OpenAPI generated artifact changes.

### Validation Commands

During focused development, use root Make targets whenever available. Final
validation is:

```text
make test
make vet
make lint
make race
make guardrails
```

The final gate is `make guardrails`. Exact fuzz commands and durations must be
recorded during implementation closeout.

## Acceptance Criteria

- Originator, hash-unchanged Forwarder, Reviser, and authorized terminal-`nd=`
  creation/continuation/completion follow the settled role and gate rules.
- No hash-equal operation emits a new instance; every hash-different operation
  emits exactly one proved inverse-recipe instance.
- Existing protocol fields remain byte-identical and all progressions are
  contiguous.
- One shared custody checker fixes ordinary adjacency and handles the complete
  ordinary/`nd=` state machine for verification and signing, including
  ordinary-`rt=` authorization of a following `nd=` signer's `d=`.
- Revision requires an exact sealed capability; OOB, policy, and group
  disclosure use closed operation-bound authorization.
- Every restricted result is a closed route-bound type without a generic byte
  accessor; local-only and OOB release prove and consume their exact authorized
  ticket route, and restriction downgrade/external release fails closed.
- RSA, Ed25519, and dual-algorithm output verify; selectors are distinct and
  private keys never cross the handle.
- Formatting, folding, padded Base64, insertion, and output are deterministic
  and immutable.
- Multi-recipient disclosure and EAI envelopes fail closed by default.
- Limits, cancellation, partial callback failure, and tampering return no
  partial message and leak no protected data.
- Versioned vectors, fuzz, abuse, race, privacy, dependency, and full
  guardrails pass.
- Durable docs and code remain English-only and architecture boundaries hold.

## Completion Evidence

- Focused unit and race tests cover rendering, custody, revision capability,
  authorization, hash gating, recipe integration, signing, self-verification,
  raw insertion, facade behavior, and restricted next-domain release.
- Draft-04 versioned vectors cover origin and revised
  `Message-Instance` fields, ordinary RSA and Ed25519 signatures,
  multi-algorithm one-recipient copy and restriction-field rendering,
  next-domain creation/continuation/completion, ordinary revision, and normal
  and header-only insertion.
- All 31 repository fuzz targets passed for at least 10 seconds each. The eight
  signing-closeout targets cover requests, hash gating, instance and signature
  rendering, custody transitions, unsigned targets, insertion, and the public
  facade.
- Abuse, cancellation, nil-interface, cardinality, atomicity, and privacy
  matrices pass. Privacy coverage exercises formatting and marshal attempts,
  callback errors, restricted-result surfaces, and actual protected message,
  envelope, route, and recipient fixture bytes.
- Focused package tests, focused race tests, `make test`, `make vet`,
  `make lint`, `make race`, and `make guardrails` pass. Govulncheck reports no
  known vulnerabilities.
- The library dependency audit remains free of daemon, Milter, OpenAPI, Cobra,
  Viper, Fx, Prometheus, OTLP, SQL, and LDAP dependencies. No concrete
  telemetry was introduced.
- `git diff --check` passes, the intended durable paths are reviewed through an
  exact raw Git manifest, and the ignored prompt pack remains outside staging.
- Skipped checks: none.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Library signing/revision only; later integrations deferred | Implemented in `lib/` with no service or adapter integration | approved | Prompt pack remains ignored and unstaged |
| Protocol | Draft-04 Sections 3, 6, 7, 8, 9 and transport constraints are explicit | Exact fields, inputs, custody, revision, and insertion behavior implemented | approved | Normative and mail-domain implementation review passed; version remains pinned |
| Custody | One complete ordinary/`nd=` checker shared by verifier and signer | Shared custody state machine covers ordinary and terminal next-domain transitions | approved | Includes adjacent ordinary-chain verifier repair and full-chain vectors |
| Security | Sealed exact capabilities, closed authorizations, opaque keys, atomic output | Fail-closed capabilities, authorizations, key handles, callback ordering, and atomic results implemented | approved | Security and restricted-release review passed |
| Privacy | Recipient disclosure default closed; protected values never diagnostic | Restricted result surfaces and aggregate privacy matrices enforce non-disclosure | approved | EAI envelope signing remains deferred |
| Boundaries | Existing owners render/hash/insert; coordinator only orchestrates | Cohesive protocol owners remain internal; root facade is the public boundary | approved | Architecture, DRY, API, and dependency review passed |
| Tests | Unit, vectors, fuzz, abuse, race, privacy, dependencies | Focused tests, versioned vectors, all 31 fuzz targets, race, privacy, and dependency audits pass | approved | Full guardrails pass with no skipped checks |
| Effort | Preparation and implementation timings recorded honestly | Exact retained timings recorded; missing starts remain unavailable | approved | Active time was not separately tracked |

## Decisions And Open Questions

- Settled: the active behavior baseline is draft-04 only.
- Settled: Originator is `m=1`/`i=1`; an existing-message role is derived from
  exact SHA-256 hash comparison.
- Settled: hash equality emits no instance; inequality emits exactly one
  inverse-recipe instance.
- Settled: every operation emits exactly one new signature; the closed
  next-domain entry may emit a terminal `nd=` and must return
  `requires_out_of_band_acceptance`.
- Settled: a cryptographically clean terminal `nd=` may be continued or
  completed only by a profile with matching `d=` plus closed exact OOB
  authorization.
- Settled: ordinary adjacent custody is enforced by one checker shared with
  verification.
- Settled: no bare PASS result authorizes revision; only a sealed capability
  bound to exact message/envelope/full relevant facts does.
- Settled: authenticated policy restrictions and group recipient disclosure
  use closed operation-bound authorization and survive in the result.
- Settled: RSA and Ed25519 may appear together, in fixed order, with distinct
  selectors and atomic self-verified output.
- Settled: private-key access is callback-only; the signer receives the opaque
  handle plus a request containing the closed algorithm and 32-byte digest.
- Settled: deterministic formatting is local policy and is frozen by goldens.
- Settled: ASCII SMTP paths only; RFC 5322 content remains byte-preserved.
- Settled: independent normative, mail-domain, security, and architecture
  review approved this specification before prompt-pack preparation.

## Explicit M11 And Later Deferments

- M11: datasource contracts and provider-backed signing-profile/private-handle
  lookup, including in-memory and flat-file providers plus LDAP/SQL design.
- M12: replay-store contracts, in-memory replay, and Valkey behavior.
- M13: daemon configuration, Fx wiring, OpenAPI server boundary, and HTTP
  signing behavior.
- M14: generated-client `dkim2ctl` workflows and service fixtures.
- M15: concrete `slog`, OpenTelemetry, Prometheus, and exporter integration.
- M16/M17: Milter and Exim envelope capture, EOM timing, action application,
  queue behavior, and fail-closed adapter integration.
- M18: broader external conformance corpus beyond this increment's required
  draft-versioned library vectors.
- M19: repository-wide hardening beyond the focused abuse/fuzz/race/privacy
  evidence required here.
- M20/M21: operator guides, external interoperability, and reference polish.
- Post-signing reviewed amendment: multi-field signing plans or more than one
  imaginary-hop field per operation.
- Post-draft clarification: SMTPUTF8/EAI envelope signing after Section 14 has
  concrete normative semantics and versioned parser/vector policy.

No deferred layer may introduce a parallel signing profile, key handle,
custody checker, field formatter, hash gate, recipe direction, authorization
model, or public signing result. Any change requires a reviewed durable spec
amendment before implementation.
